"""package.sh dry runs against this checkout, with a fake gh for the gate-flag lookup."""

import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

from tests.release import RELEASE, ROOT

SCRIPT = RELEASE / "package.sh"


@unittest.skipUnless(shutil.which("cargo") and shutil.which("jq"), "cargo and jq are required")
class Package(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix=f"pkg{os.getpid()}-")
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        self.dist = self.tmp / "dist"
        self.sha = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
        ).stdout.strip()
        cargo = (ROOT / "Cargo.toml").read_text()
        self.version = re.search(r'(?ms)^\[workspace\.package\][^\[]*?^version\s*=\s*"([^"]+)"', cargo).group(1)

    def package(self, *args: str, gh: str | None = None) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        if gh is not None:
            bin_dir = self.tmp / "bin"
            bin_dir.mkdir()
            (bin_dir / "gh").write_text(f"#!/usr/bin/env bash\n{gh}\n")
            (bin_dir / "gh").chmod(0o755)
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
        return subprocess.run(
            ["bash", str(SCRIPT), "--out", str(self.dist), "--skip-build", "--skip-test",
             "--git-sha", self.sha, *args],
            env=env, capture_output=True, text=True,
        )

    def manifest(self) -> dict:
        return json.loads((self.dist / "kekkai-release.json").read_text())

    def merged_prs(self, prs: list[dict]) -> str:
        path = self.tmp / "prs.json"
        path.write_text(json.dumps(prs))
        return f"cat {path}"

    def test_dry_run_writes_manifest_sbom_and_checksums_without_publishing(self):
        result = self.package("--skip-github")
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = self.manifest()
        self.assertEqual(manifest["schema"], "tenkai.family-release-manifest.v1")
        self.assertEqual(manifest["component"], "kekkai")
        self.assertEqual(manifest["git_sha"], self.sha)
        self.assertEqual(manifest["images"], [])
        self.assertNotIn("latest", json.dumps(manifest))
        self.assertTrue((self.dist / "kekkai.cdx.json").is_file())
        self.assertTrue((self.dist / "SHA256SUMS").is_file())

    def test_tagged_run_writes_the_workspace_versions_changelog_notes(self):
        # A version bump without its CHANGELOG section fails here.
        result = self.package("--skip-github", "--tag", f"v{self.version}")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.dist / "RELEASE_NOTES.md").read_text().strip())

    def test_tag_must_match_the_workspace_version(self):
        result = self.package("--skip-github", "--tag", "v999.0.0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match workspace version", result.stderr)

    def test_gate_flags_come_only_from_pull_requests_merged_into_the_release(self):
        prs = [
            {"mergeCommit": {"oid": self.sha}, "labels": [{"name": "risk:breaking"}, {"name": "docs"}]},
            {"mergeCommit": {"oid": "f" * 40}, "labels": [{"name": "risk:migration"}]},
            {"mergeCommit": None, "labels": [{"name": "risk:realm"}]},
        ]
        result = self.package("--tag", f"v{self.version}", gh=self.merged_prs(prs))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.manifest()["gate_flags"], ["breaking"])

    def test_tagged_run_fails_closed_when_gate_flags_cannot_be_read(self):
        # Empty gate flags would read as a release that passed no gates.
        result = self.package("--tag", f"v{self.version}", gh="echo 'HTTP 403' >&2; exit 1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not list merged pull requests", result.stderr)
        self.assertFalse((self.dist / "kekkai-release.json").exists())

    def test_tagged_run_fails_closed_on_a_truncated_search(self):
        prs = [{"mergeCommit": {"oid": "f" * 40}, "labels": []}] * 1000
        result = self.package("--tag", f"v{self.version}", gh=self.merged_prs(prs))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("gate flags would be incomplete", result.stderr)
        self.assertFalse((self.dist / "kekkai-release.json").exists())


if __name__ == "__main__":
    unittest.main()
