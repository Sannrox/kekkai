"""changelog-draft.sh in a scratch clone whose origin has final and rc tags."""

import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

from tests.release import ROOT

SCRIPT = ROOT / "scripts" / "changelog-draft.sh"


class ChangelogDraft(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix=f"cld{os.getpid()}-")
        self.addCleanup(tmp.cleanup)
        root = pathlib.Path(tmp.name)
        self.env = {
            **os.environ,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
            "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
        }
        origin, self.work = root / "origin.git", root / "w"
        self.git("init", "-q", "--bare", "-b", "main", str(origin))
        self.git("clone", "-q", str(origin), str(self.work))
        self.git("-C", str(self.work), "checkout", "-q", "-b", "main")
        for subject, tag in (("first", "v0.1.0"), ("feat: a", "v0.2.0-rc.1"), ("fix: b", None)):
            self.git("-C", str(self.work), "commit", "-q", "--allow-empty", "-m", subject)
            if tag:
                self.git("-C", str(self.work), "tag", tag)
        self.git("-C", str(self.work), "push", "-q", "--tags", "origin", "main")
        (self.work / "scripts").mkdir()
        shutil.copy(SCRIPT, self.work / "scripts")

    def git(self, *args: str) -> None:
        subprocess.run(["git", *args], env=self.env, check=True, capture_output=True)

    def test_lists_changes_since_the_last_final_tag_not_an_rc(self):
        result = subprocess.run(
            ["bash", str(self.work / "scripts" / "changelog-draft.sh")],
            env=self.env, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            ["## Unreleased (since v0.1.0)", "", "- fix: b", "- feat: a"],
        )


if __name__ == "__main__":
    unittest.main()
