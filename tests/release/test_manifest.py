import json
import pathlib
import tempfile
import unittest

from tests.release import load

manifest = load("manifest")


class GateFlags(unittest.TestCase):
    def test_maps_gate_labels_and_ignores_others(self):
        flags = manifest.gate_flags_from_labels(
            ["risk:breaking", "area:ops", "GATE:mig", "risk:realm", "docs"]
        )
        self.assertEqual(flags, ["breaking", "migration", "realm"])


class BuildManifest(unittest.TestCase):
    def test_refuses_a_short_git_sha(self):
        with self.assertRaisesRegex(SystemExit, "full lowercase SHA"):
            manifest.build_manifest(
                component="kekkai", version="0.1.0", git_sha="deadbeef", tag="v0.1.0",
                dist=pathlib.Path("."), images=[], attestations=[], gate_flags=[],
            )

    def test_lists_only_release_binaries_by_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            dist = pathlib.Path(tmp)
            (dist / "kekkai-0.1.0-x86_64-unknown-linux-gnu").write_bytes(b"bin")
            for name in ("SHA256SUMS", "kekkai-release.json", "kekkai.cdx.json", "RELEASE_NOTES.md"):
                (dist / name).write_text("{}\n")
            doc = manifest.build_manifest(
                component="kekkai", version="0.1.0", git_sha="a" * 40, tag="v0.1.0",
                dist=dist, images=[], attestations=[], gate_flags=["breaking"],
            )
        self.assertEqual(doc["schema"], manifest.SCHEMA)
        self.assertEqual([b["name"] for b in doc["binaries"]], ["kekkai-0.1.0-x86_64-unknown-linux-gnu"])
        self.assertTrue(doc["binaries"][0]["digest"].startswith("sha256:"))
        self.assertEqual(doc["images"], [])

    def test_record_attestations_drops_empty_urls(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "m.json"
            path.write_text(json.dumps({"attestations": [], "component": "kekkai"}))
            manifest.main(["record-attestations", str(path), "https://example.invalid/1", ""])
            doc = json.loads(path.read_text())
        self.assertEqual(doc["attestations"], ["https://example.invalid/1"])
        self.assertEqual(doc["component"], "kekkai")


if __name__ == "__main__":
    unittest.main()
