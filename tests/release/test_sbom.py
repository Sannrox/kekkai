import unittest
import uuid

from tests.release import load

sbom = load("sbom")

META = {
    "workspace_members": ["kekkai-sandbox 0.1.0 (path+file:///workspace/crates/kekkai)"],
    "packages": [
        {
            "id": "kekkai-sandbox 0.1.0 (path+file:///workspace/crates/kekkai)",
            "name": "kekkai-sandbox",
            "version": "0.1.0",
            "license": "Apache-2.0",
        },
        {
            "id": "libc 0.2.0 (registry+https://github.com/rust-lang/crates.io-index)",
            "name": "libc",
            "version": "0.2.0",
            "license": "MIT OR Apache-2.0",
        },
        {
            "id": "memchr 2.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
            "name": "memchr",
            "version": "2.0.0",
            "license": "MIT/Unlicense",
        },
    ],
}


class BomFromMetadata(unittest.TestCase):
    def test_names_the_published_package_with_a_serial_number(self):
        bom = sbom.bom_from_metadata(META)
        self.assertEqual(bom["bomFormat"], "CycloneDX")
        self.assertEqual(bom["metadata"]["component"]["purl"], "pkg:cargo/kekkai-sandbox@0.1.0")
        uuid.UUID(bom["serialNumber"].removeprefix("urn:uuid:"))
        self.assertEqual(sbom.bom_from_metadata(META)["serialNumber"], bom["serialNumber"])

    def test_licenses_are_spdx_expressions_the_attestation_accepts(self):
        # A compound value under `license.id` makes the document invalid.
        by_name = {c["name"]: c for c in sbom.bom_from_metadata(META)["components"]}
        self.assertEqual(by_name["libc"]["licenses"], [{"expression": "MIT OR Apache-2.0"}])
        self.assertEqual(by_name["memchr"]["licenses"], [{"expression": "MIT OR Unlicense"}])

    def test_refuses_metadata_without_the_published_package(self):
        with self.assertRaisesRegex(SystemExit, "kekkai-sandbox"):
            sbom.bom_from_metadata({"workspace_members": [], "packages": META["packages"][1:]})


if __name__ == "__main__":
    unittest.main()
