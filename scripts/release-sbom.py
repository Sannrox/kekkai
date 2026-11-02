#!/usr/bin/env python3
"""Write a CycloneDX 1.5 SBOM from `cargo metadata` (locked workspace)."""

from __future__ import annotations

import json
import subprocess
import sys
import uuid
from pathlib import Path


def cargo_metadata(root: Path) -> dict:
    raw = subprocess.check_output(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
        cwd=root,
        text=True,
    )
    return json.loads(raw)


# Cargo license strings are SPDX expressions (or the legacy "/" form), not
# single SPDX ids, so they go in CycloneDX's free-form `expression`; a
# compound value under `license.id` makes the document invalid, and the
# attestation action rejects it.
def license_entry(raw: str) -> dict:
    return {"expression": " OR ".join(part.strip() for part in raw.split("/"))}


def bom_from_metadata(meta: dict) -> dict:
    workspace = set(meta.get("workspace_members") or [])
    packages = meta.get("packages") or []
    root_pkg = None
    components = []
    for pkg in packages:
        pid = pkg.get("id")
        name = pkg.get("name")
        version = pkg.get("version")
        if pid in workspace and name == "kekkai":
            root_pkg = pkg
        purl = f"pkg:cargo/{name}@{version}"
        component = {
            "type": "library",
            "bom-ref": purl,
            "name": name,
            "version": version,
            "purl": purl,
        }
        if pkg.get("license"):
            component["licenses"] = [license_entry(pkg["license"])]
        if pid not in workspace:
            components.append(component)
    if root_pkg is None:
        raise SystemExit("cargo metadata did not include workspace package kekkai")
    root_purl = f"pkg:cargo/kekkai@{root_pkg['version']}"
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "library",
                "bom-ref": root_purl,
                "name": "kekkai",
                "version": root_pkg["version"],
                "purl": root_purl,
            }
        },
        "components": sorted(components, key=lambda item: item["bom-ref"]),
    }

    # Stable contents produce the same document identity on a rebuild.
    document = json.dumps(bom, sort_keys=True, separators=(",", ":"))
    bom["serialNumber"] = uuid.uuid5(uuid.NAMESPACE_URL, document).urn
    return bom


def self_test() -> None:
    meta = {
        "workspace_members": ["kekkai 0.1.0 (path+file:///workspace/crates/kekkai)"],
        "packages": [
            {
                "id": "kekkai 0.1.0 (path+file:///workspace/crates/kekkai)",
                "name": "kekkai",
                "version": "0.1.0",
                "license": "Apache-2.0",
            },
            {
                "id": "libc 0.2.0 (registry+https://github.com/rust-lang/crates.io-index)",
                "name": "libc",
                "version": "0.2.0",
                "license": "MIT OR Apache-2.0",
            },
        ],
    }
    meta["packages"].append(
        {
            "id": "memchr 2.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
            "name": "memchr",
            "version": "2.0.0",
            "license": "MIT/Unlicense",
        }
    )
    bom = bom_from_metadata(meta)
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["serialNumber"].startswith("urn:uuid:")
    uuid.UUID(bom["serialNumber"].removeprefix("urn:uuid:"))
    assert bom["metadata"]["component"]["version"] == "0.1.0"
    by_name = {component["name"]: component for component in bom["components"]}
    assert by_name["libc"]["licenses"] == [{"expression": "MIT OR Apache-2.0"}]
    assert by_name["memchr"]["licenses"] == [{"expression": "MIT OR Unlicense"}]
    # No license entry may carry a compound value as a single SPDX id.
    for component in bom["components"]:
        for entry in component.get("licenses", []):
            assert "license" not in entry, entry
    print("release-sbom self-test passed")


def main(argv: list[str]) -> None:
    if argv == ["--self-test"]:
        self_test()
        return
    if len(argv) != 1:
        raise SystemExit("usage: release-sbom.py OUT")
    root = Path(__file__).resolve().parent.parent
    bom = bom_from_metadata(cargo_metadata(root))
    out = Path(argv[0])
    out.write_text(json.dumps(bom, indent=2) + "\n")
    print(out)


if __name__ == "__main__":
    main(sys.argv[1:])
