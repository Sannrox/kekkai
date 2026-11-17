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


# The published package name; the library inside it is `kekkai`.
PACKAGE = "kekkai-sandbox"


def bom_from_metadata(meta: dict) -> dict:
    workspace = set(meta.get("workspace_members") or [])
    packages = meta.get("packages") or []
    root_pkg = None
    components = []
    for pkg in packages:
        pid = pkg.get("id")
        name = pkg.get("name")
        version = pkg.get("version")
        if pid in workspace and name == PACKAGE:
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
        raise SystemExit(f"cargo metadata did not include workspace package {PACKAGE}")
    root_purl = f"pkg:cargo/{PACKAGE}@{root_pkg['version']}"
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "library",
                "bom-ref": root_purl,
                "name": PACKAGE,
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


def main(argv: list[str]) -> None:
    if len(argv) != 1:
        raise SystemExit("usage: sbom.py OUT")
    root = Path(__file__).resolve().parents[2]
    bom = bom_from_metadata(cargo_metadata(root))
    out = Path(argv[0])
    out.write_text(json.dumps(bom, indent=2) + "\n")
    print(out)


if __name__ == "__main__":
    main(sys.argv[1:])
