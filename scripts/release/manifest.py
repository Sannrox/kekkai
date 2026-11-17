#!/usr/bin/env python3
"""Emit the family release manifest Tenkai later admits (digests, not tags)."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

SCHEMA = "tenkai.family-release-manifest.v1"
GATE_LABELS = {
    "risk:breaking": "breaking",
    "risk:migration": "migration",
    "risk:realm": "realm",
    "gate:break": "breaking",
    "gate:mig": "migration",
    "gate:realm": "realm",
}


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def gate_flags_from_labels(labels: list[str]) -> list[str]:
    flags: set[str] = set()
    for raw in labels:
        name = raw.strip().lower()
        if name in GATE_LABELS:
            flags.add(GATE_LABELS[name])
            continue
        if name.startswith("risk:breaking") or name == "breaking":
            flags.add("breaking")
        elif name.startswith("risk:migration") or name == "migration":
            flags.add("migration")
        elif "realm" in name:
            flags.add("realm")
    return sorted(flags)


def binaries_from_dir(dist: pathlib.Path) -> list[dict[str, str]]:
    items = []
    for path in sorted(dist.iterdir()):
        if not path.is_file():
            continue
        if path.name in {"SHA256SUMS", "RELEASE_NOTES.md", "kekkai-release.json", "kekkai.cdx.json"}:
            continue
        if path.suffix == ".cdx.json" or path.name.endswith(".intoto.jsonl"):
            continue
        items.append({"name": path.name, "digest": sha256_file(path)})
    return items


def build_manifest(
    *,
    component: str,
    version: str,
    git_sha: str,
    tag: str | None,
    dist: pathlib.Path,
    images: list[dict[str, str]],
    attestations: list[str],
    gate_flags: list[str],
) -> dict:
    if not re.fullmatch(r"[0-9a-f]{40}", git_sha):
        raise SystemExit("git_sha must be a full lowercase SHA")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(-(rc|beta)\.[0-9]+)?", version):
        raise SystemExit(f"invalid version: {version}")
    return {
        "schema": SCHEMA,
        "component": component,
        "version": version,
        "git_sha": git_sha,
        "tag": tag,
        "binaries": binaries_from_dir(dist),
        "images": images,
        "attestations": attestations,
        "gate_flags": gate_flags,
    }


def record_attestations(path: pathlib.Path, urls: list[str]) -> None:
    """Set the manifest's attestation URLs, dropping empty ones."""
    manifest = json.loads(path.read_text())
    manifest["attestations"] = [url for url in urls if url]
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def main(argv: list[str]) -> None:
    if argv[:1] == ["record-attestations"]:
        if len(argv) < 2:
            raise SystemExit("usage: manifest.py record-attestations MANIFEST [URL...]")
        record_attestations(pathlib.Path(argv[1]), argv[2:])
        return
    parser = argparse.ArgumentParser()
    parser.add_argument("--component", default="kekkai")
    parser.add_argument("--version", required=True)
    parser.add_argument("--git-sha", required=True)
    parser.add_argument("--tag", default="")
    parser.add_argument("--dist", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--attestation", action="append", default=[])
    parser.add_argument("--gate-flag", action="append", default=[])
    parser.add_argument("--label", action="append", default=[])
    args = parser.parse_args(argv)
    dist = pathlib.Path(args.dist)
    flags = list(args.gate_flag)
    flags.extend(gate_flags_from_labels(args.label))
    manifest = build_manifest(
        component=args.component,
        version=args.version,
        git_sha=args.git_sha,
        tag=args.tag or None,
        dist=dist,
        images=[],
        attestations=args.attestation,
        gate_flags=sorted(set(flags)),
    )
    out = pathlib.Path(args.out)
    out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(out)


if __name__ == "__main__":
    main(sys.argv[1:])
