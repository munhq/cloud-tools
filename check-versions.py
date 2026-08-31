#!/usr/bin/env python3
"""Assert that every manifest names one version, and optionally the tag.

A release bumps the version by hand in several files, and nothing compares them
to each other. The failure is quiet: npm serves 0.2.0 while server.json still
declares 0.1.9, the registry validates the declared version against npm, and the
publish returns a 400 that names a version nobody edited.

Seven places carry the number here. Cargo.toml is the source — it is what the
binary is built from — and the rest have to agree with it. The Dockerfile is the
one that is easy to forget, because nothing builds it in CI: its ARG VERSION
decides which release the image downloads, so a stale value produces an image of
the previous version with the current label.

Run it with no argument to check the manifests agree. Pass a version to also
require that they agree with it, which is what release CI does with the tag:

    python3 check-versions.py            # the manifests must agree
    python3 check-versions.py 0.2.0      # ...and must all say 0.2.0
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def from_json(rel, *path):
    """Read a nested key out of a JSON file, named by its path for the report."""
    target = ROOT / rel
    if not target.exists():
        sys.exit(f"{rel} is missing — the check needs updating, not skipping")
    data = json.loads(target.read_text())
    for key in path:
        data = data[key]
    return f"{rel}:{'.'.join(str(p) for p in path)}", data


def from_dockerfile(rel):
    """The Dockerfile pins the release it fetches with `ARG VERSION=x.y.z`."""
    text = (ROOT / rel).read_text()
    match = re.search(r"^ARG VERSION=([0-9][^\s]*)", text, re.M)
    if not match:
        sys.exit(f"{rel}: no ARG VERSION — the check needs updating, not skipping")
    return f"{rel}:ARG VERSION", match.group(1)


def from_cargo(rel):
    """Cargo.toml is TOML, and only the [package] version counts.

    A dependency pinned to "0.1.0" sits further down the same file, so the search
    is anchored to the first version line after [package] rather than the first
    one in the file.
    """
    text = (ROOT / rel).read_text()
    match = re.search(r'^\[package\]$(.*?)^\[', text, re.S | re.M)
    block = match.group(1) if match else text
    version = re.search(r'^version\s*=\s*"([^"]+)"', block, re.M)
    if not version:
        sys.exit(f"{rel}: no [package] version — the check needs updating, not skipping")
    return f"{rel}:package.version", version.group(1)


def collect():
    return [
        from_cargo("Cargo.toml"),
        from_json("npm/package.json", "version"),
        from_json("server.json", "version"),
        from_json("server.json", "packages", 0, "version"),
        from_dockerfile("Dockerfile"),
        # The plugin manifests. codeindex shipped two releases advertising an old
        # version because its .cursor-plugin/marketplace.json was bumped by hand
        # and missed; nothing compared it to anything.
        from_json("plugin/.claude-plugin/plugin.json", "version"),
        from_json(".cursor-plugin/marketplace.json", "metadata", "version"),
    ]


def main():
    found = collect()
    want = sys.argv[1].lstrip("v") if len(sys.argv) > 1 else None

    for where, value in found:
        print(f"  {value}  {where}")

    versions = {value for _, value in found}
    if len(versions) > 1:
        print("\nThe manifests disagree:", ", ".join(sorted(versions)), file=sys.stderr)
        sys.exit(1)

    only = versions.pop()
    if want is not None and only != want:
        print(f"\nThe manifests say {only}, the tag says {want}", file=sys.stderr)
        sys.exit(1)

    print(f"\nEvery manifest names {only}." + ("" if want is None else " It matches the tag."))


if __name__ == "__main__":
    main()
