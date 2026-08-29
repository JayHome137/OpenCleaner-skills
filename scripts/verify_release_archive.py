#!/usr/bin/env python3
"""Validate a source archive the same way a user would consume it."""
from __future__ import annotations

import argparse
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def validate_members(archive: tarfile.TarFile, root: str) -> None:
    prefix = root.rstrip("/") + "/"
    members = archive.getmembers()
    if not members or not any(member.name.startswith(prefix) for member in members):
        fail(f"archive does not contain the expected root {root}")
    names: set[str] = set()
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts:
            fail(f"archive contains an unsafe path: {member.name}")
        if member.name in names:
            fail(f"archive contains a duplicate path: {member.name}")
        names.add(member.name)
        if member.issym() or member.islnk():
            fail(f"archive contains a link entry: {member.name}")
        if not (member.isdir() or member.isfile()):
            fail(f"archive contains an unsupported entry: {member.name}")


def extract_members(archive: tarfile.TarFile, destination: Path) -> None:
    """Extract only regular files and directories after member validation."""
    for member in archive.getmembers():
        target = destination.joinpath(*PurePosixPath(member.name).parts)
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        source = archive.extractfile(member)
        if source is None:
            fail(f"archive entry has no file content: {member.name}")
        with source, target.open("wb") as output:
            while chunk := source.read(1024 * 1024):
                output.write(chunk)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()

    if not args.archive.is_file():
        fail(f"archive not found: {args.archive}")
    root = f"OpenCleaner-{args.version}"
    with tempfile.TemporaryDirectory(prefix="open-cleaner-archive-") as temporary:
        destination = Path(temporary)
        with tarfile.open(args.archive, mode="r:gz") as archive:
            validate_members(archive, root)
            extract_members(archive, destination)
        package = destination / root
        if not package.is_dir():
            fail(f"extracted package root not found: {package}")
        for command in (("scripts/validate_package.py",), ("scripts/security_scan.py",)):
            subprocess.run([sys.executable, *command], cwd=package, check=True)
    print(f"release archive validation passed: {args.archive}")


if __name__ == "__main__":
    main()
