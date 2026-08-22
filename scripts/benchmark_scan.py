#!/usr/bin/env python3
"""Measure the bounded scanner on a disposable, reproducible fixture."""
from __future__ import annotations

import hashlib
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "storage-analyzer" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from scan import ScanEngine, ScanTarget

DIRECTORIES = 24
FILES_PER_DIRECTORY = 4
FILE_SIZE_BYTES = 512 * 1024
RUNS = 3


def create_fixture(root: Path) -> None:
    for directory_index in range(DIRECTORIES):
        directory = root / f"cache-{directory_index:02d}"
        directory.mkdir()
        for file_index in range(FILES_PER_DIRECTORY):
            with (directory / f"chunk-{file_index}.bin").open("wb") as handle:
                handle.truncate(FILE_SIZE_BYTES)


def result_digest(groups: dict, root: Path) -> str:
    normalized = {
        group: [
            {**item, "path": str(Path(item["path"]).relative_to(root))}
            for item in items
        ]
        for group, items in groups.items()
    }
    payload = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def measure(root: Path, workers: int) -> dict:
    durations = []
    digests = []
    coverage = None
    for _ in range(RUNS):
        engine = ScanEngine("win32", max_workers=workers, timeout_seconds=30)
        started = time.perf_counter()
        groups, coverage = engine.scan_targets(
            [
                ScanTarget("fixture", str(root), min_kb=0),
                ScanTarget("duplicate", str(root / "cache-00"), min_kb=0, mode="exact"),
            ]
        )
        durations.append(time.perf_counter() - started)
        digests.append(result_digest(groups, root))
        if engine.errors:
            raise RuntimeError(engine.errors)
    if len(set(digests)) != 1:
        raise RuntimeError("相同 fixture 的扫描输出不稳定")
    return {
        "workers": workers,
        "runs": RUNS,
        "median_seconds": round(statistics.median(durations), 6),
        "min_seconds": round(min(durations), 6),
        "max_seconds": round(max(durations), 6),
        "result_sha256": digests[0],
        "coverage": coverage,
    }


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="storage-benchmark-") as temporary:
        fixture = Path(temporary) / "fixture"
        fixture.mkdir()
        create_fixture(fixture)
        result = {
            "fixture": {
                "directories": DIRECTORIES,
                "files_per_directory": FILES_PER_DIRECTORY,
                "logical_bytes": DIRECTORIES * FILES_PER_DIRECTORY * FILE_SIZE_BYTES,
            },
            "sequential": measure(fixture, 1),
            "bounded_parallel": measure(fixture, 4),
        }
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
