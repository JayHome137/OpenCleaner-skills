#!/usr/bin/env python3
"""Private, versioned cache for read-only directory size measurements.

The cache is an optimisation only. It never grants an operation permission;
the policy layer always re-checks the live filesystem before moving anything.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import threading
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Union

CACHE_SCHEMA_VERSION = "1.1"
CACHE_FILENAME = "scan-cache-v1.json"
DEFAULT_TTL_SECONDS = 15 * 60
MAX_CACHE_BYTES = 8 * 1024 * 1024
MAX_CACHE_ENTRIES = 20_000


def default_state_dir() -> Path:
    override = os.environ.get("OPEN_CLEANER_STATE_DIR")
    if override:
        return Path(override).expanduser()
    return Path(os.path.expanduser("~")) / ".local" / "state" / "open-cleaner"


def normalize_path(path: Union[str, os.PathLike[str]]) -> str:
    """Return the non-resolved absolute key used by the cache.

    Resolving symlinks here would make a path disappear from the invalidation
    surface. The signature function therefore rejects symlink roots instead.
    """
    return os.path.abspath(os.path.expanduser(os.fspath(path)))


def _stat_fields(value: os.stat_result) -> list[int]:
    # ctime is included deliberately: on macOS it changes for metadata and
    # replacement operations that may leave mtime/size unchanged.
    return [
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_mode),
        int(value.st_size),
        int(value.st_mtime_ns),
        int(value.st_ctime_ns),
    ]


def path_signature(path: Union[str, os.PathLike[str]]) -> Optional[str]:
    """Fingerprint a target and its direct children without following links.

    A directory's recursive contents can change while the directory's own
    mtime remains unchanged on some filesystems. Including every direct
    child's name and stat tuple catches those changes while keeping lookup
    bounded. Any race or permission failure returns ``None`` so the caller
    performs a fresh measurement and does not cache it.
    """
    try:
        normalized = normalize_path(path)
        root = os.lstat(normalized)
        if stat.S_ISLNK(root.st_mode):
            return None
        digest = hashlib.sha256()
        digest.update(json.dumps(_stat_fields(root), separators=(",", ":")).encode("ascii"))
        if stat.S_ISDIR(root.st_mode):
            children: list[tuple[str, list[int]]] = []
            with os.scandir(normalized) as entries:
                for entry in entries:
                    child = entry.stat(follow_symlinks=False)
                    children.append((entry.name, _stat_fields(child)))
            # casefold alone is not a total order on case-sensitive volumes.
            children.sort(key=lambda item: (item[0].casefold(), item[0]))
            for name, fields in children:
                digest.update(os.fsencode(name))
                digest.update(b"\0")
                digest.update(json.dumps(fields, separators=(",", ":")).encode("ascii"))
        return digest.hexdigest()
    except (OSError, TypeError, UnicodeError, ValueError):
        return None


def _valid_size(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


class ScanCache:
    """Stage cache updates in memory and publish only after a clean scan."""

    def __init__(
        self,
        state_dir: Optional[Union[str, Path]] = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        enabled: bool = True,
        now: Optional[float] = None,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        self.enabled = bool(enabled)
        self.state_dir = Path(state_dir) if state_dir is not None else default_state_dir()
        self.path = self.state_dir / CACHE_FILENAME
        self.ttl_seconds = max(1, int(ttl_seconds))
        self._clock = clock or time.time
        self._fixed_now = float(now) if now is not None else None
        # ``now`` remains a public-ish attribute for callers/tests that used
        # the first 1.1 implementation; it is refreshed on every operation
        # when no fixed clock was supplied.
        self.now = float(now) if now is not None else float(self._clock())
        self.entries: dict[str, dict[str, Any]] = {}
        self.pending: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self.stats: dict[str, Any] = {
            "enabled": self.enabled,
            "schema_version": CACHE_SCHEMA_VERSION,
            "ttl_seconds": self.ttl_seconds if self.enabled else 0,
            "hits": 0,
            "misses": 0,
            "invalidated": 0,
            "published": False,
            "status": "disabled" if not self.enabled else "ready",
        }
        if self.enabled:
            self._load()

    def _timestamp(self) -> float:
        if self._fixed_now is not None:
            self.now = self._fixed_now
        else:
            try:
                self.now = float(self._clock())
            except (TypeError, ValueError, OSError):
                self.now = float(time.time())
        return self.now

    def _load(self) -> None:
        try:
            if self.state_dir.is_symlink() or self.path.is_symlink():
                raise OSError("扫描缓存路径不能是符号链接")
            if not self.path.exists():
                return
            if not self.path.is_file():
                raise OSError("扫描缓存文件类型无效")
            if self.path.stat().st_size > MAX_CACHE_BYTES:
                raise OSError("扫描缓存超过大小上限")
            value = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise ValueError("扫描缓存顶层必须是 object")
            if value.get("schema_version") != CACHE_SCHEMA_VERSION:
                self.stats["status"] = "version_mismatch"
                return
            entries = value.get("entries")
            if not isinstance(entries, dict) or len(entries) > MAX_CACHE_ENTRIES:
                raise ValueError("扫描缓存条目无效")
            loaded: dict[str, dict[str, Any]] = {}
            for raw_path, entry in entries.items():
                if not isinstance(raw_path, str) or not isinstance(entry, Mapping):
                    continue
                normalized = normalize_path(raw_path)
                # Ignore malformed entries rather than letting one corrupt
                # record disable otherwise useful cache data.
                if not isinstance(entry.get("signature"), str) or not _valid_size(entry.get("size_kb")):
                    continue
                measured_at = entry.get("measured_at")
                if isinstance(measured_at, bool) or not isinstance(measured_at, (int, float)):
                    continue
                if not (-float("inf") < float(measured_at) < float("inf")):
                    continue
                loaded[normalized] = {
                    "signature": entry["signature"],
                    "size_kb": int(entry["size_kb"]),
                    "measured_at": float(measured_at),
                }
            self.entries = loaded
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            self.entries = {}
            self.stats["status"] = f"unavailable: {exc}"

    def lookup(self, path: Union[str, os.PathLike[str]]) -> tuple[Optional[int], Optional[str]]:
        if not self.enabled:
            return None, None
        normalized = normalize_path(path)
        signature = path_signature(normalized)
        timestamp = self._timestamp()
        with self._lock:
            entry = self.entries.get(normalized)
            if signature is None:
                self.stats["misses"] += 1
                if entry is not None:
                    self.stats["invalidated"] += 1
                    self.entries.pop(normalized, None)
                return None, None
            if entry is None:
                self.stats["misses"] += 1
                return None, signature
            measured_at = entry.get("measured_at")
            size_kb = entry.get("size_kb")
            try:
                age = timestamp - float(measured_at)
            except (TypeError, ValueError):
                age = float("inf")
            valid = (
                isinstance(measured_at, (int, float))
                and not isinstance(measured_at, bool)
                and -float("inf") < float(measured_at) < float("inf")
                and age >= 0
                and age < self.ttl_seconds
                and entry.get("signature") == signature
                and _valid_size(size_kb)
            )
            if not valid:
                self.stats["invalidated"] += 1
                self.stats["misses"] += 1
                self.entries.pop(normalized, None)
                return None, signature
            self.stats["hits"] += 1
            return int(size_kb), signature

    def stage(
        self,
        path: Union[str, os.PathLike[str]],
        size_kb: int,
        signature: Optional[str] = None,
    ) -> None:
        if not self.enabled or not _valid_size(size_kb):
            return
        normalized = normalize_path(path)
        # Re-fingerprint after measuring. A directory can change while `du`
        # runs; publishing the pre-measure signature would make a stale size
        # look valid on the next scan.
        resolved_signature = path_signature(normalized)
        if resolved_signature is None:
            return
        with self._lock:
            self.pending[normalized] = {
                "signature": resolved_signature,
                "size_kb": int(size_kb),
                "measured_at": self._timestamp(),
            }

    def discard_pending(self, status: str = "cancelled") -> None:
        """Drop staged values without touching the last published cache."""
        if not self.enabled:
            return
        with self._lock:
            self.pending.clear()
            self.stats["published"] = False
            self.stats["status"] = str(status) or "discarded"

    def commit(self) -> None:
        """Atomically publish staged entries, failing closed on path races."""
        if not self.enabled:
            return
        with self._lock:
            pending = dict(self.pending)
            existing = dict(self.entries)
        try:
            if self.state_dir.is_symlink() or self.path.is_symlink():
                raise OSError("扫描缓存路径不能是符号链接")
            self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            if self.state_dir.is_symlink() or not self.state_dir.is_dir():
                raise OSError("扫描缓存目录不能是符号链接或非目录")
            if os.name != "nt":
                os.chmod(self.state_dir, 0o700)
            merged = dict(existing)
            merged.update(pending)
            if len(merged) > MAX_CACHE_ENTRIES:
                merged = dict(
                    sorted(
                        merged.items(),
                        key=lambda item: float(item[1].get("measured_at", 0)),
                        reverse=True,
                    )[:MAX_CACHE_ENTRIES]
                )
            payload = json.dumps(
                {"schema_version": CACHE_SCHEMA_VERSION, "entries": merged},
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            if len(payload) > MAX_CACHE_BYTES:
                raise OSError("扫描缓存写入内容超过大小上限")
            temporary = self.state_dir / f".scan-cache-{secrets.token_hex(8)}.tmp"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(temporary, flags, 0o600)
            try:
                if os.name != "nt":
                    os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "wb") as handle:
                    descriptor = -1
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, self.path)
                # Ensure the rename itself is durable on filesystems that
                # support directory fsync. Failure here does not roll back a
                # successful replace, so report it as a publish warning only.
                if os.name != "nt":
                    try:
                        directory_fd = os.open(self.state_dir, os.O_RDONLY)
                        try:
                            os.fsync(directory_fd)
                        finally:
                            os.close(directory_fd)
                    except OSError:
                        pass
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
            with self._lock:
                self.entries = merged
                # Preserve values staged while this commit was writing. In
                # normal scans there are none, but this avoids losing a
                # concurrent caller's update.
                for key, value in pending.items():
                    if self.pending.get(key) == value:
                        self.pending.pop(key, None)
                self.stats["published"] = True
                self.stats["status"] = "ready"
        except (OSError, ValueError, TypeError) as exc:
            self.stats["published"] = False
            self.stats["status"] = f"write_failed: {exc}"

    def metadata(self) -> dict[str, Any]:
        with self._lock:
            metadata = dict(self.stats)
            metadata["pending"] = len(self.pending)
            metadata["entries"] = len(self.entries)
            return metadata
