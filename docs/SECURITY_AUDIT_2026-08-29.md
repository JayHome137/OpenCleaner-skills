# OpenCleaner security follow-up audit

## Scope and evidence

- Repository: `OpenCleaner-skills`, local worktree at commit `fa5e322` plus
  the uncommitted changes described by this document.
- Runtime scope: `open-cleaner/scripts/policy.py`, `file_ops.py`, `server.py`
  and their regression tests.
- Evidence: `python3 -m unittest discover -s tests -p 'test_*.py' -q`
  (`119/119`), `python3 scripts/security_scan.py`, package validation, and
  `python3 tests/macos_smoke.py` (`MACOS_SMOKE_OK`).

## Findings and fixes

| Finding | Path | Status |
| --- | --- | --- |
| Symlink parent outside `$HOME` could redirect a reviewed target | `open-cleaner/scripts/policy.py` | Fixed. Existing path components are checked from `/`; only stable macOS `/var` and `/tmp` aliases are exempted. Regression covers an alias outside the home directory. |
| Identity check and external Trash call had a path-based TOCTOU window | `open-cleaner/scripts/file_ops.py` | Mitigated. The target is atomically renamed into a private sibling staging directory, its identity is checked again, and only the staged path is handed to Finder/Trash. Failure restores only without overwriting a recreated path. |
| Local token is readable by another process running as the same user | `open-cleaner/scripts/server.py` | Accepted residual risk. The service is loopback-only and token-protected against accidental cross-origin requests, but HTTP cannot provide an OS identity boundary. The threat model is documented in `SECURITY.md`; a future Unix-socket/OS-auth design is a separate change. |

## Remaining P2 work

- Expire and garbage-collect old review-token records proactively.
- Add operation-log rotation and a bounded request/rate policy.
- Run a maintained SAST/dependency scanner in CI when the project gains
  third-party dependencies; the current guard is intentionally stdlib-only.
- Re-run remote CI after the private branch is pushed; this worktree has not
  been published or released.

## Release boundary

The repository remains private. The PolyForm Noncommercial license is unchanged;
no MIT/Apache switch, visibility change, tag, or release was performed.
