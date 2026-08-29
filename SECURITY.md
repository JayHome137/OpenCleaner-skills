# Security policy

OpenCleaner is a local, macOS-only storage analysis Skill. The scanner is
read-only; an optional local session can move explicitly authorized targets to
the macOS Trash. It never permanently deletes files or asks for administrator
privileges.

## Reporting a vulnerability

Please do not open a public issue for a security-sensitive report. Contact
`GitHub repository maintainers` with:

- affected version/commit and macOS version;
- a minimal reproduction (without personal files, tokens, or private paths);
- impact and the smallest safe mitigation.

You should receive an acknowledgement within 7 days. We will coordinate a
fix and disclosure timeline with the reporter. Reports that include personal
data will be deleted from the working notes after triage.

## Scope and threat model

The local HTTP service binds to `127.0.0.1` and uses a short-lived token. The
token protects accidental cross-origin requests; it is not an operating-system
boundary against another process running as the same macOS user. Filesystem
identity, parent identity, owner, open-file, SQLite, runtime, and rule checks
are repeated immediately before each operation. A same-user process can still
race an external Finder/Trash implementation after the atomic staging rename;
the staged object is never permanently deleted by OpenCleaner and failures are
restored only without overwriting a newly-created path.

Review tokens are short-lived and garbage-collected with a bounded in-memory
store. The operation log is private, rotates at a fixed size, and the local
HTTP surface has a small per-client rate limit; these controls reduce accidental
resource exhaustion but are not a substitute for OS-level authentication.

Out of scope: remote hosts, Windows/Linux operation, administrator/root
actions, and data recovered from a user's Trash.

## Supported versions

Only the latest `main` commit is actively maintained while the repository is
private. Historical tags are provided for provenance, not a security support
promise.
