# Changelog

## Unreleased

- Added a sanitized interactive report preview and a public-project guidance
  section to the README files.
- Added extracted-release-archive validation, a macOS/Python verification
  matrix, a tracked-file privacy scan, and a pinned CodeQL workflow.
- Updated roadmap, security, contribution, and acceptance documentation for
  the public repository state.

## 1.2.0 - 2026-08-29

- Hardened path validation to reject symlink components outside the home
  directory as well as inside it.
- Added atomic sibling staging before invoking the macOS Trash provider,
  with non-overwriting recovery on failure.
- Added security policy, threat-model disclosure, contributor guidance,
  community templates, and a dependency-free CI security tripwire.
- Added bounded review-token cleanup, 2 MiB operation-log rotation, and a
  loopback request rate limit.
- Switched the project license to Apache License 2.0 and replaced personal
  contact details with GitHub's private vulnerability-reporting flow.

## 1.1.0

- Added guarded interactive cleanup sessions, green/yellow/red reporting,
  owner-managed read-only explanations, operation history, and macOS smoke
  validation.
