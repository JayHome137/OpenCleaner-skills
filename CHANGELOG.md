# Changelog

## Unreleased

- Hardened path validation to reject symlink components outside the home
  directory as well as inside it.
- Added atomic sibling staging before invoking the macOS Trash provider,
  with non-overwriting recovery on failure.
- Added security policy, threat-model disclosure, contributor guidance,
  community templates, and a dependency-free CI security tripwire.

## 1.1.0

- Added guarded interactive cleanup sessions, green/yellow/red reporting,
  owner-managed read-only explanations, operation history, and macOS smoke
  validation.
