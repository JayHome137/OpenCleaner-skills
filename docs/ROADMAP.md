# Roadmap

The repository is public. The roadmap remains intentionally small and tied to
evidence so that safety claims do not outrun verification.

## Completed for the current public release

- Keep the macOS-only boundary and recoverable Trash invariant covered by CI.
- Publish a current threat model and security reporting path.
- Validate the interactive report on a clean macOS fixture and publish a
  sanitized preview.
- Add a reproducible release checklist, checksum, and keyless artifact
  attestation for release archives.
- Run package validation across macOS 14/Python 3.9 and macOS 15/Python 3.13.
- Keep an English quick start alongside the Chinese product documentation.
- Keep the optional local authorization modes in a separate, explicitly
  documented branch rather than changing the main default.

## Next community improvements

- Keep triage labels and a small set of `good first issue` tasks current.
- A changelog entry for every user-visible or safety-relevant change.
- Use Discussions for usage questions, ideas, and release announcements.
- Add a maintained SAST/dependency review when the code or dependency surface
  expands beyond the current standard-library implementation.

Features that broaden deletion scope, run owner tools, or require elevated
privileges are out of scope for this roadmap.
