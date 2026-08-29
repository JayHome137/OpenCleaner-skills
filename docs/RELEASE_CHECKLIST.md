# Release checklist

Use this checklist for every public release. All commands run from the
repository root and must use sanitized fixtures only.

## Before tagging

- [ ] `git status --short` is empty and the intended commit is on `main`.
- [ ] `python3 scripts/validate_package.py` passes.
- [ ] `python3 scripts/security_scan.py` passes.
- [ ] `python3 -m unittest discover -s tests -p 'test_*.py' -q` passes.
- [ ] `python3 tests/macos_smoke.py` prints `MACOS_SMOKE_OK`.
- [ ] `python3 scripts/privacy_scan.py` passes. The fixture's explicit
      `/Users/example` and `example.invalid` values are sanitized test data.
- [ ] README, CHANGELOG, SECURITY.md, and the supported-platform matrix match
      the release behavior.

## Tag and workflow

- [ ] `VERSION` equals the tag without the leading `v`.
- [ ] The release workflow validates the extracted archive, not only the
      checkout used to build it.
- [ ] The workflow publishes `SHA256SUMS` and GitHub Artifact Attestations.
- [ ] The workflow uses pinned action SHAs and least-privilege permissions.

## After publishing

- [ ] Confirm the Release is not draft/prerelease unless intentionally marked.
- [ ] Confirm the Release tag resolves to the intended commit.
- [ ] Download the archive and run:

  ```bash
  shasum -a 256 --check SHA256SUMS
  gh attestation verify OpenCleaner-X.Y.Z.tar.gz \
    --repo JayHome137/OpenCleaner-skills
  ```

- [ ] Record the workflow run URL and final verification results in the
      acceptance matrix or changelog.

History rewrites, including removal of old author emails, are a separate
privacy operation. They require a mirror-clone dry run and explicit approval
before any force-push.
