# Contributing

Thanks for helping improve OpenCleaner. The repository is public and welcomes
small, focused pull requests over broad refactors.

## Contribution flow

1. Open an issue describing the user problem and the expected safety boundary.
2. Keep one behavior change per pull request and link the issue.
3. Add or update a fixture-based regression test before changing policy code.
4. Run the local checks below and include the concise results in the PR.
5. Wait for maintainer review; security-sensitive changes are reviewed before
   any release.

## Before opening a change

- Keep the macOS-only public boundary intact.
- Keep public documentation and release metadata consistent with the current
  supported version and platform scope.
- Do not add permanent-delete, elevated-privilege, or unattended-cleanup
  behavior.
- Preserve the green/yellow/red decision model and owner-managed read-only
  boundary.
- Add a regression test for every policy or report behavior change.

Use imperative commit subjects such as `fix: reject symlinked review roots` or
`docs: clarify yellow-tier confirmation`. Do not include generated local
reports in commits.

## Local checks

```bash
python3 scripts/validate_package.py
python3 scripts/security_scan.py
python3 -m unittest discover -s tests -p 'test_*.py' -q
python3 tests/macos_smoke.py
git diff --check
```

Do not include real home-directory contents, operation tokens, or personal
paths in commits, screenshots, fixtures, or issue reports.

## What makes a good issue

Include the version/commit, macOS and Python versions, a minimal fixture, and
expected versus actual behavior. For a security issue, follow
[SECURITY.md](SECURITY.md) instead of opening a public issue.
