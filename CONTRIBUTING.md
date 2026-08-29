# Contributing

Thanks for helping improve OpenCleaner. The project is currently developed in
a private repository; contribution access is granted by the maintainer.

## Before opening a change

- Keep the macOS-only public boundary intact.
- Do not add permanent-delete, elevated-privilege, or unattended-cleanup
  behavior.
- Preserve the green/yellow/red decision model and owner-managed read-only
  boundary.
- Add a regression test for every policy or report behavior change.

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
