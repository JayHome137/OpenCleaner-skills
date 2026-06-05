# Storage Analyzer Skill

A Codex skill for read-only macOS / Windows storage analysis. It scans disk usage, helps an agent classify cleanup candidates by risk, and produces an interactive HTML report with copyable commands and optional local cleanup actions.

## Repository Layout

```text
.
├── README.md
├── scripts/
│   └── validate_package.py
└── storage-analyzer/
    ├── SKILL.md
    ├── agents/openai.yaml
    ├── assets/report_template.html
    ├── references/
    │   ├── macos.md
    │   └── windows.md
    └── scripts/
        ├── build_report.py
        ├── scan.py
        └── server.py
```

The installable skill is the `storage-analyzer/` directory. The files outside that directory are GitHub packaging and validation helpers.

## Install

Copy the skill directory into your Codex skills folder:

```bash
mkdir -p ~/.codex/skills
cp -R storage-analyzer ~/.codex/skills/storage-analyzer
```

Or install from a cloned repository by copying only the `storage-analyzer/` subdirectory.

## Usage

Invoke the skill in Codex with storage-related requests such as:

```text
Use $storage-analyzer to scan my Mac storage and generate a cleanup report.
```

The skill workflow is agent-driven:

1. Run the read-only scan script.
2. Have the agent analyze `/tmp/storage_scan.json` and write `/tmp/storage_analysis.json`.
3. Serve the interactive report with `scripts/server.py`, or build a static HTML report with `scripts/build_report.py`.

## Safety Model

The scan phase is read-only. It uses directory listing and size inspection commands only.

The interactive report server exposes local actions only for allowlisted paths from the agent-produced analysis JSON. Green items may expose trash and direct-delete actions. Yellow items may expose open-in-file-manager and reversible trash actions only when a safe subpath is explicitly listed. Red items do not expose destructive actions.

## Requirements

- Python 3 standard library only.
- macOS is the primary tested platform.
- Windows scan and trash code is included but should be verified on a real Windows machine before relying on it.

## Validate Before Publishing

Run:

```bash
python3 scripts/validate_package.py
```

This checks the expected skill files, Python syntax, frontmatter basics, UI metadata, and static report generation against a small sample analysis JSON.
