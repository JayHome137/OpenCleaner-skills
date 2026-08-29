# OpenCleaner

OpenCleaner is a macOS-only storage analysis Skill for Codex and other AI
agents. It performs read-only disk analysis, explains green/yellow/red risk
tiers, and offers only recoverable Trash operations authorized by deterministic
rules and a short-lived local session.

## Quick start

```bash
git clone https://github.com/JayHome137/OpenCleaner-skills.git
cd OpenCleaner-skills/open-cleaner
python3 scripts/scan.py --progress > /tmp/open-cleaner-scan.json
python3 scripts/classify.py /tmp/open-cleaner-scan.json /tmp/open-cleaner-analysis.json
python3 scripts/validate_plan.py /tmp/open-cleaner-analysis.json > /tmp/open-cleaner-plan.json
python3 scripts/summarize.py /tmp/open-cleaner-analysis.json /tmp/open-cleaner-plan.json
```

The first four commands are read-only and produce a Dry Run. Start the local
interactive report only after reviewing the summary:

```bash
python3 scripts/server.py /tmp/open-cleaner-analysis.json
```

Green means a deterministic rule may move an item to Trash; yellow requires a
separate human review; red is display-only. OpenCleaner never permanently
deletes files and never asks for administrator privileges.

See [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md), and the
[Chinese README](README.md) for the full scope and development workflow.
