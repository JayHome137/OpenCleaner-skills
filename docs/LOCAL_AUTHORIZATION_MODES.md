# Local authorization modes

> Experimental branch: `codex/local-auth-modes`. This design is intentionally
> not merged into `main`; users can compare the trade-offs before adoption.

The local report always binds to a random `127.0.0.1` port and retains the
short-lived browser token. The mode controls what additional user evidence is
required before a file operation.

## Choose a mode

| Mode | Protection | Residual risk | Recommended use |
| --- | --- | --- | --- |
| `token` | Rejects requests without the page token, plan ID and action IDs | Another process running as the same macOS user may read the page and replay authorized actions | Trusted single-user development machine |
| `system-confirm` | Keeps token checks and adds a separate visible macOS dialog immediately before each Trash batch | Malware with Accessibility/UI-automation permission may still click the dialog; users can also approve a misleading prompt | General users who want protection from silent local HTTP replay |
| `view-only` | Removes action IDs and operation endpoints from the page; server rejects mutating requests | Local paths remain visible in the report to the current user | Shared machine, untrusted local software, or evidence-only review |

## Run the selected mode

Default token mode:

```bash
python3 scripts/server.py /tmp/open-cleaner-analysis.json \
  --authorization-mode token
```

Visible macOS confirmation before each Trash batch:

```bash
python3 scripts/server.py /tmp/open-cleaner-analysis.json \
  --authorization-mode system-confirm
```

Read-only local report:

```bash
python3 scripts/server.py /tmp/open-cleaner-analysis.json \
  --authorization-mode view-only
```

## Threat boundary

`system-confirm` is a user-presence check, not process authentication. A normal
same-user background process can trigger the dialog but cannot silently
complete a Trash action. A process with Accessibility permission, remote-control
capability, or the ability to manipulate the user can still defeat it.

A true process-identity boundary would require a signed native helper, an
audited IPC entitlement model, and a browser-to-helper trust bridge. That is a
larger product architecture and is deliberately not implied by this branch.
