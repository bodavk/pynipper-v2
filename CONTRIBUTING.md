# Contributing to pynipper-v2

Contributions should preserve the project's central promise: findings must describe effective configuration state and must not turn unknown input into a confident security assertion.

## Before making a change

- Read [Architecture](docs/ARCHITECTURE.md).
- Follow [Extending pynipper-v2](docs/EXTENDING.md) for parser, plugin, registry, and test requirements.
- Check [Supported devices](docs/SUPPORTED_DEVICES.md) and the [roadmap](docs/ROADMAP.md) before changing maturity claims.
- Never include real credentials or unsanitized customer configurations.

## Pull requests

A focused pull request should include its tests and documentation. Parser or rule changes need secure, vulnerable, and relevant edge/override cases. New or modified findings must include stable rule IDs, sanitized evidence, and authoritative references.

Before opening a pull request, run:

```powershell
.\.venv\Scripts\python.exe scripts\run_full_regression.py
```

Explain deliberate finding-snapshot changes in the pull request. Do not refresh snapshots without reviewing the semantic difference.

Report security issues privately according to [SECURITY.md](SECURITY.md), not in a public issue.
