# Pre-Wave-5 Report — Architecture and Repository Cleanup

Report date: 2026-09-10

## Summary

The inherited repository surface has been reduced to the architecture actually executed by pynipper-v2. Public device dispatch remains registry-driven, every active platform has one analyzer and one processor, IOS plugin registration is now explicit, and the current architecture and extension contract are documented for maintainers.

## Removed runtime artifacts

- Obsolete ASA analyzer wrapper: `analyze_cisco_asa_device.py`.
- Obsolete ASA processor wrapper: `process_cisco_asa_conf.py`.
- Superseded ASA `LoggingPlugin`, `ManagementPlugin`, and `SNMPPlugin`, plus their unused `ASAPlugin` base. Their active typed equivalents remain in `PluginASAChecks` and `PluginASABaseline`.
- Unused IOS `GenericPlugin` compatibility base; active IOS plugins now inherit `BasePlugin` directly.
- Standalone legacy IOS parsing helpers; `CiscoIOSParser` is the only IOS parser contract.
- Cisco-specific issue alias package; active code uses neutral `Finding`.
- Unused `src/devices/common/types.py` registry compatibility module.
- The misspelled `get_cisco_ios_ssh_reties()` compatibility method.
- Unused `click` runtime dependency.

## Removed repository artifacts

- Obsolete generated JSON outputs and duplicate unused secure/configuration fixtures under `tests/test_data/`.
- Generated `pynipper_ng.egg-info` build metadata from the working directory.
- Inherited `TODO.md`, replaced by `docs/ROADMAP.md`.
- Placeholder “another issue” template.
- Unconfigured inherited Snyk, GitGuardian, SonarCloud, third-party Flake8, and YAML-lint workflows, plus the original repository's Sonar project file.
- Python 3.6-era build and CodeQL workflow definitions, replaced by current supported workflows.

Deleted tracked source and documentation can be recovered from repository history by the human maintainer. Generated outputs and egg metadata are intentionally reproducible and should not be restored.

## Architecture changes

- Replaced IOS module-directory scanning with the explicit ordered `IOS_PLUGINS` tuple.
- Added IOS processor duplicate protection keyed by stable rule ID and object evidence.
- Corrected CLI `--offline` propagation so it passes `online=False` to analysis.
- Removed the generated report's external jQuery dependency and vendor-specific inherited prose.
- Added a PEP 517 build-system declaration and aligned package metadata with pynipper-v2 and Python 3.10+.
- Replaced stale CODEOWNERS and issue-template ownership with the current repository owner.
- Replaced inherited CI with the permanent regression command across Python 3.10/3.13 and Linux/Windows/macOS, using current official action major versions. CodeQL now uses its supported v4 action.

Workflow version choices were checked against the official [checkout](https://github.com/actions/checkout), [setup-python](https://github.com/actions/setup-python), and [CodeQL Action](https://github.com/github/codeql-action) repositories.

## Documentation delivered

- `README.md`: current purpose, support boundary, installation, CLI examples, validation, layout, lineage, and limitations.
- `docs/ARCHITECTURE.md`: end-to-end flow, ownership boundaries, contracts, validation, and invariants.
- `docs/EXTENDING.md`: concrete workflows for a new check or device, required testing, corpus updates, and review checklist.
- `docs/STATUS.md` and `docs/ROADMAP.md`: honest target/deferred state and next waves.
- `CONTRIBUTING.md` and `SECURITY.md`: current repository-specific guidance.
- Updated component READMEs, inventories, changelogs, and historical-audit context.

The original lineage remains credited in the root README without using the original repository's badges, ownership, support claims, or operating instructions as current project documentation.

## Verification evidence

```text
319 passed, 1 warning in 1.39s
Regression corpus passed: 14 configurations
```

Additional checks:

```text
inventory_rows 29
missing_inventory_paths []
checked_markdown_files=10
missing_relative_links=0
egg-info removed
legacy parser directory removed
legacy issue directory removed
```

The warning is the existing Windows pytest-cache permission warning and does not represent a test failure.

## Open item

`NEEDS_HUMAN_REVIEW`: the local Python environment does not contain `setuptools`, so an installation/build invocation could not execute locally. `setup.py` and `pyproject.toml` are syntax/configuration changes only until the first hosted workflow run installs the declared build dependency and confirms the clean-environment package installation.

## Recommended next step

Proceed to Wave 5 quality closure: attach authoritative references to the older focused target findings, then expand the permanent corpus with sanitized real-world syntax variants. The architecture-cleanup phase stops here.
