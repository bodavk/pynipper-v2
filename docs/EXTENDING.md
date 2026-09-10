# Extending pynipper-v2

This guide covers adding a check to an existing platform and adding a new device family. Read [Architecture](ARCHITECTURE.md), [Normalized parser contract](agent_notes/NORMALIZED_PARSER_CONTRACT.md), and the closest existing parser/plugins before editing code. The architecture document contains the durable decisions that govern effective-state reconstruction, evidence handling, references, and the static-analysis boundary.

## Adding a check to an existing platform

### 1. Establish the rule contract

Before coding, record:

- the exact unsafe effective state;
- valid negation, override, abbreviated, and alternate syntax;
- version-dependent defaults;
- configuration elements that must be cross-referenced;
- a current vendor guide, CIS control, STIG ID, or other authoritative source;
- what the supplied static export cannot prove.

Choose a stable rule ID using `<vendor>.<os>.<area>.<condition>`. Do not encode severity, a transient benchmark version, or an object name in the ID.

### 2. Extend parsing when necessary

Prefer a typed parser method or normalized record over regex inside the plugin. Effective-state reconstruction belongs in the parser.

- Preserve source order and evidence.
- Apply negation/removal/disablement semantics.
- Guard numeric and structured conversions.
- Redact passwords, keys, communities, and tokens before returning evidence.
- Return explicit unknown or parse-error state when the export is insufficient.

If the shared normalized model lacks a concept, add the smallest generally meaningful typed field. If the concept is vendor-specific, expose a typed vendor-parser method instead of weakening the common contract.

### 3. Implement the plugin rule

Extend `BasePlugin`, accept `BaseDeviceParser`, narrow to the required parser type when using vendor-specific APIs, and emit `Finding` with keyword arguments.

```python
from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.issue import Finding, Severity


class PluginExampleChecks(BasePlugin):
    def analyze(self, parser):
        if not unsafe_effective_state(parser):
            return
        self.add_issue(Finding(
            rule_id="vendor.os.area.condition",
            device=parser.device_type,
            title="Specific unsafe state",
            observation="Describe the effective state and affected scope.",
            impact="Describe the security consequence.",
            recommendation="Describe the exact corrective state.",
            severity=Severity.HIGH,
            exploitability="Describe the access or precondition an attacker needs.",
            evidence=("sanitized configuration evidence",),
            references=("https://vendor.example/hardening-guide",),
        ))
```

Do not emit a generic finding for several unrelated causes. Split disabled, absent, malformed, weak, and overly broad states when they require different remediation.

### 4. Register explicitly

Add the plugin class to the platform processor's ordered plugin tuple. Never rely on filename scanning or automatic subclass discovery.

### 5. Test at three levels

Add tests for:

1. parser state, including negation/override and parse errors;
2. plugin true-positive, true-negative, and relevant edge cases;
3. the public processor, including stable rule IDs, device ID, evidence, references, and no duplicate rule/evidence identity.

Update the appropriate permanent regression fixture and manifest snapshot when the intended public output changes.

## Adding a new device family

### 1. Define the supported input

Name the exact export type and tested OS versions. A vendor name alone is insufficient: CLI, XML, JSON, API export, and backup formats often have incompatible semantics. Add an explicit unsupported-format or parse-error path rather than silently returning an empty analysis.

### 2. Implement the parser

Create `src/devices/<vendor>/<os>.py` with a `BaseDeviceParser` subclass.

Required behavior:

- call the base constructor with the input path;
- implement `get_hostname()`, `get_version()`, `get_users()`, `get_services()`, and `get_native_config()`;
- implement `get_normalized_config()` with honest knowledge states;
- preserve scope, ordering, enablement, and source evidence;
- expose parser diagnostics for malformed input;
- ensure evidence is sanitized before plugins receive it.

Use immutable dataclasses for recurring typed vendor records. Avoid dictionaries whose keys or value meanings differ by code path.

### 3. Add plugins and a processor

Create:

```text
src/analyze/<vendor>/plugins/<os>_checks_plugin.py
src/analyze/<vendor>/core/process_<os>_conf.py
```

The processor must list plugin classes explicitly, execute them once, and preserve distinct object findings while rejecting exact duplicates.

### 4. Add the analyzer

Create a thin `analyze_<os>_device.py` entry point that obtains the parser through `get_parser()`, calls the processor, and passes findings and device metadata to `generate_report()`.

### 5. Register the device once

Add one `DeviceDefinition` to `src/devices/registry.py` with:

- a unique canonical ID;
- a unique legacy numeric value;
- unambiguous aliases;
- parser and analyzer import paths;
- a display name.

Do not add separate CLI choices or dispatcher branches elsewhere.

### 6. Add acceptance tests

At minimum, add:

- registry/parser/analyzer reachability and alias coverage;
- equivalent syntax-form tests where multiple formats are supported;
- secure, vulnerable, malformed, unknown/default, disable/override, and secret-redaction cases;
- exact `Finding` assertions for rule ID, severity, observation, evidence, and references;
- a public-pipeline duplicate test;
- paired permanent corpus cases once the device is promoted to target-baseline status.

### 7. Update documentation in the same change

Update:

- `src/devices/README.md` for parser maturity;
- `src/analyze/README.md` for implemented analysis;
- `docs/SUPPORTED_DEVICES.md` for the user-facing support boundary;
- `docs/STATUS.md` for roadmap status;
- `CHANGELOG.md` or the active implementation log.

Use “basic/partial” until secure/vulnerable/edge cases and the public pipeline are verified. Registry reachability alone is not verified security coverage.

## Required validation

Run the target regression gate after any parser, plugin, processor, registry, report, or corpus change:

```powershell
.\.venv\Scripts\python.exe scripts\run_full_regression.py
```

For a deliberate snapshot change, inspect current output with `--observe`, review each semantic difference, and then edit the manifest explicitly. Never update snapshots merely to make a failure disappear.

## Review checklist

- [ ] Input format and supported versions are explicit.
- [ ] Effective state handles negation, removal, disablement, and ordering.
- [ ] Defaults are version-aware or remain unknown.
- [ ] No unguarded type coercion is present.
- [ ] Findings have one root cause and stable IDs.
- [ ] Evidence is specific, scoped, and secret-redacted.
- [ ] New or changed checks attach authoritative references.
- [ ] Secure, vulnerable, edge, malformed, and pipeline tests pass.
- [ ] Public plugin registration is explicit.
- [ ] Documentation describes only verified maturity.
- [ ] Full regression passes.
