# Extending pynipper-v2

This guide covers adding a check to an existing platform and adding a new device family. Read [Architecture](ARCHITECTURE.md), especially its parser contract and durable engineering decisions, and the closest existing parser/plugins before editing code.

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

Qualify the control against the actual export and tested release before treating omission as a finding. A current vendor guide does not establish an older release's defaults, and a policy-only export cannot establish device or operating-system posture. Organization-specific thresholds, licensed benchmark/profile mappings, and controls lacking verified source text require separate human approval; do not imply CIS conformance from an unlicensed or unverified mapping. Explicit insecure values may be assessed when authoritative evidence supports them, while missing, inherited, unsupported, or unexpanded state stays unknown.

### 2. Extend parsing when necessary

Prefer a typed parser method or normalized record over regex inside the plugin. Effective-state reconstruction belongs in the parser.

- Preserve source order and evidence.
- Apply negation/removal/disablement semantics.
- Guard numeric and structured conversions.
- Redact passwords, keys, communities, and tokens before returning evidence.
- Return explicit unknown or parse-error state when the export is insufficient.
- Gate documented defaults and legacy command aliases to the exact verified release family; an OS name alone is not applicability evidence.

If the shared normalized model lacks a concept, add the smallest generally meaningful typed field. If the concept is vendor-specific, expose a typed vendor-parser method instead of weakening the common contract.

### 3. Implement the plugin rule

Extend `BasePlugin`, accept `BaseDeviceParser`, narrow to the required parser type when using vendor-specific APIs, and emit `Finding` with keyword arguments. Pass the parser's `ConfigEvidence` objects as `evidence` (not their `.text`) so the report can cite the source line; if a plugin must rewrite evidence text, use `dataclasses.replace` to keep the line number. Plain strings remain valid for absence or derived statements, which have no source line.

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

For policy-attached inspection, model the rule-to-group-to-profile relationship in the parser. Resolve local scope before inherited shared/global scope, never borrow a same-name object from another tenant scope, and grade only enabled rules and attached objects. Keep unresolved controller inheritance distinct from a locally invalid reference. Profile configuration can establish an empty or explicitly non-blocking static state, but it cannot establish license health, content freshness, or actual runtime inspection.

For administrative-policy checks, model identity-to-role/class bindings and timeout inheritance in the parser rather than searching lines in the plugin. Keep pre-login warnings separate from post-login notices, event coverage separate from accounting-destination resolution, and browser session timeout separate from concurrent-session limits. Only apply a vendor default when its release and hierarchy are authoritative; otherwise expose an explicit unknown state. Static declarations do not prove least-privilege suitability, MFA success, remote accounting delivery, or active-session behavior without the required policy or operational context.

Treat credential-export completeness as its own fact. For example, an ArubaOS-S running configuration without a manager password line does not prove that the credential is absent unless `include-credentials` is effective or an ordered `no password manager` command proves removal. Likewise, model its manager/operator roles, login/enable authentication methods, remote CLI and serial/USB timeouts, and plaintext/TLS WebAgent switches separately; do not translate them into IOS line semantics or AOS-CX commands.

For controller-managed devices, resolve only the local or merged-effective scope actually present. A locally referenced authentication or SSH profile is not invalid merely because its definition could arrive through an unexpanded Panorama template. Preserve explicit MFA configuration separately from the unknown behavior of an external identity provider, and do not treat a committed SSH profile as runtime-active when the platform requires a separate service restart.

Do not reuse a nearby policy model merely because its syntax has similar words. Transit, local/self traffic, stateless filters and stateful zone policies need separate records when their matching or attachment semantics differ. Resolve static address/service/application groups inside the parser, preserve tenant/VDOM/zone scope, and require complete positive resolution before proving an unrestricted rule.

For VPN checks, start from an active policy or interface attachment and follow named references to the effective gateway, policy and proposal objects. Ignore unreferenced weak definitions and inactive tunnels. Report an unresolved active chain separately from an explicitly weak configured transform, and never describe configured proposals as the live negotiated security association.

Every new rule ID must match an entry in `src/analyze/common/guidance.py` (the coverage test fails otherwise). Reuse an existing entry when the weakness is the same kind across vendors; add a new entry, placed before any broader pattern, only for a genuinely different weakness. Keep its text vendor-neutral and within what a static export can prove; device-specific facts belong in the finding's observation.

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
- preserve scope, ordering, enablement, and source evidence with physical line numbers;
- group values that span several physical lines (quoted PEM material, banners, comments) with `src/devices/common/source_lines.py` or a vendor-specific delimiter rule, so their body is never read as commands;
- expose parser diagnostics for malformed input;
- ensure evidence is sanitized before plugins receive it.

Use immutable dataclasses for recurring typed vendor records. Avoid dictionaries whose keys or value meanings differ by code path.

For credential syntax, return secret-free `CredentialMetadata` from the parser. Classify only formats the export proves, keep exact default-fingerprint matching separate from storage quality, and leave future or opaque formats `UNKNOWN`. Do not infer plaintext length or composition from a hash, expose a decoded reversible value, or put the supplied value in evidence, diagnostics, exceptions, or logs. Ordered account replacement and removal are parser responsibilities.

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

If a check depends on deployment context, consume the immutable `AssessmentContext` attached to the parser. Extend the validated policy schema only when the concept is cross-platform and its precedence is unambiguous. Never infer an external, internal, edge, or trusted role from an interface name. Certificate checks likewise require explicit inputs: a timezone-aware `assessment_time` for reproducible validity, a scoped intended management identity for SAN matching, and approved SHA-256 trust-anchor fingerprints for offline chain verification. Missing inputs remain unknown, not secure or vulnerable. Tests must cover explicit roles, unknown role, inactive objects, conflicting/invalid input, report provenance, and exact temporal boundaries where applicable. See [`ASSESSMENT_POLICY.md`](ASSESSMENT_POLICY.md).

### 7. Update documentation in the same change

Update:

- `src/devices/README.md` for parser maturity;
- `src/analyze/README.md` for implemented analysis;
- `docs/SUPPORTED_DEVICES.md` for the user-facing support boundary;
- `docs/ARCHITECTURE.md` or `docs/ASSESSMENT_POLICY.md` when a lasting contract or policy boundary changes;
- `CHANGELOG.md` for notable user-facing behavior changes.

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
