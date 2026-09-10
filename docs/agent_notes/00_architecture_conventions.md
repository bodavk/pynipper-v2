# Architecture and Style Conventions

## Authoritative architecture

- `src/devices/registry.py` owns canonical device IDs, aliases, parser imports, analyzer dispatch, and display names.
- Every parser extends `BaseDeviceParser` and exposes `get_native_config()` plus `get_normalized_config()`.
- Normalized scalar and collection fields carry explicit knowledge state. Empty known state is not interchangeable with unknown or unsupported state.
- Vendor-specific parser models are appropriate where the shared model cannot preserve required hierarchy, ordering, attachment, or scope.
- Plugins extend `BasePlugin`, consume an existing parser instance, and emit neutral `Finding` objects.
- Public processors register their plugin classes in explicit ordered tuples; dynamic filename discovery and vendor compatibility plugin bases have been removed.

## Detection conventions

- Match complete tokens or anchored command forms; never infer a positive command from a substring inside its negated form.
- Resolve effective state in configuration order, including set/unset, no-form commands, delete, activate/deactivate, disablement, and inherited scope where supported.
- Evaluate fields from the same policy or object and resolve attachments before declaring exposure.
- Preserve stable rule IDs. Multiple affected objects may share a rule ID when their evidence identities remain distinct.
- Do not turn absent unversioned configuration into proof of insecurity when defaults vary by release.
- Redact secrets before constructing parser evidence or findings.
- Populate `Finding.references` for every new or materially changed security rule.

## Testing conventions

- Use pytest fixtures or temporary vendor-native configurations.
- Cover true positive, true negative, syntax variants, override/removal state, disabled/inactive state, unknown/not-applicable state, and secret redaction.
- Exercise the public analyzer pipeline in addition to direct plugin tests.
- Assert stable rule IDs and absence of duplicate `(rule_id, evidence)` findings.

## Current intentional deviations

- IOS still uses CiscoConfParse internally because its mature hierarchy representation is useful, but plugins receive the parser rather than reopening files.
- Junos and FortiOS use grammar-aware vendor parsers because line-oriented regex cannot preserve their hierarchy and mutation semantics.
- ScreenOS retains vendor-native records and an effective command stream because the same export mixes global state, interface state, and policy edit contexts.
- Check Point retains typed layer, rule, object, service, and group records alongside the shared normalized policy view because ordered-layer comparison and nested reference expansion cannot be represented faithfully by the shared policy fields alone.

The complete current architecture and extension workflow are maintained in `docs/ARCHITECTURE.md` and `docs/EXTENDING.md`. This agent note records the remediation-era conventions only.
