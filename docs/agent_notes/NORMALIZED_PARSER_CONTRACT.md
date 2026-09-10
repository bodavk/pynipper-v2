# Normalized Parser Contract

The vendor-neutral parser surface is `BaseDeviceParser.get_normalized_config()`. New shared detection logic must use this surface. Vendor-specific rules may use `get_native_config()` only when a required construct is not represented by the normalized model. `get_raw_config()` remains a temporary compatibility alias and must not be used by new code.

## Required snapshot fields

Every parser returns a `NormalizedConfig` containing:

- canonical device type;
- hostname, device model, and software version;
- management services;
- local users;
- interfaces and zones;
- ordered security policies;
- logging destinations;
- cryptographic settings.

Scalar and collection fields always carry a `KnowledgeState`:

- `known`: the parser evaluated the supported input and the value or collection is authoritative. A known collection may legitimately be empty.
- `unknown`: the parser has not yet established the value. It must not contain a value or items.
- `unsupported`: the selected input format or platform cannot represent or expose the field. The detail must explain the limitation.
- `parse_error`: input intended to be supported could not be parsed safely. The detail must identify the failure; parsers should attach evidence where available.

Configuration records separately use `ConfigurationState` to represent `enabled`, `disabled`, `configured`, or `unknown`. This prevents a configured definition from being mistaken for an enabled or effectively attached control.

## Evidence requirements

When normalized state is marked known, implementations should attach `ConfigEvidence` containing the source path, exact source text, and a positive line number when the format provides one. Secrets must be redacted before becoming evidence. Rules must not reinterpret an unknown value as disabled, absent, secure, or insecure.

Findings may also carry a tuple of `references`. New or materially changed security controls should populate it with the vendor documentation, benchmark, STIG, or other source used to justify the evaluated behavior. References are serialized independently from configuration evidence.

## Migration rule

The base implementation returns a complete explicit-unknown snapshot. Each parser-reconstruction task replaces those unknown fields with known typed records only after its grammar, scope, mutation ordering, and reference resolution are covered by vendor-native fixtures. This allows parser work to proceed incrementally without preserving the old ambiguity where `False`, `[]`, or `?` meant either absent or unimplemented.
