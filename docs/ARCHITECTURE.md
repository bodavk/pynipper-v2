# pynipper-v2 Architecture

## Design goals

The project is organized around five rules:

1. One registry defines every CLI-visible device and its parser/analyzer pair.
2. Parsers own syntax and effective-state reconstruction; plugins do not reopen files.
3. Shared analysis uses typed normalized records with explicit unknown state.
4. Public processors register plugins explicitly and return vendor-neutral findings.
5. Target-platform behavior is locked by exact permanent regression snapshots.

## End-to-end flow

```text
CLI arguments
    |
    v
src.main
    |
    v
analyze_device -> device registry -> platform analyzer
                                      |
                                      v
                              parser from get_parser
                                      |
                         +------------+-------------+
                         |                          |
                         v                          v
                vendor-native model         NormalizedConfig
                         |                          |
                         +------------+-------------+
                                      |
                                      v
                         explicit platform processor
                                      |
                                      v
                           ordered plugin classes
                                      |
                                      v
                          Finding objects + advisories
                                      |
                                      v
                              HTML or JSON report
```

## Major components

### CLI and dispatch

`src/main.py` validates command-line values. Device choices come from `get_device_choices()` rather than a hand-maintained list.

`src/analyze/analyze_device.py` validates the input path, resolves a `DeviceDefinition`, lazily imports its analyzer, and delegates the scan. Lazy import paths prevent registry/parser/analyzer import cycles.

### Authoritative device registry

`src/devices/registry.py` is the only device catalogue. Each immutable `DeviceDefinition` contains:

- canonical ID and legacy numeric value;
- accepted aliases;
- parser import path;
- analyzer import path;
- display name.

The registry builds `DeviceType`, CLI choices, parser construction, and analyzer dispatch. Alias uniqueness and registry reachability are enforced in `tests/test_architecture.py`.

### Parser layer

Every parser extends `BaseDeviceParser` and implements hostname, software version, local-user, management-service, and native-configuration accessors. `get_native_config()` exposes the vendor-specific representation when a rule genuinely requires it.

`get_normalized_config()` returns a `NormalizedConfig` containing typed values for:

- hostname, model, and software version;
- management services and permitted sources;
- local users;
- interfaces and zones;
- security policies;
- logging destinations;
- cryptographic settings.

Every normalized value or collection has a `KnowledgeState`: `KNOWN`, `UNKNOWN`, `UNSUPPORTED`, or `PARSE_ERROR`. An empty known collection means the parser established that no matching objects exist. An unknown collection means the parser cannot make that claim. Plugins must preserve this distinction.

Vendor parsers also reconstruct effective state where syntax is ordered. Examples include IOS `no` commands, Junos `delete`/`deactivate`, ScreenOS `unset`, FortiOS nested global/VDOM edits, and Check Point ordered layers and object references.

Documented defaults and legacy syntax are release-gated, not inferred from a vendor label. The ScreenOS parser, for example, exposes its documented unmatched-policy default and timeout defaults only when the export identifies the verified 6.3 family. It keeps console/Telnet, Web administration, administrator AAA, and policy/user authentication-server controls separate, resolves only active named bindings, and returns unsupported or unresolved state when the release or referenced object is not established. This pattern prevents a modern Junos control—or even a different ScreenOS release—from being silently applied to a legacy export.

Authentication relationships are parser-owned records, not plugin substring tests. A time association, for example, retains its server/peer role, address, VRF or device scope, key or NTS-profile reference, algorithm, effective resolution state, and sanitized evidence. A configured secret field may be known present, known missing, or redacted/unexported; those states must not be collapsed. Plugins evaluate every active association independently so one protected peer cannot mask another insecure peer.

AAA transport follows that relationship rule. FortiOS records resolve named RADIUS profiles through user groups to enabled remote administrators and retain transport, server identity/CA settings, TLS minimum, source interface/address and VRF. Shared-secret fields are excluded from the record and its evidence. Release capability, binding, explicit protected-path context and unknown topology remain separate facts; a configured UDP endpoint alone is not proof of an unsafe path.

SNMP access follows the same relationship boundary. Vendor parsers resolve effective users to their groups, security levels, read/write views, source ACLs or manager attachments, and active agent scope before a plugin grades protection. Authentication/privacy material is reduced immediately to present, missing, hidden/redacted, or unknown state. A secure identity never substitutes for assessment of another active identity, while an explicitly inactive agent or unbound ASA user is not reported as exposed access.

Routing trust is also relationship-scoped. Native IOS/XE and Junos records retain process/peer or interface identity, VRF/routing-instance, address family, inherited authentication/key-chain state, passive/shutdown state, directional policy attachment and prefix-limit presence. Plugins grade only active relationships. Route-policy absence is reportable only when the peer's external role is explicit; unknown inheritance, role or algorithm remains unknown. Static configuration never proves which routes were accepted at runtime.

Inspection policy follows attachment scope rather than object inventory. PAN-OS records retain enabled allow-rule profile mode, resolve groups and individual profiles in same-vsys/shared precedence, and classify exported actions. FortiOS records retain enabled accept-policy UTM mode, expand profile groups in VDOM/global/root precedence, and resolve each member independently. Custom empty and explicitly non-blocking attached profiles are distinct from unresolved references; disabled rules and unbound definitions are ignored. Unexpanded controller inheritance remains unknown, and static profile resolution never asserts subscription health, signature freshness or runtime inspection.

Traffic domains must also remain separate. FortiOS transit policies and IPv4/IPv6 local-in policies have different typed records and checks. Junos stateless firewall filters and SRX zone-pair security policies likewise use different records: the SRX model resolves static zone/global address books and applications while preserving order, deletion, deactivation and apply-groups uncertainty. A wildcard finding requires complete positive resolution; a dynamic or inherited unknown is never treated as `any`.

VPN analysis begins at an active attachment, not at an inventory of proposal objects. FortiOS resolves an enabled phase2 binding to phase1 only inside its VDOM scope. Junos resolves an active policy tunnel or interface-bound VPN through gateway, IKE policy/proposal and IPsec policy/proposal relationships. Unreferenced weak objects and disabled tunnels are ignored, while broken active chains are reported separately from explicit weak algorithms. Static configuration cannot establish negotiated transforms, peer identity, policy installation or security-association health.

Credential-bearing parsers expose `CredentialMetadata` rather than raw values. The record keeps storage format and storage assessment separate from the exact known-default comparison: a `NO_MATCH` result only means that the supplied representation did not equal a maintained fingerprint, never that the credential is strong. `UNKNOWN` and `MALFORMED` formats cannot be promoted to approved storage or used to infer plaintext length. Secret values remain inside the parser boundary; evidence contains only redacted command structure.

Management-certificate assessment uses the same separation. PAN-OS resolves an active management TLS/profile reference to a shared or device-scoped certificate object; ASA resolves effective SSL trustpoint assignments to trustpoint and certificate-chain declarations. A shared X.509 layer parses public DER/PEM and exposes only fingerprint, subject/issuer, SAN, validity interval, public-key/signature properties and CA/self-issued state. Private-key and certificate payloads are never stored in records or finding evidence. Validity requires an explicit timestamp, identity requires an exact scope mapping, and chain validation requires an approved SHA-256 anchor that is also present in the export. Missing inputs remain unknown. Static validation never claims revocation state, client trust, or which certificate is currently served.

### Analyzer layer

An analyzer is the CLI-facing orchestration function for one platform. It:

1. obtains the registered parser through `get_parser()`;
2. optionally obtains external advisory data where supported;
3. calls the platform processor;
4. gathers hostname/device metadata;
5. calls the report generator.

Analyzer modules remain thin by design. Detection logic belongs in plugins and syntax logic belongs in parsers.

An optional immutable `AssessmentContext` is created at the CLI boundary and attached to the parser before processing. It carries policy identity/provenance, explicit device and interface roles, exact protected-AAA profile declarations, and category exclusions. Processors filter excluded rule categories only after plugins finish, preserving parser coverage and effective-state reconstruction. Reports always serialize the active policy and warn that exclusions are not evidence of compliance. Role/path consumers must require an exact explicit declaration; names, addresses and routes are not topology inference.

### Processors and plugin registration

Each platform processor exposes a `process_*_conf()` function and an explicit ordered tuple of plugin classes. Explicit registration makes the public scan surface deterministic and prevents an unrelated file placed in a plugin directory from silently becoming executable analysis.

Processors instantiate each plugin once, call `analyze(parser)`, combine its findings, and may deduplicate by `(rule_id, evidence)` while preserving findings for distinct affected objects.

### Plugins

Every plugin extends `BasePlugin` and receives a constructed parser. Plugins may consume the normalized model or a typed vendor-specific parser API. Direct file I/O and independent reparsing are not allowed.

A plugin emits `Finding` instances. Each finding requires:

- stable namespaced `rule_id`;
- canonical device ID;
- title, observation, impact, and recommendation;
- typed severity;
- exploitability narrative;
- sanitized configuration evidence;
- vendor/benchmark references for new or modified checks.

One finding should describe one root cause. Multiple affected objects may share a rule ID when their evidence differs.

### Reporting

`src/report/report.py` renders findings and optional software advisories as HTML or JSON. The neutral `Finding.to_dict()` contract is the JSON boundary. HTML templates display severity, evidence, and references directly.

### Validation

Unit tests cover parser semantics, individual rules, finding validation, registry reachability, CLI behavior, and reports.

`tests/test_data/regression/manifest.json` defines the permanent target corpus. `scripts/run_full_regression.py` constructs parsers through the public factory, requests normalized state, executes public processors, rejects duplicate rule/evidence identities, compares exact finding snapshots, and then runs the entire test suite.

`.github/workflows/build-python.yml` runs the same gate across the supported Python and operating-system matrix. CodeQL remains as the repository's built-in static security workflow; unconfigured inherited third-party service workflows are intentionally not part of the current architecture.

## Supported-depth boundary

The registry contains both target-baseline and partial devices. Registration guarantees that the CLI can construct and dispatch the implementation; it does not guarantee equal detection depth. `docs/SUPPORTED_DEVICES.md` is the user-facing authority for maturity, while `docs/agent_notes/01_gap_matrix.md` records original-tool parity.

## Architectural invariants

- Do not add a second device list or dispatch chain.
- Do not treat absence as a known secure or insecure state unless the relevant platform/version default is established.
- Do not use unanchored positive substring matching where a negated command can match.
- Do not coerce untrusted tokens without parse-error handling.
- Do not expose secrets in evidence.
- Do not dynamically discover executable plugins.
- Do not add a public rule without true-positive, true-negative, edge/override, and pipeline tests.
- Do not describe a partial parser as target-baseline support.

## Durable engineering decisions

These decisions apply to future checks, parser work, and device additions:

- Reconstruct effective configuration state in parsers, preserving source order, scope, negation, removal, disablement, and inheritance where the format supports them.
- Evaluate related fields from the same policy, object, interface, or management profile; resolve attachments before reporting exposure.
- Treat missing, unsupported, malformed, and version-dependent state as explicit unknowns rather than silently secure or insecure values.
- Keep vendor-specific grammar in typed parser APIs. Extend the normalized model only for concepts that have stable meaning across platforms.
- Redact passwords, keys, communities, tokens, and other secrets before storing evidence or serializing findings.
- Require every new or materially changed finding to have a stable namespaced rule ID, one root cause, sanitized evidence, an authoritative reference, and positive/negative edge-case coverage through the public processor.
- Keep the permanent regression corpus exact and duplicate-free; snapshot changes require semantic review rather than automatic acceptance.
- Separate static configuration analysis from live operational checks such as certificate validity, licensing, runtime authorization, controller-inherited state, and current firmware support.

See [Extending pynipper-v2](EXTENDING.md) for the implementation workflow.
