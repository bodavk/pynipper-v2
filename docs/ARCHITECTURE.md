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

### Analyzer layer

An analyzer is the CLI-facing orchestration function for one platform. It:

1. obtains the registered parser through `get_parser()`;
2. optionally obtains external advisory data where supported;
3. calls the platform processor;
4. gathers hostname/device metadata;
5. calls the report generator.

Analyzer modules remain thin by design. Detection logic belongs in plugins and syntax logic belongs in parsers.

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

See [Extending pynipper-v2](EXTENDING.md) for the implementation workflow.
