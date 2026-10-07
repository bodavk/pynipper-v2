# Open improvement work

Reconciled **2026-10-07** against the current source and regression results.
This page is a navigation index, not a second implementation backlog.
[Security coverage tasks](agent_notes/SECURITY_COVERAGE_TASKS.md#current-execution-priorities--2026-10-06)
owns security-task priorities, verified scope and evidence gates.

## Documentation map

- [Architecture](ARCHITECTURE.md): runtime structure and durable engineering decisions.
- [Extending](EXTENDING.md): adding checks, controls and device support.
- [Export evidence](EXPORT_EVIDENCE.md): omitted settings, unknown evidence, scoped outcomes, policy proof and comparison limits.
- [Assessment policy](ASSESSMENT_POLICY.md): approved deployment context and offline assessment inputs.
- [Supported devices](SUPPORTED_DEVICES.md): verified formats and support boundaries.
- [Security coverage tasks](agent_notes/SECURITY_COVERAGE_TASKS.md): authoritative SC-001–SC-069 backlog.
- [Practical testing tasks](agent_notes/PRACTICAL_TESTING_TASKS.md): deferred dependency work and practical-testing history.
- [External validation tasks](agent_notes/REALWORLD_VALIDATION_TASKS.md): remaining RV-008 evidence gate and compact completed-work ledger.

[CIS review](agent_notes/CIS_BENCHMARK_COVERAGE.md) and
[external validation findings](agent_notes/REALWORLD_VALIDATION_FINDINGS.md)
are dated evidence records, not current implementation status.
[Insecure defaults by release](agent_notes/INSECURE_DEFAULTS_BY_RELEASE.md)
is the separately maintained per-row source register.
The [completed cleanup handoff](agent_notes/ACCURACY_FIX_IMPLEMENTATION_PROMPT.md)
is historical reference only.

## Current implemented foundations

- Offline single-device and batch audits, input-preserving output preflight, local advisory replay and JSON/HTML reports.
- 420 explicitly registered outcome controls; this is not complete rule coverage or benchmark certification.
- Five active and five gated attack-path patterns; HTTP clear-text administration is not yet part of the active Telnet pattern.
- Comparison family/provenance checks and mixed-instance uncertainty; stable per-object comparison identity is still open.
- Qualified F5 SSH omission finding, shared FortiOS trusted-host validation, finding-basis notes and parser-owned secret-report appendices.

The **2026-10-07 implementation review**, before this documentation-only edit,
passed 3,856 tests and all 39 corpus configurations. Current ASA comparison
expects 20 resolved and four no-longer-assessable findings; reverse comparison
has 24 new findings. Older validation counts are historical.

## Remaining work

- **Accuracy and assurance — SC-049/SC-050:** fix the newly identified PAN-OS malformed-hash false-success state; finish remaining rule mappings, scoped outcomes and vendor tests; review the conservative ASA comparison grouping. Stable subject identity is a separate stage.
- **Direct security depth:** follow the SC priority queue for evidence-ready management ACL/API, identity, VPN, routing and risky-service work. Completed stages must not be reimplemented from older wave descriptions.
- **Attack paths — SC-063:** HTTP administration and the five gated catalogue patterns require their exact same-entity admission/binding proof before expansion.
- **Deployment-specific work:** remaining IPv6/access-edge and FortiOS policy/boundary depth belongs to the named SC tasks, not duplicate tasks here.
- **PT-008 (deferred):** modernize dependencies, add reproducible constraints and fresh-install validation.
- **Advisory breadth — SC-022/PT-010:** validate and extend separate acquisition/local replay only with qualified product/module/version evidence; never introduce audit-time retrieval.

## Evidence gates kept open

These are not completed merely because adjacent checks or synthetic tests pass:

- SC-054 FortiOS rule-hit evidence: a versioned counter export and observation window.
- SC-017 Check Point anti-spoofing/implied rules: matching sanitized `objects.C` and `rules.C`.
- SC-024 F5 AFM/APM/ASM depth: real module-provisioned exports and exact active bindings.
- SC-018 remaining SonicOS zone/default/direction semantics: representative supported custom E-CLI exports.
- SC-019 and RV-008 ScreenOS screens, time and VPN anti-replay: qualified release documentation and exports.
- SC-020 PIX and SC-023 Gaia qualification: representative dialect/release exports; registry support is not parity.
- Controller inheritance: merged-effective or representative Panorama/FortiManager exports.
- Check Point FW1 `--show-secrets`: a sanitized export proving the relevant secret fields; current FW1 input remains explicitly unsupported for this option.
- SC-044 source conflicts and unqualified old-release defaults: preserve the separate register and its open rows.

## Retained maintainer boundaries and optional work

- Do not grade FortiOS log-administrator rights against a new organization role list; retain bound write-capable-role checks.
- Lifecycle data must come from a free external dataset acquired separately; do not maintain a private lifecycle list or fetch during audits.
- PAN-OS/SonicOS community-SNMP and SonicOS Telnet additions remain unscheduled unless separately approved.
- FW1 local user credentials live in a separate user database; policy exports do not prove those credentials. Gaia OS secret appendices are independently supported.
- Junos stateless-filter effectiveness needs proven attachment/order/selector semantics; runtime usage cannot be inferred.
- New dialects (FWSM, old SonicOS preferences, CatOS/NMP, CSS, Passport/Accelar, F5OS/UCS) need demand, representative exports and maintenance justification.
- Continue adding anonymized syntax fixtures and reviewing support maturity as evidence improves.
- A cracking-tool hash export remains an optional design requiring approved handling, validated formats, explicit destination/permissions and no automatic cracking.

Follow [AGENTS.md](../AGENTS.md): omission inside an exported object is known
not-configured state or a qualified default, while absent domains, malformed or
unsupported values, external inheritance and needed unqualified defaults retain
uncertainty. Do not delete sample-gated tasks or imply passes from absent findings.
