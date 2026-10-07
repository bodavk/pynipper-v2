# Historical implementation handoff: audit accuracy cleanup

**Retired as an execution prompt — 2026-10-07.** The ready SC-068/069, SC-050 stages 1–2 and profiling-qualified SC-066 scope below has been implemented. The original text is retained for traceability, not as instructions to repeat completed work or reset later functionality. Current open work lives in [Security coverage tasks](SECURITY_COVERAGE_TASKS.md) and [the documentation/open-work index](../TODO.md).

Durable contracts are maintained in [Export evidence](../EXPORT_EVIDENCE.md), [Architecture](../ARCHITECTURE.md), [Extending](../EXTENDING.md) and [AGENTS.md](../../AGENTS.md). Original 59-control and 24-resolved references below describe the pre-expansion snapshot; current source has 420 controls and the ASA comparison fixture expects 20 resolved plus four no-longer-assessable. That grouping remains a documented review item, not a reason to silently restore older expectations.

## Original handoff (historical)

Implement the ready cleanup work in the authoritative [Security coverage backlog](SECURITY_COVERAGE_TASKS.md), in this order:

1. [SC-068](SECURITY_COVERAGE_TASKS.md#sc-068): prevent batch output from replacing supplied artifacts.
2. [SC-069](SECURITY_COVERAGE_TASKS.md#sc-069): correct malformed FortiOS baseline trusted-host assessment.
3. [SC-050](SECURITY_COVERAGE_TASKS.md#sc-050), remaining P2 stages 1–2: preserve mixed-instance uncertainty and enforce comparison identity. Coordinate with [SC-049](SECURITY_COVERAGE_TASKS.md#sc-049).
4. Review the conditional P3 profiling follow-up in [SC-066](SECURITY_COVERAGE_TASKS.md#sc-066). Change performance code only if profiling establishes the stated entry gate. The future SC-050 stable-subject stage and all other evidence-gated breadth work remain outside this handoff.

These are approved scoped fixes. Continue through the ready stages without asking for confirmation between them. If research, samples or a maintainer-only decision is genuinely required for a gated stage, retain that gate, explain the evidence needed, and continue independent ready work. Do not invent a default, organizational policy or controller behavior to avoid a gate.

## Read before editing

Read [AGENTS.md](../../AGENTS.md), [Architecture](../ARCHITECTURE.md), [Extending](../EXTENDING.md), [Export evidence](../EXPORT_EVIDENCE.md), [Assessment policy](../ASSESSMENT_POLICY.md), and the named task entries. Maintainer instructions take precedence over stale completeness wording in comments or guides.

Read the current source and tests again; other changes may have landed after this handoff. Reproduce each still-open defect before changing it. If a defect is already fixed, verify its positive/negative behavior and update its status rather than reimplementing it. Do not run Git commands or delete project files. Do not copy CIS benchmark text into the repository.

The compatibility review on 2026-10-06 passed 39 permanent corpus configurations and 600 focused tests across batch, controls, accuracy cleanup, policy effectiveness, FortiOS/IOS/ASA paths, administrator profiles, offline enforcement, architecture and CIS references. This was not a fresh full-suite run. At review time there were 59 registered controls and five active/five gated attack-path patterns. Recount from source if newer work has landed; preserve additional valid implemented functionality too.

## Binding behavior

A setting omitted within an exported object is known configuration state. Report an unconfigured required protection, apply a cited release-gated default, or use the applicable missing-explicit-setting basis. Word observations as omitted/not configured. Do not introduce a whole-file completeness flag, demand defaults be restated, or suppress findings merely because another domain is absent.

Unknown is for an absent containing domain, malformed/unsupported syntax, externally managed/inherited references, or a necessary unqualified default. In self-contained exports, undefined local references remain broken-binding findings. Do not change these detector semantics as a side effect of comparison work.

Parsers own syntax, scope, effective ordering, references, knowledge and sanitized evidence. Plugins consume typed records. Preserve stable rule IDs, existing valid severities, tenant/family identity, assessment roles, exclusions, template handling and deterministic output. Do not reopen config files or parse observation text inside plugins/matchers. Audit runtime must remain fully offline: no device connections, DNS, HTTP, active probes, revocation lookups or downloads. Developer research and separate advisory acquisition are not audit operations.

## SC-068 implementation boundary

Keep the existing batch orchestrator and commands. Before output creation, validate the complete JSON/HTML/index destination set against all supplied configurations, directory-export subtrees, manifest, assessment policies and local advisory bundle. Detect resolved path aliases and existing filesystem identity, including Windows case, junction/symlink and hard-link aliases where supported. Reject duplicate output destinations, including device ID `batch-index` colliding with the consolidated index. An unsafe request is a preflight failure with no changed inputs or outputs, even with `--overwrite`.

Preserve legitimate report overwrite, ordinary per-device input failures, mixed-family processing, auto-detection, directory inputs, index hashes and optional HTML. Do not ban noncolliding output merely because it is in a flat configuration file's containing directory. Use synthetic fixtures for destructive collision tests and verify artifact hashes before/after rejection; never test against original supplied exports.

## SC-069 implementation boundary

The current baseline check accepts `ip6-trusthost1 2001:db8:::1/64` as a successful restriction; the path parser already marks it unknown. Share or extract the existing parser syntax validator and provide a small typed assessment to the baseline. Keep parser records independent of analysis Finding classes.

Validate every supplied selector's address, mask/prefix, family and supported index. Malformed/unsupported selectors cannot count as restrictions. A supplied unknown selector without a known broad weakness yields an unknown account outcome. A known broad weakness remains a finding alongside any unknown reason. A wholly omitted required restriction stays a not-configured finding.

Preserve valid IPv4-only GOOD_ADMIN/REMOTE_ADMIN fixture outcomes. Do not require both address families, infer omitted IPv6 exposure, add an external-interface role prerequisite to baseline checks, grade new roles, or alter MFA/lockout checks. Describe the family actually validated. Preserve existing defaults and path-specific listener, role, local-in, VDOM, family and release gates; sharing validation must not make a baseline finding sufficient to emit a path. Keep valid path keys/results stable. No new path catalogue entry is authorized.

## SC-050 comparison boundary

The current mixed-instance reproduction is PAN-OS rule A changing from no inspection attachment to an unexported group while rule B still has no attachment. A is unknown, B is a finding, and the aggregate is a finding; comparison incorrectly resolves A. Consume existing instance/unassessed fields. Until explicit subject bindings exist, conservatively prevent resolution of disappeared findings associated with that uncertain control and explain the limitation. Leave unchanged findings and unrelated controls alone.

Preserve the evidence-based key format for the immediate patch. Legacy aggregate-only reports remain readable using the documented fallback; do not require new metadata from every report, rebuild the Finding model, or turn all unmigrated rules into unknown. Preserve the current ASA vulnerable-to-secure positive fixture (24 resolved at review time), reverse comparison, exclusions, template/missing/error behavior, and both JSON and escaped HTML comparison views. An intentional change to a positive fixture requires a separately demonstrated semantic reason, not a blanket zero-resolution expectation.

Require matching canonical device families and known nonempty analyzer fingerprints for remediation conclusions. Resolve true registry aliases without merging PIX/ASA, FW1/Gaia or IOS-XE/IOS identities. Two absent fingerprints are not matching provenance. Preserve equivalent default-policy handling; an explicitly declared policy without a valid digest is uncertain. A family/provenance mismatch must yield a clear not-comparable explanation, with current findings still visible. A manifest ID is the auditor's declared identity, not verified physical identity. Do not change single-device detection or refuse normal audits due to comparison-only metadata limitations.

Stable subject identity is a separate planned SC-050 stage. Preserve it in the backlog; do not force an all-platform migration into this correction. Future identity must be parser-owned, scope/family qualified, secret-free and optional/additive/versioned, with old-report fallback. A missing object in a fragment is not proven deletion.

## Conditional performance work

The 200-rule timing test previously failed but passed in the latest isolated run and compatibility suite. Profile the unchanged case before editing. If no current failure or meaningful measured bottleneck exists, record the gate result and leave performance code unchanged.

If justified, use bounded per-parser caches for immutable object indexes, complete top-level selector results keyed by scope/selectors/expansion limit, and typed NAT inventory. Preserve cycle/limit/unresolved behavior and invalidate on supported reload/mutation. Avoid process-wide or partial-recursion caches. Do not change proof budgets, skip comparisons, relax timing assertions or broaden NAT/address semantics. Demonstrate cached-versus-uncached result equivalence and parser/scope isolation.

## Validation and completion

For each implemented stage, run meaningful positive, secure-negative, override/removal, malformed/unknown, scope/family, redaction and public-pipeline tests as applicable. Retain input-preservation and legitimate-overwrite positives; valid IPv4-only administrator positives; mixed-instance uncertainty; aliases/family mismatches; legacy reports; JSON/HTML parity/escaping; all current valid attack-path positives and gated negatives. Prohibit network access in public audit tests. Explain genuinely inapplicable test dimensions.

After parser/plugin/report/orchestration changes, run the complete established gate from the repository root:

```powershell
.\.venv\Scripts\python.exe scripts\run_full_regression.py
```

Do not automatically regenerate corpus expectations, loosen performance tests, alter severities or remove assertions to obtain a pass. Review every intentional report/control/snapshot difference and attribute it to the specific reproduced defect. Update only the implemented task stages, preserving stable IDs and open evidence gates. Any touched comment or guide must agree with AGENTS.md.

Finish with changed files, reproduced defects, preserved behavior, actual test results, intentional differences and remaining gates. Do not claim that unimplemented designs or passing baseline tests prove the fixes safe; acceptance requires the implemented changes and their regression results.
