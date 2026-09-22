# Tasks from outside-project configuration validation

These tasks follow the requested template because this checkout has no GAP_REMEDIATION_TASKS.md or detection-audit task file. The distinct RV- prefix is unused here. IDs remain stable while display order reflects priority. Evidence and complete, unedited reports are in [REALWORLD_VALIDATION_FINDINGS.md](REALWORLD_VALIDATION_FINDINGS.md). A finding from a sanitized example is about the supplied configuration and its stated scope, never proof of Internet reachability or live exploitation. Tasks marked Needs research must clear their evidence gate before implementation.

For every implementation task, use parser-owned effective state, typed records, explicit known/unknown/unsupported/parse-error states, explicit plugin registration, stable finding IDs, sanitized evidence and authoritative platform guidance. Test positive, negative, override/precedence, malformed/unknown, scope, redaction and the installed public CLI pipeline where applicable. After a code or corpus change, run the established full gate in [Extending pynipper-v2](../EXTENDING.md): .\.venv\Scripts\python.exe scripts\run_full_regression.py. Do not use these external configs as undisclosed in-repository test fixtures; create minimal sanitized cases and preserve provenance.

## Wave 1 — active-control misses and report trust

### Implementation record — 2026-09-22

- RV-011: Junos SRX now resolves the explicit global `security policies default-policy`, including ordered direct overrides, deletion, group inheritance and unknown group/malformed states. A `permit-all` fallback produces a high-priority unmatched-transit finding and a normalized policy coverage item even without named rules. Synthetic CLI/coverage tests and the RW-029 sample were checked.
- RV-006/RV-007: IOS/IOS-XE now classify effective RADIUS shared keys and line passwords without retaining values, and EOS classifies RADIUS keys plus a literal active TerminAttr ingestion key. IOS emits independent findings for exact known-default plaintext enable/line values and effective default SNMP communities, including removal handling. Malformed/masked material stays ungraded; redacted parser/plugin/public-CLI tests were added. Existing IOS snapshots reflect the intentionally added findings.
- Current verification: 757 tests and all 32 permanent corpus cases pass after these additions; focused public JSON/HTML secret-redaction tests are also included. RV-008 remains evidence-gated: Juniper-hosted examples confirm `no-replay` syntax and bound VPNs, but no release-specific ScreenOS 6.2/6.3 command reference establishing the control semantics and default was located. Do not infer those from Junos documentation.
- RV-005: EOS now identifies a configured server without a key binding or NTS profile as unauthenticated even when the export omits the release, since this explicit server command has no authentication reference. A server with a key reference and unknown global authentication state remains unknown; an explicitly enabled global authenticator with no server key is unresolved. Incomplete `key` and `ssl profile` options also remain unknown. All three external AVD leaf examples resolve to two unauthenticated management-VRF servers each. Sanitized synthetic tests cover the public JSON/HTML CLI, VRF independence, overrides, removal, malformed options, and key redaction.
- RV-004: IOS/IOS-XE now overlays ordered console, AUX, TTY, and VTY range mutations to resolve effective explicit `exec-timeout` values and disabled line state. Active lines above ten minutes receive a scoped excessive-timeout finding; explicit zero retains line-class-specific disabled-timeout findings. RW-001's two 90-minute ranges and RW-017's 720-minute range are now reported through the installed CLI. Safe, reset, malformed, partial, `no exec`, and `transport input none` cases are covered.
- RV-001: ASA now resolves explicit server/client SSL versions, legacy and per-protocol cipher commands, ordered removals/replacements, and WebVPN interface activation. Obsolete inbound protocols and weak offered cipher suites are reported separately only when WebVPN is attached to a configured interface and the ASA release is known. The RW-003 ASA 9.3(2) sample produces both previously missing findings through JSON and HTML; disabled, partial, malformed, client-only, and modern configurations do not receive those active-service assertions.
- RV-009: unrendered Jinja, accelerator lookup, and Fortinet placeholder markers now mark PAN-OS and FortiOS inputs as `unrendered-template`. Absence-based findings are suppressed under a conservative explicit-risk allowlist; the JSON/HTML coverage ledger records the incomplete scope and suppressed count. Comment-only markers do not trigger this state. External PAN/Forti templates completed through the installed CLI with explicit risks retained and unsupported absence claims suppressed.
- RV-003: PAN-OS now reads management password complexity from `mgt-config/password-complexity` and resolves active shared/device system-log match-list references to defined syslog-profile servers. The RW-010 Iron Skillet sample no longer produces the two false absent-control findings in JSON or HTML. Unbound, missing, and disabled forwarding profiles remain non-operational.
- RV-002: ASA IPsec transform findings now follow static/dynamic crypto-map references to interface attachments, honor replacement/removal order, and distinguish unresolved attached references from confirmed weak declarations. The RW-008 Azure sample produces one bound legacy-transform finding rather than findings for unused declarations. Synthetic multi-bound, unbound, removed, and unresolved-reference cases are covered.
- Current verification: 741 tests and all 32 permanent corpus cases pass. The external samples were used for manual validation only and were not copied into the corpus. The vulnerable IOS corpus gained one intentional active-AUX zero-timeout finding.
- RV-012: command-stack correction and controlled parser-error reports implemented. The unchanged RW-031 input now completes through the installed CLI in both JSON and HTML. Nested/repeated VDOM tests preserve active/disabled policy state and later overrides. Malformed input produces explicit parse-error coverage, no traceback or source values, and exit status 2. Template completeness is addressed separately under RV-009.
- RV-010: explicit local disk/memory state and accurate remote-forwarding wording implemented. RW-011 completes in both output formats and its logging finding no longer claims all logging is absent. Missing/invalid local status remains unknown; disabled remote sinks do not satisfy the forwarding check. General partial/template scope is addressed separately under RV-009.
- Verification: 698 tests and all 32 permanent corpus cases pass. Eleven added tests cover the parser, public CLI failure reports, redaction and local/remote logging combinations. The full run emitted a non-failing pytest cache-write warning. No corpus snapshots were changed.
- Reconciliation before this implementation: IOS type-7 placeholders are malformed payloads; IOS already labeled exact default communities in observation text and already computed the known-default enable match. RW-030's embedded report contains 12 findings despite the original summary saying zero. Preserve raw reports when correcting interpretations.

### RV-012 — Accept FortiOS `end` inside an edited table entry without crashing

**Task ID and Title:** RV-012 — Parse the documented FortiOS `end` command in an active `edit` context.

**Priority:** P0 — the installed public CLI exits with an uncaught traceback and creates no report for an AWS FortiGate reference template; a user cannot evaluate any of its controls.

**Status:** Ready after confirming the template's relevant FortiOS syntax version; the documented `end` behavior is already established.

**Source of Truth:** [RW-031](REALWORLD_VALIDATION_FINDINGS.md#RW-031), especially the complete stdout/stderr and source line 153; [Fortinet command syntax](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/508024/command-syntax) states that `end` can save both the current edited entry and its table.

**Linked Findings:** [RW-031](REALWORLD_VALIDATION_FINDINGS.md#RW-031).

**Dependencies:** Confirm the precise FortiOS release targeted by the AWS script and test whether subsequent VDOM sections and template placeholders are supported. Coordinate with RV-009 so an unresolved template is never mistaken for a complete running export.

**Architecture/Convention Notes:** The FortiOS parser owns CLI command-stack semantics and effective VDOM state. `end` must pop the current edit and its enclosing config according to Fortinet syntax, without losing parent VDOM context. Genuine malformed syntax should yield a structured parse-error/unknown coverage report rather than an uncaught exception. Keep stable existing finding IDs and sanitized errors.

**Concrete Requirements:** Affected FORTIOS. Accept `end` after `edit root` in `config vdom` and analogous edited tables, continue parsing later blocks, and preserve the explicit disabled syslog sink, active policy 1, disabled policies 2/3/5 and later `admintimeout 15` as typed effective evidence. If unsupported template tokens prevent a complete scan, expose that scope honestly through existing JSON/HTML coverage instead of a process crash. No new CLI flag or schema is required unless the established parse-error interface cannot represent the state.

**Test Requirements:** RW-031 command pattern; ordinary `next`/`end` nesting and repeated VDOM blocks; positive active and negative disabled policy checks; later timeout override; malformed/missing `end`, unknown template tokens and partial scope; error and finding redaction; installed CLI JSON/HTML and full regression.

**Acceptance Criteria:** The AWS input no longer raises an unhandled traceback; a supported scan emits an honest report, while genuinely unsupported or malformed input receives a clear parse-error/unknown result. Valid `end` nesting does not change interpretation of active versus disabled rules.

### RV-001 — Assess effective ASA SSL/WebVPN protocol and cipher policy

**Task ID and Title:** RV-001 — Assess effective ASA SSL/WebVPN protocol and cipher policy.

**Priority:** P1 — explicitly enabled TLS 1.0 and DES/3DES on a public ASA example were absent from the report.

**Status:** Implemented for explicitly configured inbound SSL policy on interface-attached WebVPN services.

**Source of Truth:** [RW-003](REALWORLD_VALIDATION_FINDINGS.md#RW-003), especially the literal ssl server-version and ssl encryption commands; [Cisco ASA VPN configuration guidance](https://www.cisco.com/c/en/us/td/docs/security/asa/asa923/configuration/vpn/asa-923-vpn-config/vpn-params.html).

**Linked Findings:** [RW-003](REALWORLD_VALIDATION_FINDINGS.md#RW-003); compare [RW-008](REALWORLD_VALIDATION_FINDINGS.md#RW-008) to avoid conflating SSL and IPsec crypto.

**Dependencies:** Confirm ASA 9.3 command semantics and current minimum-policy source; distinguish server offer from client negotiation and confirm WebVPN attachment. Research is a prerequisite for severity thresholds.

**Architecture/Convention Notes:** ASA parser resolves effective service settings; plugin consumes typed SSL policy with per-command evidence and knowledge state. Do not infer certificate validity or handshake behavior from static configuration.

**Concrete Requirements:** Affected platform ASA. Parse ssl server-version, ssl client-version where relevant, encryption/cipher suite commands, no/default overrides and active WebVPN interfaces. Report an obsolete effective minimum or offered weak suite when active. If the export is partial, version unknown, or no service attachment is proven, keep the relevant field unknown and avoid an active-service assertion. Existing CLI and report schema can stay unchanged; add normalized SSL policy fields only if needed.

**Test Requirements:** Positive TLSv1-only and DES/3DES offered with WebVPN active; negative modern-only policy and disabled WebVPN; override ordering; malformed/unknown syntax; partial snippet; redacted evidence; public CLI JSON/HTML and full regression.

**Acceptance Criteria:** RW-003's explicit active weak choices produce accurate, separately identified findings; secure/disabled/unknown cases never receive the same active-risk assertion.

### RV-002 — Stop treating unused ASA IPsec transform declarations as active

**Task ID and Title:** RV-002 — Bind ASA crypto findings to effective crypto-map/VPN use.

**Priority:** P1 — ten High findings on unused definitions overwhelm the one bound transform and erode report trust.

**Status:** Implemented for static and dynamic crypto-map bindings. Additional ASA attachment dialects remain outside the bounded resolver.

**Source of Truth:** [RW-008](REALWORLD_VALIDATION_FINDINGS.md#RW-008), Azure sample crypto-map selecting only azure-ipsec-proposal-set.

**Linked Findings:** [RW-008](REALWORLD_VALIDATION_FINDINGS.md#RW-008).

**Dependencies:** Verify ASA 9.2 transform selection and all supported crypto-map/tunnel-group attachment forms against Cisco's release documentation before changing severity.

**Architecture/Convention Notes:** Parser owns symbol resolution, command order and attachment; plugin only evaluates reachable effective transforms. Preserve source evidence and stable IDs.

**Concrete Requirements:** Affected platform ASA. Resolve transform-set definitions, crypto-map references, map-to-interface attachment and overrides. Report weak bound transforms; distinguish declarations that have no proven active reference. Unknown references, partial exports and unsupported attachment grammar must become unknown rather than secure or an active High finding. No CLI change is required; inventory may expose unused definitions separately without implying runtime risk.

**Test Requirements:** The RW-008 one-bound/many-declared pattern; multiple bound sets; disabled/replaced maps; missing object references; malformed crypto command; sanitized evidence; CLI report and regression.

**Acceptance Criteria:** Unbound DES/3DES/MD5 transform declarations from RW-008 no longer generate active High findings, while the bound proposal and weak IKE group remain assessed.

### RV-003 — Resolve PAN-OS management complexity and system forwarding in the right XML hierarchy

**Task ID and Title:** RV-003 — Resolve PAN-OS management complexity and shared system-log settings.

**Priority:** P1 — a vendor-supplied full baseline receives both a High absent-complexity finding and a Medium absent-syslog finding despite explicit settings.

**Status:** Implemented for management-level complexity and shared/device system match-list syslog bindings.

**Source of Truth:** [RW-010](REALWORLD_VALIDATION_FINDINGS.md#RW-010), vendor Iron Skillet XML; [PAN-OS CLI hierarchy for mgt-config password-complexity](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-command-hierarchy/pan-os-11-2-configure-cli-command-hierarchy).

**Linked Findings:** [RW-010](REALWORLD_VALIDATION_FINDINGS.md#RW-010).

**Dependencies:** Confirm PAN-OS 10.1 log-settings/system binding and disabled-profile semantics with vendor XML/CLI references.

**Architecture/Convention Notes:** Namespace/path resolution belongs to PAN-OS parser; checks consume typed effective complexity and forwarding records, with profile references resolved before audit. Do not equate profile declaration with enabled event forwarding.

**Concrete Requirements:** Affected platform PAN_OS. Recognize mgt-config/password-complexity enabled and all required thresholds. Resolve shared/log-settings/system match-list to a defined syslog profile and destination, including disable/no/override semantics. Missing elements in an unrendered template remain unknown. No user-facing flag is needed; report fields may need richer evidence/knowledge states.

**Test Requirements:** RW-010 paths, a genuinely absent control, a declared-but-unbound syslog profile, override/disable cases, malformed XML, Jinja template unknown state, secret redaction, public CLI and regression.

**Acceptance Criteria:** RW-010 no longer reports password-complexity absent or system forwarding absent, while absent/unbound/disabled controls still produce supported findings.

### RV-004 — Detect excessive effective IOS interactive idle timeouts

**Task ID and Title:** RV-004 — Audit effective IOS line EXEC idle timeouts.

**Priority:** P1 — two external IOS configurations set 90 minutes and 12 hours without a corresponding alert.

**Status:** Implemented for explicit effective line timeouts; omitted/default values remain ungraded.

**Source of Truth:** [RW-001](REALWORLD_VALIDATION_FINDINGS.md#RW-001), [RW-017](REALWORLD_VALIDATION_FINDINGS.md#RW-017); [Cisco IOS XE hardening guidance](https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening).

**Linked Findings:** [RW-001](REALWORLD_VALIDATION_FINDINGS.md#RW-001), [RW-017](REALWORLD_VALIDATION_FINDINGS.md#RW-017).

**Dependencies:** Qualify the ten-minute hardening threshold for each supported release and line class. Site-specific threshold configuration is separately listed as a design question in [TODO.md](../TODO.md), so do not silently invent a new CLI override.

**Architecture/Convention Notes:** IOS parser resolves line ranges, exec-timeout minutes/seconds, explicit zero, inherited/default values and disabled VTY ranges. Plugin consumes typed effective line state.

**Concrete Requirements:** Affected IOS_SWITCH, IOS_ROUTER, IOS_CATALYST and IOS_XE. Report active administrative lines with a disabled or excessive idle logout according to a cited release-applicable control; distinguish VTY, console and auxiliary. Unknown export completeness or defaults must not become an assumed safe or unsafe value. No interface change unless the separate threshold-policy design is accepted.

**Test Requirements:** 90-minute and 720-minute positives; 5- and 10-minute negatives; zero disablement; range overrides; no-exec/transport-none lines; malformed and partial line stanzas; sanitized evidence; installed CLI and regression.

**Acceptance Criteria:** The two observed VTY timeouts are assessed with line-specific evidence and correct scope; disabled lines and unknown defaults do not produce spurious alerts.

### RV-005 — Audit authenticated EOS NTP associations

**Task ID and Title:** RV-005 — Audit effective EOS NTP authentication.

**Priority:** P1 — three published EOS leaf configurations in one AVD lab expose unauthenticated configured NTP associations without a report item.

**Status:** Implemented for explicit server bindings; version-dependent NTS support remains unknown when the export has no release.

**Source of Truth:** [RW-005](REALWORLD_VALIDATION_FINDINGS.md#RW-005), [RW-009](REALWORLD_VALIDATION_FINDINGS.md#RW-009), [RW-028](REALWORLD_VALIDATION_FINDINGS.md#RW-028); [Arista EOS time-protocol documentation](https://www.arista.com/en/um-eos/eos-system-clock-and-time-protocols).

**Linked Findings:** [RW-005](REALWORLD_VALIDATION_FINDINGS.md#RW-005), [RW-009](REALWORLD_VALIDATION_FINDINGS.md#RW-009), [RW-028](REALWORLD_VALIDATION_FINDINGS.md#RW-028).

**Dependencies:** Confirm EOS command/default semantics, VRF-specific server bindings and whether the chosen release supports NTP authentication in the supplied form.

**Architecture/Convention Notes:** EOS parser should represent server, VRF, authentication enablement, trusted key and key binding as typed state. Do not expose key material.

**Concrete Requirements:** Affected ARISTA_EOS. Identify effective NTP servers and whether every active association has complete authentication. Report absent/partial binding only where applicable; unknown release or unsupported syntax remains unknown. No CLI/schema change required beyond normalized evidence if necessary.

**Test Requirements:** All three leaf examples, fully authenticated server, global versus VRF override, disabled server, unknown key, malformed syntax, scope, redaction, CLI JSON/HTML and regression.

**Acceptance Criteria:** All three leaf cases identify their unauthenticated servers without treating a configured NTP server as absent; authenticated and unresolved cases behave distinctly.

### RV-011 — Audit the Junos global inter-zone default policy

**Task ID and Title:** RV-011 — Detect an effective Junos global permit-all security policy.

**Priority:** P1 — a published SRX configuration explicitly permits unmatched inter-zone traffic, yet the successful report contains zero findings and labels security-policy coverage known with item-count zero.

**Status:** Ready for implementation after confirming the supported Junos release forms and precedence.

**Source of Truth:** [RW-029](REALWORLD_VALIDATION_FINDINGS.md#RW-029); [Juniper `default-policy` command reference](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-default-policy.html), which defines `permit-all` as permitting traffic unmatched by a policy.

**Linked Findings:** [RW-029](REALWORLD_VALIDATION_FINDINGS.md#RW-029).

**Dependencies:** Verify the command form and default for the supported SRX releases, and document precedence with explicit inter-zone/global policies and `apply-groups`. Confirm how the existing parser represents zone scope before changing the coverage ledger.

**Architecture/Convention Notes:** The Junos parser owns effective global policy state, including `set`, hierarchical, `delete` and group override forms; the analyzer consumes a typed known/unknown/unsupported value. A stable finding ID cites only the policy statement and scope. A full export is needed for absence/default claims, but an explicit `permit-all` token can be assessed in a partial example.

**Concrete Requirements:** Affected JUNOS. Parse `security policies default-policy permit-all` and later overrides, emit a high-priority finding for the effective global fail-open fallback, and explain that it governs unmatched inter-zone transit rather than device host-inbound traffic. Represent the global default in filtering coverage even when no explicit policy rules are present. An unresolved group, malformed command, unsupported release form or conflicting partial excerpt yields unknown; no new CLI option is needed, but JSON/HTML coverage and finding evidence must accurately expose this state.

**Test Requirements:** RW-029 positive; `deny-all` and explicit restrictive policy negatives; `permit-all` followed by `deny-all` and `delete`/group precedence; malformed and partial examples; inter-zone versus host-inbound scope; secret redaction; installed CLI JSON/HTML and the full regression gate.

**Acceptance Criteria:** RW-029 reports the explicit effective permit-all with a correct transit scope, and its coverage ledger no longer suggests zero applicable policy state. Restrictive, overridden and unresolved cases remain distinct without spurious findings.

## Wave 2 — parser evidence and cross-platform secret handling

### RV-006 — Classify exposed secret storage in supported configurations

**Task ID and Title:** RV-006 — Identify reversible or plaintext credential storage without disclosing values.

**Priority:** P1 — public IOS, IOS-XE and EOS exports demonstrate multiple missed stored-secret forms.

**Status:** Implemented for verified IOS/IOS-XE and EOS command forms, including the literal TerminAttr key form. Additional secret syntax requires separate qualification.

**Source of Truth:** [RW-001](REALWORLD_VALIDATION_FINDINGS.md#RW-001), [RW-002](REALWORLD_VALIDATION_FINDINGS.md#RW-002), [RW-009](REALWORLD_VALIDATION_FINDINGS.md#RW-009), [RW-012](REALWORLD_VALIDATION_FINDINGS.md#RW-012), [RW-028](REALWORLD_VALIDATION_FINDINGS.md#RW-028).

**Linked Findings:** [RW-001](REALWORLD_VALIDATION_FINDINGS.md#RW-001), [RW-002](REALWORLD_VALIDATION_FINDINGS.md#RW-002), [RW-009](REALWORLD_VALIDATION_FINDINGS.md#RW-009), [RW-012](REALWORLD_VALIDATION_FINDINGS.md#RW-012), [RW-028](REALWORLD_VALIDATION_FINDINGS.md#RW-028).

**Dependencies:** Confirm each vendor's password-7/RADIUS encoding semantics. Treat EOS TerminAttr ingestion auth as a separately qualified subcase; do not assume token reachability or reuse.

**Architecture/Convention Notes:** Parser records secret kind and protection class, never plaintext in evidence, logs or reports. Credential value analysis is separate from structural storage analysis, and this task is distinct from the optional cracking-tool export in [TODO.md](../TODO.md).

**Concrete Requirements:** Affected IOS_SWITCH, IOS_ROUTER, IOS_CATALYST, IOS_XE and ARISTA_EOS. Capture IOS type-7 local-user and RADIUS keys, plain RADIUS shared keys, EOS type-7 RADIUS key and, only after vendor qualification, TerminAttr literal ingestion-token form. Flag unsafe storage with stable finding IDs and location but no secret bytes. Redacted placeholders and unknown encoding remain unknown; no public interface change is required.

**Test Requirements:** Positive and protected negative forms, overrides, redacted placeholders, malformed secret tokens, scope, exact evidence-redaction assertions, public pipeline and full regression.

**Acceptance Criteria:** All independently observed storage weaknesses receive structure-only findings; no source credential value can be recovered from stdout, JSON, HTML or logs.

### RV-007 — Apply safe value checks to common IOS credentials and SNMP communities

**Task ID and Title:** RV-007 — Detect known weak credential values when visible in supported exports.

**Priority:** P1 — a captured IOSv device has a literal cisco enable password and a classic switch has public SNMP, yet reports identify only storage/legacy protocol rather than the known weak values.

**Status:** Implemented for the existing versioned exact known-default plaintext list and effective public/private SNMP communities.

**Source of Truth:** [RW-017](REALWORLD_VALIDATION_FINDINGS.md#RW-017), [RW-012](REALWORLD_VALIDATION_FINDINGS.md#RW-012), [RW-026](REALWORLD_VALIDATION_FINDINGS.md#RW-026), [RW-027](REALWORLD_VALIDATION_FINDINGS.md#RW-027); compare High default-community behavior in [RW-018](REALWORLD_VALIDATION_FINDINGS.md#RW-018) and [RW-020](REALWORLD_VALIDATION_FINDINGS.md#RW-020).

**Linked Findings:** [RW-012](REALWORLD_VALIDATION_FINDINGS.md#RW-012), [RW-017](REALWORLD_VALIDATION_FINDINGS.md#RW-017), [RW-018](REALWORLD_VALIDATION_FINDINGS.md#RW-018), [RW-020](REALWORLD_VALIDATION_FINDINGS.md#RW-020), [RW-026](REALWORLD_VALIDATION_FINDINGS.md#RW-026), [RW-027](REALWORLD_VALIDATION_FINDINGS.md#RW-027).

**Dependencies:** Define an auditable blocklist/strength policy and prove which value forms are readable without decryption; do not claim strength for masked/hash-only input.

**Architecture/Convention Notes:** Keep value checks separate from weak storage and crypto-algorithm rules. Compare values in memory; emit only category and sanitized location. Stable IDs and policy version are required.

**Concrete Requirements:** Affected IOS family initially; align public-community behavior with already-supported HP/PIX detection. Detect explicit known default/weak plaintext enable and line values and public SNMP community where present. Redacted, encrypted and ambiguous values remain unknown. Interface changes only if a versioned blocklist or assessment-policy override is approved; do not add an automatic cracking feature.

**Test Requirements:** Known weak and nonlisted values, case/quotation variations, overriding no commands, redacted and hashed values, partial scope, no-leak stdout/JSON/HTML, installed CLI and regression.

**Acceptance Criteria:** RW-017 distinguishes known weak value from generic weak storage and RW-012, RW-026 and RW-027 distinguish public from generic community use, without disclosing the values in evidence.

### RV-008 — Evaluate bound ScreenOS VPN anti-replay setting

**Task ID and Title:** RV-008 — Assess ScreenOS no-replay only for active VPNs.

**Priority:** P2 — two independent ScreenOS VPN examples contain the same explicit protection disablement, but this is a legacy platform.

**Status:** Needs release-specific ScreenOS command-reference evidence before implementation; Juniper-hosted configuration examples confirm syntax but not semantics/default.

**Source of Truth:** [RW-004](REALWORLD_VALIDATION_FINDINGS.md#RW-004), [RW-016](REALWORLD_VALIDATION_FINDINGS.md#RW-016); currently available [archived CLI reference](https://manualzz.com/doc/21898000/juniper-networks-security-device-cli-reference-guide).

**Linked Findings:** [RW-004](REALWORLD_VALIDATION_FINDINGS.md#RW-004), [RW-016](REALWORLD_VALIDATION_FINDINGS.md#RW-016).

**Dependencies:** Obtain vendor-hosted or authenticated ScreenOS 6.2/6.3 revision defining replay/no-replay, release defaults and VPN binding; verify the posted samples' syntax. This evidence gate precedes a security finding implementation.

**Architecture/Convention Notes:** Parser resolves VPN definition, gateway, binding and override; plugin evaluates effective anti-replay only for a configured active tunnel.

**Concrete Requirements:** Affected SCREENOS. If documentation confirms the command semantics, emit a finding for active no-replay with the tunnel evidence. Disabled/unbound definitions and unknown export completeness stay unknown or unassessed. No CLI/interface change required.

**Test Requirements:** Both observed syntaxes, replay enabled negative, later override, unbound/disabled tunnel, malformed/no version, redaction of preshared secrets, public pipeline and regression.

**Acceptance Criteria:** After the documentation prerequisite, RW-004 and RW-016 yield one accurate anti-replay finding per bound VPN, without treating every no-replay token as active.

## Wave 3 — report scope and wording

### RV-009 — Recognize unrendered deployment templates before absence-based auditing

**Task ID and Title:** RV-009 — Make template evidence scope explicit.

**Priority:** P1 — public PAN-OS and FortiOS templates produce definite-sounding High/Medium absence findings about devices that do not yet exist.

**Status:** Implemented for recognized PAN-OS and FortiOS template markers; generic excerpt handling remains in existing [TODO.md](../TODO.md).

**Source of Truth:** [RW-006](REALWORLD_VALIDATION_FINDINGS.md#RW-006), [RW-007](REALWORLD_VALIDATION_FINDINGS.md#RW-007), [RW-031](REALWORLD_VALIDATION_FINDINGS.md#RW-031), with synthetic short-input cautions in [RW-022](REALWORLD_VALIDATION_FINDINGS.md#RW-022).

**Linked Findings:** [RW-006](REALWORLD_VALIDATION_FINDINGS.md#RW-006), [RW-007](REALWORLD_VALIDATION_FINDINGS.md#RW-007), [RW-022](REALWORLD_VALIDATION_FINDINGS.md#RW-022), [RW-031](REALWORLD_VALIDATION_FINDINGS.md#RW-031).

**Dependencies:** Define supported marker grammar (Jinja delimiters, `${ACCEL_LOOKUP::...}` and vendor placeholder patterns) and a policy for rendered-but-partial inputs; do not infer incompleteness from a small file alone. RV-012 separately addresses the FortiOS parser crash.

**Architecture/Convention Notes:** Preserve explicit finding evidence that can be assessed in a template, but mark device-wide absence and unknown values as unknown. Scope metadata must be visible in JSON and HTML so zero findings are not mistaken for compliance.

**Concrete Requirements:** Affected PAN_OS and FORTIOS initially; reusable preflight for other platforms. Detect unresolved template markers, expose template/unknown coverage in existing output interfaces, and suppress or qualify absence-based checks that require a complete deployed export. No new CLI flag is required for reliably detected markers; any opt-in partial-input flag belongs to the separately tracked TODO design.

**Test Requirements:** Real template positives, rendered complete negatives, placeholders inside comments/strings, override markers, malformed XML/CLI, secret redaction, public CLI report wording and regression.

**Acceptance Criteria:** RW-006 and RW-007 still surface explicit risky template choices but no longer assert missing device-wide controls from unresolved deployment variables.

### RV-010 — Describe FortiOS logging precisely when local disk logging exists

**Task ID and Title:** RV-010 — Separate local logging from remote forwarding in FortiOS reports.

**Priority:** P2 — a public export with enabled disk logging is labelled Lack of System Logging.

**Status:** Ready.

**Source of Truth:** [RW-011](REALWORLD_VALIDATION_FINDINGS.md#RW-011), full FortiOS 5.02 export.

**Linked Findings:** [RW-011](REALWORLD_VALIDATION_FINDINGS.md#RW-011).

**Dependencies:** Verify release-specific memory/disk/FortiAnalyzer/syslog enable and override grammar.

**Architecture/Convention Notes:** FortiOS parser models local and remote destinations separately with effective state. Keep stable finding ID if the control is truly remote collection; adjust title/severity/evidence to its actual meaning.

**Concrete Requirements:** Affected FORTIOS. Recognize enabled local disk logging and any remote sinks. A missing-remote finding may remain only if the requirement is remote forwarding; it must not claim no system logging when local logging exists. Unsupported or incomplete log sections become unknown. No CLI flag needed; report text and normalized logging fields may change.

**Test Requirements:** Local-only, remote-only, both, neither, later disable/override, malformed/partial section, redaction, JSON/HTML public pipeline and regression.

**Acceptance Criteria:** RW-011 cannot be read as claiming logging is wholly absent, while genuine no-log and no-remote cases remain distinguishable.

## Evidence-gated candidates and existing work

The [SonicOS synthetic inbound allow](REALWORLD_VALIDATION_FINDINGS.md#RW-022) receives only a Medium broad-service finding, but no public SonicOS 7 full E-CLI export was found. Acquire a sanitized, versioned operator export and verify rule order, zone and object semantics before opening a new implementation task; the current synthetic result is a test-design signal, not field corroboration. The two [Check Point synthetics](REALWORLD_VALIDATION_FINDINGS.md#RW-024) parse as zero known policies without diagnostics, but their grammar is unverified, so no Check Point false-negative claim or implementation task is justified yet. Obtain representative real legacy policy files and their package/version before judging the parser.

The current [TODO.md](../TODO.md) already tracks independent PIX dialect qualification, partial-configuration selection, ScreenOS time/zone checks, Check Point Gaia export and fixture acquisition. [RW-020](REALWORLD_VALIDATION_FINDINGS.md#RW-020) and [RW-021](REALWORLD_VALIDATION_FINDINGS.md#RW-021) raise the PIX item from hypothetical to observed: real PIX 6.3 outside ACLs yielded zero known policies in successful reports. [RW-003](REALWORLD_VALIDATION_FINDINGS.md#RW-003) and the HP/PIX excerpts corroborate the partial-input scope item. These are **not** duplicated as RV tasks; prioritize the existing TODO items and require honest unknown/unsupported coverage until a legacy dialect is actually qualified. Junos 30/60-minute session settings in [RW-014](REALWORLD_VALIDATION_FINDINGS.md#RW-014) and [RW-015](REALWORLD_VALIDATION_FINDINGS.md#RW-015) remain threshold/policy questions, not an asserted vulnerability task.
