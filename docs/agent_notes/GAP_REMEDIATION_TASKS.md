# Gap remediation tasks

Remediation ledger established 2026-09-11 and maintained as tasks are implemented. Findings are in [standards findings](STANDARDS_BLINDSPOT_FINDINGS.md), [legacy comparison](LEGACY_NIPPER_COMPARISON_FINDINGS.md), and the [applicability control register](APPLICABILITY_CONTROL_REGISTER.md). Completed tasks record their bounded implementation and validation result; planned tasks remain subject to the conventions below. No Git commands were used.

## Template and status rules

No established reusable task template was found. Every task uses this exact field order:

**Task ID and Title → Priority → Status → Source of Truth → Linked Findings → Dependencies → Architecture/Convention Notes → Concrete Requirements → Test Requirements → Acceptance Criteria**

GAP-001 onward avoids historical T-* collisions. P1 means high-value supported-platform depth or a necessary evidence prerequisite; P2 means useful later depth/shared infrastructure; P3 is optional lower-priority expansion. PLANNED does not mean approved source/default assumptions: any NEEDS_RESEARCH or NEEDS_HUMAN_REVIEW condition must be resolved before dependent behavior is implemented. Only that platform/control subset is blocked, not the whole audit or all tasks.

## Waves and rationale

| Wave | Tasks | Rationale |
|---|---|---|
| 1 — Depth using existing evidence | GAP-001 (parallel research), GAP-002–005 | PAN-OS ignored policy fields, credential metadata, FW1 parsed network/service definitions and logging attributes offer immediate leverage. Small typed adapters may be needed, but new export grammars are not the starting requirement. High-impact parsing gaps do not become magically cheap “cross-cutting” checks. |
| 2 — Supported-platform parser extensions | GAP-006–017, GAP-026–027 | Administrative protection, authenticated infrastructure protocols and routing trust have high risk/reuse. Routing/session/switch depth has both standards and legacy corroboration. Certificate/AAA/control-plane work requires attachment and context evidence, so it follows the required native model work. Split platform deliveries; do not block all platforms on one difficult grammar. |
| 3 — Shared capabilities | GAP-018–022 | Shared credential engine, optional hash export, conservative ACL semantics, audit context and report content follow proven native evidence. Early GAP-003/004 inform shared designs. John export is lower priority than safe default analysis. |
| 4 — Legacy/new export scope | GAP-023–024 | New dialects and Gaia bundles need fixtures, maintenance justification and source applicability. Current Check Point system gap is valuable, but requires a separate export, unlike a small existing-policy check. Research may run early; implementation does not outrank demonstrated depth automatically. |
| Optional operational track | GAP-025 | Live certificates, hit counters, licensing/content freshness, collection and feed health need independent provenance, consent, freshness and failure semantics. No static task requires activating this track. |

Order within a wave follows dependencies and bounded platform deliveries, not numeric ID alone. GAP-026/027 retain stable IDs while residing in wave2. AAA transport is high-value standards evidence, but not claimed as corroborated by a verified legacy detector. Historical behavior is supporting capability evidence, never the authority for modern algorithms, rate thresholds or password composition.

## Mandatory implementation conventions and test gate (T0)

Read [CONTRIBUTING](../../CONTRIBUTING.md), [ARCHITECTURE](../ARCHITECTURE.md) and [EXTENDING](../EXTENDING.md). Parsers own effective syntax, removals, overrides, inheritance and scope; plugins consume typed evidence. Preserve KNOWN-empty versus UNKNOWN/UNSUPPORTED/PARSE_ERROR. Register explicitly, use stable namespaced IDs and one root cause per finding, redact secrets before evidence serialization, and cite the exact applicable primary source. Extend an existing finding for the same root cause instead of creating duplicates. Introduce normalized fields only for stable cross-platform meaning. No architecture cleanup unrelated to a linked gap is implied.

**T0 applies to every future parser, check, processor, registry, CLI, report or provider implementation:**

1. Positive vulnerable and negative secure cases that differ on the relevant property.
2. Effective-state override/negation/removal/disable and inheritance cases.
3. Malformed, unsupported, unknown-version/default and known-empty cases; no accidental safe or unsafe assertion from unknown.
4. Scope isolation across relevant interfaces, users, address families, VRFs, VDOMs, vsys, zones, layers and export/device identities.
5. Redaction assertions for secrets in observations, evidence, logs, exceptions, HTML and JSON.
6. Public registry/factory → processor/analyzer → reporting coverage, with stable IDs and duplicate rule/evidence rejection; preserve alias/export behavior.
7. Exact permanent vulnerable/secure/edge fixtures where applicable. Review intended snapshot differences semantically, then run the established gate: `.\.venv\Scripts\python.exe scripts\run_full_regression.py`.

Where a category is inapplicable (for example pure documentation research or a value with no ordered grammar), explain that in the implementation review instead of manufacturing a test that mirrors code. Runtime/provider tests use synthetic fixtures first. The entire gate is required for implementation, not claimed to have run during this documentation-only audit.

## Wave 1 — Existing evidence

<a id="GAP-001"></a>
### GAP-001 — Resolve standards revisions, release applicability and export evidence

**Task ID and Title:** GAP-001 — Resolve standards revisions, release applicability and export evidence

**Priority:** P1 prerequisite

**Status:** DONE (research deliverable) — verified 2026-09-11; bounded human policy/release decisions are explicitly deferred

**Source of Truth:** [Cisco PIX Firewall Configuration Guide: Configuring the PIX Firewall (S-PIX)](STANDARDS_BLINDSPOT_FINDINGS.md#S-PIX); [ScreenOS 6.3.0 Documentation (S-SCR)](STANDARDS_BLINDSPOT_FINDINGS.md#S-SCR); [FortiOS Best Practices: Hardening (S-FGT)](STANDARDS_BLINDSPOT_FINDINGS.md#S-FGT); [EOS User Manual: Security (S-EOS)](STANDARDS_BLINDSPOT_FINDINGS.md#S-EOS); [Check Point Gateway and Management Hardening Administration Guide (S-CP)](STANDARDS_BLINDSPOT_FINDINGS.md#S-CP); [PAN-OS Help: Device > Setup > Management (S-PAN-M)](STANDARDS_BLINDSPOT_FINDINGS.md#S-PAN-M); CIS catalogues. Versions, sections and access dates are in the linked source register or pinned legacy provenance.

**Linked Findings:** [STD-017](STANDARDS_BLINDSPOT_FINDINGS.md#STD-017), [STD-018](STANDARDS_BLINDSPOT_FINDINGS.md#STD-018), [STD-027](STANDARDS_BLINDSPOT_FINDINGS.md#STD-027), [LEG-011](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-011)

**Dependencies:** None. Resolve individual source/platform subsets independently; do not block unrelated verified controls.

**Architecture/Convention Notes:** Documentation/research task only; retain supported-device boundaries and stable STD anchors.

**Concrete Requirements:** Platforms: every matrix row, especially PIX, ScreenOS, AOS-S families, EOS and Check Point exports. Produce a control register for every A/U cell with official title/revision/release/section/URL/access date, fixture-supported evidence and an applicability disposition. Obtain ScreenOS6.3 manuals; resolve FortiOS URL/body version mismatch and EOS child versions; verify full benchmark text before using control IDs. Revalidate Junos2015 crypto advice. Record exact current defaults only for proven releases. Interface changes: none; annotate which future parser/API changes each verified control needs. Unknown mappings remain explicitly unresolved; never create a requirement just to fill a cell.

**Test Requirements:** Verify citation retrieval, release claims and fixture/source links; independent review of ambiguous mappings. Code-test categories do not apply to this research-only task.

**Acceptance Criteria:** Every unresolved entry is either backed by an applicable primary source and example export or remains an explicit blocked/deferred prerequisite with reason. No unsupported category is marked compliant; no speculative constant is promoted to an implementation task. T0 and the reviewed regression gate must pass for implementation; pure research tasks instead validate their evidence and links.

**Research Result:** [`APPLICABILITY_CONTROL_REGISTER.md`](APPLICABILITY_CONTROL_REGISTER.md) qualifies every `A`/`U` matrix cell, resolves the FortiOS URL/body and EOS child-version mismatches, rejects the stale Junos SHA-1 recommendation, and records ScreenOS, Check Point export, licensed CIS and organization-policy limits without inventing defaults.

<a id="GAP-002"></a>
### GAP-002 — Use already parsed PAN-OS password and update evidence

**Task ID and Title:** GAP-002 — Use already parsed PAN-OS password and update evidence

**Priority:** P1

**Status:** DONE (bounded static scope) — verified 2026-09-11; optional content-family applicability remains deferred

**Source of Truth:** [PAN-OS Help: Device > Setup > Management (S-PAN-M)](STANDARDS_BLINDSPOT_FINDINGS.md#S-PAN-M) — Minimum Password Complexity; [Security Policy Rule Best Practices (S-PAN-P)](STANDARDS_BLINDSPOT_FINDINGS.md#S-PAN-P) — Security profiles/logging; GAP-001 for release-specific content scheduling. Versions, sections and access dates are in the linked source register or pinned legacy provenance.

**Linked Findings:** [STD-020](STANDARDS_BLINDSPOT_FINDINGS.md#STD-020)

**Dependencies:** Resolve per-release history/username policy and applicable content-family scheduling through [GAP-001](#GAP-001) before those predicates ship.

**Architecture/Convention Notes:** Use PANOSParser policy/schedule records and existing PanOSChecksPlugin registration; extend existing finding IDs where root cause matches.

**Concrete Requirements:** Platforms: PAN_OS local XML. Required evidence: history_count, blocks_username, each parsed anti-virus/threat/WildFire schedule, enabled relevant features and available inheritance state. Add separate policy findings for approved history/username requirements; assess each supported content family after prerequisites are known. Absence with unexpanded Panorama or unsupported version is unknown, not disabled. Interface: ideally none for existing fields; add typed feature applicability only if necessary. Do not infer content freshness or licensing.

**Test Requirements:** T0 plus mixed schedules (one good family/one disabled), absent optional feature, local vs Panorama policy override, supported older releases and malformed numeric history. Demonstrate no plaintext evidence.

**Acceptance Criteria:** Previously ignored supported fields change output only under approved policy; threat-content checks remain intact and no duplicate root cause appears. Unsupported content family remains visibly unassessed. T0 and the reviewed regression gate must pass for implementation; pure research tasks instead validate their evidence and links.

**Implementation Result:** Explicit local `password-history-count=0` and `block-username-inclusion=no` now produce separate, stable findings when complexity is enabled. Missing, malformed, out-of-range and unexpanded Panorama state remains unknown. The existing Applications and Threats schedule check is unchanged; anti-virus and WildFire schedule findings remain deferred because entitlement, release applicability and organization cadence were not proved. Focused tests and the full gate pass (384 tests, 32 corpus configurations).

<a id="GAP-003"></a>
### GAP-003 — Close immediate credential storage and value-classification omissions

**Task ID and Title:** GAP-003 — Close immediate credential storage and value-classification omissions

**Priority:** P1

**Status:** DONE — verified 2026-09-11

**Resolved research (2026-09-11):** Cisco's current [Protecting Secrets on Cisco Network Devices](https://www.cisco.com/c/en/us/about/trust-center/resilient-infrastructure/protecting-secrets.html) classifies IOS-family Types 0, 4, 5 and 7 as insecure, Type 6 as secure reversible storage, and Types 8/9 as secure one-way storage. The current [ASA `enable password` command reference](https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/A-H/asa-command-ref-A-H/e-commands.html) identifies the legacy `encrypted` representation as MD5-based and `pbkdf2` as PBKDF2, so an opaque legacy `encrypted` value no longer passes the ASA checks. Arista's [EOS 4.36.1F User Security guide](https://www.arista.com/en/um-eos/eos-user-security) proves `nopassword`, clear-text/Type 0, MD5 Type 5, SHA-512, replacement, `no username`, and `default username` semantics. Juniper's current [login password format reference](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/password-edit-system-login.html) identifies `$5$` SHA-256 and `$6$` SHA-512, while [Master Password for Configuration Encryption](https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/master-password-configuration-encryption.html) confirms that `$9$` is reversible obfuscation and documents `$8$` master-password encryption. ScreenOS exports do not carry a trustworthy general storage marker in the supported grammar, so nonempty values remain `UNKNOWN`; only empty values and maintained exact plaintext/encrypted default fingerprints produce the existing default finding. Across platforms, `NO_MATCH` now records only the negative fingerprint comparison and never implies credential strength or length.

**Source of Truth:** [Cisco Guide to Harden Cisco IOS Devices (S-IOS)](STANDARDS_BLINDSPOT_FINDINGS.md#S-IOS) — password storage; [SonicOS 7.3 Device Settings: Configuring Password Compliance (S-SON-P)](STANDARDS_BLINDSPOT_FINDINGS.md#S-SON-P) — password compliance; legacy [common/nipper-common.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/common/nipper-common.c) and [IOS/process-username.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/IOS/process-username.c). Versions, sections and access dates are in the linked source register or pinned legacy provenance.

**Linked Findings:** [STD-005](STANDARDS_BLINDSPOT_FINDINGS.md#STD-005), [LEG-005](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-005)

**Dependencies:** Resolve format-specific strength policy; [GAP-018](#GAP-018) supplies reusable value analysis later.

**Architecture/Convention Notes:** Keep secret material parser-private; reuse typed users/credential metadata rather than parse evidence strings in plugins.

**Concrete Requirements:** Platforms: ASA, IOS/XE, Junos, EOS and ScreenOS where native credential evidence exists. Inventory each emitted credential type/default-fingerprint result; add missing EOS stored-credential classification and ASA/ScreenOS structural metadata checks only where format proves a property. A known-bad list remains a separate indicator, not the only definition of weakness. Unknown hash formats cannot pass as strong or imply length. Interface: typed metadata availability/format accessor if existing get_users omits it; no default credential export or Finding schema change. SonicOS unknown users wait for [GAP-017](#GAP-017).

**Test Requirements:** T0 plus arbitrary unlisted plaintext, recognized weak/strong/unknown hash formats, invalid encoded values, account deletion/override and no-secret assertions across HTML/JSON/logs.

**Acceptance Criteria:** All supported credential contexts state which property is evaluated; no negative result on a blacklist is described as strength. Secret values never leave normal analysis output. Existing namespaced IDs retained for extended root causes. T0 and the reviewed regression gate must pass for implementation; pure research tasks instead validate their evidence and links.

<a id="GAP-004"></a>
### GAP-004 — Extend FW1 containment using existing network and service definitions

**Task ID and Title:** GAP-004 — Extend FW1 containment using existing network and service definitions

**Priority:** P1

**Status:** DONE — verified 2026-09-11

**Source of Truth:** [Check Point Gateway and Management Hardening Administration Guide (S-CP)](STANDARDS_BLINDSPOT_FINDINGS.md#S-CP) — Decreasing Security Gateway Exposure with Policy; local-only [device/filter/filter-security.cpp](../../reference/nipper-ng-original/libnipper-0.12.6/device/filter/filter-security.cpp). Versions, sections and access dates are in the linked source register or pinned legacy provenance.

**Resolved research (2026-09-11):** The current Check Point [Access Control Rule Base columns](https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_SecurityManagement_AdminGuide/Content/Topics-SECMG/The-Columns-of-the-Access-Control-Rule-Base.htm) define Source/Destination as network objects or groups and service matching by IP protocol and TCP/UDP port. The [Ordered Layers and Inline Layers](https://sc1.checkpoint.com/documents/R82.10/WebAdminGuides/EN/CP_R82.10_SecurityManagement_AdminGuide/Content/Topics-SECMG/Ordered-Layers-and-Inline-Layers.htm) guide confirms sequential top-to-bottom first-match enforcement inside an Ordered Layer. GAP-004 therefore compares only positive, completely resolved rules in the same parsed layer and preserves matching time, VPN, through, and install scope. The legacy export still cannot prove compilation, installation, implied-rule placement, dynamic-object membership, or cross-layer effective policy; those states remain outside the finding proof.

**Linked Findings:** [STD-019](STANDARDS_BLINDSPOT_FINDINGS.md#STD-019), [LEG-006](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-006), [LEG-007](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-007)

**Dependencies:** [GAP-001](#GAP-001) confirms export/layer applicability for supported fixtures; no need to wait for a universal shared ACL engine.

**Architecture/Convention Notes:** Use typed FW1 objects and same-layer ordered rules. Conservative proof is required before shadow/redundancy findings.

**Concrete Requirements:** Platforms: CHECKPOINT_FW1 legacy policy exports. Evidence: parsed IP/netmask/ranges, protocol/port intervals, expanded groups, layer/order/action, time/VPN/install constraints. Add containment for static resolved subnet/port definitions, beginning currently supported positive same-layer rules. Reuse redundant_rule/shadowed_rule IDs rather than duplicate analysis. Dynamic/unresolved/negated/unsupported predicates make proof unknown. Interface: native semantic-set helper with bounded expansion, no public report change.

**Test Requirements:** T0 plus differently named equal subnets, subnet/range containment, disjoint ports, partial overlap not full shadow, mixed actions, cyclic groups, differing time/install scope and layer separation.

**Acceptance Criteria:** Only demonstrably covered traffic produces shadow/redundancy. Partial overlap has a distinct result or no finding; existing name-set cases remain correct. No runtime-unused claim. T0 and the reviewed regression gate must pass for implementation; pure research tasks instead validate their evidence and links.

<a id="GAP-005"></a>
### GAP-005 — Evaluate available logging policy evidence

**Task ID and Title:** GAP-005 — Evaluate available logging policy evidence

**Priority:** P1

**Status:** DONE (bounded static scope) — verified 2026-09-11; transport assurance remains unsupported rather than inferred

**Source of Truth:** [Cisco Guide to Harden Cisco IOS Devices (S-IOS)](STANDARDS_BLINDSPOT_FINDINGS.md#S-IOS) — logging; [Hardening Junos Devices Checklist, companion to This Week: Hardening Junos Devices, Second Edition (S-JUN)](STANDARDS_BLINDSPOT_FINDINGS.md#S-JUN) — Management Services Security; [Security Policy Rule Best Practices (S-PAN-P)](STANDARDS_BLINDSPOT_FINDINGS.md#S-PAN-P) — logging. Versions, sections and access dates are in the linked source register or pinned legacy provenance.

**Linked Findings:** [STD-025](STANDARDS_BLINDSPOT_FINDINGS.md#STD-025)

**Dependencies:** Approved release/event/severity policy; extend parser later only for omitted fields.

**Architecture/Convention Notes:** Prefer existing Junos logging severity and FortiOS scoped destination/filter state; no network delivery probes.

**Concrete Requirements:** Platforms first: JUNOS and FORTIOS; then IOS/XE/ASA/PAN_OS/AOS-S/EOS/SonicOS only where parsed attributes suffice. Required evidence: enabled destination, facilities/categories/severity, known transport and source scope. Detect explicit policy violations per destination/category and avoid interpreting one host as complete audit logging. Unknown transport/severity remains unknown. Interface: expose typed existing fields if not public; no report schema change. New transport parsers are a separately scoped follow-on under [GAP-001](#GAP-001).

**Test Requirements:** T0 plus multi-destination different severities, disabled targets, event filter overrides, unknown transports, VDOM/vsys/VRF separation and sensitive destination evidence sanitization.

**Acceptance Criteria:** Findings distinguish missing destination, insufficient event coverage and unsupported transport information. Current logging-presence rules do not duplicate new root causes; delivery and retention are not asserted. T0 and the reviewed regression gate must pass for implementation; pure research tasks instead validate their evidence and links.

**Implementation Result:** Junos now exposes typed per-host facility/severity selectors, explicit transport/port/source address and routing-instance scope. Each effective destination is assessed independently for authorization and interactive-command coverage; malformed selector severity remains unknown, deactivated/deleted targets do not count, and absent transport is described as unestablished without a transport finding. The existing missing-destination rule remains separate. FortiOS per-destination event filtering was retained and verified across multiple targets, disabled targets and VDOM scope. Delivery, retention, default transport and unparsed platform fields remain out of scope. Focused tests and the full gate pass (387 tests, 32 corpus configurations).

## Wave 2 — Parser extensions on supported platforms

<a id="GAP-006"></a>
### GAP-006 — Add IOS/XE and ASA administrative service depth

**Task ID and Title:** GAP-006 — Add IOS/XE and ASA administrative service depth

**Priority:** P1

**Status:** DONE (bounded supported scope) — verified 2026-09-13

**Source of Truth:** [Cisco Guide to Harden Cisco IOS Devices (S-IOS)](STANDARDS_BLINDSPOT_FINDINGS.md#S-IOS)/[Cisco IOS XE Software Hardening Guide (S-XE)](STANDARDS_BLINDSPOT_FINDINGS.md#S-XE) — Management Plane; [Cisco Firewall Best Practices (S-ASA)](STANDARDS_BLINDSPOT_FINDINGS.md#S-ASA) — Management Plane; legacy [IOS/report.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/IOS/report.c) and [PIX/process-ssh.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/PIX/process-ssh.c). Versions, sections and access dates are in the linked source register or pinned legacy provenance.

**Linked Findings:** [STD-010](STANDARDS_BLINDSPOT_FINDINGS.md#STD-010), [STD-012](STANDARDS_BLINDSPOT_FINDINGS.md#STD-012), [LEG-003](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-003), [LEG-004](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-004)

**Dependencies:** [GAP-001](#GAP-001) release/default mapping; PIX independently gated by [GAP-023](#GAP-023).

**Architecture/Convention Notes:** Native parser owns lines/services/AAA bindings and ordered defaults; plugin evaluates effective attachments.

**Concrete Requirements:** Platforms: IOS three IDs, IOS_XE, ASA. Evidence: line/AUX activation, session timeout, HTTPS-only settings, SSH version/suites/key metadata, exec/command authorization bindings, banner presence. Add role-specific AUX exposure, approved finite session timeout policy and secure-service/auth bindings; resolve names before describing protection. PIX remains unknown for unverified syntax. Interface: typed management session/SSH/AAA accessors, preserve Finding schema and public processor signatures unless an explicit policy context is introduced via [GAP-021](#GAP-021).

**Test Requirements:** T0 plus HTTPS-only device, CLI-only device, VTY-specific override, default/explicit/unknown timeout, disabled AUX, named method list mismatch, IPv4/IPv6 ACL scope and ASA version differences.

**Acceptance Criteria:** Each supported active channel is evaluated against the chosen release policy; unknown key/default state cannot pass. Existing HTTP/SSH rules remain stable and new session findings refer to the correct line/service. T0 and the reviewed regression gate must pass for implementation; pure research tasks instead validate their evidence and links.

**Implementation Result:** IOS and IOS-XE now expose typed effective console/AUX/TTY/VTY state, AAA login/EXEC/command method lists and server-group resolution, IPv4/IPv6 access-class attachments, explicit SSH algorithm selections and explicit RSA key modulus metadata. Analysis evaluates every active line independently, identifies cleartext input/output transport, unlimited sessions, unresolved authentication or authorization, and role-specific AUX exposure while retaining the existing HTTP/SSH rule IDs. ASA now exposes effective HTTPS service state, protocol-specific administrative AAA bindings, resolved server groups, console/SSH timeouts and release-qualified SSH protocol defaults; analysis covers active-channel authentication/accounting, disabled console timeout, legacy SSH protocol defaults and explicitly weak suites. The implementation deliberately does not invent a finite-session maximum or infer absent release-sensitive algorithm/key state. Current ASA 9.x logic is gated away from PIX until GAP-023 qualifies that dialect. Focused tests and the full gate pass (399 tests, 32 corpus configurations).

<a id="GAP-007"></a>
### GAP-007 — Model and evaluate each authenticated time association

**Task ID and Title:** GAP-007 — Model and evaluate each authenticated time association

**Priority:** P1

**Status:** DONE (bounded supported scope) — verified 2026-09-13; ScreenOS time-protocol authentication remains NEEDS_RESEARCH

**Source of Truth:** [Hardening Junos Devices Checklist, companion to This Week: Hardening Junos Devices, Second Edition (S-JUN)](STANDARDS_BLINDSPOT_FINDINGS.md#S-JUN) — authenticated NTP; [Perform the Initial Setup and Configuration for NGFWs (S-PAN-N)](STANDARDS_BLINDSPOT_FINDINGS.md#S-PAN-N) — NTP algorithms; [AOS-S 16.11 Management and Configuration Guide: sntp server (S-HP-N)](STANDARDS_BLINDSPOT_FINDINGS.md#S-HP-N) — per-server authentication; [EOS User Manual: System Clock and Time Protocols (S-EOS-N)](STANDARDS_BLINDSPOT_FINDINGS.md#S-EOS-N) — NTP/NTS. Versions, sections and access dates are in the linked source register or pinned legacy provenance.

**Linked Findings:** [STD-006](STANDARDS_BLINDSPOT_FINDINGS.md#STD-006)

**Dependencies:** [GAP-001](#GAP-001) platform algorithm/default mapping; existing detection defects discovered during work must cross-link detection audit.

**Architecture/Convention Notes:** Typed associations preserve active state, server/peer role, VRF/scope, key reference, algorithm and knowledge state.

**Concrete Requirements:** Platforms: PAN_OS, HP_PROCURVE, ARISTA_EOS first new coverage; deepen IOS/XE/ASA/Junos/FortiOS/SonicOS references as supported; ScreenOS after manual verification. Detect each unauthenticated active association and unresolved required key, then separately weak supported algorithm. Preserve FortiGuard source semantics and older platform capabilities. Interface: native time record/API first, normalized time model only if common semantics are proven. No current-time network calls.

**Test Requirements:** T0 plus one authenticated and one unauthenticated peer, dangling/wrong-scope key, deleted/trusted-key override, NTS profile, PAN-OS pre/post12.1.2, SNTP family differences and redaction of all key material.

**Acceptance Criteria:** No strong peer masks another insecure peer. Known missing auth differs from unsupported export; absent key value redaction cannot be mistaken for missing configured material. Offline result does not claim successful synchronization. T0 and the reviewed regression gate must pass for implementation; pure research tasks instead validate their evidence and links.

**Implementation Result:** PAN-OS, AOS-Switch and EOS now expose immutable native time-association records carrying role/address, device or VRF scope, authentication method, key/profile reference, algorithm, resolution state and sanitized evidence. PAN-OS evaluates primary and secondary servers independently, treats an explicitly exported-but-empty secret element as redacted/unexported rather than known missing, and gates SHA-256/SHA-512 policy at 12.1.2. AOS-S 16.10/16.11 resolves global SNTP authentication, per-server key IDs, configured material and trust state while leaving unknown families/releases unknown; MD5 remains the documented platform capability rather than an invented stronger requirement. EOS resolves global authentication, configured/trusted keys and NTS SSL trust profiles, with NTS availability gated at 4.35.0F. IOS/XE, ASA, Junos, FortiOS and SonicOS checks were deepened so every active association is evaluated independently; the former SonicOS any-secure-server masking defect is closed, FortiOS missing authentication and weak algorithms are separate root causes, ASA stronger-algorithm policy is gated at 9.13, and Junos preserves documented MD5-only platform exceptions. All key material is redacted at parser boundaries. ScreenOS remains presence-only because the required archived manual/dialect evidence is unavailable. Static analysis does not claim successful synchronization or live peer identity. Focused tests and the full gate pass (414 tests, 32 corpus configurations).

<a id="GAP-008"></a>
### GAP-008 — Complete SNMPv3 user and access-scope evidence

**Task ID and Title:** GAP-008 — Complete SNMPv3 user and access-scope evidence

**Priority:** P1

**Status:** DONE — bounded static scope verified 2026-09-13

**Source of Truth:** [Cisco Guide to Harden Cisco IOS Devices (S-IOS)](STANDARDS_BLINDSPOT_FINDINGS.md#S-IOS) — SNMPv3/access; [Hardening Junos Devices Checklist, companion to This Week: Hardening Junos Devices, Second Edition (S-JUN)](STANDARDS_BLINDSPOT_FINDINGS.md#S-JUN) — Management Services; [Aruba 2930M/F Access Security Guide for AOS-S Switch 16.11 (S-HP)](STANDARDS_BLINDSPOT_FINDINGS.md#S-HP) — access security. Versions, sections and access dates are in the linked source register or pinned legacy provenance.

**Linked Findings:** [STD-007](STANDARDS_BLINDSPOT_FINDINGS.md#STD-007)

**Dependencies:** [GAP-001](#GAP-001) verifies release-supported algorithms/views; retain existing per-platform findings.

**Architecture/Convention Notes:** Model user/group/view/manager relationships on one effective scope; do not introduce a second generic string parser.

**Concrete Requirements:** Platforms: IOS/XE v3 first; ASA algorithm depth next; HP/EOS/PAN-OS/SonicOS exposure depth after per-user evidence review. Evidence: each active user auth/privacy algorithms and known key presence, group security level, views and source restrictions. Flag insecure active access even if another user is secure; uncertain defaults/hidden key fields remain unknown. Interface: native SNMP relationship records; shared predicate only for stable semantics; unchanged Finding schema.

**Test Requirements:** T0 plus two users with different protection, view deny/allow effects, wrong group reference, inactive agent, omitted hidden key material, release-dependent SHA/AES support and no community/password leakage.

**Acceptance Criteria:** Per-user and scoped access gaps are reported without duplicate community findings. Unknown is explicit and secure-user existence never substitutes for all-access assessment. T0 and the reviewed regression gate must pass for implementation; pure research tasks instead validate their evidence and links.

**Implementation Result:** IOS/XE now exposes immutable effective SNMPv3 view, group and user relationships, including read/write view resolution, group and user ACL attachment, group security level, algorithms and secret-presence state; checks independently report unresolved references, incomplete authPriv, weak MD5/DES-class algorithms and broad source/view/write scope. ASA now resolves each configured user through its v3 group and explicitly bound SNMP host scopes, ignores unbound inactive users, and release-qualifies SHA-1 policy at 9.14 while retaining 9.16 removal boundaries for MD5/DES. AOS-S, EOS, PAN-OS and SonicOS now expose per-user secret-free records and no longer allow a secure user to mask a weaker active identity. AOS-S uses authorized-manager scope and explicit agent disablement; EOS resolves group/view/default-VRF ACL state and honors object removals or disabled default-VRF SNMP; PAN-OS and SonicOS only grade users when SNMP is attached to an active management surface. Exported, hidden and omitted key material remains a presence/unknown state and is never serialized. Existing community findings and FortiOS/Junos per-user behavior remain intact. Focused adversarial tests and the full gate pass (426 tests, 32 corpus configurations).

<a id="GAP-009"></a>
### GAP-009 — Add routing trust and route-policy analysis

**Task ID and Title:** GAP-009 — Add routing trust and route-policy analysis

**Priority:** P1

**Status:** DONE (bounded BGP/OSPF static scope) — verified 2026-09-13; EIGRP/RIP and additional platforms remain future protocol-specific work

**Source of Truth:** [Cisco Guide to Harden Cisco IOS Devices (S-IOS)](STANDARDS_BLINDSPOT_FINDINGS.md#S-IOS)/[Cisco IOS XE Software Hardening Guide (S-XE)](STANDARDS_BLINDSPOT_FINDINGS.md#S-XE) — routing protocol security; [Hardening Junos Devices Checklist, companion to This Week: Hardening Junos Devices, Second Edition (S-JUN)](STANDARDS_BLINDSPOT_FINDINGS.md#S-JUN) — Routing Protocol Security; legacy [IOS/process-router.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/IOS/process-router.c) and [IOS/process-interface.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/IOS/process-interface.c). Versions, sections and access dates are in the linked source register or pinned legacy provenance.

**Linked Findings:** [STD-002](STANDARDS_BLINDSPOT_FINDINGS.md#STD-002), [LEG-003](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-003)

**Dependencies:** [GAP-001](#GAP-001) protocol/version matrix; [GAP-021](#GAP-021) optional explicit network role/context.

**Architecture/Convention Notes:** Parsers resolve protocol inheritance and per-interface/neighbor attachments; plugins compare typed effective facts with release policy.

**Concrete Requirements:** Platforms: IOS/XE and JUNOS first. Required parser evidence: active processes, neighbors, inherited peer-group auth, interface auth/keychains, VRF/address family, import/export filters and prefix limits. Detect absent/weak auth on configured peers when applicable; missing route-policy/peer restriction only with a supported deployment rule. No configured routing process is N/A for that process-specific check. Unexpanded groups/unknown peer role remain unknown. Interface: typed native routing APIs; common normalized model only after two equivalent implementations.

**Test Requirements:** T0 plus inherited BGP key, OSPF interface override, passive interface, shutdown neighbor, separate IPv6 AF/VRF, unknown algorithm, key rollover and no arbitrary maximum-prefix threshold.

**Acceptance Criteria:** Rules identify the effective peer/process and exact missing control. Do not recommend legacy BGP damping or unsupported algorithms solely for parity. No claim about accepted live routes. T0 and the reviewed regression gate must pass for implementation; pure research tasks instead validate their evidence and links.

**Implementation Result:** IOS/XE and Junos now expose immutable, secret-free BGP neighbor and OSPFv2 interface records. The parsers resolve IOS peer-group authentication, Junos group authentication/key-chain inheritance, routing-instance/VRF and address-family scope, neighbor shutdown, OSPF passive/disabled state, interface authentication overrides, key references and rollover definitions, directional import/export policy, and prefix-limit presence. Plugins evaluate each active relationship independently, report missing authentication, simple-password OSPF authentication, and missing inbound/outbound/prefix-limit controls only for explicitly external BGP peers. Unknown peer roles, algorithms and unexpanded inheritance remain ungraded; maximum-prefix values are recorded only as present and no arbitrary numeric threshold is imposed. Focused adversarial tests and the full gate pass (433 tests, 32 corpus configurations). EIGRP/RIP and non-IOS/Junos routing protocols remain outside this bounded delivery pending their own typed grammar and release policy.

<a id="GAP-010"></a>
### GAP-010 — Add trust-boundary discovery checks

**Task ID and Title:** GAP-010 — Add trust-boundary discovery checks

**Priority:** P2

**Status:** DONE (explicit-role static scope) — verified 2026-09-14; additional vendors remain future source-qualified work

**Source of Truth:** [Cisco Guide to Harden Cisco IOS Devices (S-IOS)](STANDARDS_BLINDSPOT_FINDINGS.md#S-IOS) — CDP; [Hardening Junos Devices Checklist, companion to This Week: Hardening Junos Devices, Second Edition (S-JUN)](STANDARDS_BLINDSPOT_FINDINGS.md#S-JUN) — Chapter4 LLDP; legacy [IOS/report.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/IOS/report.c) and [NMP/report.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/NMP/report.c). Versions, sections and access dates are in the linked source register or pinned legacy provenance.

**Linked Findings:** [STD-003](STANDARDS_BLINDSPOT_FINDINGS.md#STD-003), [LEG-003](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-003)

**Dependencies:** [GAP-001](#GAP-001) platform command defaults; [GAP-021](#GAP-021) for explicit role overrides where inference is insufficient.

**Architecture/Convention Notes:** Keep effective interface state/direction in parsers. Trust role and protocol need are explicit facts, not merely an interface name.

**Concrete Requirements:** Platforms: IOS/XE and JUNOS first; EOS/AOS-S later after own sources. Evidence: global and per-port CDP/LLDP transmit/receive state, enabled interface and reliable external/required-internal role. Report unnecessary advertisement only under known exposure policy; unknown role is not insecure. Interface: typed discovery accessor plus optional assessment context; no auto-discovery network probe.

**Test Requirements:** T0 plus global enable/local disable, LLDP receive-only, required internal voice fabric, explicit external port, disabled link config, unknown role and multiple VRFs/interfaces.

**Acceptance Criteria:** Findings identify protocol/direction/port and role evidence. Necessary internal discovery stays clear; unproven context remains unassessed. T0 and the reviewed regression gate must pass for implementation; pure research tasks instead validate their evidence and links.

**Implementation Result:** IOS/XE now exposes effective per-interface CDP and directional LLDP state with global/local overrides and shutdown handling; Junos resolves LLDP `interface all`, specific-interface disablement and inactive links. Both plugins require an exact `external` interface role from the validated assessment policy and include that policy fact in finding evidence. Unknown, internal and voice-fabric roles remain unreported, as do disabled links and globally or locally disabled discovery. The permanent IOS and Junos vulnerable/hardened corpus pairs exercise the public rules. Focused adversarial tests and the full gate pass (450 tests, 32 corpus configurations). EOS/AOS-S/FortiOS expansion remains contingent on their own current sources and typed effective grammar.

<a id="GAP-011"></a>
### GAP-011 — Add role-aware switch-edge protections

**Task ID and Title:** GAP-011 — Add role-aware switch-edge protections

**Priority:** P1

**Status:** DONE (explicit access-edge static scope) — verified 2026-09-14; additional switch families remain future work

**Source of Truth:** [Cisco Guide to Harden Cisco IOS Devices (S-IOS)](STANDARDS_BLINDSPOT_FINDINGS.md#S-IOS)/[Cisco IOS XE Software Hardening Guide (S-XE)](STANDARDS_BLINDSPOT_FINDINGS.md#S-XE) — Data Plane; [AOS-S 16.11 Access Security Guide: Dynamic ARP protection (S-HP-L2)](STANDARDS_BLINDSPOT_FINDINGS.md#S-HP-L2) — Dynamic ARP protection; legacy [IOS/process-interface.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/IOS/process-interface.c). Versions, sections and access dates are in the linked source register or pinned legacy provenance.

**Linked Findings:** [STD-011](STANDARDS_BLINDSPOT_FINDINGS.md#STD-011), [STD-022](STANDARDS_BLINDSPOT_FINDINGS.md#STD-022), [LEG-003](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-003)

**Dependencies:** [GAP-001](#GAP-001) product/default verification and representative switch/router fixtures.

**Architecture/Convention Notes:** Use typed switchport/VLAN/trust relationships; device ID alone does not establish a Layer2 role.

**Concrete Requirements:** Platforms: IOS switches/Catalyst and switch-capable IOS_XE; HP_PROCURVE verified AOS-S family. Evidence: access/trunk mode, VLAN membership, DHCP snooping activation/trust, DAI/source binding and applicable port-security settings. Start explicit dangerous trust/trunk exposure and missing protections on known applicable edges. Preserve existing MACsec and HP VLAN-snooping coverage. Unknown hardware role/version is unknown. Interface: native port/VLAN protection records, no global requirement for router ports.

**Test Requirements:** T0 plus routed port, uplink trunk, trusted DHCP server link, access-edge spoofing protections, VLAN override, unsupported model and malformed bindings.

**Acceptance Criteria:** Each new rule states role and mechanism; no duplicate HP DHCP-snooping root cause. No blanket port-security/MACsec requirement on every interface; current source guard limitations are disclosed. T0 and the reviewed regression gate must pass for implementation; pure research tasks instead validate their evidence and links.

**Implementation Result:** IOS/XE now exposes typed switchport mode, access VLAN, active state, DHCP snooping/DAI VLAN activation, per-port trust, IP Source Guard and port-security state. Verified AOS-S 16.10/16.11 parsing now resolves tagged/untagged VLAN membership, DHCP/ARP trust, ARP-protected VLANs, Dynamic IP Lockdown, port security and disabled ports. Findings require the exact `access-edge` assessment role: routed ports and unknown roles are unassessed, approved uplinks may be tagged/trusted, and an access-edge trunk is reported independently without mechanism noise. AOS-S keeps its existing VLAN-level DHCP-snooping finding rather than duplicating it per port. IOS-XE MACsec applicability was corrected from every switchport to explicit `uplink`/`external` roles or actual MKA/MACsec intent. Focused tests and public IOS-XE/AOS-S vulnerable/hardened corpus pairs pass the full gate (450 tests, 32 configurations).

<a id="GAP-012"></a>
### GAP-012 — Add AAA transport and server identity analysis

**Task ID and Title:** GAP-012 — Add AAA transport and server identity analysis

**Priority:** P1

**Status:** DONE (bounded FortiOS 7.4+ administrative RADIUS scope; protected-path semantics explicit)

**Source of Truth:** [FortiOS Administration Guide: Configuring a RADIUS server (S-RAD)](STANDARDS_BLINDSPOT_FINDINGS.md#S-RAD) — RadSec; [PAN-OS Administrative Access Best Practices: Deploy Administrative Access Best Practices (S-PAN)](STANDARDS_BLINDSPOT_FINDINGS.md#S-PAN) — external service protection; [Hardening Junos Devices Checklist, companion to This Week: Hardening Junos Devices, Second Edition (S-JUN)](STANDARDS_BLINDSPOT_FINDINGS.md#S-JUN) — centralized authentication. Versions, sections and access dates are in the linked source register or pinned legacy provenance.

**Linked Findings:** [STD-001](STANDARDS_BLINDSPOT_FINDINGS.md#STD-001)

**Dependencies:** [GAP-001](#GAP-001) release capability and approved transport threat model; optional [GAP-021](#GAP-021) context.

**Architecture/Convention Notes:** Preserve named server profile bindings and scope; generic FortiOS parsed sections are only the starting syntax evidence.

**Concrete Requirements:** Platforms: FORTIOS first; then IOS/XE, Junos, ASA, PAN-OS, AOS-S, EOS and SonicOS only after applicable transport sources. Evidence: active server protocol, transport, certificate/identity settings, bound admin method and explicit protected tunnel if available. Detect explicit unsafe transport/verification under the selected deployment policy, not every UDP endpoint. Missing protected-path evidence is unknown where topology matters. Interface: typed native AAA server records; optional context for declared protective path; no packet capture or AAA attempt.

**Test Requirements:** T0 plus RadSec valid/invalid identity settings, unbound server, mixed auth groups, protected tunnel declaration, unknown path, unsupported older release and all shared-secret redaction.

**Acceptance Criteria:** A central-auth declaration cannot mask unsafe known transport; protected/unknown cases are distinct. Recommendations use an actually supported alternative, with no unverified universal TLS mandate. T0 and the reviewed regression gate must pass for implementation; pure research tasks instead validate their evidence and links.

**Implementation Result:** FortiOS now exposes immutable secret-free RADIUS profiles that resolve named server objects through user-group members/matches to enabled remote administrators. Records retain transport, primary/secondary/tertiary endpoints, RadSec CA/client-certificate and identity-check settings, TLS minimum, message-authenticator state, source address/interface, interface selection and VRF. FortiOS 7.4 is the verified RadSec capability boundary. Findings are limited to bound 7.4+ profiles with a missing CA or explicitly disabled server identity check, a legacy explicit RadSec TLS minimum, or explicitly disabled message-authenticator validation on UDP/TCP. Unbound/disabled profiles, older or unknown releases, default message validation, and UDP/TCP over an unknown path are not promoted to vulnerabilities. The assessment policy accepts exact `scope:name` protected-path declarations but those declarations do not suppress explicit integrity failures. All shared-secret fields are excluded from typed evidence. Focused adversarial tests and the public vulnerable/hardened FortiOS corpus pass the full gate (456 tests, 32 configurations). Other platforms remain gated on their own current transport syntax and sources.

<a id="GAP-013"></a>
### GAP-013 — Add management certificate object and material assessment

**Task ID and Title:** GAP-013 — Add management certificate object and material assessment

**Priority:** P1

**Status:** DONE for bounded PAN-OS and ASA offline exported-material scope; live observation remains GAP-025

**Source of Truth:** [PAN-OS Help: Device > Setup > Management (S-PAN-M)](STANDARDS_BLINDSPOT_FINDINGS.md#S-PAN-M) — General Settings/TLS profile; [Hardening Junos Devices Checklist, companion to This Week: Hardening Junos Devices, Second Edition (S-JUN)](STANDARDS_BLINDSPOT_FINDINGS.md#S-JUN) — J-Web; [SonicOS 7.3 Device Settings Administration Guide (S-SON)](STANDARDS_BLINDSPOT_FINDINGS.md#S-SON) — Certificates. Versions, sections and access dates are in the linked source register or pinned legacy provenance.

**Linked Findings:** [STD-004](STANDARDS_BLINDSPOT_FINDINGS.md#STD-004)

**Dependencies:** [GAP-001](#GAP-001) release/export certificate formats. Explicit architecture decision before offline temporal validation; [GAP-025](#GAP-025) for live chain/revocation.

**Architecture/Convention Notes:** Parser owns certificate attachments; no secret/private-key serialization. Preserve architecture static/live boundary.

**Concrete Requirements:** Platforms: PAN_OS and ASA first attachment-to-object resolution; FORTIOS/JUNOS/SonicOS as material exports permit. Evidence: certificate reference, public DER/PEM or metadata, active service binding, intended identity/trust policy. Resolve absent objects as distinct from missing material; grade key/signature/identity only with known data. If approved, supply explicit assessment timestamp for reproducible not-before/not-after evaluation. Self-signing alone is not a universal failure. Interface: typed certificate/public metadata + optional assessment policy; default report schema stays stable or gets reviewed versioning.

**Test Requirements:** T0 plus named-but-missing object, unbound weak certificate, valid public chain, unknown trust anchor, expiration boundary with frozen timestamp, malformed PEM and proof private keys never serialize.

**Acceptance Criteria:** Attachment, static material property, policy trust and live observations remain distinct. Unknown material cannot become a valid-certificate assertion; no background network validation. T0 and the reviewed regression gate must pass for implementation; pure research tasks instead validate their evidence and links.

**Implementation Result:** PAN-OS resolves management TLS settings through correctly scoped shared/device SSL/TLS profiles to certificate objects; same-name vsys objects cannot override the shared management attachment. ASA resolves effective ordered `ssl trust-point` assignments to trustpoint definitions and identity-vs-CA certificate-chain entries, including removal commands. A shared X.509 layer parses exported PEM or DER material, records secret-free metadata, matches DNS/IP SAN identities, grades public-key size and signature hash, applies inclusive not-before/not-after boundaries at an explicit timezone-aware assessment time, and verifies a supplied chain only to explicitly approved SHA-256 anchors that are present in the export. Missing policy inputs remain unknown, self-issuance alone is not a failure, and trust is not asserted from an unknown client store. Findings distinguish unresolved references, malformed material, validity, identity, algorithm and approved-anchor trust failures. Private keys and certificate payloads never enter typed records, evidence or report context; inactive/unbound objects do not emit findings. Focused tests cover valid chains, wrong anchors, missing anchors, malformed PEM/base64, expiry boundaries, identity mismatch, weak RSA and public-processor reachability. The full gate passes (464 tests, 32 configurations). Live served-certificate, client trust-store and revocation observation remain explicitly out of scope here and are tracked by GAP-025.

<a id="GAP-014"></a>
### GAP-014 — Resolve effective inspection profile contents

**Task ID and Title:** GAP-014 — Resolve effective inspection profile contents

**Priority:** P1

**Status:** DONE for bounded PAN-OS/FortiOS exported local/shared and VDOM/global scope; controller/runtime state remains unknown

**Source of Truth:** [Security Policy Rule Best Practices (S-PAN-P)](STANDARDS_BLINDSPOT_FINDINGS.md#S-PAN-P) — Security profile rule best practices; [FortiOS Best Practices: Hardening (S-FGT)](STANDARDS_BLINDSPOT_FINDINGS.md#S-FGT) — Hardening. Versions, sections and access dates are in the linked source register or pinned legacy provenance.

**Linked Findings:** [STD-013](STANDARDS_BLINDSPOT_FINDINGS.md#STD-013)

**Dependencies:** [GAP-001](#GAP-001) release-specific profile semantics and applicability; current parsed reference fields are available.

**Architecture/Convention Notes:** Keep scoped object/group resolution in parser; emit findings on active rule attachment, not unused definitions.

**Concrete Requirements:** Platforms: FORTIOS and PAN_OS. Evidence: allowed policy match/traffic scope, profile/group names, resolved enabled profile content/actions and inherited local/global scope. Detect unresolved or ineffective required profiles according to verified feature policy. Unknown Panorama/FortiManager inheritance or licensing is not absence. Interface: native inspection-profile records and reference resolver; shared output remains Finding.

**Test Requirements:** T0 plus empty named profile, group containing weak member, unbound profile, local/global override, wrong VDOM/vsys name reuse, unknown controller inheritance and disabled rule.

**Acceptance Criteria:** A profile-name-only pass no longer describes effective protection. Findings identify active rule and offending profile; no claim about live inspection or paid subscription state. T0 and the reviewed regression gate must pass for implementation; pure research tasks instead validate their evidence and links.

**Implementation Result:** PAN-OS now exposes typed rule attachments, profile groups and individual profile definitions, resolves same-vsys before shared scope, preserves known built-in profiles, and prevents same-name objects in another vsys from satisfying a reference. FortiOS exposes typed UTM inspection attachments, resolves VDOM before global/root definitions, expands `firewall profile-group` members, preserves documented built-in defaults and prevents cross-VDOM resolution. Both plugins evaluate only enabled allow/accept rules in their existing traffic scope, distinguish missing attachment, unresolved group/member, empty group/profile and explicitly non-blocking actions, and identify the active rule plus offending object in sanitized evidence. Empty or weak unbound objects and disabled rules are ignored. Panorama/FortiManager unresolved references remain unknown rather than becoming absence findings; licensing, signature freshness and runtime inspection are not asserted. Tests cover direct and grouped profiles, pass/allow/alert actions, local overrides, cross-scope name reuse, controller uncertainty and public-processor reachability. The full gate passes (470 tests, 32 configurations).

<a id="GAP-015"></a>
### GAP-015 — Define and add missing local-in, SRX policy and VPN semantics

**Task ID and Title:** GAP-015 — Define and add missing local-in, SRX policy and VPN semantics

**Priority:** P1

**Status:** DONE (bounded explicit FortiOS 7.2 CLI and Junos/SRX configuration semantics; live/controller state excluded)

**Source of Truth:** [FortiOS local-in and IPsec CLI references (S-FGT)](STANDARDS_BLINDSPOT_FINDINGS.md#S-FGT); [Junos security policy, VPN and proposal references plus RFC 8247 (S-SRX)](STANDARDS_BLINDSPOT_FINDINGS.md#S-SRX). Versions, sections, access dates and conservative applicability are in the linked source register.

**Linked Findings:** [STD-014](STANDARDS_BLINDSPOT_FINDINGS.md#STD-014), [STD-016](STANDARDS_BLINDSPOT_FINDINGS.md#STD-016)

**Dependencies:** Verified FortiOS local-in/IPsec and Junos SRX/IPsec fixtures plus standards from [GAP-001](#GAP-001); shared ACL engine [GAP-020](#GAP-020) is optional later.

**Architecture/Convention Notes:** Separate native stateful/transit/self-traffic models; do not stretch stateless Junos filter records into SRX rules.

**Concrete Requirements:** Platforms: FORTIOS and JUNOS/SRX. Evidence: FortiOS local-in IPv4/IPv6 bindings, enabled phase1/phase2 references; SRX zones/address books/applications/order and VPN attachments. First publish parser coverage then add narrow supported permissive-local-in/stateful-policy and weak referenced-proposal checks. Unresolved applications/dynamic selectors or unexpanded groups remain unknown. Interface: explicit typed APIs/new export support declarations; stable IDs and public registration; no live IPsec negotiation.

**Test Requirements:** T0 plus VDOM/zone separation, local-in versus transit, disabled tunnel, unreferenced weak proposal, application defaults, inherited address books, deletion and unsupported export.

**Acceptance Criteria:** Supported exports are named accurately; parser unsupported state cannot pass. New checks prove a static configured property and do not imply complete SRX or IPv6 policy analysis. T0 and the reviewed regression gate must pass for implementation; pure research tasks instead validate their evidence and links.

**Implementation Result:** FortiOS now exposes typed IPv4/IPv6 local-in records separately from transit policy and typed same-VDOM phase2-to-phase1 tunnel records. The analyzer reports only explicitly enabled, always-scheduled accepts whose source and sensitive management service are both unrestricted; negated, disabled, scheduled and non-management cases remain ungraded. Attached active tunnels resolve their explicit IKE/IPsec transforms, DH/PFS and replay settings; obvious legacy algorithms and unresolved same-scope chains have separate stable findings. Unreferenced phase1 objects, disabled tunnels and cross-VDOM same-name objects cannot create or satisfy findings. Junos now exposes typed SRX zone-pair policies with ordered effective state, zone/global address-book and application-set resolution, omitted-application default-any semantics, and explicit apply-groups uncertainty. It separately resolves policy-attached or interface-bound VPNs through gateway, IKE policy/proposals and IPsec policy/proposals. Only completely resolved wildcard permits are reported as broad; only explicit legacy transforms are graded. Built-in proposal sets, unexpanded inheritance, dynamic/runtime selectors, policy installation, negotiated security associations and live peer identity remain unknown or outside scope. Secret values are redacted at the parser boundary. Focused adversarial tests and the full gate pass (478 tests, 32 configurations).

<a id="GAP-016"></a>
### GAP-016 — Recover verified ScreenOS depth selectively

**Task ID and Title:** GAP-016 — Recover verified ScreenOS depth selectively

**Priority:** P2

**Status:** DONE (bounded ScreenOS 6.3 scope) — verified 2026-09-14

**Source of Truth:** [ScreenOS 6.3.0 Documentation (S-SCR)](STANDARDS_BLINDSPOT_FINDINGS.md#S-SCR) — official 6.3 catalogue metadata identifies the IPv4 CLI Reference, Administration, Fundamentals and User Authentication volumes; the official r27 release notes provide the WebUI timeout erratum. The currently inaccessible manual bodies were corroborated against an exact archived CLI-reference mirror and pinned legacy [ScreenOS/report.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/ScreenOS/report.c) behavior. Versions, sections, URLs and access date are in the linked source register or pinned legacy provenance.

**Linked Findings:** [STD-017](STANDARDS_BLINDSPOT_FINDINGS.md#STD-017), [LEG-004](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-004)

**Dependencies:** [GAP-001](#GAP-001) official 6.3 volume/revision and representative fixtures; satisfied only for the bounded default-policy and session-control subset.

**Architecture/Convention Notes:** Reuse ordered set/unset native state; migration/lifecycle warning remains separate.

**Concrete Requirements:** Platform: SCREENOS. Evidence: default firewall action, active policy scope, admin versus user/auth-server timeout, AAA profile bindings, time authentication and zone screens only if confirmed by manual/export. Implement default-allow/no-policy and auth-session controls first when applicability is verified; NTP/screens are separately gated. Unknown release or missing relevant export is unknown. Interface: typed native accessor per confirmed domain, unchanged Finding contract.

**Test Requirements:** T0 plus no-policy with known default-deny, explicit default-allow, different admin/auth-server timeouts, unset/override, zone scope and unknown archived syntax.

**Acceptance Criteria:** No speculative modern settings imported from Junos. Each check cites the recovered ScreenOS section and fixture; unsupported subsets remain deferred rather than advertised. T0 and the reviewed regression gate must pass for implementation; pure research tasks instead validate their evidence and links.

**Implementation Result:** ScreenOS now exposes typed, immutable firewall-default and session-control records only for identified 6.3 exports. Ordered `set`/`unset` state resolves explicit `policy default-permit-all`, while absence retains the documented deny default without creating a finding. Session analysis separates console/Telnet, WebUI, administrator AAA, and policy/authentication-user server timeouts; applies documented ten-minute defaults; accepts the release-note-corrected `admin auth web timeout` spelling and the legacy exported alias; resolves administrator, default-user, policy-context and dot1x server bindings; ignores unbound servers and disabled policies; and reports unresolved active references separately. Zero and values above the ten-minute project target are findings only for active, known controls. Unknown releases remain unsupported for these new inferences, and all evidence crosses the parser boundary redacted. Authenticated NTP, zone-screen adequacy, routing, certificates and runtime authentication success remain deferred because source, policy threshold or export evidence is still insufficient. Focused adversarial tests and the full gate pass (487 tests, 32 configurations).

<a id="GAP-017"></a>
### GAP-017 — Complete administrative policy evidence on secondary platforms

**Task ID and Title:** GAP-017 — Complete administrative policy evidence on secondary platforms

**Priority:** P1

**Status:** DONE (bounded static scope) — verified 2026-09-14

**Source of Truth:** [Hardening Junos Devices Checklist, companion to This Week: Hardening Junos Devices, Second Edition (S-JUN)](STANDARDS_BLINDSPOT_FINDINGS.md#S-JUN) — Access/User Authentication; [PAN-OS Help: Device > Setup > Management (S-PAN-M)](STANDARDS_BLINDSPOT_FINDINGS.md#S-PAN-M) — Authentication/banners; [Aruba 2930M/F Access Security Guide for AOS-S Switch 16.11 (S-HP)](STANDARDS_BLINDSPOT_FINDINGS.md#S-HP) — Access Security; [SonicOS 7.3 Device Settings: Configuring Password Compliance (S-SON-P)](STANDARDS_BLINDSPOT_FINDINGS.md#S-SON-P); [EOS User Manual: Security (S-EOS)](STANDARDS_BLINDSPOT_FINDINGS.md#S-EOS) — User Security. Versions, sections and access dates are in the linked source register or pinned legacy provenance.

**Linked Findings:** [STD-015](STANDARDS_BLINDSPOT_FINDINGS.md#STD-015), [STD-021](STANDARDS_BLINDSPOT_FINDINGS.md#STD-021), [STD-022](STANDARDS_BLINDSPOT_FINDINGS.md#STD-022), [STD-023](STANDARDS_BLINDSPOT_FINDINGS.md#STD-023), [STD-024](STANDARDS_BLINDSPOT_FINDINGS.md#STD-024)

**Dependencies:** [GAP-001](#GAP-001) release/product defaults; [GAP-013](#GAP-013) certificate aspects; [GAP-012](#GAP-012) remote transport aspects.

**Architecture/Convention Notes:** Deliver one platform change at a time; native typed records and existing plugin registration. Do not make every platform conform to one login grammar.

**Concrete Requirements:** Platforms/evidence: JUNOS login classes/idle-time/accounting/banner/J-Web settings; PAN_OS admin roles/lockout/MFA/session/banner/SSH profiles with local/vsys/template scope; HP_PROCURVE per-channel roles/session/banner and TLS settings for verified families; SONICOS7 custom export admin/password/AAA/session/banner/TLS; EOS CLI and eAPI AAA/accounting/users/session/banner/TLS per VRF. Add named controls only where defaults and deployment policy are resolved. Unknown SonicOS users, unexpanded Panorama or unsupported HP releases stay unknown. Interface: platform-native admin/session APIs; reuse existing policy fields; no silent common-schema population from guessed defaults.

**Test Requirements:** T0 per platform plus least-privilege class, inherited/overridden admin policy, CLI-only EOS, SonicOS incompatible export, local fallback, disabled service and malformed timeout. Include valid emergency-account exceptions under explicit policy.

**Acceptance Criteria:** Each platform delivery covers the declared admin channels and lists unsupported fields. Existing central-auth/password checks are extended or complemented without duplicate root causes. Finite thresholds and MFA applicability have authoritative justification. T0 and the reviewed regression gate must pass for implementation; pure research tasks instead validate their evidence and links.

**Implementation Progress:** The Junos delivery is complete at a bounded static-analysis scope. The parser now exposes immutable login-class/user timeout relationships, separate pre-login message and post-login announcement state, RADIUS/TACACS+ accounting event and destination resolution, and explicit J-Web session controls. Seven stable rules cover missing pre-authentication notice, absent or unresolved user class bindings, disabled/unconfigured effective CLI idle timeout, incomplete accounting events, missing or unresolved accounting destinations, explicit J-Web idle timeouts above 30 minutes, and the documented unlimited J-Web session default. `apply-groups` inheritance and malformed values remain unknown rather than becoming absence findings. Privilege-count and MFA findings remain deferred because this export alone does not establish organizational authorization intent or an emergency-account policy.

The PAN-OS delivery is also complete at a bounded static-analysis scope. The parser resolves local administrator dynamic/custom roles, local/shared authentication-profile and authentication-sequence references, global external-administrator authentication, and explicit MFA configuration state; exposes banner acknowledgement, idle timeout, failed-attempt/lockout and concurrent-session fields independently; and follows only the management SSH profile applied under `deviceconfig system ssh`. Findings cover missing/unresolved roles and authentication profiles/sequences, missing banner or acknowledgement, explicit idle timeout above 10 minutes or disabled, explicit failed-attempt limit above five or unlimited, explicit short lockout, explicit unlimited concurrent sessions, and missing/unresolved/empty or explicitly legacy PAN-OS 10+ SSH profiles. Absent and malformed numeric values, pre-10 SSH grammar, Panorama inheritance, upstream RADIUS/SAML MFA, active sessions, and post-commit SSH service restart state remain unknown. That delivery checkpoint passed 501 tests across 32 configurations.

The HP ProCurve/ArubaOS-S delivery is complete for verified 16.10/16.11 running configurations. The parser now resolves ordered manager/operator credentials and removals, expands `password all`, and treats absent credential lines as unknown unless `include-credentials` or an explicit removal proves absence. Console, Telnet, SSH, and WebAgent retain separate login/operator and enable/manager primary/secondary authentication methods plus service applicability. Remote CLI, serial/USB, and WebAgent idle timeouts are independent, including general-to-serial override behavior, documented defaults, and malformed-value uncertainty. MOTD state and WebAgent plaintext/TLS state are ordered independently. Findings cover proven missing manager protection on an applicable local path, the documented unauthenticated `authorized` method, missing MOTD, and disabled or above-10-minute applicable session timeouts. Certificate material/served-chain validation, organizational role suitability, runtime authentication and unsupported releases remain unknown. Focused and public-pipeline tests pass; the full gate passes with 509 tests across 32 configurations. SonicOS 7 custom E-CLI is the next platform delivery.

The SonicOS 7 custom E-CLI delivery is complete at a bounded static-analysis scope. The parser exposes typed built-in/local administrators, secret-free credential presence, TOTP state, inline/nested and recursive group membership with documented role precedence, global user-authentication method/local fallback, password minimum/complexity/scope, lockout/session/CLI attempt controls, CLI connection banners, and active HTTPS TLS/certificate selection. Findings cover conflicting privilege groups, known missing TOTP on full/limited local administrators, short or incomplete password policy, omitted administrator constraint scopes, disabled/weak lockout, excessive idle/CLI attempts, log-without-lockout, missing SSH connection notice, explicit TLS 1.0 allowance, and selected/default self-signed management identity. Documented omitted defaults are reconstructed only for identified 7.0-7.2 custom exports; 7.3+ omissions remain unknown because upgrades and new installations can differ. Built-in default-password state, upstream MFA, authentication success, served certificate/chain, revocation, runtime reachability and legacy preference exports remain unassessed. Focused and public-pipeline tests pass; its delivery checkpoint passed 518 tests across 32 configurations.

The Arista EOS delivery completes GAP-017 at a bounded static-analysis scope. The parser exposes typed local administrators and built-in/custom/default-role resolution; ordered login and enable authentication, EXEC and all-command authorization, and EXEC/all-command accounting lists; release-aware console, SSH and Telnet applicability plus idle/absolute timers; distinct login/MOTD banner state; AAA lockout; and active eAPI endpoints linked to named SSL profiles, certificate declarations and explicit TLS versions. Findings cover undefined role references, applicable `none` AAA methods, centralized login without all-command authorization or complete accounting, disabled/weak lockout, disabled/excessive applicable idle timers, missing pre-login notice, and active HTTPS without a profile or with an undefined/certificate-less/explicitly legacy profile. CLI-only applicability, local fallback, ordered resets/removals, repeated blocks, inactive services, malformed timers and the EOS 4.36.0F absolute-timeout boundary have focused coverage. Static exports cannot prove organizational role suitability, emergency-account procedure, upstream AAA/MFA outcome, running sessions, certificate chain/trust/revocation, or the identity actually served. TLS defaults omitted inside a valid profile remain unknown rather than passing or failing. Focused and public-pipeline tests pass; the full gate passes with 529 tests across 32 configurations.

<a id="GAP-026"></a>
### GAP-026 — Resolve control-plane and DoS policy contents

**Task ID and Title:** GAP-026 — Resolve control-plane and DoS policy contents

**Priority:** P1

**Status:** PLANNED; platform rate applicability NEEDS_HUMAN_REVIEW

**Source of Truth:** [Cisco Guide to Harden Cisco IOS Devices (S-IOS)](STANDARDS_BLINDSPOT_FINDINGS.md#S-IOS)/[Cisco IOS XE Software Hardening Guide (S-XE)](STANDARDS_BLINDSPOT_FINDINGS.md#S-XE) — CoPP; [Hardening Junos Devices Checklist, companion to This Week: Hardening Junos Devices, Second Edition (S-JUN)](STANDARDS_BLINDSPOT_FINDINGS.md#S-JUN) — Firewall Filter; [EOS User Manual: Security (S-EOS)](STANDARDS_BLINDSPOT_FINDINGS.md#S-EOS) — Control Plane Security; [FortiOS Best Practices: Hardening (S-FGT)](STANDARDS_BLINDSPOT_FINDINGS.md#S-FGT) — DoS. Versions, sections and access dates are in the linked source register or pinned legacy provenance.

**Linked Findings:** [STD-008](STANDARDS_BLINDSPOT_FINDINGS.md#STD-008)

**Dependencies:** [GAP-001](#GAP-001) platform/version/source and deployment rate policy; [GAP-021](#GAP-021) context if workload-specific limits are required.

**Architecture/Convention Notes:** Separate router self-traffic controls from firewall transit DoS; resolve attachment chains in parsers.

**Concrete Requirements:** Platforms: IOS/XE class/policy maps and Junos lo0 terms/policers first; EOS default/custom control-plane ACL/classes and FortiOS DoS anomaly content next. Evidence: referenced definitions, traffic selectors, enabled action/rate/logging and scope. Detect dangling/no-op protection and explicit disabled required controls; do not invent globally correct packet rates. ASA deeper connection limits, PAN zone protection, ScreenOS screens and SonicOS floods remain [GAP-001](#GAP-001) research subsets. Unknown hardware defaults/workload remain unknown. Interface: native control-plane/protection APIs; optional policy context; existing attachment IDs retained.

**Test Requirements:** T0 plus attached empty policy, unreferenced strong policy, class default override, wrong AF/loopback, blocking versus monitor-only anomaly, platform built-in policy and unknown rate context.

**Acceptance Criteria:** Presence is no longer presented as contents-based protection. Findings prove the applicable static defect and avoid calling ordinary transit filtering CoPP or asserting runtime capacity. T0 and the reviewed regression gate must pass for implementation; pure research tasks instead validate their evidence and links.

<a id="GAP-027"></a>
### GAP-027 — Add static configuration backup and change-audit checks

**Task ID and Title:** GAP-027 — Add static configuration backup and change-audit checks

**Priority:** P2

**Status:** PLANNED; platform transport defaults NEEDS_RESEARCH

**Source of Truth:** [Cisco Guide to Harden Cisco IOS Devices (S-IOS)](STANDARDS_BLINDSPOT_FINDINGS.md#S-IOS) — configuration change logging; [Cisco IOS XE Software Hardening Guide (S-XE)](STANDARDS_BLINDSPOT_FINDINGS.md#S-XE) — Software Configuration Management; [Hardening Junos Devices Checklist, companion to This Week: Hardening Junos Devices, Second Edition (S-JUN)](STANDARDS_BLINDSPOT_FINDINGS.md#S-JUN) — secure configuration backups; [FortiOS Best Practices: Hardening (S-FGT)](STANDARDS_BLINDSPOT_FINDINGS.md#S-FGT) — backup guidance. Versions, sections and access dates are in the linked source register or pinned legacy provenance.

**Linked Findings:** [STD-009](STANDARDS_BLINDSPOT_FINDINGS.md#STD-009)

**Dependencies:** [GAP-001](#GAP-001) release-specific archive/transport sections; [GAP-025](#GAP-025) only for actual backup success.

**Architecture/Convention Notes:** Native records retain sanitized destination and configured schedule/audit state; do not contact backup servers.

**Concrete Requirements:** Platforms: IOS/XE and Junos first, FortiOS after version attribution. Evidence: archive/transfer destination, protocol, enabled/schedule settings and configuration-change logging selectors. Detect known missing required audit configuration or explicitly insecure configured backup transport under an approved policy; redacted authentication values are not missing credentials. Unknown external backup arrangements stay unknown unless scope explicitly requires on-box scheduling. Interface: native archive/change-audit accessor, unchanged Finding schema.

**Test Requirements:** T0 plus secure remote archive, disabled/overridden schedule, external-backup declared context, unknown transfer credentials, multiple destinations and sanitized URLs.

**Acceptance Criteria:** Findings distinguish on-box configuration from backup availability/retention. No scan claims integrity or successful recovery without operational evidence; existing generic remote logging findings are not duplicated. T0 and the reviewed regression gate must pass for implementation; pure research tasks instead validate their evidence and links.

## Wave 3 — Shared capabilities

<a id="GAP-018"></a>
### GAP-018 — Build reusable offline credential analysis

**Task ID and Title:** GAP-018 — Build reusable offline credential analysis

**Priority:** P2

**Status:** PLANNED

**Source of Truth:** Legacy [common/nipper-common.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/common/nipper-common.c) simplePassword/passwordStrength/password7; [IOS/process-username.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/IOS/process-username.c); [Cisco Guide to Harden Cisco IOS Devices (S-IOS)](STANDARDS_BLINDSPOT_FINDINGS.md#S-IOS) password guidance. Versions, sections and access dates are in the linked source register or pinned legacy provenance.

**Linked Findings:** [STD-005](STANDARDS_BLINDSPOT_FINDINGS.md#STD-005), [LEG-005](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-005)

**Dependencies:** [GAP-003](#GAP-003) format/evidence inventory; [GAP-021](#GAP-021) versioned policy interface or a scoped internal equivalent.

**Architecture/Convention Notes:** Shared analysis consumes typed secret metadata through a restricted internal boundary; no public secret fields added casually.

**Concrete Requirements:** Platforms: IOS/XE, ASA, Junos, ScreenOS and EOS first; FortiOS/PAN-OS/HP/SonicOS only where supplied export actually exposes analyzable values. Evaluate storage type, available plaintext length, approved optional blocklist/default fingerprints; reversible type7 handling stays internal and opt-in if it changes exposure. Hash-only values cannot receive plaintext-strength verdicts. Interface: deterministic credential policy + result metadata; raw/decoded values excluded from Finding/logs. Cross-account reuse is a new design proposal, not verified legacy parity.

**Test Requirements:** T0 plus Unicode/long values, unlisted weak value, unknown and malformed encoding, hash-only input, user-supplied blocklist failure, duplicate account scope and no recovered-secret output.

**Acceptance Criteria:** One reusable engine produces provenance-aware property results across at least two platforms, with policy version recorded. No secret persistence by default and no claim of cracking from static hash classification. T0 and the reviewed regression gate must pass for implementation; pure research tasks instead validate their evidence and links.

<a id="GAP-019"></a>
### GAP-019 — Design optional cracking-tool hash export

**Task ID and Title:** GAP-019 — Design optional cracking-tool hash export

**Priority:** P3

**Status:** PLANNED; explicit opt-in interface required

**Source of Truth:** Legacy [common/nipper-cmdoptions.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/common/nipper-cmdoptions.c) --john; [common/nipper-common.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/common/nipper-common.c) addJohnPassword; nipper.c output writer. Versions, sections and access dates are in the linked source register or pinned legacy provenance.

**Linked Findings:** [LEG-005](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-005)

**Dependencies:** [GAP-018](#GAP-018) credential metadata; supported external format documentation and handling design reviewed before implementation.

**Architecture/Convention Notes:** Secret-bearing export is separate from normal HTML/JSON evidence. No automatic external process invocation.

**Concrete Requirements:** Platforms first: supported IOS/XE type5 and any other format independently validated; do not advertise generic all-vendor export. Evidence: recognized hash format, scoped account identifier, explicit user-selected output. Export only selected supported hashes; unknown formats are listed as unsupported without leaking raw data. Interface: explicit opt-in export option with destination handling, overwrite policy, restrictive permissions and clear scope metadata; offline mode retained. This task does not run a cracker.

**Test Requirements:** T0 adapted: authorized option on/off, unsupported/malformed hash, account naming collisions, output path/overwrite behavior, secret-free normal logs/reports and round-trip format validation using synthetic hashes.

**Acceptance Criteria:** Default scans produce no hash export and launch no cracking tool. Requested export contains only supported selected material; documentation accurately calls this export integration. T0 and the reviewed regression gate must pass for implementation; pure research tasks instead validate their evidence and links.

<a id="GAP-020"></a>
### GAP-020 — Generalize conservative ACL hygiene and effectiveness

**Task ID and Title:** GAP-020 — Generalize conservative ACL hygiene and effectiveness

**Priority:** P2

**Status:** PLANNED

**Source of Truth:** Legacy [common/nipper-acl.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/common/nipper-acl.c); LOCAL-ONLY [device/filter/filter-security.cpp](../../reference/nipper-ng-original/libnipper-0.12.6/device/filter/filter-security.cpp); [Security Policy Rule Best Practices (S-PAN-P)](STANDARDS_BLINDSPOT_FINDINGS.md#S-PAN-P) — least privilege; [Check Point Gateway and Management Hardening Administration Guide (S-CP)](STANDARDS_BLINDSPOT_FINDINGS.md#S-CP) — policy exposure. Versions, sections and access dates are in the linked source register or pinned legacy provenance.

**Linked Findings:** [STD-019](STANDARDS_BLINDSPOT_FINDINGS.md#STD-019), [LEG-006](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-006), [LEG-007](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-007)

**Dependencies:** [GAP-004](#GAP-004) FW1 semantic lessons; each platform native parser completeness; [GAP-015](#GAP-015) stateful model where needed.

**Architecture/Convention Notes:** Create common predicates only for equivalent semantics; preserve platform order/layer/action/address-family behavior.

**Concrete Requirements:** Platforms: FW1, ASA, FortiOS, ScreenOS, PAN-OS, SonicOS first; IOS/Junos filters as separately qualified adapters. Evidence: static network/service sets, active rule order, terminal action, attachments, zones/VRFs/layers, negation/time/application predicates and unknown markers. Add disabled/unlogged/broad-service hygiene and proven redundancy/post-terminal unreachable rules. Never infer runtime-unused. Unsupported NAT/application/dynamic objects block effectiveness proof, not all simple independent checks. Interface: typed adapter/semantic result with explicit coverage limitations, stable Finding IDs, no breaking JSON change without version review.

**Test Requirements:** T0 plus partial overlap versus containment, IPv6 ranges, implicit/application cleanup, shadow across incompatible zones forbidden, object cycles, NAT-dependent unknown, time-bound rules and bounded expansion/performance.

**Acceptance Criteria:** Shared engine agrees with proven native cases across at least two platforms, labels proof scope, avoids duplicates and cannot promote unsupported semantic fields to Any. Runtime hit statistics remain GAP-025. T0 and the reviewed regression gate must pass for implementation; pure research tasks instead validate their evidence and links.

<a id="GAP-021"></a>
### GAP-021 — Add explicit audit policy and assessment scope

**Task ID and Title:** GAP-021 — Add explicit audit policy and assessment scope

**Priority:** P2

**Status:** DONE (bounded policy/role/category scope) — verified 2026-09-14; target-CIDR and partial-section selection remain NEEDS_HUMAN_REVIEW

**Source of Truth:** Legacy [common/nipper-cmdoptions.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/common/nipper-cmdoptions.c) policy toggles/location/timeout; [common/nipper-acl.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/common/nipper-acl.c) option consumers. Versions, sections and access dates are in the linked source register or pinned legacy provenance.

**Linked Findings:** [LEG-008](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-008)

**Dependencies:** Inventory which checks require external context; source/default mapping [GAP-001](#GAP-001).

**Architecture/Convention Notes:** One typed immutable assessment context passed through existing dispatch; do not scatter optional dictionaries or duplicate device registry.

**Concrete Requirements:** Platforms: all pipelines. Evidence/context: policy version, approved thresholds, device role and explicitly selected rule categories. Add deterministic defaults and per-scan overrides with provenance; apply exclusions without hiding coverage. Unknown role does not become edge/internal by guess. Interface: CLI/config and processor/plugin context design, backward-compatible defaults and report policy metadata. CIDR or config-section targeting is a separate research gate: if approved, preserve references/order outside selection and describe excluded scope; no claim legacy offered it.

**Test Requirements:** T0 plus identical default outputs, selected category off, invalid policy, conflicting scope selectors, referenced objects outside chosen scope, unknown role and CLI/public factory coverage.

**Acceptance Criteria:** Every report declares active policy/exclusions. Selection cannot imply excluded data is secure. Existing callers remain compatible or receive a deliberately versioned interface change. T0 and the reviewed regression gate must pass for implementation; pure research tasks instead validate their evidence and links.

**Implementation Result:** All public analyzers now accept a backward-compatible immutable `AssessmentContext`, loaded optionally through `--assessment-policy`. The validated JSON schema carries policy version/provenance, explicit device and exact interface roles, exact protected-AAA profile declarations, and excluded rule categories. Unknown fields/roles/selectors and malformed policies fail closed. All processors apply category exclusions after parser/plugin evaluation, preserving evidence coverage, and every HTML/JSON report declares the active policy plus the warning that exclusions are not implied secure. Default scans retain deterministic output and unknown roles/paths are never inferred from names or routes. GAP-010 and GAP-011 consume explicit interface roles; GAP-012 consumes protected-path declarations. Focused CLI, validation, reporting, exclusion and public-processor tests plus the full gate pass (456 tests, 32 corpus configurations). CIDR targeting, threshold overrides and partial configuration selection were deliberately not implemented.

<a id="GAP-022"></a>
### GAP-022 — Add coverage and useful configuration report content

**Task ID and Title:** GAP-022 — Add coverage and useful configuration report content

**Priority:** P2

**Status:** PLANNED

**Source of Truth:** Legacy [IOS/report.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/IOS/report.c), [FW1/report.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/FW1/report.c) and [common/nipper-report.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/common/nipper-report.c); current architecture KnowledgeState contract. Versions, sections and access dates are in the linked source register or pinned legacy provenance.

**Linked Findings:** [STD-026](STANDARDS_BLINDSPOT_FINDINGS.md#STD-026), [LEG-009](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-009)

**Dependencies:** Parser availability inventory; [GAP-021](#GAP-021) policy metadata; avoid dependence on completing all missing parser categories.

**Architecture/Convention Notes:** Keep Findings schema stable unless versioning is explicitly approved; metadata/inventory is separate from security issues.

**Concrete Requirements:** Platforms: all11 pipelines/14 IDs. Evidence: parser/export/version provenance, assessed category/knowledge state, sanitized interfaces/policies/services and existing Finding severity/recommendations. Add coverage ledger, optional scoped inventory and concise remediation summary to HTML/JSON; explain unsupported FW1 OS state, SonicOS export and Panorama inheritance. Unknown normalized IOS/ASA must remain unknown until adapters are intentionally implemented. Interface: reviewed optional report metadata/sections and sanitized serializers; no secret-rich raw-config appendix. Executive summary is new report design, not proven old functionality.

**Test Requirements:** T0 adapted: secure/empty/unknown scans, malicious HTML strings, partially parsed exports, scoped exclusions, secret redaction in both outputs and pipeline snapshots. Check content equivalence across formats.

**Acceptance Criteria:** No-findings report explicitly states unassessed scope. Existing remediation/reference content preserved; inventories are labeled configuration data, not passed checks. Default output compatibility and intentional snapshot changes reviewed. T0 and the reviewed regression gate must pass for implementation; pure research tasks instead validate their evidence and links.

## Wave 4 — New dialect and export scope

<a id="GAP-023"></a>
### GAP-023 — Qualify legacy dialect demand and fixtures before adding support

**Task ID and Title:** GAP-023 — Qualify legacy dialect demand and fixtures before adding support

**Priority:** P3

**Status:** NEEDS_HUMAN_REVIEW; new parser work not yet approved by evidence

**Source of Truth:** Legacy [common/nipper-cmdoptions.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/common/nipper-cmdoptions.c) and nipper.c dispatch; NMP/PIX/CSS/Passport/SonicOS processors; LOCAL-ONLY libnipper.cpp aliases. Versions, sections and access dates are in the linked source register or pinned legacy provenance.

**Linked Findings:** [LEG-001](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-001), [LEG-002](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-002), [LEG-011](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-011)

**Dependencies:** [GAP-001](#GAP-001) applicable archival sources; representative redistributable sanitized fixtures, demand and maintenance owner required for each dialect.

**Architecture/Convention Notes:** One explicit registry entry per justified dialect/alias; parser identity and analyzer reuse must be source-proven. Do not copy TODO/template support claims.

**Concrete Requirements:** Candidates: independent PIX/FWSM, old SonicOS preferences, CatOS/NMP, CSS, Passport/Accelar; Nokia only if its input semantics differ usefully from FW1; local-only3Com firewall/NortelRoutingSwitch separately justified. Define parser evidence, supported release/export and minimum detection pack before selecting implementation. Unknown dialect is rejected/unsupported. Interface: explicit registry/parser/analyzer additions and documentation only after gates; no device-count target.

**Test Requirements:** Research stage validates fixture provenance and demand. Any approved implementation must meet T0 plus incompatible export rejection, alias dispatch, defaults by release and permanent public-pipeline fixtures.

**Acceptance Criteria:** Each candidate gets adopt/defer/reject with reason. No registration is described as independent support without positive/negative dialect fixtures and meaningful checks. EOL maintenance burden is recorded. T0 and the reviewed regression gate must pass for implementation; pure research tasks instead validate their evidence and links.

<a id="GAP-024"></a>
### GAP-024 — Design optional offline Check Point OS export coverage

**Task ID and Title:** GAP-024 — Design optional offline Check Point OS export coverage

**Priority:** P2 research, later implementation

**Status:** NEEDS_RESEARCH / NEEDS_HUMAN_REVIEW

**Source of Truth:** [Check Point Gateway and Management Hardening Administration Guide (S-CP)](STANDARDS_BLINDSPOT_FINDINGS.md#S-CP) — Gaia OS Hardening and Administrator Identity and Access Control. Versions, sections and access dates are in the linked source register or pinned legacy provenance.

**Linked Findings:** [STD-018](STANDARDS_BLINDSPOT_FINDINGS.md#STD-018)

**Dependencies:** [GAP-001](#GAP-001) current and legacy Gaia export documentation; matched policy/OS/gateway fixtures; value versus maintenance review.

**Architecture/Convention Notes:** Treat additional OS data as a separate provenance-bearing input, never infer it from rules.C.

**Concrete Requirements:** Platform: CHECKPOINT_FW1 with an explicitly associated Gaia/gateway/management export. Evidence: OS version/device identity, admin/AAA/services/SNMP/logging/time/cert/routing configuration in documented offline format. First deliver interface/coverage design, then implement approved narrow system controls; do not certify old policy format with current R82 guidance. Absent/mismatched OS input remains unsupported/unknown. Interface: optional multi-file bundle/manifest with identity checks and typed native OS state; current policy-only scan remains supported.

**Test Requirements:** T0 after design: matched/mismatched gateway identity, policy-only bundle, old/current OS release, multi-gateway install targets, partial/malformed OS export and sensitive admin field redaction.

**Acceptance Criteria:** Policy findings remain unchanged with no OS input. Added system findings prove their source and release; no false known-empty categories. Bundle semantics and maintenance scope approved before advertising coverage. T0 and the reviewed regression gate must pass for implementation; pure research tasks instead validate their evidence and links.

## Optional operational expansion

<a id="GAP-025"></a>
### GAP-025 — Keep operational enrichment as a separate opt-in track

**Task ID and Title:** GAP-025 — Keep operational enrichment as a separate opt-in track

**Priority:** P3 expansion

**Status:** NEEDS_RESEARCH / NEEDS_HUMAN_REVIEW

**Source of Truth:** Legacy [common/nipper-snmp.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/common/nipper-snmp.c) and nipper.c acquisition; [Security Policy Rule Best Practices (S-PAN-P)](STANDARDS_BLINDSPOT_FINDINGS.md#S-PAN-P) — rule optimization; [PAN-OS Help: Device > Setup > Management (S-PAN-M)](STANDARDS_BLINDSPOT_FINDINGS.md#S-PAN-M) — certificate state. Versions, sections and access dates are in the linked source register or pinned legacy provenance.

**Linked Findings:** [LEG-010](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-010), [LEG-007](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-007), [STD-004](STANDARDS_BLINDSPOT_FINDINGS.md#STD-004)

**Dependencies:** Explicit expansion decision; documented data APIs/formats/authentication, consent/scope design and freshness policy. Not a dependency of static baseline tasks.

**Architecture/Convention Notes:** Do not alter default offline behavior. Prefer supplied signed/provenance-bearing operational exports before live collectors; never restore SNMP read/write/TFTP merely for parity.

**Concrete Requirements:** Platforms selected individually. Candidate evidence: served certificate chain/revocation, runtime rule hits with interval/reset/install identity, content/license status, backup success, advisory feed freshness. Define per-capability provenance/assessment time and unknown/stale/mismatched states. Zero hits alone is not safe-to-delete; config trustpoint is not served certificate. Interface: separate opt-in provider/context, bounded network operations and explicit result types; automatic device changes excluded.

**Test Requirements:** T0 plus opt-in off means no network, timeout/auth failure, stale counter window, reset counters, changed installed policy, certificate mismatch and credential redaction. Synthetic provider fixtures precede any integration tests.

**Acceptance Criteria:** Each approved provider states what it observes and cannot prove. Static findings remain deterministic; no zero-hit deletion recommendation or stale-data compliance claim. Historical vulnerability tables are not imported as current intelligence. T0 and the reviewed regression gate must pass for implementation; pure research tasks instead validate their evidence and links.

## Finding-to-task ledger

Every finding has an explicit disposition. Research-dependent findings link to implementation work only subject to its stated prerequisites.

| Finding | Tasks |
|---|---|
| [STD-001](STANDARDS_BLINDSPOT_FINDINGS.md#STD-001) | [GAP-012](#GAP-012) |
| [STD-002](STANDARDS_BLINDSPOT_FINDINGS.md#STD-002) | [GAP-009](#GAP-009) |
| [STD-003](STANDARDS_BLINDSPOT_FINDINGS.md#STD-003) | [GAP-010](#GAP-010) |
| [STD-004](STANDARDS_BLINDSPOT_FINDINGS.md#STD-004) | [GAP-013](#GAP-013), [GAP-025](#GAP-025) |
| [STD-005](STANDARDS_BLINDSPOT_FINDINGS.md#STD-005) | [GAP-003](#GAP-003), [GAP-018](#GAP-018) |
| [STD-006](STANDARDS_BLINDSPOT_FINDINGS.md#STD-006) | [GAP-007](#GAP-007) |
| [STD-007](STANDARDS_BLINDSPOT_FINDINGS.md#STD-007) | [GAP-008](#GAP-008) |
| [STD-008](STANDARDS_BLINDSPOT_FINDINGS.md#STD-008) | [GAP-026](#GAP-026) |
| [STD-009](STANDARDS_BLINDSPOT_FINDINGS.md#STD-009) | [GAP-027](#GAP-027) |
| [STD-010](STANDARDS_BLINDSPOT_FINDINGS.md#STD-010) | [GAP-006](#GAP-006) |
| [STD-011](STANDARDS_BLINDSPOT_FINDINGS.md#STD-011) | [GAP-011](#GAP-011) |
| [STD-012](STANDARDS_BLINDSPOT_FINDINGS.md#STD-012) | [GAP-006](#GAP-006) |
| [STD-013](STANDARDS_BLINDSPOT_FINDINGS.md#STD-013) | [GAP-014](#GAP-014) |
| [STD-014](STANDARDS_BLINDSPOT_FINDINGS.md#STD-014) | [GAP-015](#GAP-015) |
| [STD-015](STANDARDS_BLINDSPOT_FINDINGS.md#STD-015) | [GAP-017](#GAP-017) |
| [STD-016](STANDARDS_BLINDSPOT_FINDINGS.md#STD-016) | [GAP-015](#GAP-015) |
| [STD-017](STANDARDS_BLINDSPOT_FINDINGS.md#STD-017) | [GAP-001](#GAP-001), [GAP-016](#GAP-016) |
| [STD-018](STANDARDS_BLINDSPOT_FINDINGS.md#STD-018) | [GAP-001](#GAP-001), [GAP-024](#GAP-024) |
| [STD-019](STANDARDS_BLINDSPOT_FINDINGS.md#STD-019) | [GAP-004](#GAP-004), [GAP-020](#GAP-020) |
| [STD-020](STANDARDS_BLINDSPOT_FINDINGS.md#STD-020) | [GAP-002](#GAP-002) |
| [STD-021](STANDARDS_BLINDSPOT_FINDINGS.md#STD-021) | [GAP-017](#GAP-017) |
| [STD-022](STANDARDS_BLINDSPOT_FINDINGS.md#STD-022) | [GAP-011](#GAP-011), [GAP-017](#GAP-017) |
| [STD-023](STANDARDS_BLINDSPOT_FINDINGS.md#STD-023) | [GAP-017](#GAP-017) |
| [STD-024](STANDARDS_BLINDSPOT_FINDINGS.md#STD-024) | [GAP-017](#GAP-017) |
| [STD-025](STANDARDS_BLINDSPOT_FINDINGS.md#STD-025) | [GAP-005](#GAP-005) |
| [STD-026](STANDARDS_BLINDSPOT_FINDINGS.md#STD-026) | [GAP-022](#GAP-022) |
| [STD-027](STANDARDS_BLINDSPOT_FINDINGS.md#STD-027) | [GAP-001](#GAP-001) |
| [LEG-001](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-001) | [GAP-023](#GAP-023) |
| [LEG-002](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-002) | [GAP-023](#GAP-023) |
| [LEG-003](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-003) | [GAP-006](#GAP-006), [GAP-009](#GAP-009), [GAP-010](#GAP-010), [GAP-011](#GAP-011) |
| [LEG-004](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-004) | [GAP-006](#GAP-006), [GAP-016](#GAP-016) |
| [LEG-005](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-005) | [GAP-003](#GAP-003), [GAP-018](#GAP-018), [GAP-019](#GAP-019) |
| [LEG-006](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-006) | [GAP-004](#GAP-004), [GAP-020](#GAP-020) |
| [LEG-007](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-007) | [GAP-004](#GAP-004), [GAP-020](#GAP-020), [GAP-025](#GAP-025) |
| [LEG-008](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-008) | [GAP-021](#GAP-021) |
| [LEG-009](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-009) | [GAP-022](#GAP-022) |
| [LEG-010](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-010) | [GAP-025](#GAP-025) |
| [LEG-011](LEGACY_NIPPER_COMPARISON_FINDINGS.md#LEG-011) | [GAP-001](#GAP-001), [GAP-023](#GAP-023) |

## Completion boundary for this audit

The three Markdown documents provide source inventory, current-source research with explicit unresolved applicability, legacy provenance and prioritized traceable tasks. They do not implement these tasks. No runtime API, schema, code or snapshot changes are authorized by this audit deliverable. Future implementation should first select a bounded task/platform subset, resolve its named prerequisites, then satisfy T0.
