# Detection Logic Audit Remediation Tasks

This backlog remediates the findings in `DETECTION_AUDIT_FINDINGS.md`. It is prioritized for the configuration mix most often encountered by the project: Cisco (IOS, IOS-XE, and ASA), Fortinet FortiGate/FortiOS, Check Point FW1, and Juniper (Junos and ScreenOS). Other implemented vendors remain tracked but are deferred. A task is complete only when its implementation and the stated regression tests are both merged. Examples in tests must use valid vendor configuration syntax; invented test-only commands are not acceptable.

## Current execution order

1. **Wave 0 — shared blockers:** T-001, T-002, T-003. Establish device reachability, a trustworthy finding schema, normalized evidence, and explicit unknown state.
2. **Wave 1 — target parser and pipeline correctness:** T-004, T-005, T-006, T-008, T-009. Repair ASA duplicate execution and the FortiOS, Check Point, Junos, and ScreenOS representations before adding rules.
3. **Wave 2 — Cisco correctness:** T-012, T-013, T-014, T-015, T-016, T-025, T-026. Make existing IOS, ASA, and IOS-XE detections dependable.
4. **Wave 3 — FortiGate, Check Point, and Juniper correctness:** T-017, T-018, T-020, T-021, T-023. Rebuild existing rules on effective state and typed policies.
5. **Wave 4 — target-platform coverage:** T-028, T-029, T-031, T-033, T-034. Add the missing high-value baseline controls only after correctness work for that platform is complete.
6. **Deferred — secondary vendors:** T-007, T-010, T-011, T-019, T-022, T-024, T-027, T-030, T-032. Reassess these when the target-platform baseline is stable or the observed device mix changes.

Within a wave, independent device tasks may run in parallel. A later wave may start for one vendor once that vendor's explicit dependencies are complete; it does not need to wait for unrelated devices in the preceding wave.

**Cumulative validation status (2026-09-10):** Waves 0-4 for the prioritized target vendors are complete and covered by the permanent paired corpus in `tests/test_data/regression/`. The reusable gate is `scripts/run_full_regression.py`; its latest run passed 14/14 corpus cases and 317/317 tests. The secondary-vendor tasks listed as deferred above remain open.

## Foundation and parser tasks

## Task T-001: Make one device registry authoritative

- **Status:** Complete (2026-09-09)
- **Priority:** Critical
- **Effort:** Medium
- **Fixes findings:** ARCH-01
- **Approach:** Replace the disconnected CLI enum, parser-factory branches, and analyzer-dispatch branches with one registry record per supported device. Each record should own canonical ID, aliases, parser constructor, analyzer entry point, and display name. Generate CLI choices from that registry and fail explicitly when a registered device lacks an implementation.
- **Depends on:** None
- **Test needed:** Parameterize over every registry entry and prove that its canonical ID and aliases pass CLI validation, construct the expected parser, and reach the expected analyzer. Add a negative test for an unknown device ID and a uniqueness test for aliases.

## Task T-002: Introduce a vendor-neutral, validated finding schema

- **Status:** Complete (2026-09-09)
- **Priority:** Critical
- **Effort:** Medium
- **Fixes findings:** ARCH-02, ARCH-03
- **Approach:** Replace positional `CiscoIOSIssue` construction with a neutral finding type using keyword-only fields. Add stable rule ID, device/vendor, title, observation, impact, recommendation, severity, exploitability/ease, and evidence. Validate severity against an enum and keep exploitability as prose or a separately typed value. Migrate serializers without silently relabeling old data.
- **Depends on:** None
- **Test needed:** Schema tests must reject swapped/invalid fields, serialize severity and exploitability separately, preserve evidence, and prove that findings from every device use the neutral type. Add a compatibility test for any intentionally supported legacy report reader.

## Task T-003: Define normalized parser contracts with explicit unknown state

- **Status:** Complete (2026-09-09)
- **Priority:** Critical
- **Effort:** Large
- **Fixes findings:** ARCH-04, ARCH-05
- **Approach:** Add typed normalized records for management services, users, interfaces/zones, policies, logging destinations, cryptographic settings, software version, and source evidence. Model configured, effective, disabled, and unknown separately. Keep vendor-native trees behind clearly vendor-specific accessors instead of the common base contract. Document which normalization fields every supported parser must populate.
- **Depends on:** None
- **Test needed:** Contract tests for every parser must validate record types, required evidence, explicit unknowns, and consistent meanings for service state. Tests must prove that no parser substitutes `False`, an empty collection, or `?` for unknown information.

## Task T-004: Make ASA analysis single-path and deduplicated

- **Status:** Complete (2026-09-09)
- **Priority:** Critical
- **Effort:** Small
- **Fixes findings:** ARCH-06
- **Approach:** Choose one ASA processor, remove the inactive/overlapping path, and register each rule exactly once. Give every rule a stable ID and add a final duplicate guard keyed by rule ID plus configuration object/evidence, without using that guard to hide genuinely distinct objects.
- **Depends on:** T-002
- **Test needed:** Run a fixture containing logging, Telnet, SSH, and SNMP defects through the public analyzer and assert exactly one finding per rule/object. Retain a case with two distinct insecure objects to prove both survive.

## Task T-005: Replace the FortiOS ad-hoc tree builder with a grammar-aware parser

- **Status:** Complete (2026-09-09)
- **Priority:** Critical
- **Effort:** Large
- **Fixes findings:** FORTI-01, FORTI-07, FORTI-08, FORTI-09
- **Approach:** Tokenize quoted and escaped values, validate `config`/`edit`/`next`/`end` nesting, retain object order and line evidence, and model global versus VDOM scope. Preserve typed scalar/list values rather than raw quoted strings. Parse administrators, firmware/model metadata, interfaces, policies, and logging sections; surface malformed input as a structured parse error.
- **Depends on:** T-003
- **Test needed:** Use real FortiOS snippets with quoted `all`, multiple VDOMs, global scope, nested objects, escaped text, and malformed nesting. Assert typed values, correct scope, line evidence, explicit parse errors, users, and version extraction.

## Task T-006: Build a typed Check Point FW1 S-expression parser

- **Status:** Complete (2026-09-09)
- **Priority:** Critical
- **Effort:** Large
- **Fixes findings:** CP-01, CP-02
- **Approach:** Parse the supported Check Point export into typed objects, rules, services, and named fields while preserving order, references, disabled state, action, tracking, source, destination, install-on scope, and source evidence. Enforce balanced delimiters and required field structure with useful parse diagnostics. Reuse the bundled original parser semantics as a migration reference.
- **Depends on:** T-003
- **Test needed:** Golden tests from representative Check Point exports must cover nested objects, ordered rules, named references, disabled rules, comments containing keywords, empty collections, and malformed/unbalanced input. Round-trip semantic snapshots should show field names and rule boundaries are retained.

## Task T-007: Support an explicitly identified SonicOS export format

- **Priority:** Low
- **Effort:** Large
- **Fixes findings:** SW-01, SW-05
- **Approach:** Select and document the supported SonicOS source format/version. Parse its real preference/export keys or documented CLI structure into typed administrators, access rules, zones/interfaces, management access, VPN proposals, logging, and firmware metadata. Detect incompatible input early instead of producing an empty but apparently successful analysis.
- **Depends on:** T-003
- **Test needed:** Add sanitized real-format fixtures for the supported format, an original-Nipper-compatible export, and an incompatible dialect. Assert format identification, populated users/version/policies/services, preserved evidence, and an explicit unsupported-format error.

## Task T-008: Parse both Junos hierarchy and `display set` semantics

- **Status:** Complete (2026-09-10)
- **Priority:** Critical
- **Effort:** Large
- **Fixes findings:** JUN-01, JUN-05
- **Approach:** Add a hierarchy-aware Junos parser or normalize both brace syntax and `display set` output into the same typed model. Preserve statement hierarchy, groups/application where supported, `inactive:` and `delete` semantics, term order, user classes/authentication, and software/model metadata.
- **Depends on:** T-003
- **Test needed:** Feed equivalent hierarchical and set-format configurations and assert identical normalized services, users, filters, and system state. Include inactive statements, delete lines, multi-line terms, groups or an explicit unsupported diagnostic, and version extraction.

## Task T-009: Model ScreenOS objects and policy continuations

- **Status:** Complete (2026-09-10)
- **Priority:** Critical
- **Effort:** Large
- **Fixes findings:** SCREEN-04, SCREEN-05
- **Approach:** Parse ScreenOS commands into typed interfaces/zones, management methods, manager-IP restrictions, users, version, address/service objects, and ordered policy records. Correlate `set policy id`, continuation commands, disable commands, and remove/unset operations before exposing effective state.
- **Depends on:** T-003
- **Test needed:** Real ScreenOS fixtures must cover interface management, manager-IP restrictions, multi-line policy creation, policy disable/remove operations, object references, users, and version. Assert that later mutations change the effective policy rather than creating unrelated lines.

## Task T-010: Normalize PAN-OS configuration scope and references

- **Priority:** Low
- **Effort:** Large
- **Fixes findings:** PAN-01, PAN-06
- **Approach:** Replace isolated XPath assumptions with a normalized PAN-OS model that handles device/vsys/template scope as supported, interface management-profile references, rulebases, log-forwarding profile references, password profiles/settings, administrators, and software metadata. Distinguish definitions from attachments and effective usage.
- **Depends on:** T-003
- **Test needed:** XML fixtures must include multiple vsys, defined-but-unused profiles, attached profiles, rule references, namespace/scope variations, administrators, and version metadata. Assert correct reference resolution and explicit unknowns for unsupported Panorama inheritance.

## Task T-011: Correct the ArubaOS-Switch/ProCurve parser baseline

- **Priority:** Low
- **Effort:** Medium
- **Fixes findings:** HP-01, HP-05, HP-06
- **Approach:** Parse positive and negated WebAgent, SSH, Telnet, SNMP, user, and version/model syntax using command boundaries rather than substrings. Encode documented platform/version defaults only when the version is known; otherwise return unknown. Preserve effective state after later `no` commands.
- **Depends on:** T-003
- **Test needed:** Valid ArubaOS-Switch fixtures must cover service defaults, explicit enable/disable ordering, `no ip ssh`, WebAgent HTTP/HTTPS variants, local users, and version/model banners. Assert negated commands never match positive state and unknown versions do not inherit a fabricated default.

## Detection correctness tasks

## Task T-012: Rebuild Cisco IOS HTTP detection as an effective-state rule

- **Status:** Complete (2026-09-09)
- **Priority:** High
- **Effort:** Medium
- **Fixes findings:** IOS-01, IOS-02, IOS-03, IOS-04, IOS-05
- **Approach:** Parse exact positive/negative HTTP and HTTPS commands in configuration order, distinguish absent/default/disabled state by platform version, and evaluate authentication and access-class only for an enabled server. Support named and numbered ACL references without numeric coercion, and capture the full authentication method.
- **Depends on:** T-003
- **Test needed:** Table-driven tests must cover absent state, `no ip http server`, later overrides, HTTPS-only, named and numbered ACLs, every supported authentication form, and disabled servers with stray auth/ACL lines. Include malformed values and assert no crash.

## Task T-013: Rebuild Cisco IOS SSH detection and numeric handling

- **Status:** Complete (2026-09-09)
- **Priority:** High
- **Effort:** Medium
- **Fixes findings:** IOS-06, IOS-07, IOS-08, IOS-09, IOS-10, IOS-11, IOS-12, IOS-13
- **Approach:** Derive global SSH server state from the actual enabling prerequisites and version mode, separate disabled/unconfigured/SSHv1/compatibility states, and apply documented retry/timeout defaults when the platform supports them. Parse numeric values defensively, use one documented timeout threshold, and replace the outbound `ip ssh source-interface` claim with checks for VTY transport and access-class controls.
- **Depends on:** T-003
- **Test needed:** Cover unconfigured, disabled, SSHv1, SSHv2, compatibility, omitted defaults, boundary values, invalid numeric tokens, VTY Telnet/SSH combinations, IPv4/IPv6 access classes, and outbound source-interface configuration. Assert each condition maps to the correct rule and malformed input never crashes.

## Task T-014: Stop fabricating Cisco IOS versions

- **Status:** Complete (2026-09-09)
- **Priority:** High
- **Effort:** Small
- **Fixes findings:** IOS-14
- **Approach:** Preserve the version exactly as parsed, including train/build qualifiers where available. If advisory lookup requires a normalized form, use a documented mapping with confidence/status and never append a guessed release component. Skip or mark advisory correlation unknown when the version is insufficient.
- **Depends on:** T-003
- **Test needed:** Test common IOS version banner forms, qualifiers, missing versions, and malformed banners. Assert no invented `(1)` value appears and advisory lookup is suppressed or explicitly uncertain when normalization is not lossless.

## Task T-015: Rebuild ASA management, logging, TLS, and ACL rules

- **Status:** Complete (2026-09-09)
- **Priority:** High
- **Effort:** Large
- **Fixes findings:** ASA-01, ASA-05, ASA-06, ASA-07, ASA-08
- **Approach:** Parse management grants separately from timeout settings; model IPv4/IPv6 source networks, interface trust scope, and effective SSH/Telnet exposure. Determine logging from active destinations and severity, parse documented ASA SSL/TLS commands, and evaluate typed active ACL entries rather than raw text. Emit evidence for the exact grant, destination, protocol setting, or ACE.
- **Depends on:** T-003, T-004
- **Test needed:** ASA fixtures must cover timeout-only configurations, broad and narrow IPv4/IPv6 grants, inside/outside interfaces, logging enabled without a destination, valid syslog destinations, real `ssl` syntax, remarks/inactive text, object-groups, and broad versus restricted ACEs.

## Task T-016: Replace ASA password and SNMP string heuristics

- **Status:** Complete (2026-09-09)
- **Priority:** High
- **Effort:** Medium
- **Fixes findings:** ASA-02, ASA-03, ASA-04
- **Approach:** Identify credential storage type and documented weak/default states without pretending four literals are a general strength audit. Parse SNMP server/host/community/user configuration structurally, distinguish versions and access modes, and use exact normalized default-community comparisons rather than substring matching. Do not print secrets in evidence.
- **Depends on:** T-002, T-003, T-004
- **Test needed:** Cover encrypted/hash/plain/default credentials, empty values, strong values containing `public` as a substring, exact default communities with case policy, RO/RW, SNMPv3 auth/privacy, and redaction. Assert no duplicate findings through the public pipeline.

## Task T-017: Rebuild FortiOS management exposure detection

- **Status:** Complete (2026-09-10)
- **Priority:** High
- **Effort:** Medium
- **Fixes findings:** FORTI-02, FORTI-03
- **Approach:** Read `allowaccess` from each interface in its VDOM, join it to interface role/address/zone and administrator trusted-host restrictions, and independently flag enabled insecure protocols. Report exposure scope instead of treating a protocol anywhere as globally exposed.
- **Depends on:** T-005
- **Test needed:** Cover HTTP/Telnet on WAN, LAN-only management, SSH/HTTPS, multiple VDOMs, trusted hosts, no trusted hosts, administrative interfaces, and explicit disablement. Assert findings identify the specific interface and effective permitted sources.

## Task T-018: Correct FortiOS policy, TLS, and logging semantics

- **Status:** Complete (2026-09-10)
- **Priority:** High
- **Effort:** Large
- **Fixes findings:** FORTI-04, FORTI-05, FORTI-06
- **Approach:** Evaluate enabled firewall policies using source/destination interfaces, addresses, services, action, schedule, NAT, status, and logging. Treat interface `any` separately from address/service wildcards. Normalize documented admin TLS version settings and determine logging from enabled targets with reachable configuration, not section existence alone.
- **Depends on:** T-005
- **Test needed:** Include disabled rules, interface-only wildcards, true any-any-any accepts, deny rules, address groups, quoted values, documented TLS spellings, syslog enabled/disabled states, FortiAnalyzer/FortiManager targets, and per-VDOM overrides.

## Task T-019: Make PAN-OS checks attachment- and scope-aware

- **Priority:** Low
- **Effort:** Large
- **Fixes findings:** PAN-02, PAN-03, PAN-04, PAN-05
- **Approach:** Evaluate management protocols only on profiles attached to interfaces and include permitted-IP/interface scope. For security rules, honor disabled state, action, zones, applications, users, services, and ordering. Require an attached log-forwarding profile or equivalent rule logging behavior. Evaluate the effective password complexity enabled state and thresholds.
- **Depends on:** T-010
- **Test needed:** Cover unused versus attached management profiles, permitted IPs, disabled/deny/restricted/broad rules, application-default, attached and orphaned log profiles, log-at-session settings, absent/disabled/enabled complexity, and multi-vsys separation.

## Task T-020: Assemble Junos effective services, filters, and root-login state

- **Status:** Complete (2026-09-10)
- **Priority:** High
- **Effort:** Medium
- **Fixes findings:** JUN-02, JUN-03, JUN-04
- **Approach:** Consume the typed Junos hierarchy, exclude inactive/delete statements, distinguish HTTP from HTTPS, assemble match/action clauses by firewall-filter term, and evaluate SSH root-login using the final effective statement. Preserve family, interface attachment, and term order when judging filter scope.
- **Depends on:** T-008
- **Test needed:** Equivalent brace/set tests must cover inactive/delete service statements, HTTPS-only, multi-line broad and restricted terms, accept versus discard, unattached filters, term ordering, and every supported root-login value.

## Task T-021: Rebuild ScreenOS management and policy checks on typed state

- **Status:** Complete (2026-09-10)
- **Priority:** High
- **Effort:** Medium
- **Fixes findings:** SCREEN-01, SCREEN-02, SCREEN-03
- **Approach:** Detect Telnet/web/SSH on the actual interface management commands, join interfaces to zones and manager-IP restrictions, and report only effective exposure. Evaluate enabled accept policies with independent source, destination, service, zone, and action fields; require all relevant wildcard dimensions for an any-any-service finding.
- **Depends on:** T-009
- **Test needed:** Cover per-interface management, trusted/untrusted zones, manager-IP restrictions, disabled management, policy continuations, disabled policies, source-only/destination-only wildcards, broad accept rules, and deny rules.

## Task T-022: Parse and evaluate ArubaOS-Switch SNMP and SSH crypto

- **Priority:** Low
- **Effort:** Medium
- **Fixes findings:** HP-02, HP-03, HP-04
- **Approach:** Model SNMP communities/users, access level, version, ACL restriction, and SNMPv3 auth/privacy. Parse documented SSH cipher/KEX/MAC commands for the detected firmware family and evaluate effective algorithms only while SSH is enabled. Replace substring/default-word checks with structured comparisons to a versioned policy.
- **Depends on:** T-011
- **Test needed:** Cover strong community names containing `public`, exact defaults, RO/RW, SNMPv3 auth/privacy, restricted managers, valid/weak KEX and cipher suites, negations, SSH disabled, and unknown firmware behavior.

## Task T-023: Evaluate Check Point rules within rule boundaries

- **Status:** Complete (2026-09-10)
- **Priority:** High
- **Effort:** Medium
- **Fixes findings:** CP-03, CP-04
- **Approach:** Distinguish object definitions from built-in wildcard references and inspect one typed rule at a time. Resolve source, destination, service, action, disabled state, install-on scope, and tracking before classifying broad access. Attach findings to rule UID/name/order and avoid treating keywords in comments as semantics.
- **Depends on:** T-006
- **Test needed:** Cover legitimate object names containing `any`, comments containing `accept`, keywords split across different rules, disabled rules, broad accept and deny rules, service restrictions, install-on targets, tracking, and unresolved references.

## Task T-024: Rebuild SonicOS credential, management, and VPN checks

- **Priority:** Low
- **Effort:** Large
- **Fixes findings:** SW-02, SW-03, SW-04
- **Approach:** Detect documented default/unchanged administrator conditions without flagging every configured password. Resolve management access through interface/zone settings and source restrictions. Parse active VPN policies/proposals structurally, normalize algorithms case-insensitively, and compare complete suites to a versioned policy.
- **Depends on:** T-007
- **Test needed:** Use supported-format fixtures for changed/default administrators, WAN/LAN management, source restrictions, HTTP/HTTPS coexistence, active/inactive VPN policies, DES/3DES/MD5 and modern suites, mixed case, and proposals not referenced by an active policy.

## Task T-025: Make IOS-XE MACsec and crypto checks scope-aware

- **Status:** Complete (2026-09-09)
- **Priority:** High
- **Effort:** Large
- **Fixes findings:** XE-01, XE-02, XE-03
- **Approach:** Define which interface roles are in scope for MACsec, exclude shutdown/non-L2/loopback/tunnel interfaces, and resolve MKA policy, key chain, MACsec activation, cipher, and attachment validity. Extend crypto evaluation across active IKEv1/IKEv2/IPsec families and compare complete algorithms/DH/PRF suites to a versioned policy.
- **Depends on:** T-003
- **Test needed:** Cover loopbacks, shutdown ports, routed and L2 links, dangling MKA references, valid MACsec chains, alternative protected roles, IKEv1/IKEv2 proposals, transform sets, weak DH/hash/encryption combinations, inactive definitions, and modern suites.

## Task T-026: Compose IOS-XE from an IOS-family baseline

- **Status:** Complete (2026-09-09)
- **Priority:** High
- **Effort:** Small
- **Fixes findings:** XE-04
- **Approach:** Introduce explicit plugin composition so IOS-XE runs the applicable IOS-family baseline exactly once plus IOS-XE-only rules. Define opt-outs for commands whose semantics differ and keep stable rule IDs across the family.
- **Depends on:** T-004, T-012, T-013, T-014, T-025
- **Test needed:** A public IOS-XE analysis must detect HTTP, SSH, VTY, and IOS-XE-specific crypto/MACsec conditions with no duplicates. Add an IOS comparison fixture to prove shared baseline rules behave consistently.

## Task T-027: Correct Arista eAPI state and protocol scoping

- **Priority:** Low
- **Effort:** Medium
- **Fixes findings:** AR-01, AR-02
- **Approach:** Parse children of each `management api http-commands` block, determine activation, VRF/listen scope, ACLs, and HTTP versus HTTPS independently. Do not let unrelated `protocol https` text satisfy the rule, and do not report an inactive definition as exposed.
- **Depends on:** T-003
- **Test needed:** Cover absent, shutdown, and active eAPI blocks; HTTP-only, HTTPS-only, and simultaneous protocols; unrelated HTTPS commands; management VRFs; and ACL/source restrictions. Assert exact block evidence.

## Coverage expansion tasks

## Task T-028: Restore a meaningful Cisco IOS security baseline

- **Status:** Complete (2026-09-10)
- **Priority:** High
- **Effort:** Extra large
- **Fixes findings:** IOS-15
- **Approach:** Port and modernize the missing original-Nipper IOS controls in small rule packs: AAA/accounting, VTY/console, users/secrets, SNMP, logging, NTP, banners, unnecessary services, interface/source routing controls, control-plane protection, and cryptographic policy. Use current Cisco guidance, stable rule IDs, applicability metadata, and typed parser evidence; do not infer safety from mere command absence when defaults vary by release.
- **Depends on:** T-002, T-003, T-012, T-013, T-014
- **Test needed:** Build a versioned IOS corpus with one positive and one negative case per control, default-state cases, negation/override cases, and an end-to-end expected rule-ID snapshot. Include migrated original-Nipper fixtures only after validating their syntax.

## Task T-029: Restore a meaningful Cisco ASA security baseline

- **Status:** Complete (2026-09-10)
- **Priority:** High
- **Effort:** Extra large
- **Fixes findings:** ASA-09
- **Approach:** Add version/applicability-aware checks for AAA/accounting, local users/secrets, console/ASDM/HTTP management, SNMPv3, NTP, certificates, VPN/IPsec crypto, threat detection, interface/routing exposure, failover, and additional original-Nipper controls. Reuse the single ASA pipeline and neutral finding schema.
- **Depends on:** T-002, T-003, T-004, T-015, T-016
- **Test needed:** Maintain a sanitized ASA corpus spanning supported releases and routed/firewall management scenarios. Require positive, negative, disabled, and not-applicable cases per rule plus an end-to-end no-duplicates assertion.

## Task T-030: Expand the PAN-OS firewall baseline

- **Priority:** Low
- **Effort:** Extra large
- **Fixes findings:** PAN-07
- **Approach:** Add PAN-OS rule packs over the normalized model for administrator authentication/MFA, password policy, management certificates/TLS/source restrictions, SNMPv3, NTP, remote logging, firmware posture, unused/insecure services, policy logging/profiles, and platform-specific security controls. Keep applicability, configuration scope, inheritance limits, and defaults explicit.
- **Depends on:** T-010, T-019
- **Test needed:** For each supported PAN-OS configuration scope, add positive/negative/not-applicable fixtures for every new rule. Include vsys isolation, inherited/unknown-state cases, reference resolution, and stable end-to-end rule-ID snapshots.

## Task T-031: Expand Junos and ScreenOS baselines

- **Status:** Complete (2026-09-10)
- **Priority:** High
- **Effort:** Extra large
- **Fixes findings:** JUN-06, SCREEN-06
- **Approach:** For Junos, implement current hardening controls for authentication, SSH algorithms, services, SNMP, logging, NTP, routing-engine/control-plane filters, and interface protections. For ScreenOS, restore the original administration, policy, service, logging, SNMP, NTP, user, and VPN analyses that remain applicable. Share concepts only where normalized semantics truly match.
- **Depends on:** T-008, T-009, T-020, T-021
- **Test needed:** Add vendor-native hierarchical/set Junos pairs and real ScreenOS command streams. Each rule needs positive, negative, inactive/disabled, override-order, and unknown/not-applicable cases with source evidence.

## Task T-032: Expand HP, Arista, and SonicOS baselines

- **Priority:** Low
- **Effort:** Extra large
- **Fixes findings:** HP-07, AR-03, SW-06
- **Approach:** Build independent secondary-platform backlogs on the corrected models: ArubaOS-Switch/ProCurve AAA, management, logging/NTP and service/interface controls; Arista AAA/roles, SSH, SNMP, APIs, management VRFs, logging/NTP and control plane; and SonicOS access rules, management, SNMPv3, syslog/NTP, certificates, security services and firmware. Mark unsupported versions/formats explicitly.
- **Depends on:** T-007, T-011, T-022, T-024, T-027
- **Test needed:** Create a sanitized real-configuration corpus for each platform with rule-level positive/negative/disabled/not-applicable cases, version or format identification, reference resolution, secret redaction, and public-pipeline snapshots showing stable IDs and no duplicate findings.

## Task T-033: Expand the FortiGate/FortiOS security baseline

- **Status:** Complete (2026-09-10)
- **Priority:** High
- **Effort:** Extra large
- **Fixes findings:** FORTI-10
- **Approach:** Add FortiOS rule packs over the corrected VDOM-aware model for administrator trusted hosts, authentication sources and MFA, password and lockout policy, administrative timeout, management certificates/TLS/SSH, SNMPv3, NTP, FortiAnalyzer/FortiCloud/syslog, FortiGuard and firmware posture, unused interfaces/services, policy logging and security profiles, local/remote log filters, and DoS policies. Define applicability by FortiOS version and VDOM/global scope.
- **Depends on:** T-005, T-017, T-018
- **Test needed:** Add sanitized real FortiGate configurations spanning supported releases, global and multi-VDOM modes. Every rule needs positive, negative, disabled, inherited/unknown, and not-applicable cases plus stable end-to-end rule-ID snapshots.

## Task T-034: Expand the Check Point FW1 security-policy baseline

- **Status:** Complete (2026-09-10)
- **Priority:** High
- **Effort:** Extra large
- **Fixes findings:** CP-05
- **Approach:** Restore typed ordered policy, object, group, and service analysis from the original implementation where still applicable, then add current checks for cleanup rules, disabled/expired/shadowed rules where determinable, overly broad access, risky services, source/destination negation, install-on scope, tracking/logging, policy-layer behavior, and unresolved objects. Clearly delimit what offline exports cannot prove.
- **Depends on:** T-006, T-023
- **Test needed:** Build golden sanitized exports containing multiple policy layers, inline/nested groups, disabled rules, broad and restricted access, cleanup rules, tracking states, install-on targets, unresolved references, and keyword-bearing comments. Assert ordered evaluation, rule-bound evidence, and stable rule IDs.

## Traceability check

- **Architecture:** ARCH-01 through ARCH-06 are covered by T-001 through T-004.
- **Cisco IOS:** IOS-01 through IOS-15 are covered by T-012 through T-014 and T-028.
- **Cisco ASA:** ASA-01 through ASA-09 are covered by T-015, T-016, and T-029; duplicate execution is handled by T-004.
- **FortiOS:** FORTI-01 through FORTI-10 are covered by T-005, T-017, T-018, and T-033.
- **PAN-OS:** PAN-01 through PAN-07 are covered by T-010, T-019, and T-030.
- **JunOS:** JUN-01 through JUN-06 are covered by T-008, T-020, and T-031.
- **ScreenOS:** SCREEN-01 through SCREEN-06 are covered by T-009, T-021, and T-031.
- **HP ProCurve:** HP-01 through HP-07 are covered by T-011, T-022, and T-032.
- **Check Point:** CP-01 through CP-05 are covered by T-006, T-023, and T-034.
- **SonicOS:** SW-01 through SW-06 are covered by T-007, T-024, and T-032.
- **IOS-XE:** XE-01 through XE-04 are covered by T-025 and T-026.
- **Arista EOS:** AR-01 through AR-03 are covered by T-027 and T-032.
