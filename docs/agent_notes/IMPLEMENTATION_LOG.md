# Implementation Log

## 2026-09-10 — T-031 Junos and ScreenOS baseline expansion

Status: Verified complete.

Implemented:

- Added serialized security references to the neutral finding schema and rendered references and evidence in HTML reports.
- Added Junos effective logging and cryptographic normalization.
- Added Junos baseline controls for authentication order, login attempts and lockout, super-user authentication, weak credential storage, explicit SSH algorithm lists, legacy services, SNMP community/SNMPv3 security, remote syslog, matching NTP authentication keys, lo0 Routing Engine filters, and IPv4 redirects.
- Added a ScreenOS effective command stream with set/unset processing and redacted evidence.
- Corrected ScreenOS HTTPS normalization so interface SSL requires global SSL activation.
- Added ScreenOS baseline controls for EOL posture, manager source restrictions, session timeout, login attempts, SSHv2, HTTPS activation/ciphers, known default credentials and hashes, banners, effective remote logging, active interface-scoped SNMP, NTP, high-risk policy logging, and active referenced VPN proposals.
- Registered both baseline plugins in the public Juniper processing pipelines.
- Updated parser/analyzer/support documentation to distinguish target, correctness, and basic coverage.

Verification evidence:

```text
293 passed, 1 warning in 1.17s
```

The warning is the existing Windows pytest-cache permission warning and does not represent a test failure.

## 2026-09-10 — T-033 FortiGate/FortiOS baseline expansion

Status: Verified complete.

Implemented:

- Added central FortiOS evidence redaction for passwords, secrets, authentication/privacy credentials, pre-shared secrets, and key fields.
- Exposed stable public parser helpers for scoped sections and field evidence, and expanded normalized management cryptographic settings.
- Added administrator trusted-host, remote-group, centralized-authentication, and local privileged MFA checks.
- Added version-aware password-policy, lockout, administrative timeout, HTTPS certificate, strong-crypto, SSHv1/weak algorithm, and Diffie-Hellman checks.
- Added active-interface-aware SNMP community and SNMPv3 authPriv checks, including disabled-agent and global-to-VDOM behavior.
- Added NTP synchronization, custom-server, key-binding, and legacy-hash checks with redacted key evidence.
- Added WAN policy logging and active security-profile checks, plus explicit local/remote event-filter findings and secondary syslog/FortiAnalyzer destination handling.
- Added FortiGuard automatic-update, firmware-update ownership, WAN auxiliary-service, strictly scoped unused-interface, and DoS policy/anomaly/logging checks.
- Registered the baseline through the public FortiOS processing pipeline and documented 7.x default inference versus explicit-only handling for older or unversioned exports.

Verification evidence:

```text
305 passed, 1 warning in 1.28s
```

The warning is the existing Windows pytest-cache permission warning and does not represent a test failure.

`NEEDS_HUMAN_REVIEW`: the 12-character administrator password threshold is the project baseline. Fortinet documents the supported field and range but does not prescribe that exact threshold; replace it with the organization's approved benchmark value if different.

## 2026-09-10 — T-034 Check Point FW1 offline-policy baseline expansion

Status: Verified complete.

Implemented:

- Added typed Check Point layer, rule, network object, service object, and nested-group records while retaining the shared normalized policy view.
- Preserved per-layer order, enabled state, action, source/destination/service, negation, VPN, install-on, through, tracking, comments, and directly exported time/expiry context.
- Added compatibility for legacy anonymous object and rule names and prevented duplicate rule evaluation when both rules and rulebase metadata files are present.
- Added explicit cleanup-rule/action/logging and exported-gateway stealth-rule checks.
- Added disabled permissive, literal-date expired, partially broad, risky-service, negated accept, Any install-on, and sensitive untracked rule checks.
- Added conservative same-layer shadow and redundancy analysis with group expansion. Comparisons are skipped for negated/empty fields, unknown actions, differing time/VPN/through state, or incompatible install-on scope.
- Added unresolved rule references and nested network/service group-member checks only when a usable matching object export exists.
- Registered the baseline through the public Check Point pipeline and added secure/vulnerable multi-layer, disabled, unknown, legacy grammar, syntax-variant, and stable pipeline regression coverage.

Verification evidence:

```text
316 passed, 1 warning in 1.51s
```

The warning is the existing Windows pytest-cache permission warning and does not represent a test failure.

Offline limits: these exports cannot prove successful policy compilation/installation, runtime dynamic-object membership, hit counts, implied-rule state, or conflicts across different layers. Expiry findings require a directly exported literal date.

`NEEDS_HUMAN_REVIEW`: the small risky-service catalogue (clear-text administration, legacy file-sharing, and common remote-control ports) is a project policy baseline rather than a Check Point-mandated list; align it with the organization's approved service-risk catalogue.

## 2026-09-10 — Phase F cumulative target-platform validation

Status: Verified complete for the prioritized target set.

Implemented:

- Added `tests/test_data/regression/` with paired vulnerable and hardened configurations for Cisco IOS, Cisco IOS-XE, Cisco ASA, FortiOS, Junos, ScreenOS, and Check Point FW1.
- Added an exact manifest snapshot that preserves repeated rule IDs when distinct configuration objects carry different evidence.
- Added `scripts/run_full_regression.py`, which validates the authoritative registry, constructs every target parser through the public factory, requests the normalized model, executes the public platform pipeline, rejects duplicate rule/evidence identities, and compares exact rule IDs and finding counts.
- Added the permanent corpus to pytest so normal test runs cannot bypass it.
- Rebuilt the stale implementation inventory, added the original-versus-current device gap matrix, and wrote `FINAL_QUALITY_REPORT.md` with before/after depth and explicit deferred risks.

Verification evidence:

```text
PASS cisco-ios-vulnerable (IOS_ROUTER): 23 findings
PASS cisco-ios-secure (IOS_ROUTER): 0 findings
PASS cisco-iosxe-vulnerable (IOS_XE): 15 findings
PASS cisco-iosxe-secure (IOS_XE): 0 findings
PASS cisco-asa-vulnerable (ASA): 13 findings
PASS cisco-asa-secure (ASA): 0 findings
PASS fortios-vulnerable (FORTIOS): 20 findings
PASS fortios-secure (FORTIOS): 0 findings
PASS junos-vulnerable (JUNOS): 11 findings
PASS junos-secure (JUNOS): 0 findings
PASS screenos-vulnerable (SCREENOS): 16 findings
PASS screenos-hardened (SCREENOS): 1 findings
PASS checkpoint-fw1-vulnerable (CHECKPOINT_FW1): 13 findings
PASS checkpoint-fw1-secure (CHECKPOINT_FW1): 0 findings
Regression corpus passed: 14 configurations
317 passed, 1 warning in 1.37s
```

The single hardened ScreenOS finding is the expected platform end-of-life result. The warning is the existing Windows pytest-cache permission warning and does not represent a test failure.

Residual quality note: older focused target plugins have verified Level-2 detection behavior but do not yet serialize their source references on each finding. Their source material remains recorded in audit/task documentation; the final report tracks per-finding reference attachment as the first follow-up rather than overstating full standard compliance.

## 2026-09-10 — Pre-Wave-5 architecture and repository cleanup

Status: Verified complete, with hosted packaging verification flagged below.

Implemented:

- Removed obsolete ASA analyzer/processor wrappers, three superseded ASA plugins and their base class, legacy IOS parser/issue/plugin-base compatibility packages, an unused registry compatibility module, the misspelled SSH compatibility method, and an unused runtime dependency.
- Removed obsolete generated test outputs, a duplicate unused secure fixture, generated egg metadata, inherited TODO content, an unused issue template, and unconfigured/outdated third-party workflows and Sonar metadata.
- Replaced IOS dynamic plugin discovery with explicit ordered registration and object-aware deduplication.
- Corrected `--offline` to disable online advisory lookup.
- Rebuilt the root README and project status, architecture, extension, roadmap, contribution, and security documentation around the current codebase while preserving original-project attribution.
- Modernized the generated HTML report and removed its external jQuery runtime dependency.
- Added a PEP 517 build declaration, current repository metadata, current ownership metadata, a cross-platform full-regression workflow, and supported CodeQL configuration.

Verification evidence:

```text
319 passed, 1 warning in 1.39s
Regression corpus passed: 14 configurations
inventory_rows 29
missing_inventory_paths []
checked_markdown_files=10
missing_relative_links=0
```

The warning is the existing Windows pytest-cache permission warning. Removal searches found no live references to the deleted runtime modules.

`NEEDS_HUMAN_REVIEW`: the local interpreter lacks `setuptools`, so the clean-environment editable installation must be confirmed by the first hosted workflow run. The build dependency is declared in `pyproject.toml`.
