# Open improvement work

Reconciled on 2026-09-22. The prioritized, source-backed implementation backlog for all 16 device IDs is [High-risk security coverage tasks](agent_notes/SECURITY_COVERAGE_TASKS.md). It contains 44 tasks, including explicit evidence prerequisites, parser/detection contracts, interface constraints and acceptance tests. Completed RV task bodies were removed from [external-validation tasks](agent_notes/REALWORLD_VALIDATION_TASKS.md); RV-008 remains open. This index retains genuinely open work outside that focused review.

An item is not permission to turn absent or incomplete configuration evidence into a finding: first verify the vendor grammar, applicable release, authoritative control source, and representative sanitized fixtures. Follow [Extending pynipper-v2](EXTENDING.md) for implementation and validation requirements.

## Priority: practical-testing defects

- [x] PT-001 to PT-004 ([details](agent_notes/PRACTICAL_TESTING_TASKS.md)): MarkupSafe pin, FortiOS and cross-vendor multi-line value parsing, and evidence line numbers.
- [x] PT-005 to PT-007: report readability, layered explanations and related-control hints.
- [ ] **PT-010 (high priority)**: opt-in CVE lookup for the configured software version through the free NVD CVE/CPE APIs, with offline bundle replay. See the [analysis](agent_notes/PRACTICAL_TESTING_TASKS.md#pt-010). **First stage done 2026-09-25**; remaining: one live validation run against NVD, then F5 per-module, AOS-S naming, vendor-feed cross-checks and feature correlation.
- [ ] PT-008 (deferred): dependency modernisation.
- [ ] PT-009 (low priority): label findings as explicit insecure value vs. missing explicit hardening setting. **Progress 2026-09-25:** `FindingBasis` model, report note and JSON field done, declared for a representative rule set; remaining: declare the basis in the other plugins rule by rule.

## Priority: report secret visibility (maintainer priority)

- [ ] Complete opt-in report-secret visibility across supported families. The CLI now provides `--show-secrets` for parser-qualified credential lines on IOS/IOS-XE/ASA, FortiOS, Junos, ScreenOS, SonicOS 7, AOS-S, EOS, and F5 TMOS; default findings remain masked, unsupported families fail explicitly, and sensitive output requires a new path. SonicOS coverage is limited to explicit built-in/local administrator passwords. Extend parser-owned mappings to remaining families and additional secret types only with precise effective-state and redaction tests. Do not imply hashes can be reversed or hidden values recovered. **Progress 2026-09-24:** added PAN-OS (element-only excerpts), IOS/IOS-XE/ASA/EOS SNMP and NTP keys, IOS/IOS-XE/EOS routing keys, and fail-closed Windows ACL restriction (`icacls`). IOS TACACS+/IKE keys, ASA tunnel-group/AAA keys and Junos RADIUS/TACACS+/NTP/SNMP/IKE/routing keys were added the same day. AOS-S and ScreenOS non-administrator secrets were added on 2026-09-25. SonicOS non-administrator secrets (RADIUS/TACACS+/LDAP, SNMP communities, VPN shared secrets) were added on 2026-09-25 from the SonicOS/X 7 E-CLI reference. Check Point Gaia OS (password hashes, SNMP communities, SNMPv3 users) was added on 2026-09-25 with SC-023. Remaining: a real Windows run of the ACL path, and Check Point FW1 `objects.C` (see the maintainer decision below).

## Priority: cleartext protocols and credential protection (maintainer request, 2026-09-25)

Wave 4 of the [coverage backlog](agent_notes/SECURITY_COVERAGE_TASKS.md#wave-4--cleartext-protocols-credential-protection-and-attack-simplifying-settings). **Cisco (IOS, IOS-XE, ASA, PIX), FortiGate, Check Point and F5 first**, current and legacy releases. Every item is an evidence gate: read and cite the vendor source for syntax and defaults before implementing.

P1:

- [ ] [SC-025](agent_notes/SECURITY_COVERAGE_TASKS.md#sc-025) Cisco Smart Install (`vstack`) enabled. **Done 2026-09-26** (explicit `vstack`; older releases without the line stay unknown).
- [ ] [SC-031](agent_notes/SECURITY_COVERAGE_TASKS.md#sc-031) AAA without protection: TACACS+/RADIUS servers without keys, LDAP without TLS, RADIUS without Message-Authenticator (IOS, ASA, FortiOS, F5). **First stage done 2026-09-26** (IOS/ASA TACACS+ keys, ASA and FortiOS LDAP); RADIUS Message-Authenticator for IOS/ASA/F5 remains.
- [ ] [SC-034](agent_notes/SECURITY_COVERAGE_TASKS.md#sc-034) IKEv1 aggressive mode with pre-shared keys (IOS, ASA, FortiOS, F5; Check Point needs a sample). **First stage done 2026-09-26** for IOS, ASA, FortiOS and F5.
- [ ] [SC-035](agent_notes/SECURITY_COVERAGE_TASKS.md#sc-035) Recoverable stored secrets: IOS/ASA keys without `password encryption aes`, FortiOS `private-data-encryption` off, legacy FortiOS `AK1` hashes. **First stage done 2026-09-26** (IOS, ASA, FortiOS private-data-encryption); `AK1` hashes remain.
- [ ] [SC-039](agent_notes/SECURITY_COVERAGE_TASKS.md#sc-039) FortiGate SSL-VPN: old TLS, factory certificate, open source address, no login-attempt limit. **First stage done 2026-09-26** (explicit values on an active SSL-VPN).
- [x] [SC-041](agent_notes/SECURITY_COVERAGE_TASKS.md#sc-041) F5 self-IP port lockdown exposing SSH and the configuration utility on traffic VLANs. **Done 2026-09-26.**

P2:

- [ ] [SC-026](agent_notes/SECURITY_COVERAGE_TASKS.md#sc-026) More IOS legacy/cleartext services (`service pad`, `ip identd`, `mop`, rsh/rcp, `tftp-server`, `ip dns server`, `ip finger`) and IOS-XE insecure gNMI.
- [ ] [SC-027](agent_notes/SECURITY_COVERAGE_TASKS.md#sc-027) IOS HTTPS server TLS version and ciphers.
- [ ] [SC-028](agent_notes/SECURITY_COVERAGE_TASKS.md#sc-028) HSRP/VRRP/GLBP without authentication or with plain-text authentication (IOS first, then EOS/Junos).
- [ ] [SC-029](agent_notes/SECURITY_COVERAGE_TASKS.md#sc-029) VTP server/client without a password.
- [ ] [SC-030](agent_notes/SECURITY_COVERAGE_TASKS.md#sc-030) Root SSH login and bash shells (F5, Gaia), F5 remote-user default admin role, F5 password history.
- [ ] [SC-032](agent_notes/SECURITY_COVERAGE_TASKS.md#sc-032) Cleartext log transport where TLS is available (IOS-XE, ASA, FortiAnalyzer, F5).
- [ ] [SC-033](agent_notes/SECURITY_COVERAGE_TASKS.md#sc-033) Device serving NTP or answering control queries without restriction (IOS, FortiOS, F5; then EOS/Junos).
- [ ] [SC-036](agent_notes/SECURITY_COVERAGE_TASKS.md#sc-036) Credentials in URLs, `ip ftp password`, HTTP client passwords, F5 monitors with basic-auth headers.
- [ ] [SC-037](agent_notes/SECURITY_COVERAGE_TASKS.md#sc-037) SNMPv1/v2c trap and inform communities.
- [ ] [SC-038](agent_notes/SECURITY_COVERAGE_TASKS.md#sc-038) FortiGate HA heartbeat without authentication/encryption (Check Point ClusterXL research).
- [ ] [SC-040](agent_notes/SECURITY_COVERAGE_TASKS.md#sc-040) FortiGate maintainer account and USB auto-install.
- [ ] [SC-042](agent_notes/SECURITY_COVERAGE_TASKS.md#sc-042) F5 weak client-side TLS, unvalidated server-side TLS, unencrypted persistence cookies.
- [ ] [SC-043](agent_notes/SECURITY_COVERAGE_TASKS.md#sc-043) Shared risky-service catalogue for firewall policies (Check Point, ASA, FortiOS, F5 virtuals).
- [ ] [SC-044](agent_notes/SECURITY_COVERAGE_TASKS.md#sc-044) Release-gated insecure defaults for IOS 12.x, ASA 8.x, PIX, FortiOS 5.x/6.0, BIG-IP 11.x/12.x and FW1 R6x/R7x.
- [ ] Gaia OS items (allowed clients, web UI TLS, SSH ciphers, AAA, NTP, syslog) live in [SC-023](agent_notes/SECURITY_COVERAGE_TASKS.md#sc-023); F5 APM in [SC-024](agent_notes/SECURITY_COVERAGE_TASKS.md#sc-024).

## Detection and parser coverage

- [ ] Continue open work across [SC-001 through SC-044](agent_notes/SECURITY_COVERAGE_TASKS.md#current-coverage-and-explicit-per-device-work) in the documented risk/evidence waves; SC-001, SC-002, SC-009 and SC-012 have bounded explicit-state coverage, SC-007 is implemented and SC-011 is partly implemented. This replaces the former broad F5, routing, access-edge, ScreenOS and certificate-expansion bullets; do not maintain duplicate implementations here.

## Inputs and assessment scope

- [x] Improve `-d` usability: present one recommended name per configuration family, preserve existing IDs as compatibility aliases, and allow conservative automatic identification of recognizable exports. Ambiguous or unsupported inputs request an explicit family rather than silently choosing a parser; device role stays separate from configuration format. CLI, fixture, help-text, and report-device-type tests cover the behavior.

## Maintainer decisions (2026-09-25)

- SC-011: do **not** grade FortiOS log-administrator rights against an organization role list. Keep only the existing bound write-capable role checks.
- SC-022: an end-of-support warning is wanted **only** if a freely accessible, externally maintained version/lifecycle source can be used through an API, so the project does not maintain its own list. **Done 2026-09-25 with endoflife.date** (free API, community maintained, schema 1.2.1). It covers FortiOS, PAN-OS, Cisco IOS XE and F5 BIG-IP. Junos, ASA, EOS, SonicOS, AOS-S and classic IOS are not covered by that dataset and are reported as "not covered". Vendor feeds for those remain a possible later stage.
- Not scheduled: SNMPv1/v2c community checks for PAN-OS and SonicOS, and SonicOS Telnet management.
- PT-009: add a fourth basis, "required setting not configured", for absence rules such as a missing NTP server or remote syslog destination.
- Check Point `--show-secrets` (checked 2026-09-25): locally managed users and their passwords live in the separate user database `fwauth.NDB`, not in `objects.C`/`rules.C` ([CheckMates](https://community.checkpoint.com/t5/Management/Working-with-Checkpoint-files/td-p/33712)). Whether `objects.C` carries RADIUS/TACACS+ or VPN shared secrets (possibly encrypted) could not be confirmed without a sample. The FW1 family therefore stays *unsupported* (explicitly rejected), not "not applicable"; revisit with a sanitized `objects.C` (nice to have, below). Gaia OS exports are supported since 2026-09-25 (SC-023).

## Nice to have (distant future, needs sample exports the maintainer does not have)

Kept open on purpose; do not close or delete. Each needs a real sanitized export before implementation.

- [ ] SC-017 Check Point anti-spoofing and implied rules (matched `objects.C` + `rules.C` needed).
- [ ] SC-024 F5 module-specific protection (SCF from a unit with AFM, APM or ASM provisioned). **First stage done 2026-09-25 from F5 documentation:** AFM default-accept, and inactive or transparent ASM policies bound to an enabled virtual server. Remaining: validate against a real export; APM access-policy bypass.
- [ ] SC-018 remainder: zone defaults, protocol direction and exclusion lists (a real `show current-config` export). The explicit zone stage is done.
- [ ] SC-019 ScreenOS screens and authenticated time, and RV-008 VPN anti-replay (ScreenOS 6.3 export).
- [ ] SC-020 Cisco PIX qualification (PIX 6.x export).
- [ ] SC-023 Check Point Gaia OS posture input (Gaia `show configuration` export). **First stage done 2026-09-25 from the R81 Gaia Administration Guide:** new `checkpoint-gaia` family with Telnet, SNMP, password-policy, idle-timeout and banner checks and `--show-secrets`. Remaining: validate against a real export; remote AAA, NTP, syslog and web-UI settings.
- [ ] Check Point FW1 `--show-secrets`: qualify secret fields in a sanitized `objects.C` (Gaia OS is already supported).

## Low priority (maintainer decision, 2026-09-24)

These items stay recorded but are scheduled after the SC backlog work that can be done without new vendor evidence and after `--show-secrets` completion.

- [ ] Extend bounded policy-effectiveness analysis to Junos stateless firewall filters where attachment, term order, address/service semantics, and unsupported predicates can be proven. Expand other native adapters only when equivalent evidence and adversarial tests are available; never infer runtime-unused rules from configuration alone.
- [ ] Qualify additional discovery and IPv6 access-edge protections only where explicit roles and fixtures demonstrate value beyond the prioritized SC tasks. No blanket discovery disablement or platform defaults inferred from names.
- [ ] PIX qualification is owned by [SC-020](agent_notes/SECURITY_COVERAGE_TASKS.md#sc-020); optional Check Point OS posture is owned by [SC-023](agent_notes/SECURITY_COVERAGE_TASKS.md#sc-023). Other new/legacy dialects (FWSM, old SonicOS preferences, CatOS/NMP, CSS, Passport/Accelar, F5OS/UCS) require demonstrated demand, representative exports and maintenance justification before becoming implementation tasks.
- [ ] Add anonymized fixtures for newly encountered, supported configuration syntax and review maturity claims in [Supported devices](SUPPORTED_DEVICES.md) as evidence improves.
- [ ] Design a user-requested cracking-tool hash export for individually validated formats, if its handling and maintenance are approved. Keep normal findings, logs, and reports secret-free; require explicit destination, overwrite, permissions, and format rules, and never launch a cracking tool automatically.
