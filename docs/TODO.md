# Open improvement work

Reconciled on 2026-09-22. The prioritized, source-backed implementation backlog for all 15 device IDs is [High-risk security coverage tasks](agent_notes/SECURITY_COVERAGE_TASKS.md). It contains 24 tasks, including explicit evidence prerequisites, parser/detection contracts, interface constraints and acceptance tests. Completed RV task bodies were removed from [external-validation tasks](agent_notes/REALWORLD_VALIDATION_TASKS.md); RV-008 remains open. This index retains genuinely open work outside that focused review.

An item is not permission to turn absent or incomplete configuration evidence into a finding: first verify the vendor grammar, applicable release, authoritative control source, and representative sanitized fixtures. Follow [Extending pynipper-v2](EXTENDING.md) for implementation and validation requirements.

## Priority: practical-testing defects

- [x] PT-001 to PT-004 ([details](agent_notes/PRACTICAL_TESTING_TASKS.md)): MarkupSafe pin, FortiOS and cross-vendor multi-line value parsing, and evidence line numbers.
- [x] PT-005 to PT-007: report readability, layered explanations and related-control hints.
- [ ] **PT-010 (high priority)**: opt-in CVE lookup for the configured software version through the free NVD CVE/CPE APIs, with offline bundle replay. See the [analysis](agent_notes/PRACTICAL_TESTING_TASKS.md#pt-010). **First stage done 2026-09-25**; remaining: one live validation run against NVD, then F5 per-module, AOS-S naming, vendor-feed cross-checks and feature correlation.
- [ ] PT-008 (deferred): dependency modernisation.
- [ ] PT-009 (low priority): label findings as explicit insecure value vs. missing explicit hardening setting. **Progress 2026-09-25:** `FindingBasis` model, report note and JSON field done, declared for a representative rule set; remaining: declare the basis in the other plugins rule by rule.

## Priority: report secret visibility (maintainer priority)

- [ ] Complete opt-in report-secret visibility across supported families. The CLI now provides `--show-secrets` for parser-qualified credential lines on IOS/IOS-XE/ASA, FortiOS, Junos, ScreenOS, SonicOS 7, AOS-S, EOS, and F5 TMOS; default findings remain masked, unsupported families fail explicitly, and sensitive output requires a new path. SonicOS coverage is limited to explicit built-in/local administrator passwords. Extend parser-owned mappings to remaining families and additional secret types only with precise effective-state and redaction tests. Do not imply hashes can be reversed or hidden values recovered. **Progress 2026-09-24:** added PAN-OS (element-only excerpts), IOS/IOS-XE/ASA/EOS SNMP and NTP keys, IOS/IOS-XE/EOS routing keys, and fail-closed Windows ACL restriction (`icacls`). IOS TACACS+/IKE keys, ASA tunnel-group/AAA keys and Junos RADIUS/TACACS+/NTP/SNMP/IKE/routing keys were added the same day. AOS-S and ScreenOS non-administrator secrets were added on 2026-09-25. SonicOS non-administrator secrets (RADIUS/TACACS+/LDAP, SNMP communities, VPN shared secrets) were added on 2026-09-25 from the SonicOS/X 7 E-CLI reference. Remaining: a real Windows run of the ACL path, and Check Point (see the maintainer decision below).

## Detection and parser coverage

- [ ] Continue open work across [SC-001 through SC-024](agent_notes/SECURITY_COVERAGE_TASKS.md#current-coverage-and-explicit-per-device-work) in the documented risk/evidence waves; SC-001, SC-002, SC-009 and SC-012 have bounded explicit-state coverage, SC-007 is implemented and SC-011 is partly implemented. This replaces the former broad F5, routing, access-edge, ScreenOS and certificate-expansion bullets; do not maintain duplicate implementations here.

## Inputs and assessment scope

- [x] Improve `-d` usability: present one recommended name per configuration family, preserve existing IDs as compatibility aliases, and allow conservative automatic identification of recognizable exports. Ambiguous or unsupported inputs request an explicit family rather than silently choosing a parser; device role stays separate from configuration format. CLI, fixture, help-text, and report-device-type tests cover the behavior.

## Maintainer decisions (2026-09-25)

- SC-011: do **not** grade FortiOS log-administrator rights against an organization role list. Keep only the existing bound write-capable role checks.
- SC-022: an end-of-support warning is wanted **only** if a freely accessible, externally maintained version/lifecycle source can be used through an API, so the project does not maintain its own list. This needs an analysis of candidate sources first (for example endoflife.date and vendor lifecycle feeds). Scheduled after the quick wins.
- PT-009: add a fourth basis, "required setting not configured", for absence rules such as a missing NTP server or remote syslog destination.
- Check Point `--show-secrets` (checked 2026-09-25): locally managed users and their passwords live in the separate user database `fwauth.NDB`, not in `objects.C`/`rules.C` ([CheckMates](https://community.checkpoint.com/t5/Management/Working-with-Checkpoint-files/td-p/33712)). Whether `objects.C` carries RADIUS/TACACS+ or VPN shared secrets (possibly encrypted) could not be confirmed without a sample. The family therefore stays *unsupported* (explicitly rejected), not "not applicable"; revisit with a sanitized `objects.C` (nice to have, below).

## Nice to have (distant future, needs sample exports the maintainer does not have)

Kept open on purpose; do not close or delete. Each needs a real sanitized export before implementation.

- [ ] SC-017 Check Point anti-spoofing and implied rules (matched `objects.C` + `rules.C` needed).
- [ ] SC-024 F5 module-specific protection (SCF from a unit with AFM, APM or ASM provisioned).
- [ ] SC-018 remainder: zone defaults, protocol direction and exclusion lists (a real `show current-config` export). The explicit zone stage is done.
- [ ] SC-019 ScreenOS screens and authenticated time, and RV-008 VPN anti-replay (ScreenOS 6.3 export).
- [ ] SC-020 Cisco PIX qualification (PIX 6.x export).
- [ ] SC-023 Check Point Gaia OS posture input (Gaia `show configuration` export).
- [ ] Check Point `--show-secrets`: qualify secret fields in a sanitized `objects.C`.

## Low priority (maintainer decision, 2026-09-24)

These items stay recorded but are scheduled after the SC backlog work that can be done without new vendor evidence and after `--show-secrets` completion.

- [ ] Extend bounded policy-effectiveness analysis to Junos stateless firewall filters where attachment, term order, address/service semantics, and unsupported predicates can be proven. Expand other native adapters only when equivalent evidence and adversarial tests are available; never infer runtime-unused rules from configuration alone.
- [ ] Qualify additional discovery and IPv6 access-edge protections only where explicit roles and fixtures demonstrate value beyond the prioritized SC tasks. No blanket discovery disablement or platform defaults inferred from names.
- [ ] PIX qualification is owned by [SC-020](agent_notes/SECURITY_COVERAGE_TASKS.md#sc-020); optional Check Point OS posture is owned by [SC-023](agent_notes/SECURITY_COVERAGE_TASKS.md#sc-023). Other new/legacy dialects (FWSM, old SonicOS preferences, CatOS/NMP, CSS, Passport/Accelar, F5OS/UCS) require demonstrated demand, representative exports and maintenance justification before becoming implementation tasks.
- [ ] Decide and specify whether target-CIDR targeting or partial-configuration selection are useful and safe. Retain referenced objects and rule order, disclose excluded scope, and avoid presenting exclusions as compliance. Benchmark threshold/profile extensions are scoped prerequisites in SC-002/005/021, not blanket changes to generic policy. **Real-world corroboration:** [ASA](agent_notes/REALWORLD_VALIDATION_FINDINGS.md#RW-003), [HP](agent_notes/REALWORLD_VALIDATION_FINDINGS.md#RW-018) and [PIX](agent_notes/REALWORLD_VALIDATION_FINDINGS.md#RW-020) excerpts produced absence-based findings without a complete-export guarantee.
- [ ] Add anonymized fixtures for newly encountered, supported configuration syntax and review maturity claims in [Supported devices](SUPPORTED_DEVICES.md) as evidence improves.
- [ ] Design a user-requested cracking-tool hash export for individually validated formats, if its handling and maintenance are approved. Keep normal findings, logs, and reports secret-free; require explicit destination, overwrite, permissions, and format rules, and never launch a cracking tool automatically.
- [ ] Design optional operational-evidence inputs or providers for questions static configuration cannot answer, such as served certificates and revocation, installed-policy identity and rule-hit windows, subscription/content state, backup results, and live advisory freshness. Keep default scans offline and deterministic, record evidence provenance and staleness, and do not equate zero hits with a safe-to-delete rule.
