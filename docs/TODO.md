# Open improvement work

Reconciled on 2026-09-22. The prioritized, source-backed implementation backlog for all 15 device IDs is [High-risk security coverage tasks](agent_notes/SECURITY_COVERAGE_TASKS.md). It contains 24 tasks, including explicit evidence prerequisites, parser/detection contracts, interface constraints and acceptance tests. Completed RV task bodies were removed from [external-validation tasks](agent_notes/REALWORLD_VALIDATION_TASKS.md); RV-008 remains open. This index retains genuinely open work outside that focused review.

An item is not permission to turn absent or incomplete configuration evidence into a finding: first verify the vendor grammar, applicable release, authoritative control source, and representative sanitized fixtures. Follow [Extending pynipper-v2](EXTENDING.md) for implementation and validation requirements.

## Priority: practical-testing defects

- [x] PT-001 to PT-004 ([details](agent_notes/PRACTICAL_TESTING_TASKS.md)): MarkupSafe pin, FortiOS and cross-vendor multi-line value parsing, and evidence line numbers.
- [ ] PT-005 to PT-007: report readability, layered explanations and related-control hints.
- [ ] PT-008 (deferred): dependency modernisation.

## Priority: report secret visibility

- [ ] Complete opt-in report-secret visibility across supported families. The CLI now provides `--show-secrets` for parser-qualified credential lines on IOS/IOS-XE/ASA, FortiOS, Junos, ScreenOS, SonicOS 7, AOS-S, EOS, and F5 TMOS; default findings remain masked, unsupported families fail explicitly, and sensitive output requires a new path. SonicOS coverage is limited to explicit built-in/local administrator passwords. Extend parser-owned mappings to remaining families and additional secret types only with precise effective-state and redaction tests. Do not imply hashes can be reversed or hidden values recovered; review Windows ACL handling and output containment before declaring this fully complete.

## Detection and parser coverage

- [ ] Continue open work across [SC-001 through SC-024](agent_notes/SECURITY_COVERAGE_TASKS.md#current-coverage-and-explicit-per-device-work) in the documented risk/evidence waves; SC-001, SC-002, SC-009 and SC-012 have bounded explicit-state coverage, SC-007 is implemented and SC-011 is partly implemented. This replaces the former broad F5, routing, access-edge, ScreenOS and certificate-expansion bullets; do not maintain duplicate implementations here.
- [ ] Extend bounded policy-effectiveness analysis to Junos stateless firewall filters where attachment, term order, address/service semantics, and unsupported predicates can be proven. Expand other native adapters only when equivalent evidence and adversarial tests are available; never infer runtime-unused rules from configuration alone.
- [ ] Qualify additional discovery and IPv6 access-edge protections only where explicit roles and fixtures demonstrate value beyond the prioritized SC tasks. No blanket discovery disablement or platform defaults inferred from names.

## Inputs and assessment scope

- [x] Improve `-d` usability: present one recommended name per configuration family, preserve existing IDs as compatibility aliases, and allow conservative automatic identification of recognizable exports. Ambiguous or unsupported inputs request an explicit family rather than silently choosing a parser; device role stays separate from configuration format. CLI, fixture, help-text, and report-device-type tests cover the behavior.
- [ ] PIX qualification is owned by [SC-020](agent_notes/SECURITY_COVERAGE_TASKS.md#sc-020); optional Check Point OS posture is owned by [SC-023](agent_notes/SECURITY_COVERAGE_TASKS.md#sc-023). Other new/legacy dialects (FWSM, old SonicOS preferences, CatOS/NMP, CSS, Passport/Accelar, F5OS/UCS) require demonstrated demand, representative exports and maintenance justification before becoming implementation tasks.
- [ ] Decide and specify whether target-CIDR targeting or partial-configuration selection are useful and safe. Retain referenced objects and rule order, disclose excluded scope, and avoid presenting exclusions as compliance. Benchmark threshold/profile extensions are scoped prerequisites in SC-002/005/021, not blanket changes to generic policy. **Real-world corroboration:** [ASA](agent_notes/REALWORLD_VALIDATION_FINDINGS.md#RW-003), [HP](agent_notes/REALWORLD_VALIDATION_FINDINGS.md#RW-018) and [PIX](agent_notes/REALWORLD_VALIDATION_FINDINGS.md#RW-020) excerpts produced absence-based findings without a complete-export guarantee.
- [ ] Add anonymized fixtures for newly encountered, supported configuration syntax and review maturity claims in [Supported devices](SUPPORTED_DEVICES.md) as evidence improves.

## Separately opt-in capabilities

- [ ] Design a user-requested cracking-tool hash export for individually validated formats, if its handling and maintenance are approved. Keep normal findings, logs, and reports secret-free; require explicit destination, overwrite, permissions, and format rules, and never launch a cracking tool automatically.
- [ ] Design optional operational-evidence inputs or providers for questions static configuration cannot answer, such as served certificates and revocation, installed-policy identity and rule-hit windows, subscription/content state, backup results, and live advisory freshness. Keep default scans offline and deterministic, record evidence provenance and staleness, and do not equate zero hits with a safe-to-delete rule.
