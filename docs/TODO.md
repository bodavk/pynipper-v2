# Open improvement work

This is a list of improvements not yet implemented at their full intended scope. Items are grouped by subject, not by priority or implementation order. An item is not permission to turn absent or incomplete configuration evidence into a finding: first verify the vendor grammar, applicable release, authoritative control source, and representative sanitized fixtures. Follow [Extending pynipper-v2](EXTENDING.md) for implementation and validation requirements.

## Detection and parser coverage

- [ ] Extend bounded policy-effectiveness analysis to Junos stateless firewall filters where attachment, term order, address/service semantics, and unsupported predicates can be proven. Expand other native adapters only when equivalent evidence and adversarial tests are available; never infer runtime-unused rules from configuration alone.
- [ ] Assess additional routing protocols, such as EIGRP and RIP, and additional platform-specific routing-trust controls where supported exports and current vendor guidance establish effective peer/interface state.
- [ ] Extend trust-boundary discovery and access-edge protections to additional applicable device families, using explicit assessment roles rather than names or inferred topology.
- [ ] Qualify and implement ScreenOS authenticated-time and zone-screen checks beyond the verified 6.3 session/default-policy subset. Do not infer requirements or defaults from incomplete legacy manuals or exports.
- [ ] Expand management-certificate public-material resolution on platforms that currently expose only certificate selection or partial metadata, where a supported export includes the necessary objects. Preserve explicit assessment-time, intended-identity, and trust-anchor requirements; do not claim the configured certificate is the one served at runtime.
- [ ] Add further vendor-specific checks or normalized fields only for observed configuration syntax with source-qualified semantics and secure, vulnerable, override, malformed, and unknown-state fixtures.

## Inputs and assessment scope

- [ ] Qualify legacy or additional input dialects against observed audit demand and representative sanitized exports before adding registry entries. Candidates include independent PIX/FWSM, older SonicOS preferences, CatOS/NMP, CSS, Passport/Accelar, and other legacy formats; a shared vendor name is not proof of compatible syntax. **Real-world corroboration:** [two PIX 6.3 examples](agent_notes/REALWORLD_VALIDATION_FINDINGS.md#RW-020) returned successful reports with zero known policies despite bound outside ACLs; prioritize honest unsupported coverage and PIX dialect qualification.
- [ ] Design an optional, provenance-checked Check Point Gaia/gateway/management OS export alongside the existing Firewall-1 policy export. Keep policy-only scans valid and system posture unknown when no matched OS export is supplied.
- [ ] Decide and specify whether assessment-policy threshold overrides, target-CIDR targeting, or partial-configuration selection are useful and safe. Any implementation must retain referenced objects and rule order, disclose excluded scope, and avoid presenting exclusions as compliance. **Real-world corroboration:** [ASA](agent_notes/REALWORLD_VALIDATION_FINDINGS.md#RW-003), [HP](agent_notes/REALWORLD_VALIDATION_FINDINGS.md#RW-018) and [PIX](agent_notes/REALWORLD_VALIDATION_FINDINGS.md#RW-020) excerpts produced absence-based findings without a complete-export guarantee.
- [ ] Add anonymized fixtures for newly encountered, supported configuration syntax and review maturity claims in [Supported devices](SUPPORTED_DEVICES.md) as evidence improves.

## Separately opt-in capabilities

- [ ] Design a user-requested cracking-tool hash export for individually validated formats, if its handling and maintenance are approved. Keep normal findings, logs, and reports secret-free; require explicit destination, overwrite, permissions, and format rules, and never launch a cracking tool automatically.
- [ ] Design optional operational-evidence inputs or providers for questions static configuration cannot answer, such as served certificates and revocation, installed-policy identity and rule-hit windows, subscription/content state, backup results, and live advisory freshness. Keep default scans offline and deterministic, record evidence provenance and staleness, and do not equate zero hits with a safe-to-delete rule.
