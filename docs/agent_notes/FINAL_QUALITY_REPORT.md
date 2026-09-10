# Final Quality Report — Prioritized Detection Remediation

Report date: 2026-09-10

## Summary

The prioritized remediation program for Cisco IOS, Cisco IOS-XE, Cisco ASA, Fortinet FortiOS, Check Point Firewall-1, Juniper Junos, and Juniper ScreenOS is complete at the target-baseline level. The project is materially beyond its original shallow substring-checking state: these public pipelines now parse effective configuration state, retain scoped evidence, distinguish unknown from absent state, emit typed stable findings, and include broad baseline packs.

This is not a claim of universal device coverage or complete original-Nipper parity. Waves 6-7 subsequently raised PAN-OS, HP/ArubaOS-Switch, SonicOS 7 E-CLI, and Arista EOS to bounded expanded static baselines and closed T-030/T-032. Several missing legacy platforms and controls requiring live operational state remain explicit.

## Verification evidence

The reusable validation command is:

```text
.venv\Scripts\python.exe scripts\run_full_regression.py
```

Observed in this report session:

```text
Regression corpus passed: 32 configurations
367 passed, 1 warning in 1.42s
```

The warning is the existing Windows pytest-cache permission warning. It does not indicate a test failure.

The permanent corpus contains a vulnerable and hardened case for each of eleven public pipelines, a sanitized syntax-variant case for each of the six older focused platforms, and a third scope/default/inactive-object case for each Wave 6 platform. Exact duplicate-preserving rule-ID snapshots are stored in `tests/test_data/regression/manifest.json`.

| Pipeline | Vulnerable | Hardened | Syntax variant | Snapshot result |
|---|---:|---:|---:|---|
| Cisco IOS | 23 | 0 | 0 | Pass |
| Cisco IOS-XE | 15 | 0 | 0 | Pass |
| Cisco ASA | 13 | 0 | 1 | Pass; retained uRPF baseline finding |
| FortiOS | 20 | 0 | 3 | Pass; deliberately incomplete baseline controls retained |
| Junos | 11 | 0 | 0 | Pass |
| ScreenOS | 16 | 1 | 1 | Pass; hardened/variant findings are intentional EOL posture |
| Check Point FW1 | 13 | 0 | — | Pass |
| PAN-OS | 14 | 0 | 1 | Pass; scope finding records unresolved Panorama inheritance |
| ArubaOS-Switch / HP ProCurve | 12 | 0 | 0 | Pass; unknown-release defaults remain unknown |
| Arista EOS | 11 | 0 | 0 | Pass; inactive eAPI objects do not produce findings |
| SonicOS 7 E-CLI | 10 | 0 | 0 | Pass; disabled rule/VPN objects do not produce findings |
| **Total** | **158** | **1** | **6** | **32/32 configurations passed** |

Across the vulnerable cases, the corpus asserts 141 distinct rule IDs. The 158 emitted vulnerable findings include IOS rules deliberately reused by the IOS-XE composition and repeated Check Point IDs for distinct policy objects; object-level repeats are retained only when rule-bound evidence differs. The complete corpus emits 165 findings including intentional scope, lifecycle, and syntax-variant results.

## Detection depth before and after

The pre-remediation code audit recorded 84 defects across architecture and device logic, including 36 false-negative paths, 24 false-positive paths, five crash paths, and twelve coverage gaps. Target checks were predominantly Level 0/1: raw substring searches, unreliable absence/default assumptions, unguarded coercion, unscoped rules, and incomplete evidence.

| Target | Before | Verified current state |
|---|---|---|
| Shared architecture | Conflicting registries, vendor-specific finding type, ambiguous common parser fields | One lazy authoritative registry, neutral validated finding schema, typed normalized records, explicit unknown state |
| Cisco IOS | Level 0/1 HTTP/SSH checks with negation, default, coercion, and VTY-scope defects | Level-2 behavior for focused rules plus a version-gated Level-2 baseline; selected cross-referenced rules reach Level 3 |
| Cisco IOS-XE | IOS inheritance plus shallow string checks | IOS effective-state composition plus active MACsec/IKE/IPsec reference analysis; Level 2 with selected Level-3 rules |
| Cisco ASA | Overlapping pipelines and token-position assumptions | Single deduplicated typed pipeline, scoped management/logging/TLS/ACL/SNMP analysis, and Level-2 baseline with selected Level-3 rules |
| FortiOS | Ad-hoc tree building, broken VDOM/interface scope, weak default handling | Grammar-aware global/VDOM model, active-object checks, version-aware baseline; Level 2 with selected Level-3 rules |
| Junos | Flat substring scanning without hierarchy/effective state | Hierarchy/display-set normalization, inactive/delete semantics, attached-filter and system baseline; Level 2 with selected Level-3 rules |
| ScreenOS | Flat line scanning without effective unset/continuation semantics | Effective set/unset model, scoped management, continued policies, VPN references, EOL-aware baseline; Level 2 with selected Level-3 rules |
| Check Point FW1 | Parenthesis slicing and cross-rule keyword mixing | Typed layers/rules/objects/services, same-layer policy reasoning, group/reference expansion; Level 2 with substantial Level-3 analysis |

## What the result means operationally

For the prioritized formats, the checks are no longer “too basic to detect most common misconfigurations” in the sense that prompted the audit. The baseline now covers high-value management exposure, authentication, credential storage, logging, SNMP, NTP, cryptography/VPN, interface/control-plane protections, and broad policy behavior where the platform export provides that state.

It still is not a replacement for a live control-plane assessment. Static configurations cannot prove runtime reachability, applied/installed policy, certificate validity, dynamic object membership, authentication-server health, hit counts, or compensating controls outside the file.

## Wave 5 quality closure

The earlier serialized-citation gap is closed. Every `Finding` constructor in all target plugin files supplies references, including the Cisco IOS and ASA baseline helpers that an older inventory had incorrectly marked as already cited. `tests/test_focused_plugin_references.py` rejects target constructors without references and validates focused constants against authoritative vendor HTTPS domains. The public regression runner requires every emitted target finding to contain an HTTPS source and rejects insecure external reference URLs.

The six new permanent cases cover ordered enable/disable and set/unset behavior, alternate `ip ssh timeout` spelling, named and IPv6 VTY controls, removed ASA IPv4/IPv6 management grants, quoted FortiOS values and disabled policy objects, inactive/unused weak crypto definitions, native hierarchical Junos, and a malformed quoted ScreenOS line that must produce a diagnostic without preventing later valid commands from being analyzed.

## Residual risks and deferred work

1. **Static-analysis boundaries.** T-030 and T-032 are closed, but static exports cannot prove certificate validity/expiry, active licenses or subscriptions, current vendor-support status, runtime authorization results, or effective state inherited from an unavailable controller hierarchy.
2. **Legacy dialect qualification.** ASA corpus coverage does not independently qualify PIX or FWSM syntax. IOS Catalyst coverage does not imply CatOS/NMP support.
3. **Corpus provenance.** The permanent fixtures are sanitized, purpose-built representative configurations. Adding sanitized examples derived from customer exports will improve grammar and edge-case confidence without casually changing expected rule semantics.
4. **Offline Check Point limits.** The legacy export cannot prove successful compilation/installation, dynamic-object runtime membership, hit counts, implied rules, or interactions between separately evaluated policy layers.
5. **ScreenOS lifecycle.** A hardened ScreenOS configuration correctly retains one EOL finding; configuration hardening cannot remove the platform lifecycle risk.

## Recommended next steps

1. Plan the next program using observed configuration volume and measured false-positive/false-negative feedback.
2. Add sanitized customer-derived fixtures opportunistically when new syntax is encountered, after secret removal and explicit expected-result review.
3. Maintain the full regression command as the required cross-platform repository workflow and consider live-state/advisory correlation as a separate opt-in architecture.

## Conclusion

The target-platform remediation is verified and useful, but deliberately bounded. Pynipper-v2 now has a credible static configuration-audit baseline for the device families most commonly encountered by this project. Its main remaining quality risk is unevenness outside that target set, not the earlier systemic inability to reason about effective configuration state or the now-closed focused-plugin citation gap.
