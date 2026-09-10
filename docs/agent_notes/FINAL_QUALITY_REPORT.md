# Final Quality Report — Prioritized Detection Remediation

Report date: 2026-09-10

## Summary

The prioritized remediation program for Cisco IOS, Cisco IOS-XE, Cisco ASA, Fortinet FortiOS, Check Point Firewall-1, Juniper Junos, and Juniper ScreenOS is complete at the target-baseline level. The project is materially beyond its original shallow substring-checking state: these public pipelines now parse effective configuration state, retain scoped evidence, distinguish unknown from absent state, emit typed stable findings, and include broad baseline packs.

This is not a claim of universal device coverage or complete original-Nipper parity. PAN-OS, HP/ArubaOS-Switch, SonicOS, and Arista EOS remain intentionally deferred at basic depth, and several legacy platforms are missing.

## Verification evidence

The reusable validation command is:

```text
.venv\Scripts\python.exe scripts\run_full_regression.py
```

Observed in this report session:

```text
319 passed, 1 warning in 1.39s
Regression corpus passed: 14 configurations
```

The warning is the existing Windows pytest-cache permission warning. It does not indicate a test failure.

The permanent corpus contains a vulnerable and hardened case for each of seven public target pipelines. Exact duplicate-preserving rule-ID snapshots are stored in `tests/test_data/regression/manifest.json`.

| Pipeline | Vulnerable findings | Hardened findings | Snapshot result |
|---|---:|---:|---|
| Cisco IOS | 23 | 0 | Pass |
| Cisco IOS-XE | 15 | 0 | Pass |
| Cisco ASA | 13 | 0 | Pass |
| FortiOS | 20 | 0 | Pass |
| Junos | 11 | 0 | Pass |
| ScreenOS | 16 | 1 | Pass; the remaining finding is intentional EOL posture |
| Check Point FW1 | 13 | 0 | Pass |
| **Total** | **111** | **1** | **14/14 configurations passed** |

Across the vulnerable cases, the corpus asserts 94 distinct rule IDs. The 111 emitted findings include IOS rules deliberately reused by the IOS-XE composition and repeated Check Point IDs for distinct policy objects; object-level repeats are retained only when rule-bound evidence differs.

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

## Residual risks and deferred work

1. **Serialized citation gap in older focused plugins.** The new baseline plugins and Check Point focused rule attach source references to findings. Older focused IOS, IOS-XE, ASA, FortiOS, Junos, and ScreenOS plugins have their sources recorded in audit/task documentation but do not yet serialize those URLs per finding. Their detection behavior is Level 2, but they do not fully satisfy the project's per-finding citation standard. A small follow-up task should add references without changing rule semantics.
2. **Deferred secondary vendors.** T-007, T-010, T-011, T-019, T-022, T-024, T-027, T-030, and T-032 remain open for SonicOS, PAN-OS, HP/ArubaOS-Switch, and Arista EOS. These implementations must continue to be described as basic/partial.
3. **Legacy dialect qualification.** ASA corpus coverage does not independently qualify PIX or FWSM syntax. IOS Catalyst coverage does not imply CatOS/NMP support.
4. **Corpus provenance.** The permanent fixtures are sanitized, purpose-built representative configurations. Adding sanitized examples from real customer exports will improve grammar and edge-case confidence without changing expected rule semantics casually.
5. **Offline Check Point limits.** The legacy export cannot prove successful compilation/installation, dynamic-object runtime membership, hit counts, implied rules, or interactions between separately evaluated policy layers.
6. **ScreenOS lifecycle.** A hardened ScreenOS configuration correctly retains one EOL finding; configuration hardening cannot remove the platform lifecycle risk.

## Recommended next steps

1. Add serialized vendor/benchmark references to the older target focused plugins and assert them in tests.
2. Grow each target corpus directory with sanitized real-world syntax variants and malformed-input cases.
3. Start the deferred secondary-vendor wave in observed-demand order, without weakening the Level-2 acceptance bar.
4. Maintain the full regression command as the required cross-platform repository workflow; this was integrated during the post-Phase-F architecture cleanup.

## Conclusion

The target-platform remediation is verified and useful, but deliberately bounded. Pynipper-v2 now has a credible static configuration-audit baseline for the device families most commonly encountered by this project. Its main remaining quality risk is unevenness outside that target set, not the earlier systemic inability to reason about effective configuration state.
