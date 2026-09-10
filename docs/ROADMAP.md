# Roadmap

## Wave 5 — Target quality closure (completed 2026-09-10)

- Attached authoritative vendor references to every finding from all seven target pipelines, including the older focused IOS, IOS-XE, ASA, FortiOS, Junos, and ScreenOS plugins and the Cisco IOS/ASA baseline helpers, with source-level and emitted-finding enforcement.
- Expanded the permanent corpus from 14 to 20 cases with sanitized real-export syntax patterns, effective overrides, inactive objects, hierarchical input, and recoverable malformed values/lines.
- Kept `scripts/run_full_regression.py` and its cross-platform repository workflow as the target-platform quality gate.

## Wave 6 — Secondary-vendor correctness (completed 2026-09-10)

- Palo Alto PAN-OS: reconstructed device/vsys scope, interface-profile and log-profile references, dedicated MGT state, rules, administrators, DNS/NTP, SNMPv3, password policy, and explicit Panorama inheritance limits.
- HP ProCurve/ArubaOS-Switch: replaced substring/default guesses with ordered service, SNMP, SSH algorithm, AAA, logging, NTP, user, version, and model state; documented defaults are limited to AOS-S 16.10.
- SonicWall SonicOS: restricted support to SonicOS 7 E-CLI `show current-config custom`, rejected incompatible/legacy formats, and added typed interface, rule, VPN, logging, NTP, SNMP, and security-service checks.
- Arista EOS: reconstructed active eAPI protocol/VRF/ACL state and added AAA, SNMP, logging, and NTP coverage.
- Expanded the permanent gate to 32 configurations across eleven public pipelines; the Wave 6 closeout passed 364 tests.

## Wave 7 — Secondary baseline depth (completed 2026-09-10)

- Closed T-030 with PAN-OS management SSL/TLS profile and certificate resolution, minimum TLS policy, automatic threat-content installation, system-log forwarding, and normalized TLS evidence.
- Closed T-032 with ArubaOS-Switch password control, centralized accounting and DHCP-snooping coverage; Arista explicit SSH algorithms, empty-password policy, service ACL and exec authorization; and SonicOS authenticated NTP plus Capture ATP dependency/applicability checks.
- Kept live certificate validity, licensing/subscription state, and time-sensitive firmware currency out of static absence findings when the supported export cannot prove them.
- Retained the 32-case permanent corpus and expanded the complete suite to 367 passing tests.

## Next planning cycle

- Rank additions using observed configuration volume, false-positive/false-negative feedback, authoritative documentation, and fixture availability.
- Decide separately whether to add missing legacy dialects, new platforms, or an opt-in live-state/advisory layer.
- Add anonymized customer-derived grammar fixtures whenever a newly observed syntax family is safely available.

## Future expansion decisions

Legacy original-Nipper dialects and new platforms should be ranked by observed configuration volume, available authoritative documentation, safe parser feasibility, and maintenance cost. Registry entries are added only with an explicit input format and tested analyzer path; target-baseline status additionally requires paired permanent corpus coverage.
