# Project Status

Last verified: 2026-09-14

## Current state

The architecture and Waves 0-7 are verified. Cisco IOS, IOS-XE, ASA, FortiOS, Check Point FW1, Junos, ScreenOS, PAN-OS, ArubaOS-Switch/ProCurve, SonicOS, and Arista EOS run through the permanent public-pipeline corpus. The gate covers 32 configurations and enforces exact findings, unique rule/evidence identities, normalized parser construction, and HTTPS references for every emitted corpus finding. The active remediation program has completed GAP-006 through GAP-016 plus bounded GAP-021. IOS/XE and Junos have typed BGP/OSPF routing trust and explicitly role-scoped discovery analysis; IOS/XE and AOS-S add role-aware switch-edge protection; FortiOS 7.4+ resolves administrative RADIUS/RadSec transport and identity state; PAN-OS and ASA assess scoped management certificate material; PAN-OS/FortiOS resolve active policy inspection groups and profiles through local/shared or VDOM/global scope; FortiOS/Junos expose distinct local-in or SRX stateful-policy models plus attached static IKE/IPsec proposal chains; and ScreenOS 6.3 now resolves explicit default-permit policy state and separate console/Telnet, WebUI, administrator-AAA, and policy/user authentication timeout domains. The latest verified result is 487 passing tests; rerun the documented regression command for current evidence.

The prior Waves 0-7 program is closed, including T-030 and T-032; the current gap-remediation program remains active. The project is still not at universal device parity: the four secondary platforms have bounded static baselines rather than the broader depth of the seven prioritized platforms, and several original Nipper dialects are not implemented. A supplied assessment time permits reproducible offline certificate validity assessment, but the certificate actually served, live chain/revocation state, license/subscription state, runtime reachability, and current firmware support require operational data and are not inferred from incomplete configuration evidence.

## Next work

1. Implement GAP-017 one secondary platform at a time, beginning with the best-supported administrative-policy evidence and retaining explicit release/export boundaries.
2. Continue the remaining parser-extension tasks in dependency order while preserving the static/live evidence boundary.

See `docs/ARCHITECTURE.md`, `docs/EXTENDING.md`, `docs/SUPPORTED_DEVICES.md`, and `docs/agent_notes/01_gap_matrix.md` for detailed boundaries and future-maintenance guidance.
