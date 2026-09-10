# Project Status

Last verified: 2026-09-10

## Current state

The architecture and Waves 0-7 are verified. Cisco IOS, IOS-XE, ASA, FortiOS, Check Point FW1, Junos, ScreenOS, PAN-OS, ArubaOS-Switch/ProCurve, SonicOS, and Arista EOS run through the permanent public-pipeline corpus. The gate covers 32 configurations and enforces exact findings, unique rule/evidence identities, normalized parser construction, and HTTPS references for every emitted corpus finding. The latest verified result is 367 passing tests; rerun the documented regression command for current evidence.

The planned detection-remediation program is closed, including T-030 and T-032. The project is still not at universal device parity: the four secondary platforms have bounded static baselines rather than the broader depth of the seven prioritized platforms, and several original Nipper dialects are not implemented. Live certificate validity, license/subscription state, runtime reachability, and current firmware support require operational data and are not inferred from incomplete configuration evidence.

## Next work

1. Plan the next program from observed customer configuration volume and false-positive/false-negative feedback.
2. Separately assess missing legacy platforms and possible live-state/advisory integrations; do not combine registry reachability with detection parity.

See `docs/ARCHITECTURE.md`, `docs/EXTENDING.md`, `docs/SUPPORTED_DEVICES.md`, and `docs/agent_notes/01_gap_matrix.md` for detailed boundaries and future-maintenance guidance.
