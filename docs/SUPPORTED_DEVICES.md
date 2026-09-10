# Supported Devices

This table separates registry support from detection depth. “Target baseline” means the parser and the high-priority security baseline have current effective-state tests. “Correctness baseline” means the focused checks are verified but the broader expansion task is still open. “Basic” means the format is registered but known parser or rule-depth work remains.

| Vendor | Device/OS | Parser | Detection status |
|---|---|---|---|
| Cisco | IOS | `CiscoIOSParser` | Target baseline |
| Cisco | IOS-XE | `CiscoIOSXEParser` | Target baseline |
| Cisco | ASA / PIX | `CiscoASAParser` | Target baseline |
| Fortinet | FortiGate / FortiOS | `FortiOSParser` | Target baseline; documented-default inference for 7.x and explicit-state analysis for older/unversioned exports |
| Check Point | Firewall-1 legacy management export | `CheckPointFW1Parser` | Target offline-policy baseline; runtime/compiled-policy state remains out of scope |
| Juniper | Junos | `JunOSParser` | Target baseline |
| Juniper | ScreenOS | `JuniperScreenOSParser` | Target baseline; platform is EOL |
| Palo Alto | PAN-OS | `PaloAltoPANOSParser` | Basic; T-010/T-019/T-030 open |
| HP / Aruba | ProCurve / ArubaOS-Switch | `HPProCurveParser` | Basic; T-011/T-022/T-032 open |
| SonicWall | SonicOS | `SonicOSParser` | Basic; T-007/T-024/T-032 open |
| Arista | EOS | `AristaEOSParser` | Basic; T-027/T-032 open |

The canonical IDs and accepted aliases are defined in `src/devices/registry.py`.

The seven target pipelines are continuously checked against paired vulnerable/hardened fixtures by `scripts/run_full_regression.py`. Registry support for a basic/partial device does not imply that it is included in this target-quality corpus.
