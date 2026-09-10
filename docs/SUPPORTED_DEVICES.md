# Supported Devices

This table separates registry support from detection depth. “Target baseline” means the parser and high-priority security baseline have current effective-state tests. “Expanded static baseline” means the planned secondary-platform packs are closed but deliberately bounded by what the supported export proves. “Basic” means the format is registered but known parser or rule-depth work remains.

| Vendor | Device/OS | Parser | Detection status |
|---|---|---|---|
| Cisco | IOS | `CiscoIOSParser` | Target baseline |
| Cisco | IOS-XE | `CiscoIOSXEParser` | Target baseline |
| Cisco | ASA / PIX | `CiscoASAParser` | Target baseline |
| Fortinet | FortiGate / FortiOS | `FortiOSParser` | Target baseline; documented-default inference for 7.x and explicit-state analysis for older/unversioned exports |
| Check Point | Firewall-1 legacy management export | `CheckPointFW1Parser` | Target offline-policy baseline; runtime/compiled-policy state remains out of scope |
| Juniper | Junos | `JunOSParser` | Target baseline |
| Juniper | ScreenOS | `JuniperScreenOSParser` | Target baseline; platform is EOL |
| Palo Alto | PAN-OS XML | `PaloAltoPANOSParser` | Expanded static baseline; local device/vsys references, management TLS/certificate policy, content scheduling and system logging verified; Panorama inheritance explicit unknown |
| HP / Aruba | ProCurve / ArubaOS-Switch running configuration | `HPProCurveParser` | Expanded static baseline; ordered service/SNMP/SSH/AAA/accounting/password/logging/NTP/DHCP-snooping state, with defaults limited to AOS-S 16.10 |
| SonicWall | SonicOS 7 E-CLI `show current-config custom` | `SonicOSParser` | Expanded static baseline; interface/rule/VPN/operations, authenticated NTP and explicit threat-service dependency state; incompatible and legacy preference exports rejected |
| Arista | EOS | `AristaEOSParser` | Expanded static baseline; active eAPI VRF/protocol/ACL plus explicit management SSH algorithms, ACLs, empty-password policy and exec authorization |

The canonical IDs and accepted aliases are defined in `src/devices/registry.py`.

Eleven public pipelines are continuously checked by `scripts/run_full_regression.py`. Its 32 permanent inputs comprise the prior 20 target cases plus paired and edge-case configurations for all four secondary platforms. Registry reachability and expanded-baseline status do not imply universal vendor-version or full target-baseline parity. Static exports also cannot prove live certificate validity, active subscription/licensing state, or whether a software release is currently supported.
