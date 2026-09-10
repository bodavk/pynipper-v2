# Pynipper-v2 Device Gap Matrix

Assessment date: 2026-09-10

Statuses describe tested detection depth, not merely whether a registry entry exists.

- `SUPPORTED_VERIFIED`: the parser and prioritized security baseline have effective-state positive/negative regression coverage.
- `SUPPORTED_PARTIAL`: a registered parser and basic checks exist, but known parser, dialect, scope, or baseline work remains.
- `MISSING`: no registered parser/check pipeline exists for that original-device dialect.

## Original Nipper device scope

| Original device/dialect | Status | Current mapping and limit |
|---|---|---|
| Cisco IOS switch | SUPPORTED_VERIFIED | `IOS_SWITCH` uses the verified IOS parser and pipeline |
| Cisco IOS router | SUPPORTED_VERIFIED | `IOS_ROUTER` is in the permanent corpus |
| Cisco Catalyst using IOS | SUPPORTED_VERIFIED | `IOS_CATALYST` shares the verified IOS parser |
| Cisco Catalyst CatOS/NMP | MISSING | No CatOS/NMP grammar |
| Cisco ASA | SUPPORTED_VERIFIED | ASA syntax has paired corpus coverage |
| Cisco PIX | SUPPORTED_PARTIAL | Registry alias uses the ASA parser; legacy PIX syntax is not separately qualified |
| Cisco FWSM | MISSING | No separately qualified FWSM grammar |
| Cisco CSS | MISSING | No parser or checks |
| Juniper ScreenOS | SUPPORTED_VERIFIED | Paired corpus includes a hardened EOL configuration and vulnerable configuration |
| Check Point Firewall-1 | SUPPORTED_VERIFIED | Offline management-export policy/object analysis; runtime installation state is out of scope |
| Nortel Passport | MISSING | No parser or checks |
| SonicWall SonicOS | SUPPORTED_PARTIAL | SonicOS 7 E-CLI expanded static baseline verified; WebUI preferences/6.x remain unsupported and live certificate/license/firmware state is out of scope |
| 3Com SuperStack3 Firewall | MISSING | No parser or checks |
| Bay Networks Accelar | MISSING | No parser or checks |
| HP ProCurve | SUPPORTED_PARTIAL | ArubaOS-Switch expanded static baseline verified; documented defaults remain limited to AOS-S 16.10 and other releases are explicit-state only |
| Nokia IPSO | MISSING | No parser or checks |
| Nortel Routing Switch | MISSING | No parser or checks |

## Added device scope beyond original Nipper

| Added device/dialect | Status | Current mapping and limit |
|---|---|---|
| Fortinet FortiGate/FortiOS | SUPPORTED_VERIFIED | Grammar-aware global/VDOM parser and target baseline; paired corpus coverage |
| Cisco IOS-XE | SUPPORTED_VERIFIED | IOS composition plus IOS-XE MACsec/IKE/IPsec; paired corpus coverage |
| Juniper Junos | SUPPORTED_VERIFIED | Hierarchical/display-set parser and target baseline; paired corpus coverage |
| Palo Alto PAN-OS | SUPPORTED_PARTIAL | Local XML scope/reference and expanded static baseline verified; Panorama merged state and live certificate/firmware state remain out of scope |
| Arista EOS | SUPPORTED_PARTIAL | eAPI plus explicit SSH/authorization static baseline verified; implicit/default SSH suites and live certificate/firmware state remain out of scope |

## Priority conclusion

The commonly encountered target set—Cisco IOS/IOS-XE/ASA, FortiOS, Check Point FW1, Junos, and ScreenOS—has verified target-baseline coverage. Waves 6-7 added bounded expanded static baselines for PAN-OS, HP/ArubaOS-Switch, SonicOS 7 E-CLI, and Arista EOS and closed T-030/T-032. Legacy original-only platforms and any live-state/advisory layer remain separate expansion decisions.
