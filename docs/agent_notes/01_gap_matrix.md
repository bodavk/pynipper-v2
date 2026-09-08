# Phase 1: Gap Matrix

## Device Support Gap Analysis

| Device Type from Original Nipper | pynipper-ng Status | Notes |
| :--- | :--- | :--- |
| Cisco IOS Switches | `SUPPORTED_UNVERIFIED` | Basic parser exists, but coverage is incomplete and untested. |
| Cisco IOS Routers | `SUPPORTED_UNVERIFIED` | Basic parser exists, but coverage is incomplete and untested. |
| Cisco IOS Catalysts | `SUPPORTED_UNVERIFIED` | Basic parser exists, but coverage is incomplete and untested. |
| Cisco NMP Catalysts | `MISSING` | No support in pynipper-ng. |
| Cisco CatOS Catalysts | `MISSING` | No support in pynipper-ng. |
| Cisco PIX Firewall | `MISSING` | No support in pynipper-ng. |
| Cisco ASA Firewall | `MISSING` | No support in pynipper-ng. |
| Cisco FWSM Firewall | `MISSING` | No support in pynipper-ng. |
| Cisco CSS | `MISSING` | No support in pynipper-ng. |
| Juniper ScreenOS | `MISSING` | No support in pynipper-ng. |
| CheckPoint Firewall-1 | `MISSING` | No support in pynipper-ng. |
| Nortel Passport | `MISSING` | No support in pynipper-ng. |
| SonicWALL SonicOS | `MISSING` | No support in pynipper-ng. |
| 3Com SuperStack3 | `MISSING` | No support in pynipper-ng. |
| Bay Networks Accelar | `MISSING` | No support in pynipper-ng. |
| HP ProCurve | `MISSING` | No support in pynipper-ng. |
| Nokia IPSO | `MISSING` | No support in pynipper-ng. |
| Nortel RoutingSwitch | `MISSING` | No support in pynipper-ng. |

## Feature/Check Gap Analysis

| Feature Category | pynipper-ng Status | Notes |
| :--- | :--- | :--- |
| Cisco IOS HTTP Checks | `SUPPORTED_UNVERIFIED` | Basic HTTP plugin exists. |
| Cisco IOS SSH Checks | `SUPPORTED_UNVERIFIED` | Basic SSH plugin exists. |
| Password Decoding (Type 7) | `MISSING` | Not yet implemented in pynipper-ng. |
| Logging Audit | `MISSING` | No dedicated logging plugin. |
| SNMP Audit | `MISSING` | No dedicated SNMP plugin. |
| ACL/Filter Audit | `MISSING` | No dedicated ACL auditing logic. |
| VPN Audit | `MISSING` | No dedicated VPN auditing logic. |
| NTP Audit | `MISSING` | No dedicated NTP auditing logic. |
| Password Cracking (John) | `MISSING` | No export to John-the-Ripper format. |
