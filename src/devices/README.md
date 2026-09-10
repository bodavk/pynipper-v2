# Device parsers

The authoritative device list is `src/devices/registry.py`. Every registered parser implements `BaseDeviceParser` and returns both its native representation and a `NormalizedConfig` snapshot with explicit knowledge state.

## Parser maturity

| Device ID | Parser | Current parser scope |
|---|---|---|
| `IOS_SWITCH`, `IOS_ROUTER`, `IOS_CATALYST` | `CiscoIOSParser` | Verified IOS-family parsing used by HTTP, SSH, and baseline controls |
| `IOS_XE` | `CiscoIOSXEParser` | Verified IOS composition plus IOS-XE MACsec and active crypto references |
| `ASA`, `PIX` | `CiscoASAParser` | Verified typed management, ACL, logging, credentials, SNMP, and baseline state |
| `FORTIOS` | `FortiOSParser` | Verified grammar-aware CLI parsing with VDOM/global scope, mutation ordering, secret-redacted evidence, and expanded management/crypto normalization |
| `JUNOS` | `JunOSParser` | Verified hierarchical and display-set parsing, including effective services, filters, logging, and crypto |
| `SCREENOS` | `JuniperScreenOSParser` | Verified ordered set/unset parsing for management, users, objects, policies, logging, and crypto |
| `CHECKPOINT_FW1` | `CheckPointFW1Parser` | Verified S-expression parsing with typed ordered layers, rules, network/service objects, nested groups, negation, VPN/install/track/time context, and legacy anonymous-name support |
| `PAN_OS` | `PaloAltoPANOSParser` | PAN-OS XML device/vsys interfaces, attached management profiles, dedicated MGT state, ordered rules, log references, administrators, password policy, DNS/NTP, SNMPv3, management SSL/TLS profiles, content schedules, system-log forwarding, version, and explicit unknown Panorama inheritance |
| `HP_PROCURVE` | `HPProCurveParser` | ArubaOS-Switch running configuration with ordered services, users, SNMPv3/communities, SSH suites, authorized managers, AAA/accounting, password control, VLAN/DHCP-snooping, syslog, SNTP, version, and model; default tables are limited to AOS-S 16.10 |
| `SONICOS` | `SonicOSParser` | SonicOS 7 E-CLI `show current-config custom` only; typed interfaces, management, access rules, VPN proposals, syslog, authenticated NTP, and explicit security-service/dependency state; incompatible formats fail explicitly |
| `ARISTA_EOS` | `AristaEOSParser` | EOS metadata plus active eAPI HTTP/HTTPS, shutdown, VRF and service-ACL scope, local users, AAA/exec authorization, explicit management SSH policy, SNMP, syslog, and NTP |

Registered aliases are resolved centrally. Additions must include registry, parser-contract, analyzer-dispatch, and alias tests.

The permanent corpus includes 32 inputs across eleven public pipelines. Its paired and edge-case PAN-OS, ArubaOS-Switch, SonicOS, and Arista EOS configurations cover unknown defaults, inactive APIs and objects, format rejection, scope isolation, reference resolution, ordered negation, and Wave 7 advanced state.

See [`docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md) for parser responsibilities and [`docs/EXTENDING.md`](../../docs/EXTENDING.md) before adding a device or input dialect.
