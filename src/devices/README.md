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
| `PAN_OS` | `PaloAltoPANOSParser` | Basic parser; scope/reference reconstruction remains scheduled |
| `HP_PROCURVE` | `HPProCurveParser` | Basic parser; SNMP/SSH correctness work remains scheduled |
| `SONICOS` | `SonicOSParser` | Basic parser; an authoritative export format and deeper state model remain scheduled |
| `ARISTA_EOS` | `AristaEOSParser` | Basic parser; eAPI effective-state correction remains scheduled |

Registered aliases are resolved centrally. Additions must include registry, parser-contract, analyzer-dispatch, and alias tests.

See [`docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md) for parser responsibilities and [`docs/EXTENDING.md`](../../docs/EXTENDING.md) before adding a device or input dialect.
