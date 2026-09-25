# pynipper-v2

`pynipper-v2` reviews exported network-device configurations for security risks. It runs primarily offline and produces HTML or JSON reports with findings, evidence, severity, and remediation guidance. The installed command is `pynipper-ng` for compatibility with the original project.

## Supported devices

| Coverage | Configuration families |
|---|---|
| Primary baselines | Cisco IOS/IOS-XE and ASA; FortiGate/FortiOS; Check Point Firewall-1 management exports; Juniper Junos and ScreenOS |
| Expanded static baselines | Palo Alto PAN-OS; HP ProCurve/ArubaOS-Switch; SonicWall SonicOS 7 E-CLI; Arista EOS |
| Basic support | F5 BIG-IP TMOS saved tmsh/SCF text exports |

Coverage varies by device, software release, and export format. [Supported devices](docs/SUPPORTED_DEVICES.md) lists the exact input and detection boundaries.

## What a report tells you

The checks cover applicable management access, authentication, credentials, logging, network policy, routing trust, VPN, cryptography, and platform protections. They favor effective settings and attached policies over unused configuration objects. Each report also includes a coverage ledger showing what was assessed, unknown, unsupported, or excluded.

This is **static configuration analysis**, not a live device test. An empty findings list is not a clean bill of health: missing export data, inherited or dynamic settings, and runtime behavior may remain unknown. In particular, the tool cannot confirm live reachability, policy installation, negotiated VPN state, the certificate actually served, or whether a backup succeeded. See [Supported devices](docs/SUPPORTED_DEVICES.md) for platform-specific limits.

## Install

Python 3.10 or newer is required. From the repository root:

```powershell
# Windows PowerShell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
```

```bash
# Linux or macOS
python3 -m venv .venv
.venv/bin/python -m pip install -e .
```

## Run an audit

```powershell
pynipper-ng -d cisco-ios -i tests\test_data\cisco_ios_example.conf -o HTML -f report.html -x
```

`-d` selects the configuration family; it defaults to `auto` when omitted. Auto-detection works only for distinctive exports and stops with guidance when, for example, IOS and IOS-XE cannot be distinguished. Use `-d cisco-ios` or `-d cisco-ios-xe` explicitly in that case. Older device IDs still work, but the short names shown by `pynipper-ng --help` are recommended. Device role (such as switch or access edge) is separate from the configuration family.

`-i` supplies the export, `-o` selects `HTML` or `JSON`, and `-f` names the report. `-x` keeps the run offline by disabling the optional Cisco openVuln advisory lookup (IOS, only when API credentials are configured).

### Known CVEs for the configured release (opt-in)

`--cve-lookup` asks the free [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities) which CVEs affect the software release recorded in the export. The report then lists them with their CVSS score and flags any in the CISA Known Exploited Vulnerabilities catalog:

```
pynipper-ng -d fortios -i fortigate.conf -o HTML -f report.html --cve-lookup
```

- The lookup sends only the product and release (a CPE name such as `cpe:2.3:o:fortinet:fortios:7.4.6`) to NVD, never configuration content. Default runs make no request.
- Without an API key NVD allows about one request every six seconds, so a lookup takes a few requests and some seconds. A free key from NVD raises the limit: set `NVD_API_KEY` or add `API_KEY` under `[NVD]` in the `-c` configuration file. The key is never written to a report.
- Some exports only state a release train (IOS-XE `version 17.9`). Supply the exact running release with `--software-version 17.9.4a`.
- `--cve-save FILE` stores the NVD responses; `--cve-data FILE` replays them later without network access (for example together with `-x`).
- Qualified families: IOS, IOS-XE, ASA, FortiOS, Junos, ScreenOS, PAN-OS, Arista EOS, SonicOS and F5 BIG-IP (LTM module only). AOS-S, PIX and Check Point policy exports are reported as not supported.
- A listed CVE means NVD records the release as affected. It does not show that the vulnerable feature is enabled, and NVD may lack product data for very recent CVEs. If a release is missing from NVD's CPE dictionary, the report says so instead of claiming there are no CVEs.

Reports mask credential values by default. `--show-secrets` adds a separate, unmasked source-line appendix for parser-qualified credentials on Cisco IOS/IOS-XE/ASA, FortiOS, Junos, ScreenOS, SonicOS 7, HP ProCurve/ArubaOS-Switch, Arista EOS, F5 BIG-IP TMOS and PAN-OS (secret XML elements only). On Cisco IOS/IOS-XE/ASA and Arista EOS it also covers effective SNMP communities/v3 keys and NTP keys; on IOS/IOS-XE/EOS it adds bound BGP/OSPF/RIP/EIGRP keys, TACACS+ keys and IKE pre-shared keys, on ASA tunnel-group pre-shared keys and AAA server keys, and on Junos active RADIUS/TACACS+ secrets, NTP keys, SNMP communities and v3 keys, IKE pre-shared keys and routing authentication keys; it does **not** unmask normal finding evidence or guarantee that every secret in an export was found. The option requires an explicit `-f` pointing to a new file and is rejected for other families. Treat the resulting HTML/JSON file as sensitive, especially on shared systems; see [Security](SECURITY.md).

Check Point Firewall-1 expects a directory with matching export files, such as `rules.C` and `objects.C`. F5 BIG-IP expects a saved tmsh/SCF text file. The [supported-device guide](docs/SUPPORTED_DEVICES.md) describes other input formats.

For checks that need facts outside the export—such as interface roles, audit time, certificate expectations, or organization-specific requirements—pass a JSON file with `--assessment-policy`. These checks remain conservative when context is not supplied. See [Assessment policy](docs/ASSESSMENT_POLICY.md) for the schema and examples.

If parsing fails, inspect the report's `parse_error` coverage rather than treating an empty findings list as a successful audit. PAN-OS and FortiOS deployment templates with unresolved markers are marked `unrendered-template`; use a rendered device export for a complete assessment.

## Develop and validate

Run the unit suite and permanent configuration corpus together:

```powershell
.\.venv\Scripts\python.exe scripts\run_full_regression.py
```

Start with [Architecture](docs/ARCHITECTURE.md) for the parser, analyzer, and report flow, then [Extending pynipper-v2](docs/EXTENDING.md) to add checks or device support. The [parser](src/devices/README.md) and [analyzer](src/analyze/README.md) guides document their contracts. See also [Contributing](CONTRIBUTING.md), [Security](SECURITY.md), the [improvement list](docs/TODO.md), and the [changelog](CHANGELOG.md).

Never add real credentials, private keys, or unsanitized customer configurations to issues or tests.

## Project lineage

This project is a substantially extended fork of [syn-4ck/pynipper-ng](https://github.com/syn-4ck/pynipper-ng), itself inspired by [arpitn30/nipper-ng](https://github.com/arpitn30/nipper-ng). The current architecture, device coverage, and validation process are documented here.
