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
pynipper-ng -d IOS_ROUTER -i tests\test_data\cisco_ios_example.conf -o HTML -f report.html -x
```

`-d` selects the device family, `-i` supplies its export, `-o` selects `HTML` or `JSON`, and `-f` names the report. `-x` keeps the run offline by disabling optional Cisco advisory lookup. Run `pynipper-ng --help` for device IDs, aliases, and all options.

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
