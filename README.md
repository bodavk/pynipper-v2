# pynipper-v2

`pynipper-v2` is an offline-first security configuration analyzer for network devices. It parses exported configurations, evaluates effective security state, and produces HTML or JSON findings with stable rule IDs, severity, remediation guidance, source evidence, and—where implemented—vendor or benchmark references.

The installed command remains `pynipper-ng` for compatibility with existing usage.

## Current scope

The primary, regression-gated platforms are:

| Vendor | Configuration family | Status |
|---|---|---|
| Cisco | IOS | Target baseline |
| Cisco | IOS-XE | Target baseline |
| Cisco | ASA | Target baseline |
| Fortinet | FortiGate / FortiOS | Target baseline |
| Check Point | Firewall-1 legacy management exports | Target offline-policy baseline |
| Juniper | Junos | Target baseline |
| Juniper | ScreenOS | Target baseline; the platform is end-of-life |

PAN-OS, HP ProCurve/ArubaOS-Switch, SonicWall SonicOS 7 E-CLI, and Arista EOS have expanded, tested static baselines. Wave 7 closed their planned T-030/T-032 packs without claiming the same breadth as the seven prioritized target platforms or universal version/dialect support. See [Supported devices](docs/SUPPORTED_DEVICES.md) for precise boundaries and the [Wave 7 report](docs/agent_notes/WAVE7_SECONDARY_BASELINE_REPORT.md) for evidence and limitations.

## What the analyzer can and cannot prove

The target pipelines inspect management exposure, authentication and credentials, logging, SNMP, NTP, cryptography/VPN, interfaces/control-plane protections, and policy breadth where those concepts exist in the supplied export.

This is static analysis. It cannot prove runtime reachability, policy installation, certificate validity, external authentication health, dynamic object membership, or controls that are not present in the configuration files. Check Point analysis has additional offline-export limits documented in the supported-device guide.

## Requirements and installation

- Python 3.10 or newer
- A virtual environment is recommended

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e .
```

Linux or macOS:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e .
```

## Usage

Analyze a configuration without external advisory lookups:

```powershell
pynipper-ng --device IOS_ROUTER --input tests\test_data\cisco_ios_example.conf --output-type HTML --output-filename report.html --offline
```

Generate JSON instead:

```powershell
pynipper-ng -d FORTIOS -i path\to\fortigate.conf -o JSON -f report.json -x
```

Check Point Firewall-1 uses a directory containing matching export files such as `rules.C` and `objects.C`:

```powershell
pynipper-ng -d CHECKPOINT_FW1 -i path\to\checkpoint-export -o HTML -f report.html -x
```

Useful options:

| Option | Meaning | Default |
|---|---|---|
| `-d`, `--device` | Canonical device ID or registered alias | Required |
| `-i`, `--input` | Configuration file, or a directory for Check Point exports | Required |
| `-o`, `--output-type` | `HTML` or `JSON` | `HTML` |
| `-f`, `--output-filename` | Report path | `report.html` |
| `-x`, `--offline` | Disable external Cisco advisory lookup | Online lookup is allowed when credentials exist |
| `-c`, `--configuration` | Tool configuration containing optional API credentials | Bundled `default.conf` |

Accepted device IDs and aliases are generated from `src/devices/registry.py`; run `pynipper-ng --help` for the current list.

## Validation

Run the permanent target-platform corpus and the complete unit suite:

```powershell
.\.venv\Scripts\python.exe scripts\run_full_regression.py
```

The corpus contains paired vulnerable and hardened configurations for every target pipeline and compares exact, duplicate-preserving finding snapshots. A mismatch causes a non-zero exit.

The repository workflow runs this same gate on Python 3.10 and 3.13 across Linux, Windows, and macOS.

To run only the tests:

```powershell
.\.venv\Scripts\python.exe -m pytest tests -q
```

## Project structure

```text
src/devices/                 parser implementations and authoritative registry
src/devices/common/          parser contract and normalized configuration models
src/analyze/                 platform processors and security plugins
src/analyze/common/          shared plugin and Finding contracts
src/report/                  HTML/JSON report generation
tests/                       parser, plugin, architecture, and report tests
tests/test_data/regression/  permanent target-platform corpus and snapshots
scripts/                     repository validation utilities
docs/                        architecture, extension, support, and quality documents
```

The end-to-end design is documented in [Architecture](docs/ARCHITECTURE.md). To add a check or device family, follow [Extending pynipper-v2](docs/EXTENDING.md); it includes required contracts, test cases, corpus updates, and documentation steps.

## Security and contributions

- [Contributing guide](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Project status](docs/STATUS.md)
- [Roadmap](docs/ROADMAP.md)
- [Change history](CHANGELOG.md)

Do not include real credentials, private keys, community strings, or unsanitized customer configurations in issues, tests, or reports.

## Project lineage

This repository is a substantially extended fork of [syn-4ck/pynipper-ng](https://github.com/syn-4ck/pynipper-ng), which was itself a Python-oriented continuation inspired by [arpitn30/nipper-ng](https://github.com/arpitn30/nipper-ng). Their work remains acknowledged here, while the current architecture, device matrix, validation process, and documentation describe `pynipper-v2` as it exists today.
