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
| Juniper | ScreenOS | Target baseline; EOL, with additional default-policy and session-control semantics qualified for 6.3 exports |

PAN-OS, HP ProCurve/ArubaOS-Switch, SonicWall SonicOS 7 E-CLI, and Arista EOS have expanded, tested static baselines. Their support remains bounded by the documented input dialects and static-analysis limits. See [Supported devices](docs/SUPPORTED_DEVICES.md) for precise boundaries and [Architecture](docs/ARCHITECTURE.md) for the extension model.

## What the analyzer can and cannot prove

The target pipelines inspect management exposure, authentication and credentials, logging, SNMP, NTP, cryptography/VPN, interfaces/control-plane protections, policy breadth, and bounded BGP/OSPF routing trust where those concepts exist in the supplied export. IOS/IOS-XE, Junos and EOS control-plane analysis resolves active attachments into matching policy, class, ACL/filter and policer/rate-action content; omitted system-owned policies remain unknown/platform-managed, and configured rates are not declared adequate without workload context. FortiOS evaluates enabled IPv4/IPv6 DoS anomalies independently for pass/block behavior, logging and threshold state. FortiOS 7.4+ additionally resolves administrative RADIUS bindings and checks concrete RadSec identity/TLS failures without treating every legacy RADIUS path as insecure. Junos resolves named-user login classes and effective CLI timeouts, pre-login notices, remote accounting coverage/destinations, and explicit J-Web session bounds while retaining unexpanded group inheritance as unknown. PAN-OS resolves local administrator roles/authentication profiles, explicit management banner/session/lockout settings, and applied PAN-OS 10+ SSH profiles while preserving Panorama and upstream MFA uncertainty. ArubaOS-S 16.10/16.11 resolves manager/operator credential state, channel-specific login/enable methods, remote CLI/serial/WebAgent idle timeouts, MOTD state, and independent WebAgent plaintext/TLS enablement; credentials omitted without `include-credentials` and unsupported releases remain unknown. FortiOS and PAN-OS active allow policies resolve attached inspection groups and profiles so an empty, explicitly non-blocking or invalid object cannot pass on its name alone. Check Point FW1, PAN-OS, Cisco ASA, IOS/IOS-XE interface ACLs, FortiOS, Junos SRX, ScreenOS and SonicOS share conservative IPv4/IPv6 and protocol/port containment primitives for proven redundancy and shadowing while retaining platform-native scope and ordering. Proof remains limited to fully resolved static predicates: dynamic or inherited objects, schedules, negation, unsupported applications and other unmodeled match state block effectiveness conclusions. FortiOS IPv4/IPv6 local-in policy is assessed separately from transit policy, while FortiOS and Junos follow only active policy/interface VPN attachments to explicit IKE/IPsec proposal chains. Junos SRX zone-pair analysis is likewise separate from stateless firewall filters, and runtime-unused claims always require operational counters and an observation window.

This is static analysis. It cannot prove runtime reachability, policy installation, negotiated VPN transforms or peer identity, the certificate actually served or its live revocation status, external authentication health, dynamic object membership, runtime-unused rules, or controls that are not present in the configuration files. PAN-OS, ASA and active-HTTPS FortiOS can evaluate exported public certificate material reproducibly when the assessment policy supplies a timestamp, intended identity and approved exported trust-anchor fingerprints. Junos administrative RADIUS/RadSec and attached ASA connection-limit analysis are also bounded to explicit configuration evidence; neither proves live transport or rate adequacy. Check Point analysis has additional offline-export limits documented in the supported-device guide.

Reports include an explicit normalized coverage ledger. Optional configuration inventory is off by default and limited to sanitized management services, interfaces, effectively attached policies and logging destinations; it never serializes evidence, credentials, certificate material or raw configuration. IOS/IOS-XE inventory excludes unattached ACL definitions and preserves absent model/default information as unknown.

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
| `--assessment-policy` | Optional JSON policy containing explicit roles, protected AAA paths, configuration-backup scope, credential length/blocklist policy, certificate time/identity/trust inputs, opt-in sanitized report inventory, and category exclusions | Built-in policy; all contextual facts unknown, no inventory, and no exclusions |

Accepted device IDs and aliases are generated from `src/devices/registry.py`; run `pynipper-ng --help` for the current list.

If a FortiOS input fails structural parsing, the command writes a report with `parse_error` coverage and exits with status 2. No security checks run on that failed input; the report's empty finding list does not indicate a successful audit.

PAN-OS and FortiOS inputs containing unresolved deployment-template markers are marked `unrendered-template` in report coverage. Findings that require a complete configuration are suppressed; explicit configured risks may still be reported. Audit a rendered, full device export before treating absent findings as assurance.

See [Assessment policy](docs/ASSESSMENT_POLICY.md) for the validated JSON schema and its conservative scope rules. Excluded categories are recorded in the report and are never represented as compliant.

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
docs/                        architecture, extension, support, and assessment-policy guides
```

The end-to-end design and normalized parser contract are documented in [Architecture](docs/ARCHITECTURE.md). To add a check or device family, follow [Extending pynipper-v2](docs/EXTENDING.md); it includes required contracts, test cases, corpus updates, and documentation steps. The [parser](src/devices/README.md) and [analyzer](src/analyze/README.md) guides describe the current implementation boundaries.

## Security and contributions

- [Contributing guide](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Supported devices and input boundaries](docs/SUPPORTED_DEVICES.md)
- [Assessment policy](docs/ASSESSMENT_POLICY.md)
- [Open improvement work](docs/TODO.md)
- [Change history](CHANGELOG.md)

Do not include real credentials, private keys, community strings, or unsanitized customer configurations in issues, tests, or reports.

## Project lineage

This repository is a substantially extended fork of [syn-4ck/pynipper-ng](https://github.com/syn-4ck/pynipper-ng), which was itself a Python-oriented continuation inspired by [arpitn30/nipper-ng](https://github.com/arpitn30/nipper-ng). Their work remains acknowledged here, while the current architecture, device matrix, validation process, and documentation describe `pynipper-v2` as it exists today.
