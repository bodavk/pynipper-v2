# pynipper-v2

pynipper-v2 checks saved network-device configurations for security problems. You give it a configuration export and it writes an HTML or JSON report with each finding, the configuration lines behind it, its severity and how to fix it.

It works offline by default, and nothing is sent anywhere unless you turn on the optional CVE lookup.

The installed command is `pynipper-ng`, kept for compatibility with the original project.

## Supported devices

**Full baselines**

- Cisco IOS and IOS-XE
- Cisco ASA (and PIX)
- Fortinet FortiGate (FortiOS)
- Juniper Junos
- Juniper ScreenOS
- Check Point Firewall-1 (policy export: `rules.C` + `objects.C`)

**Extended baselines**

- Palo Alto PAN-OS (XML export)
- HP ProCurve / ArubaOS-Switch
- SonicWall SonicOS 7 (E-CLI `show current-config custom`)
- Arista EOS

**Basic support**

- F5 BIG-IP (saved tmsh/SCF text export)
- Check Point Gaia OS (Clish `show configuration` output)

Depth varies by device, software release and export format. See [Supported devices](docs/SUPPORTED_DEVICES.md) for exactly what is checked on each one.

## Install

You need Python 3.10 or newer. From the repository folder:

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

## Quick start

```powershell
pynipper-ng -i my-router.conf -f report.html
```

The device type is detected automatically when the export makes it clear. If it can't tell (for example IOS vs. IOS-XE), it asks you to choose with `-d`.

Common options:

| Option | What it does |
|---|---|
| `-i FILE` | The configuration export to check (a folder for Check Point Firewall-1) |
| `-f FILE` | Report file name |
| `-o HTML` / `-o JSON` | Report format (HTML is the default) |
| `-d NAME` | Set the device type yourself. Run `pynipper-ng --help` for the names, e.g. `cisco-ios`, `fortios`, `checkpoint-gaia` |
| `-x` | Stay fully offline (turns off the optional Cisco openVuln lookup, which only runs for IOS with API credentials) |
| `--assessment-policy FILE` | Add facts the export can't show, such as interface roles or your own requirements. See [Assessment policy](docs/ASSESSMENT_POLICY.md) |
| `--cve-lookup` | Look up known CVEs and end-of-support status for the software release (see below) |
| `--show-secrets` | Add an unmasked credential appendix (see below) |

Example with an explicit device type and JSON output:

```powershell
pynipper-ng -d cisco-ios -i tests\test_data\cisco_ios_example.conf -o JSON -f report.json -x
```

## Reading the report

Checks cover management access, authentication, passwords and keys, logging, firewall policy, routing, VPN, cryptography and platform protections. Each report also has a coverage section that lists what was checked, what was unknown and what isn't supported.

Keep in mind:

- **This is a static review of a saved file, not a live test.** It can't see whether a policy is installed, what certificate is actually served, or whether a backup succeeded.
- **No findings doesn't mean secure.** Missing data, inherited settings and runtime behavior may be unknown. Check the coverage section.
- **Unset values are not reported as problems** unless the vendor documents an insecure default. Each finding says whether it comes from an explicit value, a documented default or a missing required setting.
- If a report shows a `parse_error`, the export couldn't be read. PAN-OS and FortiOS templates with unfilled placeholders are marked `unrendered-template`; use a real device export instead.

## Known CVEs and end of support (opt-in)

```powershell
pynipper-ng -i fortigate.conf -f report.html --cve-lookup
```

- Asks the free [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities) which CVEs affect the release in the export. The report lists them with their CVSS score and marks those in the CISA Known Exploited Vulnerabilities catalog.
- Also shows end-of-support status from [endoflife.date](https://endoflife.date) for FortiOS, PAN-OS, Cisco IOS XE and F5 BIG-IP.
- **Only the product and version are sent** (for example `cpe:2.3:o:fortinet:fortios:7.4.6`), never configuration content. endoflife.date receives only the product name.
- If the export only shows a release train (IOS-XE `version 17.9`), give the exact release with `--software-version 17.9.4a`.
- Without an API key a lookup takes a few seconds. A free NVD key makes it faster: set `NVD_API_KEY`, or `API_KEY` under `[NVD]` in the `-c` configuration file. The key is never written to a report.
- `--cve-save FILE` stores the responses; `--cve-data FILE` replays them later offline.
- Works for IOS, IOS-XE, ASA, FortiOS, Junos, ScreenOS, PAN-OS, Arista EOS, SonicOS, ArubaOS-Switch 16.x and F5 BIG-IP (each provisioned module is looked up). PIX, older ProCurve releases and Check Point are reported as not supported.
- A listed CVE means NVD records the release as affected. It doesn't prove the vulnerable feature is turned on.
- Behind a company proxy that inspects HTTPS, the Windows certificate store is used automatically. If you still get a TLS error, set `REQUESTS_CA_BUNDLE` to your organization's CA file.

## Showing secrets (opt-in)

Reports hide passwords, keys and community strings by default. `--show-secrets` adds a separate appendix with the original credential lines, for example to hand hashes to a password review.

- It needs `-f` pointing to a **new** file; existing files are never overwritten.
- Treat that report as a credential file and don't share or upload it.
- Supported on every family except Check Point Firewall-1 policy exports. [Supported devices](docs/SUPPORTED_DEVICES.md#what---show-secrets-shows) lists what is shown per device, and [Security](SECURITY.md) explains how the file is protected.

## For developers

Run the unit tests and the permanent configuration corpus:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts\run_full_regression.py
```

Where to start:

- [Architecture](docs/ARCHITECTURE.md): how parsers, analyzers and reports fit together
- [Extending pynipper-v2](docs/EXTENDING.md): adding checks or a new device
- [Parser guide](src/devices/README.md) and [analyzer guide](src/analyze/README.md)
- [Contributing](CONTRIBUTING.md), [Security](SECURITY.md), [open work](docs/TODO.md), [changelog](CHANGELOG.md)

Never put real credentials, private keys or unsanitized customer configurations in issues or tests.

## Project history

A substantially extended fork of [syn-4ck/pynipper-ng](https://github.com/syn-4ck/pynipper-ng), which was inspired by [arpitn30/nipper-ng](https://github.com/arpitn30/nipper-ng).
