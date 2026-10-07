# pynipper-v2

pynipper-v2 checks saved network-device configurations for security problems. You give it a configuration export and it writes an HTML or JSON report with each finding, the configuration lines behind it, its severity and how to fix it.

Configuration audits run offline. Optional advisory downloads use a separate command; audits read saved bundles locally.

The installed command is `pynipper-ng`, kept for compatibility with the original project.

## Supported devices

**Full baselines**

- Cisco IOS and IOS-XE
- Cisco ASA (PIX aliases remain provisional)
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
| `-x` | Compatibility flag; every audit is already offline |
| `--assessment-policy FILE` | Add facts the export can't show, such as interface roles or your own requirements. See [Assessment policy](docs/ASSESSMENT_POLICY.md) |
| `--cve-data FILE` | Read known CVEs and end-of-support data from a local advisory bundle |
| `--show-secrets` | Add an unmasked credential appendix (see below) |

Example with an explicit device type and JSON output:

```powershell
pynipper-ng -d cisco-ios -i tests\test_data\cisco_ios_example.conf -o JSON -f report.json -x
```

## Reading the report

Checks cover management access, authentication, passwords and keys, logging, firewall policy, routing, VPN, cryptography and platform protections. Each report also has a coverage section that lists what was checked, what was unknown and what isn't supported. Registered controls cover many existing checks, but coverage is not yet exhaustive; [open work](docs/TODO.md) distinguishes remaining implementation from evidence gates.

Keep in mind:

- **This is a static review of a saved file, not a live test.** It can't see whether a policy is installed, what certificate is actually served, or whether a backup succeeded.
- **No findings doesn't mean secure.** Missing data, inherited settings and runtime behavior may be unknown. Check the coverage section.
- **Omitted settings and unknown evidence are different.** A required protection missing inside an exported object can be a finding; documented defaults are release-qualified. Absent sections, malformed/unsupported values, external inheritance and needed unverified defaults remain unknown. See [export evidence](docs/EXPORT_EVIDENCE.md).
- If a report shows a `parse_error`, the export couldn't be read. PAN-OS and FortiOS templates with unfilled placeholders are marked `unrendered-template`; use a real device export instead.

## Many devices at once

List the exports in a JSON manifest and audit them in one run. Each device gets its own JSON report (add `--html` for HTML too), plus a `batch-index.json` with input hashes, assessment-policy hashes and an analyzer fingerprint. A failing device doesn't stop the others, and existing reports are never overwritten unless you pass `--overwrite`.

Before creating outputs, batch checks every report/index destination against all supplied artifacts, export-directory subtrees and filesystem aliases. Unsafe collisions fail without changing inputs or outputs; `--overwrite` only permits replacing safe report files. Noncolliding reports may share a flat configuration file's directory.

```powershell
python -m src.batch run --manifest batch.json --output-dir reports\2026-10
python -m src.batch compare --old reports\2026-09\batch-index.json --new reports\2026-10\batch-index.json --output comparison.json
```

```json
{"schema-version": 1,
 "devices": [{"id": "edge-fw-1", "input": "exports/fw1.conf", "device": "auto",
              "assessment-policy": "policy.json", "export-scope": "full running configuration"}]}
```

`compare` lists findings as new, unchanged, resolved, no longer assessable or not comparable. Resolution requires a matching canonical device family, known matching analyzer fingerprints and matching qualified policy provenance. Missing/failed exports, exclusions, templates and scoped control uncertainty are not fixes. Manifest IDs are auditor-declared identities, not verified physical devices. Finding keys remain evidence-based; without subject bindings, uncertainty conservatively blocks resolution for the affected control. Old aggregate-only reports remain readable with an explicit limitation note. See [comparison and cache contracts](docs/EXPORT_EVIDENCE.md#batch-safety-and-comparison).

## Known CVEs and end of support (opt-in)

```powershell
python -m src.advisories fetch -d fortios --software-version 7.4.6 --output fortios-advisories.json
pynipper-ng -i fortigate.conf -f report.html --cve-data fortios-advisories.json
```

- Asks the free [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities) which CVEs affect the release in the export. The report lists them with their CVSS score and marks those in the CISA Known Exploited Vulnerabilities catalog.
- Also shows end-of-support status from [endoflife.date](https://endoflife.date) for FortiOS, PAN-OS, Cisco IOS XE and F5 BIG-IP.
- **Only the product and version are sent** (for example `cpe:2.3:o:fortinet:fortios:7.4.6`), never configuration content. endoflife.date receives only the product name.
- If the export only shows a release train (IOS-XE `version 17.9`), give the exact release with `--software-version 17.9.4a`.
- Without an API key a lookup takes a few seconds. A free NVD key makes it faster: set `NVD_API_KEY`, or `API_KEY` under `[NVD]` in the `-c` configuration file. The key is never written to a report.
- The separate `fetch` command stores responses in a new file; `--cve-data FILE` replays them during an offline audit. Old audit flags `--cve-lookup` and `--cve-save` now explain how to migrate. Cisco credentials no longer trigger automatic lookup.
- Works for IOS, IOS-XE, ASA, FortiOS, Junos, ScreenOS, PAN-OS, Arista EOS, SonicOS, ArubaOS-Switch 16.x and F5 BIG-IP (supply each provisioned module with repeated `--module ltm`, `--module apm`, etc. when fetching). PIX, older ProCurve releases and Check Point are reported as not supported.
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
.\.venv\Scripts\python.exe -m pytest tests -q
.\.venv\Scripts\python.exe scripts\run_full_regression.py
```

Where to start:

- [Architecture](docs/ARCHITECTURE.md): how parsers, analyzers and reports fit together
- [Extending pynipper-v2](docs/EXTENDING.md): adding checks or a new device
- [Export evidence](docs/EXPORT_EVIDENCE.md): incomplete exports, scoped outcomes and policy-proof limits
- [Parser guide](src/devices/README.md) and [analyzer guide](src/analyze/README.md)
- [Contributing](CONTRIBUTING.md), [Security](SECURITY.md), [open work](docs/TODO.md), [changelog](CHANGELOG.md)

Never put real credentials, private keys or unsanitized customer configurations in issues or tests.

## Project history

A substantially extended fork of [syn-4ck/pynipper-ng](https://github.com/syn-4ck/pynipper-ng), which was inspired by [arpitn30/nipper-ng](https://github.com/arpitn30/nipper-ng).
