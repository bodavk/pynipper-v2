# Open tasks from practical testing

Recorded **2026-09-24** from hands-on use of the tool. These are defects and usability gaps. PT-001 to PT-007 were implemented on 2026-09-24 (see status per task); PT-008 is open. Follow [Architecture](../ARCHITECTURE.md) and [Extending](../EXTENDING.md). Every task finishes with `.\.venv\Scripts\python.exe scripts\run_full_regression.py`, and any snapshot change must be reviewed deliberately.

| ID | Priority | Title |
|---|---|---|
| PT-001 | P1 | Pin MarkupSafe so a fresh install works (**done**) |
| PT-002 | P1 | FortiOS: parse quoted values that span several lines (**done**) |
| PT-003 | P1 | Audit all other parsers for multi-line values (**done**) |
| PT-004 | P1 | Show source line numbers with finding evidence (**done**, see remaining gaps) |
| PT-005 | P2 | Redesign the HTML report for readability (**done**) |
| PT-006 | P2 | Layered, user-friendly finding explanations (**done**) |
| PT-007 | P2 | Point to related findings and compensating controls (**done**) |
| PT-008 | P3 | Modernise the dependency stack (long-term fix for PT-001) |
| PT-009 | P3 | Say whether a finding is an insecure value or a missing explicit hardening setting |
| PT-010 | P1 | Look up known CVEs for the software version found in the configuration (opt-in) (**first stage done**) |

<a id="pt-001"></a>
### PT-001: Pin MarkupSafe
**Problem:** `requirements.txt` pins `Jinja2==2.11.3` but leaves MarkupSafe unpinned. MarkupSafe 2.1 and later removed `soft_unicode`, so on a fresh install the report module fails to import. Existing venvs work only because they already have MarkupSafe 2.0.1.
**Fix:** Add `markupsafe<2.1` (for example `==2.0.1`) to `requirements.txt`, which `setup.py` also reads.
**Acceptance:** `pip install -e .` into a fresh venv, then the full regression passes. Add a CHANGELOG entry.
**Status:** Done. `MarkupSafe>=2.0,<2.1` added with a comment; a fresh `pip install .` resolves MarkupSafe 2.0.1 and the report module imports.

<a id="pt-002"></a>
### PT-002: FortiOS multi-line quoted values
**Problem:** A real FortiGate export stores `set private-key "-----BEGIN ...` along with certificates, CA material and some secrets across several physical lines. The parser tokenizes each physical line on its own, and `shlex` raises "No closing quotation". The result is a parse-error report with no checks run. `_tokens()` only handles one-line PEM with escaped `\n`.
**Fix, owned by the parser:**
- Build logical lines by joining physical lines until the quotes balance, honoring escaped quotes.
- Record the starting physical line number and put that in the evidence.
- Keep the one-line `\n` escape form working.
- Private keys and secrets never enter records or evidence. Only presence or redacted state is kept.
- Public certificate material continues into the certificate evaluator.
- An unterminated quote at end of file is still a controlled `PARSE_ERROR`, reported with the start line.
**Tests:**
- Private key, certificate, CA certificate, a multi-line secret and a multi-line `comments`/replacement-message value.
- Both the escaped one-line form and the real multi-line form.
- CRLF input.
- Unterminated quote at end of file.
- Redaction in JSON and HTML output.
- Findings after the multi-line block still keep correct line numbers.
- A sanitized permanent corpus input.

**Status:** Done. New shared helper `src/devices/common/source_lines.py` (`group_double_quoted_lines`, `single_line_evidence`). FortiOS joins logical lines, keeps first-line evidence with a `<value continues to line N>` marker, and prints the whole value in the opt-in secret appendix. Added corpus case `fortios-multiline-values` (with a throwaway self-signed public certificate and a fake key) and `tests/test_multiline_values_pt002.py`.

<a id="pt-003"></a>
### PT-003: Multi-line values on the other supported families
**Problem:** The same class of bug may exist wherever a parser works line by line.
**Scope:** For each parser, build a sanitized fixture with that platform's real multi-line constructs, then fix any failure in the parser the same way as PT-002. Constructs to check:
- **IOS/IOS-XE:** delimited `banner` blocks, `crypto pki certificate chain` hex blocks, `key pubkey-chain`/`key-string` blocks.
- **ASA:** `crypto ca certificate chain ... quit`, banners.
- **Junos:** multi-line quoted strings (certificates, SSH keys, announcement/message text).
- **ScreenOS:** multi-line quoted values.
- **EOS:** `banner ... EOF` blocks and SSL certificate/key material.
- **AOS-S:** multi-line quoted MOTD/banner text.
- **SonicOS:** certificate/key and banner values.
- **F5 TMOS:** multi-line quoted strings and certificate/key blocks inside `{ }`.
- **PAN-OS XML and Check Point:** confirm they are unaffected.
**Acceptance:** A per-family result table in this file listing construct, status and test. Every failing construct is fixed and has a regression test, and nothing is redacted less than before.

**Status:** Done. Results (tests in `tests/test_multiline_values_pt002.py`):

| Family | Construct | Before | Now |
|---|---|---|---|
| FortiOS | quoted PEM key/cert, comments, replacemsg buffer | parse error, no checks | grouped (PT-002) |
| Junos display-set | multi-line quoted string | misdetected as hierarchical, silent empty analysis | grouped; unterminated = parse error |
| Junos hierarchical | multi-line quoted string | OK (lexer handles it) | unchanged |
| ScreenOS | multi-line quoted banner | shlex diagnostic; body lines read as commands | grouped; unterminated = diagnostic |
| AOS-S (HP) | multi-line `banner motd "..."` | body lines read as commands (false findings); banner not recognized | grouped; banner recognized |
| SonicOS 7 | multi-line quoted banner | body lines read as commands | grouped; unterminated = diagnostic |
| IOS / IOS-XE | delimited `banner <type> ^C ... ^C` | CiscoConfParse OK, but line scanners read body as commands (false SNMP findings) | body masked, line numbers kept |
| IOS / IOS-XE, ASA | `crypto pki/ca certificate chain` hex blocks | OK (indented children) | unchanged |
| IOS / IOS-XE / EOS, ASA | blank lines | CiscoConfParse dropped them, shifting evidence line numbers | comment placeholders keep physical numbering |
| EOS | `banner login` ... `EOF` | body read as commands (false credential finding) | body masked |
| F5 TMOS | multi-line quoted text, iRule braces | OK | unchanged (smoke test) |
| PAN-OS XML, Check Point | multi-line text | OK by grammar | unchanged |

<a id="pt-004"></a>
### PT-004: Source line numbers in evidence
**Problem:** `Finding.evidence` holds plain strings, so the report can't tell the user where to look in the configuration. Parsers already keep `ConfigEvidence.line_number` in many records.
**Fix:**
- Add an optional structured evidence location (sanitized text plus line number, and source file for multi-file inputs such as Check Point) to `Finding`. This is an addition: the existing `evidence` strings and JSON keys stay, and a new key is added alongside them.
- Plugins pass the parser's `ConfigEvidence` through.
- Where no line is available, show "line not available". Never guess one.
- Migrate plugins family by family.
**Tests:** Line numbers are correct after multi-line blocks and ordered overrides. The duplicate test still works. A coverage test tracks which rules have locations.

**Status:** Done (`tests/test_evidence_lines_pt004.py`). `Finding` accepts `ConfigEvidence` or strings and adds `evidence_locations` (`text`, `line`, `source`, `line_origin`) to JSON. About 160 plugin sites now pass `ConfigEvidence` instead of `.text`. Processors call `attach_source_lines`, which fills a line only for text equal to exactly one input line (`source-match`). PAN-OS records XML element start lines, and Check Point fields keep their expression line. The HTML shows `Line N (file)`. Corpus coverage is 320 of 402 evidence entries; the rest are absence or derived statements.
**Remaining gaps (low priority):** Some derived texts could cite a parser line if the parser exposed it. Examples: ASA `interface <nameif>` and "active ssh management grant", ScreenOS "ScreenOS version", HP "credential configured", EOS redacted SNMP community. Migrate them when those checks are next touched.

<a id="pt-005"></a>
### PT-005: HTML report readability
**Problem:** Every finding looks alike, so the important details don't stand out.
**Fix:**
- An executive summary: severity counts and the top risks.
- Findings sorted by severity with coloured severity badges.
- A consistent layout per finding: what was found, why it matters, how to fix it, then evidence with line numbers (PT-004).
- A table of contents or filter by severity/category.
- Collapsible technical detail.
- Coverage and unknown state visually separated from findings.
- Print-friendly, fully offline (no external assets), and autoescaping kept.
- JSON output stays unchanged apart from additions.
**Tests:** Template tests for ordering, escaping, the secret appendix and parse-error reports. Manual review against the real FortiGate and IOS samples.

**Status:** Done.
- New template, `style.css` and `report.js` (the filter is optional: the report is complete without JavaScript).
- View data comes from `src/report/explanations.py`.
- Checked in Chromium at desktop and 420 px widths, in light and dark mode, with no horizontal scroll on mobile.
- Tests are in `tests/test_report_readability_pt005_007.py`.
- Still to do: review against the real (non-sanitized) samples.

<a id="pt-006"></a>
### PT-006: Layered finding explanations
**Problem:** Descriptions are technically correct but vague for readers who don't administer the platform every day.
**Fix:**
- Add optional guidance keyed by `rule_id`: a plain-language summary, a concrete example of how an attacker could exploit the weakness, and a more technical explanation.
- Keep this guidance in a per-vendor text catalogue owned by the analyzer layer, not in the parsers.
- Rewrite Critical and High rules first, then Medium.
- Wording must not claim more than the static evidence proves.
**Tests:** Every guidance key matches a real rule ID. A coverage test lists rules that still have no guidance.

**Status:** Done, with one deliberate change: the catalogue is one vendor-neutral module (`src/analyze/common/guidance.py`) rather than per-vendor files. The same weakness has the same explanation on every vendor, and device-specific detail stays in each finding's observation.
- 37 entries cover all 457 static and dynamic rule IDs, and the test requires full coverage.
- Possible follow-up: rule-specific entries for individual high-value rules where the shared text is too generic.

<a id="pt-007"></a>
### PT-007: Related findings and compensating controls
**Problem:** Users aren't told which other controls to check when they see a finding. For example, a broad policy or broad admin rights should prompt a look at logging and audit settings.
**Fix:**
- A small, explicit mapping of rule categories to related control categories (for example broad policy or privilege → logging/audit; weak authentication → source restriction, MFA or lockout).
- The report lists related findings that appear in the same report.
- Where there are none, it says the control should be verified manually, because not assessed does not mean secure.
- This is report-layer only: no new detections and no risk scoring.
**Tests:** Mapping integrity, rendering when related findings are present, and rendering when they are absent.

**Status:** Done. There are 18 areas with explicit relations. Cards list up to five related findings per area, and JSON lists all of them.

<a id="pt-008"></a>
### PT-008: Dependency modernisation (deferred)
**Problem:** Jinja2 2.11.3 (with MarkupSafe 2.0.x) is old, has known advisories, and is the root cause of PT-001. Other pins are old as well (`requests 2.31`, `tqdm 4.56`).
**Fix:**
- Move to maintained Jinja2 3.x and MarkupSafe versions, and adapt the templates.
- Use a lock or constraints file.
- Add a CI job that does a fresh install.
**Priority:** Lower than current work, so do this after the PT-00x bugfixes.

<a id="pt-009"></a>
### PT-009: Explicit insecure value versus missing explicit hardening (low priority)
**Problem:** Some findings fire because a recommended hardening setting is not explicitly configured, rather than because an insecure value is set. For example, a VTY line without `transport input ssh` is reported whatever the release default is. Rule text often says "not explicitly…", but the report does not show this basis consistently, so a reader may think the device is proven insecure.
**Fix:**
- Give each finding a basis: explicit insecure value, documented release default, or missing explicit hardening setting (default not assessed).
- The rule sets the basis where the finding is created; plugins set it explicitly, and the tool never infers it from the wording.
- Show it as a short note on the finding card and in JSON (additive).
- Missing-explicit-setting findings should say that the effective value may already be safe on some releases, and should name the recommended explicit setting.
**Tests:** Basis is set for representative rules of each kind; HTML/JSON rendering; no change to rule IDs or snapshots.
**Status:** In progress (2026-09-25). `FindingBasis` (`explicit-value`, `documented-default`, `missing-explicit-setting`) is an optional `Finding` argument, also accepted by the vendor `_finding` helpers. `to_dict()` adds `basis`; the HTML card shows a labelled note and JSON adds `basis-note` (`src/report/explanations.py`, `BASIS_TEXT`). Declared for: IOS `vty.telnet` (missing `transport input` vs. explicit telnet/all), `vty.insecure_output_transport`, `ip.source_route`, SSH version/retries/timeout (explicit vs. documented default); ASA `management.certificate`; FortiOS `password_policy.disabled` (absent on 7.x = documented default, explicit disable) and `management.insecure_protocol`; EOS `authentication.lockout_disabled`; Junos `ssh.root_login`. Second batch (2026-09-25): explicit-value for configured default communities (IOS, ASA, EOS, AOS-S, F5), write communities (ASA, F5), SNMPv3 users without authPriv (IOS, ASA, EOS, AOS-S) and with MD5/DES (IOS, ASA, EOS, AOS-S, F5), and Junos insecure management services. Deliberately left undeclared: FortiOS/Junos/PAN-OS/SonicOS SNMPv3 security levels and F5 `v3_security` (the level may come from a release default), AOS-S `community_access` (unrestricted may be the default), and absence rules such as missing NTP or remote syslog, which fit none of the three labels. Corpus: 20 of 243 findings carry a basis. Tests: `tests/test_finding_basis_pt009.py`. Remaining: declare the basis in the other rules, one rule at a time, from the code branch that raises the finding.

<a id="pt-010"></a>
### PT-010: CVE lookup for the configured software version (high priority, maintainer request 2026-09-25)

#### Analysis

**What already exists.** Every parser has `get_version()`. Only the Cisco IOS analyzer queries advisories: the Cisco PSIRT openVuln API, which needs a registered client ID and secret in `default.conf`. Every other analyzer passes an empty advisory list. The report already has a "Software advisories" section and a JSON `vulnerabilities` list. The existing `CiscoVuln` has no `to_dict()`, so a JSON report with openVuln results would fail to serialize.

**Version quality in exports** (checked on the regression corpus):

| Family | Example | Precise enough? |
|---|---|---|
| FortiOS | `7.4.6` (from the `#config-version` header) | yes |
| Junos | `22.4R1.10` | yes: release `22.4`, update `R1`; the trailing `.10` build is not used in CPE names |
| PAN-OS | `11.2.3` (`detail-version`) | yes; a hotfix `-h1` goes in the CPE update field |
| EOS | `4.29.2F` | yes |
| ASA | `9.18(4)` | yes, maps to `9.18.4` |
| IOS | `15.2(4)M7` (when the `show version` banner is present) | yes |
| IOS-XE | `17.9` (the `version` line holds only the train) | **no**: a train cannot be matched to affected releases, so the operator must supply the release (`--software-version 17.9.4a`) |
| SonicOS | `7.1.2-7019` | yes |
| F5 TMOS | `16.1.5` | partly: CVEs are recorded per module; the first stage queries LTM only |
| ScreenOS | `6.3.0r27.0` | yes: `6.3.0` plus update `r27` |
| AOS-S | `YA.16.10.0023` | CPE naming not qualified: unsupported for now |
| Check Point FW1 | policy export has no gateway version | no |

**Free data sources considered.**
- **NVD CVE API 2.0** (NIST): free; an API key is optional but raises the rate limit (without a key, about one request per 6 seconds). It supports `cpeName` + `isVulnerable`, which returns CVEs whose applicability statements (including version ranges) match a CPE name from the official dictionary. Each CVE record also carries CISA KEV fields (`cisaExploitAdd`, `cisaVulnerabilityName`), so known-exploited status needs no second download. **Chosen.**
- **NVD CPE API 2.0**: `cpeMatchString` confirms that the exact product/version exists in the CPE dictionary. This matters because a `cpeName` query for a name that is not in the dictionary returns no CVEs, and "not in the dictionary" must not be reported as "no CVEs".
- **CISA KEV JSON feed**: free, but it has no version data, and NVD already includes the KEV fields. Not needed.
- **Vendor APIs**: Cisco openVuln is free but needs registration (kept as is). Fortinet, Juniper, Arista, SonicWall and F5 have no free version-query API. Palo Alto publishes JSON/CSAF, which is a possible later stage.
- **OSV.dev**: covers open-source ecosystems, not network operating systems.

**Limits that must be visible in the report.**
- NVD enrichment lags: recent CVEs may have no CPE data yet, so they are missed. The result is "known to NVD", not "complete".
- A version match is not exploitability. Most network-OS CVEs need a specific feature (SSL VPN, GlobalProtect, web UI and so on) or a hardware platform. This stage does not correlate CVEs with the configuration. When the applicability statement combines the OS with a platform condition (`AND`), the entry is marked as conditional.
- The configuration shows the version it was saved with, which may differ from the running version.
- Privacy: the lookup sends only the product CPE and version to NVD, never configuration content. It is still an outbound request, so it is **opt-in**. Default runs stay offline and deterministic, as the architecture requires (see also SC-022: never silently query vendors).
- CVEs are shown as software advisories, not as configuration `Finding`s. No rule IDs are added and no snapshots change.

#### Task

- New CLI options:
  - `--cve-lookup`: query NVD online. Rejected together with `-x`.
  - `--software-version VALUE`: operator-supplied release, recorded as `version-origin: operator`.
  - `--cve-save FILE`: save the raw NVD responses as a replayable bundle.
  - `--cve-data FILE`: replay a bundle offline. It must match the device's product and version.
  - An NVD API key may be given in the configuration file (`[NVD] API_KEY`) or in the `NVD_API_KEY` environment variable. It is never written to the report.
- New package `src/advisories/`:
  - version-to-CPE mapping per family, with a precision gate;
  - an NVD client with pagination, rate limiting, timeouts and an injectable HTTP function for tests;
  - a neutral `SoftwareAdvisory` model (CVE, description, CVSS score/version/severity, KEV date, conditional flag, NVD status, URL);
  - a lookup status record.
- Analyzers call one shared helper and add `software-advisories` status to the report data. The Cisco openVuln path stays. `CiscoVuln` gains `to_dict()`.
- Report: status line (source, CPE name, version and its origin, retrieval time, counts), the limitations, and a table sorted KEV first and then by CVSS. JSON adds `software-advisories` and fuller `vulnerabilities` records.
- Statuses: `not-requested`, `completed`, `unavailable` (with a reason: unsupported family, imprecise version, not in the CPE dictionary, bundle mismatch) and `error` (network or HTTP failure). A report is always produced.

**Tests (no network):** version mapping and the precision gate per family; CPE selection (exact version/update, deprecated names skipped); pagination; KEV and conditional marking; sorting; error and unavailable statuses; bundle save and replay; the conflict with `-x`; the API key is never serialized; HTML/JSON rendering; default runs make no request.

**Status:** First stage done (2026-09-25): `src/advisories/` (versions, nvd, model, service), CLI options, all 12 analyzers, HTML/JSON rendering and `tests/test_cve_lookup_pt010.py` (36 tests, no network). The NVD API could not be reached from the development sandbox (egress policy), so the request format follows the NVD API 2.0 documentation and schema (`cpeMatchString`, `cpeName` + `isVulnerable`, `resultsPerPage`/`startIndex`/`totalResults`, `apiKey` header, `cisaExploitAdd`). First maintainer run (2026-09-25, Windows) failed with `SSLError`: certifi was current, so the likely cause is HTTPS inspection by a local proxy/antivirus. Fix: requests now verify against the OS store via `truststore` (new requirement), and TLS errors name the reason and the options (`REQUESTS_CA_BUNDLE`, `--cve-data`). Second maintainer run (FortiOS 6.4.2) reported 0 CVEs. Checked live on 2026-09-25 through the maintainer's browser: the CPE step was correct, but the CVE API returned `resultsPerPage: 0` with `totalResults: 134` whenever 2000 (or the default page size) was requested; 1000 and 1999 worked. Fixed with a page size of 1000 and a guard that turns an empty page with results into an error. A trimmed real record is in `tests/test_data/advisories/`. **Validate one real `--cve-lookup --cve-save` run** (for example FortiOS 7.4.6 and a Junos release) before relying on it, and keep the saved bundle out of the repository (`*.nvd.json` is ignored).

**Later stages:** Palo Alto and Cisco vendor feeds as cross-checks; F5 per provisioned module; AOS-S CPE qualification; correlating CVEs with the features the configuration enables (for example SSL VPN or GlobalProtect).

