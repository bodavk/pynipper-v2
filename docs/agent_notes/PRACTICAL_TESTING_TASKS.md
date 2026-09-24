# Open tasks from practical testing

Recorded **2026-09-24** from hands-on use of the tool. These are defects and usability gaps. PT-001 to PT-004 were implemented on 2026-09-24 (see status per task); PT-005 to PT-008 are open. Follow [Architecture](../ARCHITECTURE.md) and [Extending](../EXTENDING.md). Every task finishes with `.\.venv\Scripts\python.exe scripts\run_full_regression.py`, and any snapshot change must be reviewed deliberately.

| ID | Priority | Title |
|---|---|---|
| PT-001 | P1 | Pin MarkupSafe so a fresh install works (**done**) |
| PT-002 | P1 | FortiOS: parse quoted values that span several lines (**done**) |
| PT-003 | P1 | Audit all other parsers for multi-line values (**done**) |
| PT-004 | P1 | Show source line numbers with finding evidence (**done**, see remaining gaps) |
| PT-005 | P2 | Redesign the HTML report for readability |
| PT-006 | P2 | Layered, user-friendly finding explanations |
| PT-007 | P2 | Point to related findings and compensating controls |
| PT-008 | P3 | Modernise the dependency stack (long-term fix for PT-001) |

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

<a id="pt-006"></a>
### PT-006: Layered finding explanations
**Problem:** Descriptions are technically correct but vague for readers who don't administer the platform every day.
**Fix:**
- Add optional guidance keyed by `rule_id`: a plain-language summary, a concrete example of how an attacker could exploit the weakness, and a more technical explanation.
- Keep this guidance in a per-vendor text catalogue owned by the analyzer layer, not in the parsers.
- Rewrite Critical and High rules first, then Medium.
- Wording must not claim more than the static evidence proves.
**Tests:** Every guidance key matches a real rule ID. A coverage test lists rules that still have no guidance.

<a id="pt-007"></a>
### PT-007: Related findings and compensating controls
**Problem:** Users aren't told which other controls to check when they see a finding. For example, a broad policy or broad admin rights should prompt a look at logging and audit settings.
**Fix:**
- A small, explicit mapping of rule categories to related control categories (for example broad policy or privilege → logging/audit; weak authentication → source restriction, MFA or lockout).
- The report lists related findings that appear in the same report.
- Where there are none, it says the control should be verified manually, because not assessed does not mean secure.
- This is report-layer only: no new detections and no risk scoring.
**Tests:** Mapping integrity, rendering when related findings are present, and rendering when they are absent.

<a id="pt-008"></a>
### PT-008: Dependency modernisation (deferred)
**Problem:** Jinja2 2.11.3 (with MarkupSafe 2.0.x) is old, has known advisories, and is the root cause of PT-001. Other pins are old as well (`requests 2.31`, `tqdm 4.56`).
**Fix:**
- Move to maintained Jinja2 3.x and MarkupSafe versions, and adapt the templates.
- Use a lock or constraints file.
- Add a CI job that does a fresh install.
**Priority:** Lower than current work, so do this after the PT-00x bugfixes.
