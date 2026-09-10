# AGENT INSTRUCTIONS: Pynipper-v2 — Detection Quality Remediation & Continued Device Support

You are using a Windows PC — adjust shell commands accordingly (e.g. `dir` vs `ls`, path separators, activating venvs with `.venv\Scripts\activate`).

## Purpose of This Document

This is a self-contained instruction set for an autonomous coding agent (Claude Code, Gemini CLI, or similar) working locally on `bodavk/pynipper-v2`, a personal fork of `syn-4ck/pynipper-ng`. **This is a continuation of prior agent work, not a fresh start.** Prior sessions (run mostly on a free-tier Gemini 3.1 Flash model) made real progress but left the repo in a state where documentation and changelog claims do not reliably reflect what the code actually does. Do not trust `CHANGELOG_AGENT.md`, `TODO.md`, or any prior "done" marker at face value — verify against actual source and tests before building on top of anything.

**Git is fully out of scope for the agent.** The human manages all git operations (staging, commits, branches, pushes) manually. The agent must never run `git add`, `git commit`, `git push`, `git branch`, `git merge`, `git checkout -b`, or touch remotes in any way. Just edit files in the working tree. If you want to note that a logical unit of work is complete, write it to `docs/agent_notes/IMPLEMENTATION_LOG.md` — that log is the review trail, not commit history.

---

## Standing Rules (Apply Every Session, for the Entire Project Lifecycle)

These are not phase-specific — re-read them before any work session and apply them throughout, regardless of which phase you're in.

1. **No git operations of any kind.** See above.
2. **Never mark anything as done, verified, or complete without pasting the evidence in the same session.** This is the single biggest failure mode observed in prior work: `TODO.md` marked issues complete and `CHANGELOG_AGENT.md` claimed verified plugins for five new devices, while `src/analyze/README.md` and `src/devices/README.md` — the actual living documentation — still showed only two plugins and listed most original-parity devices as outstanding. A claim without pasted test output, a pasted diff, or a pasted before/after config-and-finding trace is not a completed task. It's a draft.
3. **Documentation must be updated in the same session as the code it describes, and only after verification.** If you touch a parser or plugin, update `src/devices/README.md`, `src/analyze/README.md`, `docs/SUPPORTED_DEVICES.md`, and `CHANGELOG_AGENT.md` in that same pass — and only write claims there that you just personally verified, not aspirational statements about what you intended to build.
4. **Match the existing codebase's architecture and conventions before introducing new ones.** Detailed in its own section below.
5. **Meet the Detection Logic Quality Standard for every check, old or new.** Detailed in its own section below — this directly addresses confirmed weaknesses found in the current codebase.
6. **Cite sources for every security check.** Vendor hardening guide URL, CIS control ID, STIG ID, or CVE ID. If you can't find a specific current control ID, write `NEEDS_HUMAN_REVIEW: control ID unverified` rather than inventing one or leaving the threshold unsourced. (The current `ssh_time-out` check enforces a 120-second threshold that isn't cited to anything and doesn't even match its own docstring's stated 60-second limit — this is exactly the failure mode to avoid.)
7. **Stop and produce a written report at the end of each phase** before proceeding to the next. Do not silently chain phases.
8. **Flag uncertainty explicitly as `NEEDS_HUMAN_REVIEW`** in code comments and phase reports rather than guessing silently.

---

## Confirmed Findings From Code-Level Audit (Starting Ground Truth)

This section is not hypothetical — it's based on direct review of `src/analyze/cisco/ios_router/plugins/http_plugin.py` and `ssh_plugin.py`, the two oldest and most mature plugins in the codebase, which are the reference implementation every other device's plugins were supposedly modeled on. If these two have this many real defects, assume every plugin generated in prior sessions needs the same scrutiny — do not treat "it already exists" as "it already works."

**Confirmed bugs (not style opinions — these produce wrong findings):**

- **False positive via unanchored substring matching (`http_plugin.py`, `_has_http`):** the check searches for `"ip http server"` and separately for `"no ip http server"`, but checks the positive match first. Since `"ip http server"` is a literal substring of `"no ip http server"`, ciscoconfparse's `find_objects()` (unanchored regex search) matches both, and the positive branch always wins. **A device with HTTP explicitly and correctly disabled is reported as vulnerable.** The `http_disable` branch is dead code.
- **Unhandled crash on named ACLs (`http_plugin.py`, `_get_cisco_ios_http_access_list`):** `int(num)` is called on whatever token follows `ip http access-class`. Named ACLs (e.g. `MGMT-ACL`) are common in real configs and will raise an uncaught `ValueError`, crashing the scan rather than producing a finding.
- **Docstring/code threshold mismatch (`ssh_plugin.py`, SSH timeout check):** the finding text states the acceptable range is "0 and 60 seconds"; the actual condition checks `timeout > 120`. A 90-second timeout is silently treated as compliant by the code while the report text says otherwise. Neither number is cited to any standard.
- **Conflated findings (`ssh_plugin.py`, `get_cisco_ios_ssh`):** "SSH not configured at all" and "SSH configured but using v1" trigger the identical finding, worded entirely around protocol-version risk. These are different problems needing different remediation text.
- **Same unguarded `int()` pattern repeated** in the SSH retry-count check — systemic, not a one-off.

**Confirmed coverage/precision gaps:**

- No check exists for Telnet still being enabled on VTY lines, or a positive check that `transport input ssh` is actually configured — `_has_cisco_ios_ssh` only looks for three specific disable-patterns and assumes SSH is active otherwise, with no awareness of what actually enables SSH on IOS (RSA keys + hostname + domain-name).
- The SSH source-interface check fires unconditionally on any device without a dedicated SSH source interface — a legitimate, common secure configuration (e.g. relying on ACLs or VRF separation) gets flagged every time, producing noise rather than signal.
- No finding in either file cites a specific CIS control, STIG ID, or vendor doc.

**Confirmed documentation/reality mismatch (from prior audit of docs, still valid):**

- `src/devices/README.md` lists only `IOS_SWITCH`, `IOS_ROUTER`, `IOS_CATALYST` as supported, with PIX, ASA, FWSM, CatOS, NMP, CSS, ScreenOS, Nortel Passport, SonicWALL SonicOS, and CheckPoint FW1 still under "TODO" — i.e., original-parity work is not actually done.
- `CHANGELOG_AGENT.md` claims a `BaseDeviceParser` refactor plus new parsers/plugins for Palo Alto, FortiOS, Cisco IOS-XE, JunOS, and Arista EOS, and claims completed parity checks for SonicWALL SonicOS and HP ProCurve — none of which appear in `src/devices/README.md`.
- `src/analyze/README.md` still lists exactly two plugins total (`http_plugin`, `ssh_plugin`), contradicting the changelog's claim of verified plugins for five new device families.
- `TODO.md` marks "Translate nipper-ng checks to pynipper-ng modules" and "Unit tests and build/testing in CI" as done — these are the upstream project's own long-open issues (#4, #42), and the two-plugin reality directly contradicts "done."

**What this means for how you work from here:** treat every existing device parser and plugin — old baseline and newly-claimed alike — as unverified until you've personally read the code and run it against both a clean and a deliberately-vulnerable config. Phase A below makes this mandatory before any new feature work.

---

## Architecture & Style Fidelity — Read Before Writing Any Code

The goal is to *extend* pynipper-ng, not rebuild it in the agent's preferred style. Before writing any new parser or plugin:

1. **Study at least 2-3 existing device parsers and 3-5 existing plugins in full** before writing new code. Record in `docs/agent_notes/00_architecture_conventions.md`:
   - Base class(es) used, which methods are abstract vs. overridden (confirm whether `BaseDeviceParser` — introduced in a prior session — is now the actual convention, or whether it coexists inconsistently with an older base class; resolve and document which is canonical)
   - Naming conventions for files, classes, methods, variables
   - How configuration sections are represented internally
   - How `find_objects`/regex patterns are structured (and specifically: whether they're anchored, whether `exactmatch` is used, how negation is handled — given the confirmed bug above, do not copy the existing unanchored-substring-with-separate-negation-search pattern without fixing it)
   - How `Issue`/`Finding` objects are constructed (see `CiscoIOSIssue`) and what fields are mandatory
   - How severity and compliance mappings are represented (currently: not represented at all in the two audited plugins — this needs to change, see Detection Logic Quality Standard)
   - How plugins are registered/discovered (verify the actual loader mechanism by reading it)
   - Test file structure and naming conventions in actual use

2. **Reuse existing shared utilities rather than reimplementing.** Search before writing any utility-shaped code.

3. **Only deviate from existing patterns for a concrete technical reason**, documented in-code and in `00_architecture_conventions.md` under "Deviations." A demonstrated bug in the existing pattern (like the ones confirmed above) is a valid reason to deviate — but the fix should be applied consistently across all plugins that share the flawed pattern, not just the one you happen to be touching.

4. **If no established pattern exists for something new**, propose the minimal extension that fits the existing philosophy and flag it in the phase report as a new convention.

5. **Keep the plugin philosophy intact:** one plugin = one focused check or tightly related group, self-contained. Do not introduce a fundamentally different check-authoring paradigm without flagging it as a proposal for human approval first.

---

## Detection Logic Quality Standard

This section exists because the confirmed findings above show the existing detection logic is not reliably correct, not just "simple." Every check — new or fixed — must clear this bar.

### The core anti-pattern to eliminate: unanchored substring/negation matching

**Do not write checks like this** (the actual bug pattern found in `http_plugin.py`):
```python
enabled = cisco_parser.find_objects("ip http server")
disabled = cisco_parser.find_objects("no ip http server")
if len(enabled) > 0:
    return True   # BUG: this also matches "no ip http server"
elif len(disabled) > 0:
    return False
```
**Instead:** anchor the pattern and/or check for the negation prefix explicitly on the matched line, e.g. match `r'^\s*(no\s+)?ip http server\s*$'` and branch on whether group 1 (`no `) was present, or use `exactmatch=True` where the library supports it, or filter matched objects to exclude any whose text starts with `no `. Whichever approach, the fix must be applied to every plugin using this pattern, not just one.

### Mandatory checklist for every check (new or being fixed)

- [ ] **Negation-safe:** explicitly handles `no <command>` rather than relying on substring non-matching to imply absence.
- [ ] **Multiple syntax variants covered:** e.g. numbered vs. named ACLs, `ip http access-class <n>` vs. `ip http access-class ipv4 <name>`, shorthand vs. full keyword forms (`ip ssh auth` vs `ip ssh authentication`).
- [ ] **No unguarded type coercion:** any `int()`/`float()` conversion of a parsed token must handle the case where the token isn't numeric (named ACLs, keywords, etc.) without crashing the scan.
- [ ] **Docstring/finding text matches the enforced threshold exactly.** If the human-readable description says a range or limit, the code must enforce that exact value — verify this by re-reading both side by side before considering the check done.
- [ ] **One root cause per finding.** Don't conflate "feature absent" and "feature present but misconfigured" into a single finding with one description — these need different titles/remediation text, or the code needs to distinguish which is at fault.
- [ ] **Specific enough to avoid firing on legitimate secure configurations.** If a check will fire on a large fraction of real, defensible configs (like the current SSH source-interface check), either narrow its trigger condition or lower its severity and reframe it as advisory, not a flat "misconfiguration."
- [ ] **Cited to a specific, current standard.** A CIS control ID, STIG ID, vendor hardening guide section, or CVE — verified as current, not assumed from training data. `NEEDS_HUMAN_REVIEW` if you can't confirm one.
- [ ] **Tested against both a true-positive and true-negative sample config**, and ideally an edge-case sample (e.g., named ACL, shorthand syntax) that would break a naive implementation.

### Detection Depth Levels (use this to self-assess before calling a check "done")

- **Level 0 (unacceptable):** single unanchored substring match, no negation handling, no type-safety, no citation. This describes the current `http_plugin.py`/`ssh_plugin.py` baseline — do not ship new code at this level.
- **Level 1 (minimum acceptable):** anchored/negation-safe matching, guarded type coercion, at least one cited standard.
- **Level 2 (target):** Level 1 plus multiple syntax variants covered and tested true-positive/true-negative pairs.
- **Level 3 (stretch):** Level 2 plus cross-referencing multiple related config elements to reduce false positives (e.g., checking both that HTTP is enabled *and* whether a compensating ACL/auth method exists, to differentiate severity rather than firing one flat "HTTP enabled" finding regardless of context — the existing plugin structure already gestures at this with separate access-list/auth checks, which is good; extend that pattern rather than replacing it).

---

## Phase A: Verify & Reconcile Prior Agent Claims

**Do this before anything else.** Do not proceed to new device work while the existing baseline is unverified and the docs are wrong.

- [ ] Read every existing plugin file (not just the two already audited above) end to end. For each, apply the Detection Logic Quality Standard checklist and record a Detection Depth Level.
- [ ] Read every existing device parser file end to end, including whatever was added in the `BaseDeviceParser` refactor. Confirm it's used consistently — check for leftover code still assuming an older base class.
- [ ] For each specific claim in `CHANGELOG_AGENT.md`, check it against actual files on disk: does the parser file exist? Does it parse successfully against a real sample config? Do the claimed plugins exist, run, and produce correct findings on both a clean and vulnerable sample? Record a verified/unverified/false status for each claim in `docs/agent_notes/00_CHANGELOG_AUDIT.md`.
- [ ] Fix `src/devices/README.md`, `src/analyze/README.md`, and `TODO.md` to state only what is actually verified true right now. Remove or correct any inaccurate "done" markers.
- [ ] Fix the two confirmed bugs in `http_plugin.py` and `ssh_plugin.py` (substring/negation matching, unguarded `int()`, threshold mismatch, conflated SSH finding) as part of this phase — they're small, well-understood, and block trusting anything built on the same pattern.
- [ ] Produce `docs/agent_notes/0A_PHASE_REPORT.md`: what was actually verified true, what was found false or unverified, what was fixed, what remains.

**STOP. Present this report before proceeding.**

---

## Phase B: Full Inventory & Gap Matrix

- [ ] Enumerate every device parser and plugin now actually confirmed to exist (post Phase A), with Detection Depth Level per plugin, in `docs/agent_notes/01_pynipper_inventory.csv`.
- [ ] From a local reference copy of the original nipper-ng (`arpitn30/nipper-ng` — clone it yourself if not already present locally; this is a read-only reference, not part of the working repo, so add `reference/` to `.gitignore` if not already there), extract the authoritative original device list and rough check categories per device into `docs/agent_notes/01_original_nipper_inventory.csv`.
- [ ] Produce `docs/agent_notes/01_gap_matrix.md` marking every original-tool device as `SUPPORTED_VERIFIED` / `SUPPORTED_PARTIAL` / `SUPPORTED_UNVERIFIED` / `MISSING`, based on Phase A's real verification, not prior claims.
- [ ] Separately list the five devices added beyond original scope (Palo Alto, FortiOS, IOS-XE, JunOS, Arista EOS) with the same verified status — these need retrofitting to the Detection Logic Quality Standard just like everything else, they don't get a pass for being "already built."
- [ ] **Phase B Report** (`docs/agent_notes/01_PHASE_REPORT.md`).

**STOP. Present before proceeding.**

---

## Phase C: Task Generation — Fixing & Completing Existing Devices

For every plugin/parser at Detection Depth Level 0 or 1, and every `MISSING`/`SUPPORTED_PARTIAL` original-tool device, create a task file at `docs/agent_notes/tasks/<parity|quality>/<NN>_<slug>.md`:

```markdown
# Task: <Name>

## Status
Not started / In progress / Blocked / Done

## Priority
<CRITICAL | HIGH | MEDIUM | LOW>

## Type
<New device parity | Existing plugin quality fix | Existing parser completion>

## Source of Truth
- Original nipper-ng reference: <path>
- Vendor config/hardening guide: <link, verified current>
- CIS Benchmark / STIG control ID: <specific ID, or NEEDS_HUMAN_REVIEW>

## Architecture Notes
- Closest existing parser/plugin to model from:
- Expected deviation, if any, and why:

## Requirements
<Parser sections to extract, or specific checks to fix/add, referencing the
Detection Logic Quality Standard checklist explicitly for each>

## Test Requirements
- [ ] Clean/secure sample config (near-zero findings)
- [ ] Vulnerable sample config (expected findings only, no more/less)
- [ ] Edge-case sample exercising a syntax variant (named ACL, shorthand form, etc.)
- [ ] Unit tests asserting exact Finding/Issue objects produced

## Acceptance Criteria
- [ ] Every check meets Detection Depth Level 2 minimum
- [ ] Docs updated (src/devices/README.md, src/analyze/README.md, SUPPORTED_DEVICES.md)
      in the same session, reflecting only verified behavior
- [ ] No unguarded type coercion anywhere in new/changed code

## Notes / Open Questions
```

- [ ] Prioritize fixing existing Level-0/1 checks (cheap, high-value, prevents shipping known-wrong findings) above net-new device work.
- [ ] **Phase C Report** (`docs/agent_notes/02_PHASE_REPORT.md`) with priority order and T-shirt sizing.

**STOP. Present before implementing anything.**

---

## Phase D: Task Generation — New Device Expansion

Only after Phase C's fixes are underway or complete. Same task template as Phase C, `Type: New device expansion`, for devices beyond original nipper-ng scope not yet covered (Cisco NX-OS, pfSense/OPNsense, MikroTik RouterOS, cloud security-group exports, etc. — research and rank by market relevance × feasibility × standards availability in `docs/agent_notes/03_new_device_candidates.md` first).

**STOP. Present before implementing.**

---

## Phase E: Implementation Loop

Repeat per task, in priority order:

1. Re-read `00_architecture_conventions.md` and the Detection Logic Quality Standard before writing code.
2. Implement, applying the mandatory checklist to every check.
3. Write/run tests; confirm no regressions (`pytest tests/ -v --cov=src`).
4. Update docs in the same pass, stating only verified behavior.
5. Update the task file's status and acceptance criteria.
6. Append a completion note to `docs/agent_notes/IMPLEMENTATION_LOG.md` — what was implemented, what was verified (paste evidence), what's flagged `NEEDS_HUMAN_REVIEW`.
7. Do not proceed to the next task until this one is Done or explicitly deferred with a reason.

After every 5 tasks, or end of session, write a cumulative status update to `IMPLEMENTATION_LOG.md`.

---

## Phase F: Continuous Validation

- [ ] Maintain `tests/test_data/regression/` — every sample config used anywhere stays as a permanent regression corpus.
- [ ] Maintain `scripts/run_full_regression.sh` (or `.py`) running every parser/plugin against every regression config, failing loudly on mismatch. Run manually after each task.
- [ ] After Phase C's fix list is complete, re-run the full corpus and produce `docs/agent_notes/FINAL_QUALITY_REPORT.md` comparing Detection Depth Levels before/after.

---

## Model Selection (Free-Tier Balance of Cost vs. Quality)

Switch models at phase boundaries rather than using one model throughout.

| Phase | Recommended Model | Reasoning |
|---|---|---|
| A (verify prior claims, fix confirmed bugs) | Best available reasoning/preview model | Highest-stakes phase — this is exactly the kind of multi-file cross-referencing and subtle-bug-finding work that benefits most from frontier reasoning |
| B (inventory, gap matrix) | Stable mid-tier | Mostly mechanical once Phase A's verified state exists |
| C & D (task generation) | Stable mid-tier; escalate to frontier only for ambiguous architecture calls | Task-writing is templated once the gap matrix exists |
| E (implementation loop) | Stable mid-tier for most tasks; fast/cheap model for small, fully-specified tasks; frontier for anything touching the shared negation-matching fix across multiple plugins | Well-specified tasks are closer to mechanical execution |
| F (regression validation) | Stable mid-tier | Mechanical verification |

If unsure which model is currently active, don't try to switch yourself — that's a human action via the CLI's model picker. Just note which model you used in each phase report.

---

## Reporting Template

```markdown
# Phase <N> Report — <Phase Name>

## Summary

## Verified True (with evidence)

## Found False or Unverified (with evidence)

## Fixed This Session

## Architecture Deviations Introduced (if any)

## Open Questions for Human

## Recommended Next Steps
```

---

## Anti-Patterns to Avoid

- Marking anything done, verified, or supported without pasted evidence from this session.
- Writing or leaving in place unanchored substring matching for enable/disable detection without explicit negation handling.
- Any unguarded `int()`/`float()` on a parsed config token.
- A finding's description text stating a threshold that doesn't match the code's actual enforced threshold.
- Conflating two distinct root causes into one finding.
- Inventing a CIS/STIG control ID or CVE number instead of citing a real one or flagging `NEEDS_HUMAN_REVIEW`.
- Updating `CHANGELOG_AGENT.md` with a claim not simultaneously reflected in `src/devices/README.md` / `src/analyze/README.md`.
- Any `git` command whatsoever.
- Introducing a new architectural pattern without checking for an existing one first and documenting the deviation.
- Proceeding past a phase stop-point without explicit human go-ahead.