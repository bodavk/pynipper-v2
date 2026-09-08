
# AGENT INSTRUCTIONS: Pynipper-ng Device Support Parity & Expansion (Fork Workflow)
You are using a windows PC, adjust your commands accordingly. 
## Purpose of This Document

This file is a self-contained instruction set for an autonomous coding agent (Claude Code, Gemini CLI, or similar) to execute a 
multi-phase project on `bodavk/pynipper-v2`, a personal fork of `syn-4ck/pynipper-ng`. The agent should treat each Phase as a checkpoint: complete it, verify it, push it, document it, then move to the next.

**Do not skip verification steps.** This project's entire value is accuracy of security detection — an agent that "completes" tasks without validating them against real configurations produces a tool that is actively dangerous to rely on.

**Repo setup for this project:**
- **Working repo (origin):** `https://github.com/bodavk/pynipper-v2.git` — already cloned locally, opened in VS Code. All agent work happens here.
- **Upstream reference:** `https://github.com/syn-4ck/pynipper-ng.git` — the original project this was forked from. Add as a second remote, fetch from it for reference/comparison, but **never push to it and never open PRs against it** unless the human explicitly asks for that in a future session.
- **Legacy reference:** `https://github.com/arpitn30/nipper-ng.git` — the original C++ nipper-ng that pynipper-ng itself is a rewrite of. Cloned read-only into a `reference/` folder for comparison purposes only, never merged into the working tree.

This is a normal fork-based git workflow — the agent should push to `origin` (the fork) freely as work completes. It should never push to `upstream`.

---

## Ground Rules for the Agent

1. **Work in branches, push to `origin` as you go.** Branch per phase/task (e.g., `phase-1-audit`, `task-parity-cisco-pix`), merge into `main` on the fork once a phase/task's exit criteria are met, and push `main` after each merge. Real remote backup, no local-only risk.
2. **Never push to `upstream`, never open a PR against `syn-4ck/pynipper-ng`,** unless explicitly instructed to in a future session. `upstream` is fetch-only, for reference and diffing.
3. **Match the existing codebase's architecture and conventions before introducing new ones.** This is critical and detailed in its own section below — read it before writing any code.
4. **Every new device parser or plugin must ship with a test config and a test case.** No exceptions. A parser with no test is treated as incomplete.
5. **Do not delete or silently alter existing plugin behavior** without logging the change in `CHANGELOG_AGENT.md` with a reason.
6. **Cite sources** for every security check you add (vendor hardening guide URL, CIS control ID, STIG ID, or CVE ID). Checks without a traceable source are not acceptable — do not invent thresholds or "best practices" from training data alone; verify against current vendor/CIS documentation.
7. **Prefer small, reviewable commits** over large ones. One device parser = one commit. One plugin = one commit (or a small logical group). Since there's no code-review-by-others happening, commit messages and phase reports are the primary review trail — write them as if a human reviewer will read them later, because they will.
8. **Stop and produce a written report** at the end of each Phase before proceeding — do not silently chain all phases in one pass.
9. **If you cannot verify something (no test config available, ambiguous vendor doc), mark it explicitly as `NEEDS_HUMAN_REVIEW`** in code comments and in the phase report. Do not guess silently.

---

## Architecture & Style Fidelity — Read Before Writing Any Code

The goal of this project is to *extend* pynipper-ng, not to rebuild it in the agent's preferred style. Divergent architecture across device parsers/plugins makes the codebase harder to maintain long-term and defeats the purpose of a plugin-based design. Before writing any new parser or plugin, the agent must:

1. **Study at least 2-3 existing device parsers and 3-5 existing plugins in full** before writing a single new line of code for a new device. Note down (in `docs/agent_notes/00_architecture_conventions.md`):
   - The exact base class(es) used and which methods are abstract vs. overridden
   - Naming conventions for files, classes, methods, and variables (snake_case vs camelCase, plugin ID formats, etc.)
   - How configuration sections are represented internally (dict shape, dataclass, custom object — whatever it actually is, not what any prior documentation assumed it was)
   - How regex patterns are typically structured and organized (inline vs. class-level constants, compiled vs. ad-hoc)
   - How `Finding`/issue objects are constructed and what fields are mandatory vs. optional
   - How severity levels and compliance mappings are represented in existing code
   - Docstring style and comment conventions
   - How plugins are registered/discovered (the actual loader mechanism, verified by reading it, not assumed)
   - Test file structure and naming conventions, and what testing framework/assertions style is already in use

2. **Reuse existing shared utilities rather than reimplementing.** If the codebase already has a helper for e.g. stripping comments, tokenizing config blocks, or decoding Cisco Type-7 passwords, use it. Search before writing (`grep -r` or equivalent) any utility-shaped code.

3. **Only deviate from existing patterns when there's a concrete technical reason**, and when you do, document why in both the code (a comment) and in `docs/agent_notes/00_architecture_conventions.md` under a "Deviations" section. Valid reasons include: the existing pattern genuinely cannot represent a new device's config paradigm (e.g., block/brace-delimited JunOS-style config vs. flat IOS-style lines), or the existing pattern has a demonstrated bug being fixed as part of this work. "I would have designed it differently" is not a valid reason.

4. **If the existing architecture has no established pattern for something new** (e.g., no prior device used a completely different config syntax family), propose the minimal extension that fits the existing philosophy, note it as a new convention going forward, and flag it in the phase report so the human is aware a new pattern was introduced rather than an existing one reused.

5. **Keep the plugin philosophy intact:** one plugin = one focused check (or a small tightly related group), self-contained, with its own compliance mapping and severity — mirroring however the current codebase already does this. Do not introduce a fundamentally different check-authoring paradigm (e.g., a giant rules-engine YAML file) without flagging it as an architecture proposal for human approval first, separate from normal task execution.

This section applies throughout Phases 2-5 whenever new code is written, not just once at the start.

---

## Phase 0: Environment & Remote Setup

### Tasks
- [ ] Confirm the working directory is the local clone of the fork:
  ```bash
  cd /path/to/pynipper-v2
  git remote -v
  ```
  Expect `origin` to point at `bodavk/pynipper-v2`. If it doesn't, stop and flag this to the human — do not proceed on the wrong repo.
- [ ] Add the original pynipper-ng project as an `upstream` remote, fetch-only in practice (never pushed to):
  ```bash
  git remote add upstream https://github.com/syn-4ck/pynipper-ng.git
  git fetch upstream
  ```
- [ ] Confirm current branch is `main` (or whatever the fork's default branch is) and it's clean:
  ```bash
  git status
  git branch -a
  ```
- [ ] Clone the legacy reference project (the original C++ nipper-ng) into a local-only reference folder, excluded from the working repo's history:
  ```bash
  mkdir -p reference
  git clone --depth 1 https://github.com/arpitn30/nipper-ng.git reference/nipper-ng-original
  echo "reference/" >> .gitignore
  git add .gitignore && git commit -m "chore: ignore local reference copy of original nipper-ng"
  git push origin main
  ```
- [ ] Inspect and document the actual repo structure (do not assume — the real layout may differ from any prior documentation):
  ```bash
  find . -type f -name "*.py" | grep -v test | grep -v reference | sort > docs/agent_notes/current_file_inventory.txt
  ```
- [ ] Read and record, verbatim into `docs/agent_notes/00_baseline.md`:
  - `README.md`
  - `CONTRIBUTING.md`
  - `TODO.md`
  - `src/devices/README.md`
  - `src/analyze/README.md` (if present)
  - Any `CHANGELOG.md`
- [ ] Complete the **Architecture & Style Fidelity** study described above and write `docs/agent_notes/00_architecture_conventions.md` before proceeding to Phase 1.
- [ ] Set up a working Python environment matching `setup.py` / `requirements.txt`. Use a local virtual environment so nothing pollutes system Python. Confirm the existing test suite (if any) runs cleanly before making any changes:
  ```bash
  python -m venv .venv
  source .venv/bin/activate   # or .venv\Scripts\activate on Windows
  pip install -e .
  pip install pytest pytest-cov
  pytest tests/ -v 2>&1 | tee docs/agent_notes/00_baseline_test_run.txt
  ```
- [ ] Note the commit hash of both `origin/main` and `upstream/main` (or default branch) at the start of this work, in `docs/agent_notes/00_baseline.md`, so drift from upstream can be tracked later if desired.
- [ ] Commit and push all Phase 0 documentation:
  ```bash
  git add docs/
  git commit -m "docs: phase 0 baseline and architecture conventions notes"
  git push origin main
  ```

### Exit Criteria
- `origin` confirmed as `bodavk/pynipper-v2`, `upstream` added and fetched.
- `docs/agent_notes/00_baseline.md` and `docs/agent_notes/00_architecture_conventions.md` exist, committed and pushed.
- Baseline test suite result recorded (pass/fail/none).

---

## Phase 1: Full Inventory & Gap Analysis

**Goal:** Produce a ground-truth, evidence-based comparison of (a) what pynipper-ng currently supports and does, (b) what the original nipper-ng supported, and (c) where the gaps are. No plan in Phase 2+ should be written until this inventory exists — do not work from assumptions or prior conversation summaries.

### 1.1 Inventory pynipper-ng's current state

- [ ] Enumerate every device parser under `src/devices/` (or wherever device-parsing code actually lives — confirm via file inventory, not assumption). For each, record:
  - File path
  - Device/vendor/OS claimed to be supported
  - Which config commands/sections it actually parses (grep for regex patterns and dict keys)
  - Whether it has any associated tests or example config files
- [ ] Enumerate every analysis plugin under `src/analyze/**/plugins/`. For each, record:
  - Plugin ID, title, severity
  - What it checks (summarize the actual regex/logic, not the docstring — verify they match)
  - Any compliance mapping present (CIS/STIG/NIST/none)
  - Whether a corresponding test exists
- [ ] Produce `docs/agent_notes/01_pynipper_inventory.csv` with columns:
  `component_type, name, file_path, device_scope, has_tests, compliance_mapping_present, notes`

### 1.2 Inventory original nipper-ng's device & check coverage

- [ ] From `reference/nipper-ng-original` (read-only reference), extract the authoritative device list. Look in:
  - `README`/`INSTALL`/`docs/`
  - Source directories under `device/` (C++ device class names typically map 1:1 to supported platforms)
- [ ] For each device type in the original tool, identify (as best as extractable from source/comments):
  - Vendor and product line (e.g., "Cisco PIX", "Juniper NetScreen ScreenOS", "CheckPoint FW1")
  - Config dialect/version supported
  - Rough count and categories of checks performed for that device (auth, logging, ACL, routing, crypto, services)
- [ ] Produce `docs/agent_notes/01_original_nipper_inventory.csv` with columns:
  `vendor, device_type, os_dialect, source_path_in_original, approximate_check_categories`

### 1.3 Cross-reference and gap matrix

- [ ] Produce `docs/agent_notes/01_gap_matrix.md`, a table listing every device type from the original tool with a status column:
  - `SUPPORTED_VERIFIED` — pynipper-ng has a parser AND it was validated against a real/representative config in this phase
  - `SUPPORTED_UNVERIFIED` — parser exists but no test config / no validation
  - `SUPPORTED_PARTIAL` — parser exists but clearly only handles a subset of the config dialect (note specifics)
  - `MISSING` — no parser exists at all
- [ ] For every plugin/check category in the original tool, note whether pynipper-ng has an equivalent, using the same status vocabulary.

### 1.4 Validate existing "already supported" devices

This directly satisfies the "check validity of all devices that pynipper already supports" requirement. Do this for every parser marked `SUPPORTED_*` above.

For each existing device parser:
- [ ] Locate or create a **representative sample configuration** for that device/OS version (use publicly available vendor documentation examples, Cisco's own configuration guides, or anonymized/synthetic configs — never use a real customer config from the internet without confirming it's meant as a public teaching example). Store these under `tests/test_data/<vendor>/` in the working repo.
- [ ] Run the parser against the sample and manually diff the parsed output against the raw config to confirm:
  - No silently dropped sections
  - No regex that only matches a narrow syntax variant (e.g., only matches `enable secret 5 ...` but not `enable secret 9 ...`, or only matches config with no leading whitespace when real `show running-config` output may have different indentation/EOL conventions)
  - Correct handling of comments, negated commands (`no ...`), and multi-line blocks (e.g., `interface X ... !`)
- [ ] Run every plugin scoped to that device against the sample config and manually verify each finding is *correct* (true positive) and check for obvious *false negatives* (known-bad config lines that should have triggered a finding but didn't).
- [ ] Record verification results in `docs/agent_notes/01_validation_results/<device_name>.md` with: sample config used (or link/description of source), parser issues found, plugin issues found, fixes applied (if trivial) or ticket created (if substantial — see Phase 2 task format).
- [ ] **Any parser or plugin bug found here that is a quick, low-risk fix should be fixed immediately in this phase**, following the existing code's conventions (see Architecture & Style Fidelity section), with its own commit and test.

### Exit Criteria
- `01_pynipper_inventory.csv`, `01_original_nipper_inventory.csv`, `01_gap_matrix.md` exist and are internally consistent (every device in the gap matrix appears in both inventories or is explicitly marked missing from one side).
- Every currently-claimed-supported device has a validation report, even if the report says "could not obtain a representative config, marked NEEDS_HUMAN_REVIEW."
- A short **Phase 1 Report** (`docs/agent_notes/01_PHASE_REPORT.md`) summarizing: total devices in original tool, total in pynipper-ng, count in each status bucket, top 5 riskiest gaps, top 5 validation bugs found.
- All Phase 1 work committed on a `phase-1-audit` branch, merged into `main`, and pushed to `origin`:
  ```bash
  git checkout -b phase-1-audit
  # ... work, commits ...
  git checkout main
  git merge phase-1-audit
  git push origin main
  ```

**STOP. Present the Phase 1 Report to the human before proceeding to Phase 2.**

---

## Phase 2: Task Generation — Achieving Original Device Parity

**Goal:** Convert every `MISSING`, `SUPPORTED_PARTIAL`, and non-trivial `SUPPORTED_UNVERIFIED` item from the Phase 1 gap matrix into a fully specified, independently executable task. Do not implement anything yet in this phase unless it's a genuinely trivial 1-line fix already handled in Phase 1.4.

### 2.1 Task file format

For every gap, create a task file at `docs/agent_notes/tasks/parity/<NN>_<device_slug>.md` using this exact template:

```markdown
# Task: <Device Name> Parser & Checks (Parity with Original Nipper-ng)

## Status
- [ ] Not started / In progress / Blocked / Done

## Priority
<CRITICAL | HIGH | MEDIUM | LOW> — based on: how commonly deployed the device is today,
severity of what's missed by not supporting it, and how much original-tool functionality
depends on it.

## Source of Truth
- Original nipper-ng reference: <path in reference/nipper-ng-original>
- Vendor config guide(s): <links — verify these are live and current, not assumed>
- Vendor hardening guide: <link, e.g. Cisco Security Configuration Guide, CIS Benchmark, DISA STIG>

## Architecture Notes
- Which existing parser(s)/plugin(s) most closely resemble this one and should be used
  as the template: <e.g. "src/devices/cisco/ios_router.py — same vendor, adapt for
  firewall-specific sections">
- Any expected deviation from existing patterns and why: <or "None expected">

## Scope
- Device/vendor: 
- OS/firmware versions to support: 
- Config dialect quirks to handle (comments syntax, block delimiters, line continuation, etc.):

## Parser Requirements
1. File location: `src/devices/<vendor>/<device>.py`
2. Must extract at minimum the following sections (list explicitly, derived from what
   the original tool checked — do not under-scope):
   - [ ] Hostname / device identity
   - [ ] Local user accounts & password storage
   - [ ] Enable/privileged access credentials
   - [ ] AAA / remote auth server config
   - [ ] SNMP config
   - [ ] SSH/Telnet/console/management access config
   - [ ] Logging config
   - [ ] Interfaces
   - [ ] ACLs / firewall rules / filter policies
   - [ ] Routing protocol config (if applicable to device class)
   - [ ] VPN/crypto config (if applicable to device class)
   - [ ] NTP config
   - [ ] Any device-class-specific sections (e.g., zones for firewalls, VLANs for switches)
3. Must follow the `BaseDevice` interface already used by existing parsers, and follow
   the naming/style conventions documented in `docs/agent_notes/00_architecture_conventions.md`.

## Plugin/Check Requirements
List every check the original tool performed for this device (derived from Phase 1.2
inventory), each as its own sub-checklist item, in the SAME format as existing pynipper-ng
plugins:
   - [ ] <Check name> — maps to original nipper-ng check `<name/id if identifiable>`
   - [ ] <Check name> — ...
   (repeat for all identified checks)

Additionally add any check that's missing from the original tool but is now standard
practice for this device class (cross-reference against current CIS Benchmark / vendor
guide — cite the control ID).

## Test Requirements
- [ ] At least one clean/secure sample config (should produce zero or near-zero findings)
- [ ] At least one intentionally-vulnerable sample config exercising every check above
      (should produce exactly the expected findings — no more, no less)
- [ ] Unit tests for the parser's extraction logic (assert on parsed dict/object structure)
- [ ] Unit tests for each plugin (assert exact Finding objects/count produced)
- [ ] Test files placed under `tests/test_devices/<vendor>/` and `tests/test_plugins/<vendor>/`,
      following the existing test suite's structure and naming conventions

## Acceptance Criteria
- [ ] Parser handles all listed sections without exceptions on both sample configs
- [ ] All plugins produce correct true positives on the vulnerable sample
- [ ] All plugins produce zero false positives on the clean sample
- [ ] Code follows the conventions in `docs/agent_notes/00_architecture_conventions.md`;
      any deviation is documented there and in-code
- [ ] Code reviewed against `CONTRIBUTING.md` style rules
- [ ] Registered in device factory / CLI `-d` device type list
- [ ] Documentation updated: `src/devices/README.md` and `docs/SUPPORTED_DEVICES.md`

## Notes / Open Questions
<Anything the agent was unsure about — flag NEEDS_HUMAN_REVIEW here explicitly>
```

### 2.2 Devices to generate tasks for (from original nipper-ng)

Use Phase 1 inventory to confirm the exact list, but at minimum ensure tasks are generated for any of these found to be `MISSING` or `SUPPORTED_PARTIAL`:

- [ ] Cisco PIX Firewall
- [ ] Cisco ASA Firewall
- [ ] Cisco FWSM Firewall
- [ ] Cisco Catalyst (CatOS dialect, distinct from IOS)
- [ ] Cisco Content Services Switch (CSS)
- [ ] Juniper NetScreen (ScreenOS)
- [ ] CheckPoint Firewall-1 (device config)
- [ ] CheckPoint Management Server (policy/objects config)
- [ ] Nokia IP Firewall (IPSO)
- [ ] Nortel Passport
- [ ] SonicWALL SonicOS
- [ ] 3Com switches/routers
- [ ] Bay Networks devices
- [ ] HP devices (ProCurve, etc.)

**Do not assume this list is exhaustive** — it must be reconciled against the actual Phase 1.2 inventory, which may surface additional or fewer device types depending on what the original source tree actually contains.

### 2.3 Prioritization

- [ ] Create `docs/agent_notes/tasks/parity/00_PRIORITY_ORDER.md` ranking all generated tasks. Suggested ranking heuristic (state your actual reasoning per item, don't just apply this blindly):
  1. Devices still commonly deployed in production networks today (e.g., ASA remains widespread even as EOL approaches; PIX is long EOL and lower priority)
  2. Devices representing a fundamentally different config paradigm not yet covered (e.g., first firewall with zone-based policy, first non-Cisco vendor) — these validate the architecture generalizes
  3. Everything else, roughly by "approximate check category count" from Phase 1.2 (more original functionality = more value recovered)

### Exit Criteria
- One task file per gap, following the exact template
- A priority-ordered index file
- **Phase 2 Report** (`docs/agent_notes/02_PHASE_REPORT.md`) summarizing task count, priority breakdown, and estimated relative effort (T-shirt sizing: S/M/L/XL) per task
- All Phase 2 work committed on a `phase-2-tasks` branch, merged into `main`, and pushed to `origin`

**STOP. Present the Phase 2 Report and task list to the human before implementing anything or proceeding to Phase 3.**

---

## Phase 3: Task Generation — New Device Support Beyond Original Scope

**Goal:** Identify and specify tasks for network devices that are common in *current* (2025/2026) production environments but were never supported by the original nipper-ng (which stopped development ~9 years ago). This directly expands the tool's relevance rather than just restoring old functionality.

### 3.1 Research current device landscape

- [ ] Web-search and document (with sources) the current market-relevant device categories not covered above, e.g.:
  - Cisco IOS-XE (modern syntax differences vs classic IOS — confirm whether existing IOS parser already handles this or needs its own dialect handling)
  - Cisco NX-OS (Nexus data center switches)
  - Fortinet FortiGate (FortiOS)
  - Palo Alto Networks (PAN-OS)
  - Juniper JunOS (modern, distinct from legacy ScreenOS)
  - Arista EOS
  - pfSense / OPNsense
  - MikroTik RouterOS
  - Ubiquiti EdgeOS/UniFi
  - AWS/Azure/GCP security group & network ACL exports (cloud-native "firewall" equivalents — optional stretch goal, flag as its own category since input format differs completely from CLI-text configs)
- [ ] For each candidate, do a quick feasibility/value assessment: how common is it, is config export text-based and parseable, is there public documentation of hardening standards (CIS Benchmarks exist for many of these).
- [ ] Produce `docs/agent_notes/03_new_device_candidates.md` ranking candidates by (market relevance × feasibility × standards-availability).

### 3.2 Generate task files

- [ ] For each approved candidate (confirm priority list with human before generating full tasks — this can be a lighter-weight check-in than a full phase stop), create a task file at `docs/agent_notes/tasks/expansion/<NN>_<device_slug>.md` using the **same template as Phase 2.1**, but with the "Source of Truth" section pointing to:
  - Current vendor documentation (not the original nipper-ng, since it never supported this device)
  - Current CIS Benchmark for that platform if one exists
  - Relevant DISA STIG if one exists
  - Relevant CISA hardening guidance if applicable

### 3.3 Architecture check before scaling out

- [ ] Before generating a large number of new-device tasks, do a short architecture review: does the current `BaseDevice`/plugin/loader design actually generalize cleanly to very different config paradigms (e.g., JSON/structured config like PAN-OS XML, or block-based config like JunOS `{ }` syntax, vs. flat line-based IOS-style config)?
- [ ] If the architecture doesn't generalize well, create `docs/agent_notes/tasks/expansion/00_ARCHITECTURE_REFACTOR.md` specifying what changes to `BaseDevice` (e.g., pluggable tokenizers/parsers per config syntax family) are needed **before** device-specific tasks can be implemented — while staying as close as possible to the spirit of the existing design (extend, don't replace). Flag this as a blocking prerequisite task, ranked above device-specific expansion tasks.

### Exit Criteria
- Candidate list with reasoning
- Task files for approved new devices
- Architecture refactor task if needed
- **Phase 3 Report** (`docs/agent_notes/03_PHASE_REPORT.md`)
- All Phase 3 work committed on a `phase-3-tasks` branch, merged into `main`, and pushed to `origin`

**STOP. Present Phase 3 Report to the human before implementation.**

---

## Phase 4: Implementation (Only After Human Sign-off on Phases 1–3)

This phase is intentionally left as a controlled execution loop rather than a single "implement everything" instruction. All pushes go to `origin` (`bodavk/pynipper-v2`) only — never to `upstream`.

### Execution loop (repeat per task, in priority order)

1. [ ] Pick the single highest-priority `Not started` task from Phase 2 or Phase 3 task lists.
2. [ ] Create a branch off `main`: `git checkout -b task-<task-id>-<slug>`
3. [ ] Re-read the relevant section(s) of `docs/agent_notes/00_architecture_conventions.md` and the specific existing parser/plugin named in the task's "Architecture Notes" field before writing code.
4. [ ] Implement the parser per the task's Parser Requirements section, matching existing conventions.
5. [ ] Implement each plugin per the task's Plugin/Check Requirements section, one at a time, each with its own test, matching existing conventions.
6. [ ] Write/finalize all Test Requirements from the task file.
7. [ ] Run the full test suite (`pytest tests/ -v --cov=src`) and confirm:
   - No regressions in previously-passing tests
   - New tests pass
   - Coverage for new files meets or exceeds project average
8. [ ] Update `docs/SUPPORTED_DEVICES.md` and `src/devices/README.md`.
9. [ ] Update the task file's Status checkbox and Acceptance Criteria checkboxes.
10. [ ] Commit with a message referencing the task file: `git commit -m "feat(devices): add <device> parser + checks (task parity/03)"`
11. [ ] Merge back into `main` and push to `origin`:
    ```bash
    git checkout main
    git merge task-<task-id>-<slug>
    git push origin main
    ```
12. [ ] Append a short completion note to `docs/agent_notes/IMPLEMENTATION_LOG.md`: what was implemented, what was verified, any `NEEDS_HUMAN_REVIEW` flags remaining, and any architecture deviations introduced.
13. [ ] **Do not proceed to the next task until this one is marked Done or explicitly deferred with a reason.**

### Batch reporting
- [ ] After every 5 completed tasks (or end of a work session, whichever is sooner), produce a short cumulative status update in `docs/agent_notes/IMPLEMENTATION_LOG.md`: tasks done, tasks remaining, any architecture issues discovered mid-implementation that affect remaining tasks.

---

## Phase 5: Continuous Validation

This is not a one-time phase — treat it as an ongoing discipline the agent applies throughout Phase 4, and as a final pass at the end.

- [ ] Maintain `tests/test_data/regression/` — every sample config used anywhere in this project (Phase 1 validation + Phase 2/3 test fixtures) stays in the working repo as a permanent regression corpus, tracked in git and pushed to `origin`.
- [ ] Add a script `scripts/run_full_regression.sh` (or `.py`) that runs every device parser against every regression config and every plugin against expected findings, failing loudly on any mismatch. Run this manually after each merged task.
- [ ] At the end of implementing all parity tasks (end of working through the Phase 2 list), re-run the full regression corpus and produce `docs/agent_notes/FINAL_PARITY_REPORT.md` comparing final device/check counts against the original tool's counts from Phase 1.

---

## Staying in Sync with Upstream (Optional, Human-Directed Only)

The fork may want to periodically pull in upstream changes if `syn-4ck/pynipper-ng` receives updates during this project. The agent should **only** do this if explicitly asked, using:
```bash
git fetch upstream
git merge upstream/main    # or rebase, per human's preference at the time
```
Conflicts from this kind of merge should always be surfaced to the human rather than resolved silently, since they may indicate the upstream project changed something this project's new code depends on.

The agent should never assume this is wanted as part of routine phase/task work — it's a separate, occasional action taken only on explicit instruction.

---

## Reporting Templates (use these exact headers for consistency)

### Phase Report Template
```markdown
# Phase <N> Report — <Phase Name>

## Summary
<2-4 sentences>

## Completed
- 

## Findings / Issues Discovered
- 

## Architecture Deviations Introduced (if any)
- 

## Open Questions for Human
- 

## Recommended Next Steps
- 
```

---

## Anti-Patterns the Agent Must Avoid

- ❌ Writing a device parser or plugin based only on "general knowledge" of what a vendor's config looks like, without citing a real config example or current vendor doc.
- ❌ Marking a device `SUPPORTED_VERIFIED` without an actual test run against a sample config.
- ❌ Inventing CIS/STIG control IDs or CVE numbers. If unsure of the exact ID, write `NEEDS_HUMAN_REVIEW: control ID unverified` rather than fabricating one.
- ❌ Silently changing severity ratings or check logic of existing plugins while doing unrelated work.
- ❌ Combining multiple unrelated devices/checks into one giant commit or one giant task file.
- ❌ Proceeding past a Phase stop-point without an explicit human go-ahead.
- ❌ Any `git push` to `upstream`, or any `gh pr create` / GitHub CLI operation targeting `syn-4ck/pynipper-ng`, unless explicitly instructed to in a future session.
- ❌ Introducing a new architectural pattern (new base classes, new config representation, new plugin paradigm) without first checking whether the existing codebase already has a way to do it, and without documenting the deviation.
- ❌ Treating this document as fully exhaustive — if Phase 1 reveals the real repo structure differs meaningfully from what's assumed here, update this instruction file itself (as `AGENT_INSTRUCTIONS.md` in the repo) to reflect reality, and note the deviation in the phase report.
