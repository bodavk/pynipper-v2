# Instructions for coding agents

Read this before changing parsers, plugins, findings or the task backlog. These
are maintainer decisions. Do not reverse them without explicit maintainer approval,
even if a task description seems to suggest otherwise.

## Omitted settings are findings, not unknowns

A configuration export normally leaves out default values and features that were
never configured. Treat an omitted setting by where it is missing:

1. **Explicit value present** → judge the value (`FindingBasis.EXPLICIT_VALUE`).
2. **Omitted inside an object or section that is in the export** (a security rule,
   an interface, an administrator, an enabled management service, the system or
   management section) → this is known configuration state, not missing evidence:
   - a cited vendor source documents the default → apply it
     (`DOCUMENTED_DEFAULT`, release-gated; for example FortiOS interface `status`
     defaults to `up`, policy `utm-status` defaults to `disable`);
   - the feature gives no protection unless configured (no security profile on an
     allow rule, no AAA binding for an active management protocol, no update
     schedule, no SSH/TLS profile for an enabled service) → report it
     (`REQUIRED_SETTING_MISSING`);
   - a default matters but is not verified → `MISSING_EXPLICIT_SETTING`.
   The observation must say the setting is **not configured / omitted**, not that
   a wrong value was set. The report's basis note explains this to the auditor.
3. **Unknown only when**:
   - the whole containing section or domain is absent from the export (a fragment,
     for example a PAN-OS file with only a hostname and no `mgt-config`);
   - the value is malformed or uses unsupported syntax;
   - it references an object that is not in the export (unresolved, or inherited
     from Panorama, a template or a controller);
   - a needed default is not verified for the identified release.

Never require an export to restate a vendor default (FortiOS backups omit
`set status up`). Never suppress a not-configured finding only because
whole-file completeness cannot be proven; there is deliberately no "export is
complete" flag. The presence of the containing object is the evidence.

## Other standing rules

- Never copy CIS benchmark text into the repository; cite recommendation numbers
  and paraphrase. CIS PDFs stay outside the repository.
- An absent setting may be reported from a vendor default only with a cited vendor
  source; a CIS recommendation is not a source for a default.
- Keep reports concise: group low-priority hygiene items into one informational
  `<vendor>.hardening.cis_hygiene` finding instead of many small findings.
- Parsers own syntax, scope, ordering and references; plugins consume typed records.
  See `docs/ARCHITECTURE.md`, `docs/EXTENDING.md` and `docs/EXPORT_EVIDENCE.md`.
- Keep stable rule IDs; give the auditor enough context to assess the risk.
- Sample-dependent tasks stay open as "evidence gate"; never close or delete them.
- Do not delete files; the maintainer commits changes.
