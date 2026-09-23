# Open tasks from external configuration validation

Reconciled against source on **2026-09-22**. Completed implementation task bodies have been removed from the open backlog. Their IDs remain in the compact ledger below for traceability. Raw reports and historical interpretations remain in [REALWORLD_VALIDATION_FINDINGS.md](REALWORLD_VALIDATION_FINDINGS.md); the new risk-focused security expansion backlog is [SECURITY_COVERAGE_TASKS.md](SECURITY_COVERAGE_TASKS.md).

## Completed work removed from the backlog

| Former task | Verified implemented scope | Source/test evidence |
|---|---|---|
| RV-001 | ASA explicit active WebVPN SSL protocol/cipher policy | [ASA parser](../../src/devices/cisco/asa.py), [SSL public-pipeline tests](../../tests/test_realworld_asa_ssl.py) |
| RV-002 | ASA static/dynamic crypto-map transforms bound to interfaces | [ASA baseline tests](../../tests/test_asa_baseline_wave4.py) |
| RV-003 | PAN management password-complexity hierarchy and system-log forwarding resolution | [PAN path tests](../../tests/test_realworld_panos_paths.py) |
| RV-004 | IOS effective console/AUX/TTY/VTY idle-timeout ranges and overrides | [IOS timeout tests](../../tests/test_realworld_ios_timeouts.py) |
| RV-005 | EOS authenticated NTP association state, including malformed/unknown cases | [EOS NTP tests](../../tests/test_realworld_eos_ntp.py) |
| RV-006 | Added IOS/XE RADIUS/line and EOS RADIUS/TerminAttr credential metadata without exposing values | [Stored-secret tests](../../tests/test_realworld_stored_secrets.py), [metadata tests](../../tests/test_credential_metadata_gap003.py) |
| RV-007 | Safe exact known-default credential/community checks, effective overrides and redaction | [Credential analysis tests](../../tests/test_credential_analysis_gap018.py), [stored-secret tests](../../tests/test_realworld_stored_secrets.py) |
| RV-009 | PAN/Forti unrendered-template scope and conservative absence suppression | [Template scope tests](../../tests/test_realworld_template_scope.py) |
| RV-010 | Forti local disk/memory evidence and accurate remote-forwarding wording | [Forti external-validation tests](../../tests/test_realworld_fortios.py) |
| RV-011 | Junos effective global default policy, including deletion/groups/unknown states | [Junos default-policy tests](../../tests/test_realworld_junos_default_policy.py) |
| RV-012 | Forti end/edit stack handling and controlled parse-error reporting | [Forti external-validation tests](../../tests/test_realworld_fortios.py) |

Verification for this reconciliation: 65 real-world regression tests plus 36 ASA-baseline and credential tests passed. A non-failing pytest cache-permission warning occurred. Earlier implementation records reported complete regression/corpus passes; those historical counts are not represented as a new full regression run. No runtime code or snapshots changed in this documentation review.

Scope limits still apply: ASA SSL/proposals require proven active bindings; template detection does not reconstruct arbitrary missing configuration; metadata checks do not crack passwords; configured AAA or time authentication does not prove live operation. Further breadth belongs to the linked SC tasks, not to reopening completed RV bodies.

Historical interpretation correction retained: RW-030's embedded JSON contains **12 security-audit findings**, despite the original summary describing zero. An empty CVE/vulnerabilities array is not an empty configuration-security report. Preserve the raw evidence.

## Remaining open task

For the task below, follow [Architecture](../ARCHITECTURE.md) and [Extending](../EXTENDING.md): parser-owned effective state, typed records, explicit knowledge states, stable rule IDs, sanitized evidence and qualified authoritative sources. Tests must cover positive/negative, override, malformed/unknown, inactive/unbound, scope, redaction and the public JSON/HTML CLI, followed by `.\.venv\Scripts\python.exe scripts\run_full_regression.py`. Do not add externally sourced configurations as undisclosed fixtures.

<a id="rv-008"></a>
### RV-008 — Evaluate bound ScreenOS VPN anti-replay setting

**Task ID and Title:** RV-008 — Assess ScreenOS no-replay only for active VPNs.

**Priority:** P2 — two independent ScreenOS VPN examples contain the same explicit protection disablement, but this is a legacy platform.

**Status:** Needs release-specific ScreenOS command-reference evidence before implementation; Juniper-hosted configuration examples confirm syntax but not semantics/default.

**Source of Truth:** [RW-004](REALWORLD_VALIDATION_FINDINGS.md#RW-004), [RW-016](REALWORLD_VALIDATION_FINDINGS.md#RW-016); currently available [archived CLI reference](https://manualzz.com/doc/21898000/juniper-networks-security-device-cli-reference-guide).

**Linked Findings:** [RW-004](REALWORLD_VALIDATION_FINDINGS.md#RW-004), [RW-016](REALWORLD_VALIDATION_FINDINGS.md#RW-016).

**Dependencies:** Obtain vendor-hosted or authenticated ScreenOS 6.2/6.3 revision defining replay/no-replay, release defaults and VPN binding; verify the posted samples' syntax. This evidence gate precedes a security finding implementation.

**Architecture/Convention Notes:** Parser resolves VPN definition, gateway, binding and override; plugin evaluates effective anti-replay only for a configured active tunnel.

**Concrete Requirements:** Affected SCREENOS. If documentation confirms the command semantics, emit a finding for active no-replay with the tunnel evidence. Disabled/unbound definitions and unknown export completeness stay unknown or unassessed. No CLI/interface change required.

**Test Requirements:** Both observed syntaxes, replay enabled negative, later override, unbound/disabled tunnel, malformed/no version, redaction of preshared secrets, public pipeline and regression.

**Acceptance Criteria:** After the documentation prerequisite, RW-004 and RW-016 yield one accurate anti-replay finding per bound VPN, without treating every no-replay token as active.
