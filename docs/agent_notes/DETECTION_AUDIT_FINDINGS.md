# Detection Logic Audit Findings

Audit date: 2026-09-09

This audit is based on the implementation, not README/status claims. Every base class, issue class, device parser, analyzer/processor, and analysis plugin under `src/` was read in full. Tests and bundled original Nipper sources were used as corroborating evidence; tests were not treated as specifications.

## Summary

- **Total findings:** 84
- **Architecture-level findings:** 6 distinct findings
- **By device:** Architecture 6; Cisco IOS 15; Cisco ASA 9; FortiOS 10; PAN-OS 7; JunOS 6; ScreenOS 6; HP ProCurve 7; Check Point 5; SonicOS 6; IOS-XE 4; Arista EOS 3.
- **By category:** 1: 4; 2: 6; 3: 3; 4: 12; 5: 4; 6: 2; 7: 1; 8: 2; 9: 11; 10: 14; 11: 2; 12: 4; 13: 5; 14: 7; 15: 7.
- **By failure mode:** False negative 36; False positive 24; Crash 5; Coverage gap 12; Noise 3; Silent architectural inconsistency 4.

## Audited surface

- **Shared foundation:** `src/analyze/common/base_plugin.py`, `src/analyze/common/issue.py`, `src/devices/common/base_parser.py`, `src/devices/common/types.py`, Cisco IOS/ASA plugin bases, `CiscoIOSIssue`, report serialization, device factory and dispatch.
- **Parsers:** Cisco IOS, IOS-XE, ASA, FortiOS, PAN-OS, JunOS, ScreenOS, Arista EOS, HP ProCurve, Check Point FW1 (including its nested-file parser), and SonicOS.
- **Plugins:** all 16 plugin modules under `src/analyze/**/plugins/`.
- **Pipelines:** every `analyze_*_device.py` and `process_*_conf.py` module.

## Architecture findings

### [ARCH-01] [ARCHITECTURE] `DeviceType` / `get_parser()` / `analyze_device()` — seven implemented devices are unreachable through the CLI

**Category:** 12
**Failure mode:** Coverage gap
**Problem:** `main()` restricts `--device` to `DeviceType`, but that enum contains only IOS, PIX/ASA, Check Point, and ScreenOS. Dispatch and parser factory branches additionally advertise SonicOS, HP ProCurve, PAN-OS, FortiOS, IOS-XE, JunOS, and Arista EOS. Those seven analyzers cannot be selected through the installed command.
**Affected plugins/devices:** every plugin for SonicOS, HP ProCurve, PAN-OS, FortiOS, IOS-XE, JunOS, and Arista EOS.
**Example that breaks it:** `pynipper-ng -d FORTIOS ...` is rejected by `argparse` before `get_parser("FORTIOS", ...)` can run.
**Current behavior:** the public CLI exposes only the smaller enum even though the factory and dispatcher contain additional implementations.
**Correct behavior:** one authoritative device registry must drive enum/CLI choices, parser construction, and analyzer dispatch, with a reachability test for every registered device.
**Standard reference:** repository contracts in `src/devices/common/types.py`, the parser factory, analyzer dispatch, and CLI entry point.

### [ARCH-02] [ARCHITECTURE] `CiscoIOSIssue` — non-IOS findings use a Cisco-IOS-specific data class

**Category:** 11
**Failure mode:** Silent architectural inconsistency
**Problem:** `CiscoIOSIssue` is the only device-specific issue class, yet it is directly instantiated by ASA unified checks, Check Point, ScreenOS, SonicOS, HP, PAN-OS, FortiOS, IOS-XE, JunOS, and Arista. The generic `Issue` class already exists and is used by three ASA plugins, so the internal type contract is inconsistent.
**Affected plugins/devices:** `PluginASAChecks`, `PluginCheckPointChecks`, `PluginScreenOSChecks`, `PluginSonicOSChecks`, `PluginHPChecks`, `PluginPANOSChecks`, `PluginFortiOSChecks`, `PluginIOSXEChecks`, `PluginJunOSChecks`, `PluginAristaChecks`.
**Example that breaks it:** a FortiGate “Broad Firewall Policy” serializes as a `CiscoIOSIssue`, making type-based routing, filtering, and future device-specific report logic incorrect.
**Current behavior:** findings from ten non-IOS plugin families are represented by a Cisco IOS-specific class while other ASA findings use the generic class.
**Correct behavior:** use one vendor-neutral `Issue`/`Finding` type with an explicit device field, or create and consistently use correct per-device subclasses.
**Standard reference:** repository contracts in `src/analyze/common/issue.py`, `src/analyze/cisco/ios/issue.py`, and the report serializer.

### [ARCH-03] [ARCHITECTURE] `Issue.__init__` / `CiscoIOSIssue.__init__` — severity strings are silently stored as exploit ease

**Category:** 11
**Failure mode:** Silent architectural inconsistency
**Problem:** both constructors define positional slot four as `ease`. Most non-IOS plugins pass bare values such as `"High"` or `"Critical"`, while IOS and the generic ASA plugins pass prose describing exploitability. There is no severity field, and report serialization labels the value `ease`.
**Affected plugins/devices:** all findings emitted by the unified ASA, Check Point, ScreenOS, SonicOS, HP, PAN-OS, FortiOS, IOS-XE, JunOS, and Arista plugins.
**Example that breaks it:** FortiOS passes `"Critical"` for a broad policy; JSON emits `"ease": "Critical"`, so severity is unavailable and the field's meaning varies by plugin.
**Current behavior:** one serialized field alternates between severity labels and exploitability prose depending on the emitting plugin.
**Correct behavior:** define a typed finding schema with separate `severity` and `ease`/exploitability fields; require keyword arguments and validate values.
**Standard reference:** repository constructor and serialization contracts in `src/analyze/common/issue.py`, `src/analyze/cisco/ios/issue.py`, and the report serializer.

### [ARCH-04] [ARCHITECTURE] `BaseDeviceParser.get_raw_config()` — one interface exposes four incompatible object models

**Category:** 12
**Failure mode:** Silent architectural inconsistency
**Problem:** the base annotation is `Any` and explicitly permits a native object. Implementations return `CiscoConfParse`, XML `Element`, nested `dict`, or `list[str]`. Every plugin therefore depends on an undocumented concrete parser despite accepting `BaseDeviceParser`.
**Affected plugins/devices:** all plugins; `.find_objects()` consumers (IOS/ASA/IOS-XE/Arista), `.findall()` consumers (PAN-OS), `.get()` consumers (FortiOS/Check Point), and line-iteration consumers (JunOS/ScreenOS/HP/SonicOS).
**Example that breaks it:** a plugin written against the apparent base type can call `.get()` after receiving an XML element or `.find_objects()` after receiving a list and crash.
**Current behavior:** plugins are nominally typed against one base parser but must know and cast to an undocumented vendor-native object model.
**Correct behavior:** expose normalized typed models for users, services, interfaces, policies, logging, and crypto; keep native parser access behind explicitly vendor-specific APIs.
**Standard reference:** repository base contract in `src/devices/common/base_parser.py` and its parser implementations.

### [ARCH-05] [ARCHITECTURE] `BaseDeviceParser.get_services()` — common-looking booleans have incompatible and placeholder semantics

**Category:** 12
**Failure mode:** Silent architectural inconsistency
**Problem:** the contract says “configured management services,” but implementations omit keys, invent defaults, or return constants. IOS omits SSH; PAN-OS and ScreenOS always return all-false placeholders; FortiOS reads non-existent global-admin keys; HP assumes Telnet enabled; other parsers scan unrelated substring syntaxes.
**Affected plugins/devices:** IOS helper consumers plus ASA Telnet, FortiOS admin access, JunOS management, HP Telnet/web, and SonicOS HTTP checks; future callers are equally exposed.
**Example that breaks it:** a real FortiGate with `set allowaccess http` on a WAN interface yields `http=False`, while a caller sees the same shape as a trustworthy ASA result.
**Current behavior:** identical-looking boolean dictionaries mean active, configured, assumed-default, or unimplemented depending on the parser.
**Correct behavior:** define a normalized service record including protocol, enabled/effective state, interface/zone, permitted sources, config evidence, and an explicit unknown state.
**Standard reference:** repository base contract in `src/devices/common/base_parser.py` and each parser's `get_services()` implementation.

### [ARCH-06] [ARCHITECTURE] ASA processing pipeline — the active loader executes overlapping plugins and emits duplicate findings

**Category:** 12
**Failure mode:** Noise
**Problem:** `analyze_asa_device()` uses dynamic `process_asa_conf()`, which loads `PluginASAChecks` plus `LoggingPlugin`, `ManagementPlugin`, and `SNMPPlugin`. The unified plugin duplicates logging, Telnet, unrestricted SSH, and SNMP checks. A separate `process_cisco_asa_conf()` runs only the unified plugin but is not used by dispatch.
**Affected plugins/devices:** Cisco ASA `PluginASAChecks`, `LoggingPlugin`, `ManagementPlugin`, `SNMPPlugin`.
**Example that breaks it:** the checked-in `tests/test_data/asa_output.json` contains two logging, two Telnet, two unrestricted-SSH, and two SNMP findings for one condition.
**Current behavior:** the public ASA analysis path executes both the unified rules and their legacy equivalents and reports the same root condition more than once.
**Correct behavior:** choose one ASA pipeline, remove overlapping registration, and assign stable rule IDs so one root condition produces one finding.
**Standard reference:** repository execution contracts in `src/analyze/cisco/asa/analyze_asa_device.py`, both ASA processors, and `tests/test_data/asa_output.json`.

## Cisco IOS findings

### [IOS-01] [CISCO IOS] `http_plugin.py:_has_http` — positive HTTP pattern matches the negated command

**Category:** 2
**Failure mode:** False positive
**Problem:** `find_objects("ip http server")` is evaluated before `find_objects("no ip http server")`; the positive text is a substring of the negative.
**Example that breaks it:** `no ip http server` makes `http_enable` non-empty and reports HTTP enabled.
**Current behavior:** returns `True`; the negative branch is effectively dead for normal running-config.
**Correct behavior:** anchor exact positive/negative commands or evaluate normalized final state.
**Standard reference:** [Cisco HTTP Services Configuration Guide](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/https/configuration/xe-17/https-xe-17-book.pdf).

### [IOS-02] [CISCO IOS] `http_plugin.py:_has_http` / `CiscoIOSParser.get_services` — absence is treated as HTTP enabled

**Category:** 5
**Failure mode:** False positive
**Problem:** both paths return HTTP enabled when neither command is present. Current Cisco IOS-XE documentation states HTTP/HTTPS servers are disabled by default.
**Example that breaks it:** a minimal config with no `ip http server` produces an HTTP finding.
**Current behavior:** assumes insecure-by-default without version/platform qualification.
**Correct behavior:** model the default by detected OS/version; for current IOS-XE, absence means disabled.
**Standard reference:** [Cisco IOS-XE HTTP Services Guide](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/https/configuration/xe-17/https-xe-17-book.pdf).

### [IOS-03] [CISCO IOS] `PluginHTTP.analyze` — HTTP ACL/auth checks run while HTTP is disabled

**Category:** 8
**Failure mode:** False positive
**Problem:** `analyze()` always invokes the access-class and authentication checks; neither is gated on effective HTTP enablement.
**Example that breaks it:** a securely disabled server with `no ip http server` and no HTTP ACL/auth receives “ACL restrict” and “Authentication mode” findings.
**Current behavior:** reports controls that are irrelevant to a disabled service.
**Correct behavior:** first determine effective service state; run compensating-control checks only when clear-text HTTP is enabled.
**Standard reference:** [Cisco IOS XE HTTP Services configuration guide](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/https/configuration/xe-17/https-xe-17-book.pdf).

### [IOS-04] [CISCO IOS] `http_plugin.py:_get_cisco_ios_http_access_list` — named ACLs crash the scan

**Category:** 3
**Failure mode:** Crash
**Problem:** the token after `ip http access-class` is unconditionally passed to `int()`.
**Example that breaks it:** `ip http access-class MGMT-ACL` raises `ValueError`.
**Current behavior:** aborts analysis instead of recognizing a valid named ACL.
**Correct behavior:** preserve ACL identifiers as strings and resolve either numbered or named ACLs.
**Standard reference:** [Cisco IP Access List configuration guidance](https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html).

### [IOS-05] [CISCO IOS] `http_plugin.py:_get_cisco_ios_http_auth` — the regex returns the optional suffix, not the auth method

**Category:** 4
**Failure mode:** False negative
**Problem:** the regex has two capture groups, but `re_match_typed()` defaults to group 1. For `ip http authentication local`, group 1 is `entication`; the actual method is group 2. Presence is then treated as sufficient without validating the method.
**Example that breaks it:** `ip http authentication bogus` returns `entication` and passes.
**Current behavior:** any full-form line is considered configured; abbreviated `ip http auth local` can return the empty default.
**Correct behavior:** capture only the value (`(?:entication)?`) and validate supported secure authentication modes.
**Standard reference:** [Cisco IOS XE HTTP Services configuration guide](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/https/configuration/xe-17/https-xe-17-book.pdf).

### [IOS-06] [CISCO IOS] `ssh_plugin.py:_has_cisco_ios_ssh` — unrelated line scopes determine one global SSH state

**Category:** 15
**Failure mode:** False negative
**Problem:** any `transport input none`, `no transport input ssh`, or `no ip ssh` anywhere makes SSH “disabled,” without checking whether the line is AUX/TTY/VTY or whether other VTY ranges allow SSH. Conversely absence of all three means “enabled” without RSA keys, hostname/domain, auth, or VTY SSH transport.
**Example that breaks it:** secure AUX hardening (`line aux 0` + `transport input none`) plus SSH-enabled VTY lines makes `_has_cisco_ios_ssh()` return false.
**Current behavior:** collapses per-line service state into an incorrect global Boolean.
**Correct behavior:** derive effective SSH server prerequisites and evaluate every VTY range separately.
**Standard reference:** [Cisco Configure SSH on Routers](https://www.cisco.com/c/en/us/support/docs/security-vpn/secure-shell-ssh/4145-ssh.html).

### [IOS-07] [CISCO IOS] `ssh_plugin.py:get_cisco_ios_ssh` — disabled, unconfigured, compatibility-mode, and SSHv1 share one finding

**Category:** 6
**Failure mode:** Noise
**Problem:** one OR condition emits SSHv1-specific observation/remediation for four distinct states.
**Example that breaks it:** a device intentionally exposing no SSH receives text claiming SSHv1 traffic is interceptable.
**Current behavior:** the finding cannot tell whether to enable SSH, configure VTY prerequisites, or force v2.
**Correct behavior:** separate “SSH not available/configured” from “SSH enabled without v2-only mode.”
**Standard reference:** [Cisco Configure SSH on Routers](https://www.cisco.com/c/en/us/support/docs/security-vpn/secure-shell-ssh/4145-ssh.html).

### [IOS-08] [CISCO IOS] `ssh_plugin.py:get_cisco_ios_ssh_reties` — omitted retry setting is treated as insecure despite a default of 3

**Category:** 5
**Failure mode:** False positive
**Problem:** the helper returns `""` when absent and the check always flags it. Cisco documents the default authentication retry count as 3, which satisfies the code's stated maximum of 5.
**Example that breaks it:** SSHv2 with no explicit `ip ssh authentication-retries` is reported vulnerable.
**Current behavior:** confuses “not explicitly configured” with “unbounded.”
**Correct behavior:** apply version-aware defaults before threshold evaluation.
**Standard reference:** [Cisco SSH command reference](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/command-reference/b_wireless_cr/configuration-commands-g-to-z.html).

### [IOS-09] [CISCO IOS] `ssh_plugin.py:get_cisco_ios_ssh_reties` — retry coercion is unguarded

**Category:** 3
**Failure mode:** Crash
**Problem:** `int(retries)` is called on any captured non-empty token.
**Example that breaks it:** malformed/truncated `ip ssh authentication-retries many` raises `ValueError` and aborts the scan.
**Current behavior:** parser corruption is fatal and produces no audit result.
**Correct behavior:** typed parsing must emit an explicit parse-error/unknown state without stopping other checks.
**Standard reference:** [Cisco IOS Security command reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/d1/sec-d1-cr-book/sec-cr-i3.html).

### [IOS-10] [CISCO IOS] `ssh_plugin.py:get_cisco_ios_ssh_timeout` — omitted timeout is treated as zero instead of the documented default

**Category:** 5
**Failure mode:** False positive
**Problem:** absence becomes `0` and is flagged, while Cisco documents a default negotiation timeout of 120 seconds.
**Example that breaks it:** a default SSH configuration with no explicit timeout receives the finding even though the code accepts an explicit `120`.
**Current behavior:** identical effective states (implicit 120, explicit 120) receive opposite results.
**Correct behavior:** use the platform/version default when absent.
**Standard reference:** [Cisco SSH command reference](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/command-reference/b_wireless_cr/configuration-commands-g-to-z.html).

### [IOS-11] [CISCO IOS] `ssh_plugin.py:_get_cisco_ios_ssh_timeout` — timeout coercion is unguarded

**Category:** 3
**Failure mode:** Crash
**Problem:** the captured token is passed directly to `int()`.
**Example that breaks it:** `ip ssh time-out default` or a truncated/corrupt token raises `ValueError`.
**Current behavior:** one malformed line aborts every later check/report.
**Correct behavior:** validate numeric syntax/range and surface unknown input as a parser finding.
**Standard reference:** [Cisco IOS Security command reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/d1/sec-d1-cr-book/sec-cr-i3.html).

### [IOS-12] [CISCO IOS] `ssh_plugin.py:get_cisco_ios_ssh_timeout` — description and enforced threshold disagree

**Category:** 7
**Failure mode:** Noise
**Problem:** the observation says the acceptable timeout is “between 0 and 60 seconds,” while code accepts 1–120 and flags 0 or values above 120.
**Example that breaks it:** `ip ssh time-out 90` passes code but violates the report's claimed range.
**Current behavior:** operators cannot infer the actual policy from the finding.
**Correct behavior:** select a sourced threshold and make code, text, and tests identical.
**Standard reference:** [Cisco IOS hardening guide (example uses 120)](https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html).

### [IOS-13] [CISCO IOS] `ssh_plugin.py:get_cisco_ios_ssh_interface` — an outbound-client source command is presented as inbound access control

**Category:** 6
**Failure mode:** False positive
**Problem:** `ip ssh source-interface` selects the source address for this device's outgoing SSH client connections; it does not restrict which interfaces or hosts may manage the SSH server.
**Example that breaks it:** VTY `access-class MGMT in` correctly restricts administrators, but absence of `ip ssh source-interface` is still flagged.
**Current behavior:** recommends an unrelated command and misses the actual inbound control.
**Correct behavior:** audit VTY `access-class` coverage for all VTY ranges; audit client source-interface separately if desired.
**Standard reference:** [Cisco `ip ssh source-interface` reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/d1/sec-d1-cr-book/sec-cr-i3.html).

### [IOS-14] [CISCO IOS] `CiscoIOSParser.get_version` — fabricated `(1)` versions can query the wrong advisory set

**Category:** 10
**Failure mode:** False positive
**Problem:** when the version token lacks parentheses, the parser appends `(1)` and submits that invented version to Cisco's advisory API.
**Example that breaks it:** `version 15.2` becomes `15.2(1)` even if the actual train/release is different.
**Current behavior:** vulnerability results can be for a release the device never ran.
**Correct behavior:** preserve unknown precision, collect a real `show version` identifier, or skip exact-version matching with an explicit uncertainty note.
**Standard reference:** [Cisco IOS XE Software Hardening Guide](https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening); repository advisory lookup and `CiscoIOSParser.get_version()` contracts.

### [IOS-15] [CISCO IOS] plugin set — original Nipper and current hardening controls are mostly absent

**Category:** 9
**Failure mode:** Coverage gap
**Problem:** only HTTP and four SSH checks exist. Missing original-Nipper categories include password strength/encryption/enable secret, AAA, Telnet/VTY/AUX timeouts, logging, SNMP, NTP, banners, source routing, BOOTP/small services, CDP, interface redirects/proxy ARP/unreachables, switch trunk/port security, uRPF, and routing-protocol authentication.
**Example that breaks it:** `snmp-server community public rw`, no logging hosts, plaintext type-0 users, and unauthenticated OSPF produce no findings.
**Current behavior:** a report can appear complete while ignoring most management/control-plane hardening.
**Correct behavior:** restore normalized checks with device-role/version awareness and traceable rule IDs.
**Standard reference:** bundled original `reference/nipper-ng-original/0.11.10/IOS/report.c:91-500`; [Cisco IOS-XE Software Hardening Guide](https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening).

## Cisco ASA findings

### [ASA-01] [CISCO ASA] `CiscoASAParser.get_services` — Telnet timeout is mistaken for an access grant

**Category:** 2
**Failure mode:** False positive
**Problem:** `find_objects("^telnet")` counts every Telnet-prefixed command, including `telnet timeout`, as service exposure.
**Example that breaks it:** `telnet timeout 5` with no `telnet <network> <mask> <interface>` line reports Telnet enabled.
**Current behavior:** presence of a tuning command is treated as an allowed source.
**Correct behavior:** parse only access-grant syntax and retain interface/source scope.
**Standard reference:** [Cisco ASA command reference for SSH/Telnet commands](https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/S/asa-command-ref-S/so-st-commands.html).

### [ASA-02] [CISCO ASA] `PluginASAChecks.check_weak_enable_password` — four literals stand in for password strength/encryption

**Category:** 1
**Failure mode:** False negative
**Problem:** only exact case-sensitive `cisco`, `cisco123`, `admin`, and `password` values are flagged; encryption type, plaintext storage, length, and missing secret are ignored.
**Example that breaks it:** `enable password Spring2026` or a one-character plaintext value passes.
**Current behavior:** almost every weak password is treated as secure.
**Correct behavior:** parse hash/encryption metadata, detect plaintext and structural policy violations, and optionally use a broad denylist as a secondary signal.
**Standard reference:** bundled original PIX password strength/dictionary checks in `reference/nipper-ng-original/0.11.10/PIX/report-passwords.c`.

### [ASA-03] [CISCO ASA] `PluginASAChecks.check_snmp_communities` — only two exact default strings are considered insecure

**Category:** 1
**Failure mode:** False negative
**Problem:** community strength, write access, ACL/scope, and SNMP version are not evaluated.
**Example that breaks it:** `snmp-server community a` or an unrestricted writable v2c community passes.
**Current behavior:** only exact `public`/`private` is detected.
**Correct behavior:** parse version, permission, source/interface restrictions, and structural secret strength; prefer authenticated/private SNMPv3.
**Standard reference:** [Cisco ASA General Operations Guide, SNMP chapter](https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/general/asa-916-general-config.pdf).

### [ASA-04] [CISCO ASA] `snmp_plugin.py:get_insecure_community_issue` — substring matching flags strong communities

**Category:** 2
**Failure mode:** False positive
**Problem:** it searches for `"public"` or `"private"` anywhere in the full line.
**Example that breaks it:** `snmp-server community NotPublicButRandomized` is flagged because it contains `Public` only if same case; `myprivatekey` is always flagged.
**Current behavior:** token boundaries and case normalization are inconsistent with the unified plugin.
**Correct behavior:** parse the community token, then apply explicit default and structural-strength rules.
**Standard reference:** [Cisco ASA General Operations configuration guide](https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/general/asa-916-general-config.pdf).

### [ASA-05] [CISCO ASA] `PluginASAChecks.check_unrestricted_ssh` — source breadth is judged without trust scope or IPv6 syntax

**Category:** 15
**Failure mode:** False positive
**Problem:** every IPv4 `0.0.0.0/0` grant is labeled “network/internet” exposure regardless of the named interface, while IPv6 any-source forms are not parsed.
**Example that breaks it:** `ssh 0.0.0.0 0.0.0.0 mgmt-only` on an isolated OOB interface gets the same finding as `outside`; `ssh ::/0 outside` can be missed.
**Current behavior:** both overstates trusted OOB access and under-covers alternate syntax.
**Correct behavior:** classify interface/zone exposure, parse IPv4/IPv6 forms, and report the concrete reachable scope.
**Standard reference:** [Cisco ASA command reference for SSH/Telnet commands](https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/S/asa-command-ref-S/so-st-commands.html).

### [ASA-06] [CISCO ASA] `PluginASAChecks.check_logging` / `LoggingPlugin` — global enablement is treated as meaningful external logging

**Category:** 14
**Failure mode:** False negative
**Problem:** both checks only test `logging enable`. They do not require a logging destination, suitable severity, secure transport, or active host; one finding's remediation nevertheless claims external syslog.
**Example that breaks it:** `logging enable` with no `logging host` passes both checks.
**Current behavior:** local/global activation is conflated with centralized auditability.
**Correct behavior:** separately evaluate enablement, destinations, severity, reachability/source interface, and secure transport.
**Standard reference:** [Cisco ASA logging guide](https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/general/asa-916-general-config/monitor-syslog.html).

### [ASA-07] [CISCO ASA] `CiscoASAParser.get_ssl_min_version` / `check_ssl_version` — the parser recognizes the test's invented command, not ASA syntax

**Category:** 4
**Failure mode:** False negative
**Problem:** code searches `ssl minimum-version`; Cisco ASA uses `ssl server-version`. Absence is ignored even though documented ASA defaults include TLSv1 on relevant releases.
**Example that breaks it:** `ssl server-version tlsv1` is returned as empty and produces no finding; the repository fixture's `ssl minimum-version tlsv1` is not real ASA syntax.
**Current behavior:** tests pass against a synthetic dialect while actual insecure configurations pass silently.
**Correct behavior:** parse `ssl server-version`, version-specific defaults, maximums, ciphers, and DTLS separately.
**Standard reference:** [Cisco ASA `ssl server-version` reference](https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/S/asa-command-ref-S/so-st-commands.html).

### [ASA-08] [CISCO ASA] `PluginASAChecks.check_wide_open_acls` — text search both misses broad rules and can match inert text

**Category:** 4
**Failure mode:** False negative
**Problem:** only `permit ip any any` and `permit tcp any any` are recognized. UDP/ICMP/IPv6/object forms are missed; rule activation and remarks are not parsed.
**Example that breaks it:** `access-list OUT extended permit udp any any` passes. Conversely a remark containing `permit ip any any` can be flagged.
**Current behavior:** ACL semantics are approximated by two unanchored substrings.
**Correct behavior:** parse ACL action/protocol/source/destination/ports, inactive state, address family, objects, binding direction, and interface scope.
**Standard reference:** bundled original PIX ACL processing in `reference/nipper-ng-original/0.11.10/PIX/process-access-list.c`.

### [ASA-09] [CISCO ASA] plugin set — major original and current hardening controls are absent

**Category:** 9
**Failure mode:** Coverage gap
**Problem:** missing categories include structural password/dictionary checks, AAA, management timeouts, SSH protocol/ciphers, SNMP write/version/restriction checks, floodguard, uRPF/anti-spoofing, HTTP/HTTPS access scope, interface/policy/NAT semantics, and complete logging validation.
**Example that breaks it:** insecure SNMPv2c RW, no AAA accounting, weak SSH protocol settings, and no anti-spoofing can all coexist without findings.
**Current behavior:** seven shallow checks are presented as an ASA audit.
**Correct behavior:** implement normalized, scope-aware controls and parity tests derived from real ASA configs.
**Standard reference:** bundled original `reference/nipper-ng-original/0.11.10/PIX/report.c:75-152`; [Cisco ASA General Operations Guide](https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/general/asa-916-general-config.pdf).

## FortiOS findings

### [FORTI-01] [FORTIOS] `FortiOSParser._parse_config` / `check_broad_policies` — quoted values never equal unquoted literals

**Category:** 13
**Failure mode:** False negative
**Problem:** the parser retains raw value text, including quotes, while checks compare exact scalar strings such as `"any"` and `"accept"`.
**Example that breaks it:** normal FortiOS lines `set srcintf "any"` and `set dstintf "any"` become `"\"any\""` and never equal `"any"`.
**Current behavior:** the synthetic unquoted unit fixture fires; typical exported configuration does not.
**Correct behavior:** tokenize quoted FortiOS values into normalized scalar/list types with preserved raw evidence.
**Standard reference:** [FortiOS system interface CLI reference](https://docs.fortinet.com/document/fortigate/8.0.0/cli-reference/317104469/config-system-interface).

### [FORTI-02] [FORTIOS] `FortiOSParser.get_services` — management protocols are read from the wrong configuration section

**Category:** 4
**Failure mode:** False negative
**Problem:** code looks for `http-access`/`telnet-access` under `config system admin`. FortiGate interface management exposure is configured with `allowaccess` under `config system interface`; administrator sections instead contain account/trusted-host settings.
**Example that breaks it:** WAN `set allowaccess ping http telnet` yields both service booleans false.
**Current behavior:** real insecure management exposure is invisible.
**Correct behavior:** parse per-interface `allowaccess`, interface status/role/VDOM, and administrator trusted hosts.
**Standard reference:** [FortiOS `config system interface`](https://docs.fortinet.com/document/fortigate/8.0.0/cli-reference/317104469/config-system-interface).

### [FORTI-03] [FORTIOS] `PluginFortiOSChecks.check_admin_access` — management exposure has no interface or trusted-host context

**Category:** 15
**Failure mode:** False negative
**Problem:** a single global Boolean cannot distinguish WAN exposure from OOB/LAN access and never evaluates `trustedhost1..10` restrictions.
**Example that breaks it:** HTTP on `wan1` with unrestricted administrators and HTTP on an isolated management interface with all admins restricted would receive the same result if service parsing worked.
**Current behavior:** scope-sensitive risk is collapsed and currently missed due to FORTI-02.
**Correct behavior:** emit evidence per interface/VDOM and effective administrator source set.
**Standard reference:** [Fortinet administrator best practices](https://docs.fortinet.com/document/fortigate/6.2.0/hardening-your-fortigate/582009/systemadministrator-bestpractices).

### [FORTI-04] [FORTIOS] `PluginFortiOSChecks.check_broad_policies` — interface wildcards are mislabeled as any-any-any policy semantics

**Category:** 13
**Failure mode:** False positive
**Problem:** the check tests only `srcintf`, `dstintf`, and action. It ignores `srcaddr`, `dstaddr`, `service`, schedule, disabled/status, users, NAT, and policy order, yet calls the rule “any-any-any.”
**Example that breaks it:** interfaces `any`→`any`, source `AdminSubnet`, destination `Web01`, service `HTTPS`, action accept is flagged as unrestricted; a real any-address/any-service rule on named interfaces is missed.
**Current behavior:** the compared fields do not represent the claimed policy breadth.
**Correct behavior:** normalize and evaluate all match dimensions plus enablement/order, then describe exactly which dimensions are broad.
**Standard reference:** [FortiGate system-hardening guidance](https://docs.fortinet.com/document/managed-fortigate-service/latest/service-catalog-use-cases/252497/ngfw-2-system-hardening).

### [FORTI-05] [FORTIOS] `PluginFortiOSChecks.check_tls_settings` — accepted value spellings do not match FortiOS

**Category:** 4
**Failure mode:** False negative
**Problem:** code checks `TLSv1.0` and `TLSv1.1`; FortiOS CLI values are `TLSv1` and `TLSv1-1`. It also ignores `admin-https-ssl-versions`, which directly governs web administration.
**Example that breaks it:** `set ssl-min-proto-version TLSv1-1` produces no finding.
**Current behavior:** the insecure enumerations it tests are not the vendor's enumerations.
**Correct behavior:** use versioned accepted enums and audit the management-specific TLS version/cipher settings.
**Standard reference:** [FortiOS `config system global`](https://docs.fortinet.com/document/fortigate/7.2.12/cli-reference/339914554/config-system-global).

### [FORTI-06] [FORTIOS] `PluginFortiOSChecks.check_syslog` — section existence is treated as active logging and other valid targets are rejected

**Category:** 14
**Failure mode:** False negative
**Problem:** a present `log syslogd setting` passes even when `status disable` (the default) or no usable server is set. Conversely FortiAnalyzer/FortiCloud-only central logging is flagged because that exact key is absent.
**Example that breaks it:** `config log syslogd setting; set status disable; end` produces no finding.
**Current behavior:** both disabled syslog and alternative valid logging architectures are misclassified.
**Correct behavior:** evaluate enabled, configured destinations across supported target types and VDOM overrides, plus filters/source/transport.
**Standard reference:** [FortiOS log settings and targets](https://docs.fortinet.com/document/fortigate/7.6.0/administration-guide/250999/log-settings-and-targets).

### [FORTI-07] [FORTIOS] `FortiOSParser._parse_config` — VDOM/global nesting makes every plugin lookup miss

**Category:** 10
**Failure mode:** False negative
**Problem:** plugins assume `system global`, `firewall policy`, and logging sections are top-level. In multi-VDOM/global exports, the parser nests them under path elements such as `vdom` and edited VDOM names.
**Example that breaks it:** `config vdom; edit root; config firewall policy ...` stores policies below `vdom/root/firewall policy`; `.get("firewall policy", {})` returns empty.
**Current behavior:** an entire class of real FortiGate configurations yields no policy findings.
**Correct behavior:** explicitly model global and per-VDOM roots and iterate each scope.
**Standard reference:** [FortiOS VDOM syslog override example](https://docs.fortinet.com/document/fortigate/7.6.5/administration-guide/875512/configuring-syslog-overrides-for-vdoms).

### [FORTI-08] [FORTIOS] `FortiOSParser._parse_config` — nesting errors crash or silently corrupt the tree

**Category:** 10
**Failure mode:** Crash
**Problem:** every `next`/`end` blindly calls `path.pop()`; unmatched terminators raise `IndexError`, while EOF with unclosed blocks is accepted. `unset`, `append`, `select`, comments, and repeated semantic operations are ignored.
**Example that breaks it:** a truncated export beginning with `end` crashes; a missing final `end` returns a plausible but wrongly nested dict.
**Current behavior:** malformed input is either fatal or silently trusted.
**Correct behavior:** use a stateful grammar with line-numbered validation, supported operations, and explicit parse diagnostics.
**Standard reference:** [FortiOS CLI reference](https://docs.fortinet.com/document/fortigate/8.0.0/cli-reference/317104469/config-system-interface); FortiOS configuration block grammar used throughout the same CLI reference.

### [FORTI-09] [FORTIOS] `FortiOSParser.get_users/get_version` — security-relevant identity and version data are hard-coded unknown

**Category:** 10
**Failure mode:** False negative
**Problem:** users always return `[]` and version always returns `?`, despite admin blocks and configuration headers carrying relevant data.
**Example that breaks it:** default admin without trusted hosts, weak/no password policy, and a vulnerable firmware release cannot be associated with any parser result.
**Current behavior:** downstream checks cannot audit administrators or version-dependent defaults.
**Correct behavior:** parse administrator records, authentication/profile/trusted-host fields, password-policy state, and version metadata.
**Standard reference:** [Fortinet administrator account options](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/14906/administrator-account-options).

### [FORTI-10] [FORTIOS] plugin set — core FortiGate hardening controls are missing

**Category:** 9
**Failure mode:** Coverage gap
**Problem:** missing checks include trusted hosts, MFA/auth sources, password policy, admin lockout/idle timeout, interface `allowaccess`, strong crypto/static-key/SSH algorithms/DH, NTP, banners, unused interfaces/services, FortiGuard update state, policy logging/security profiles, local/remote log filters, and DoS policies.
**Example that breaks it:** `strong-crypto disable`, unrestricted admins, disabled password policy, no lockout, stale updates, and allow rules without logging produce no findings.
**Current behavior:** four checks cover only fragments, two of which do not match real syntax.
**Correct behavior:** implement version-aware checks over normalized global/VDOM/interface/admin/policy models.
**Standard reference:** [Fortinet system hardening use case](https://docs.fortinet.com/document/managed-fortigate-service/latest/service-catalog-use-cases/252497/ngfw-2-system-hardening); [FortiOS password policy](https://docs.fortinet.com/document/fortigate/7.0.4/administration-guide/364729).

## PAN-OS findings

### [PAN-01] [PAN-OS] `PluginPANOSChecks.check_insecure_management` — management profiles are queried at the wrong XPath

**Category:** 4
**Failure mode:** False negative
**Problem:** code searches `.//mgt-config/profiles/entry`; PAN-OS interface management profiles live under `network/profiles/interface-management-profile`.
**Example that breaks it:** a real profile with `<network><profiles><interface-management-profile><entry><http>yes</http>` is never inspected.
**Current behavior:** the synthetic test XML validates a non-vendor hierarchy.
**Correct behavior:** parse the actual hierarchy and distinguish dedicated MGT-interface settings from dataplane interface profiles.
**Standard reference:** [PAN-OS CLI hierarchy](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-command-hierarchy/pan-os-11-2-configure-cli-command-hierarchy).

### [PAN-02] [PAN-OS] `check_insecure_management` — unused profiles are flagged and attached-profile scope is ignored

**Category:** 15
**Failure mode:** False positive
**Problem:** even if the XPath were fixed, any profile containing HTTP would trigger without proving it is assigned to an enabled interface or whether permitted IPs/zone exposure make it reachable.
**Example that breaks it:** an unused legacy profile with HTTP enabled produces the same issue as an assigned WAN profile.
**Current behavior:** definition existence is treated as effective exposure.
**Correct behavior:** resolve profile assignments, interface state/zone, and permitted IP addresses before reporting.
**Standard reference:** [Use Interface Management Profiles to Restrict Access](https://docs.paloaltonetworks.com/ngfw/networking/configure-interfaces/use-interface-management-profiles-to-restrict-access).

### [PAN-03] [PAN-OS] `PluginPANOSChecks.check_broad_rules` — disabled and application/zone-restricted rules are labeled unrestricted

**Category:** 15
**Failure mode:** False positive
**Problem:** the check considers only first source/destination/service member and action. It ignores `disabled`, from/to zones, application, users, category, schedule, profiles, logging, and rulebase order.
**Example that breaks it:** a disabled allow rule with source/destination/service `any`, or an active rule limited to one application and trusted zones, is reported as “any-any-any security bypass.”
**Current behavior:** rule semantics and effective reachability are overstated.
**Correct behavior:** normalize all rule match/action/state dimensions and report breadth with context.
**Standard reference:** [PAN-OS security-policy rule best practices](https://docs.paloaltonetworks.com/best-practices/security-policy-best-practices/security-policy-best-practices/deploy-security-policy-best-practices/security-policy-rule-best-practices).

### [PAN-04] [PAN-OS] `PluginPANOSChecks.check_syslog` — an unattached server profile passes as forwarding

**Category:** 14
**Failure mode:** False negative
**Problem:** code only checks whether any `.//log-settings/syslog` element exists. PAN-OS requires log-forwarding profiles and assignments to policy rules (and separate management-plane log settings).
**Example that breaks it:** an unused syslog server profile exists, but no rule has `<log-setting>` and management logs are not forwarded; the check passes.
**Current behavior:** destination definition is conflated with active forwarding.
**Correct behavior:** validate destination health/configuration, log-forwarding profiles, rule assignments, and management-plane forwarding separately.
**Standard reference:** [PAN-OS Log Forwarding](https://docs.paloaltonetworks.com/network-security/security-policy/administration/objects/log-forwarding).

### [PAN-05] [PAN-OS] `PluginPANOSChecks.check_weak_password` — disabled or empty complexity sections pass

**Category:** 14
**Failure mode:** False negative
**Problem:** only section absence is flagged; `<enabled>no</enabled>` and thresholds of zero pass.
**Example that breaks it:** `<password-complexity><enabled>no</enabled><minimum-length>0</minimum-length></password-complexity>` is considered secure.
**Current behavior:** configuration presence is substituted for enforcement.
**Correct behavior:** require enabled state and audit concrete length, character, history, username, and expiration controls with version-aware policy.
**Standard reference:** [PAN-OS CLI password-complexity hierarchy](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-command-hierarchy/pan-os-11-2-configure-cli-command-hierarchy).

### [PAN-06] [PAN-OS] `PaloAltoPANOSParser.get_services/get_users/get_version` — three base methods are placeholders

**Category:** 10
**Failure mode:** False negative
**Problem:** services always return all false, users always empty, and version always `?` regardless of XML.
**Example that breaks it:** Telnet/HTTP enabled on management interfaces and local superusers cannot be discovered through the shared parser API.
**Current behavior:** future shared checks receive confident false/empty values rather than unknown.
**Correct behavior:** parse real nodes or return an explicit unsupported/unknown result that cannot be mistaken for secure absence.
**Standard reference:** [PAN-OS interface management profile documentation](https://docs.paloaltonetworks.com/ngfw/networking/configure-interfaces/use-interface-management-profiles-to-restrict-access).

### [PAN-07] [PAN-OS] plugin set — major management and policy best-practice checks are absent

**Category:** 9
**Failure mode:** Coverage gap
**Problem:** missing checks include permitted management IPs/profile assignment, MGT access protocols/TLS/certificates, admin roles/authentication/MFA, full password thresholds, NTP/DNS/update services, policy logging/log-forwarding attachment, security profiles, default-rule overrides, zones/app/user/category/schedule context, and disabled/shadowed rules.
**Example that breaks it:** allow rules without security profiles or logging, unrestricted SSH management, and password complexity enabled with zero thresholds pass.
**Current behavior:** four existence/text checks stand in for a firewall audit.
**Correct behavior:** build normalized management, administrator, logging, and ordered rulebase models.
**Standard reference:** [PAN-OS security policy best practices](https://docs.paloaltonetworks.com/best-practices/security-policy-best-practices/security-policy-best-practices/deploy-security-policy-best-practices/security-policy-rule-best-practices); [PAN-OS management profiles](https://docs.paloaltonetworks.com/ngfw/networking/configure-interfaces/use-interface-management-profiles-to-restrict-access).

## JunOS findings

### [JUN-01] [JUNOS] `JunOSParser.__init__` — hierarchical Junos configuration is silently unsupported

**Category:** 10
**Failure mode:** False negative
**Problem:** the parser stores stripped lines and assumes `display set`; it neither detects nor parses normal brace-delimited configuration.
**Example that breaks it:** `system { services { telnet; } }` yields all services false and no finding.
**Current behavior:** an unsupported input dialect is accepted as if securely empty.
**Correct behavior:** detect input format, parse both hierarchical and set forms, or fail explicitly with a format diagnostic.
**Standard reference:** [Junos remote-access configuration guide](https://www.juniper.net/documentation/us/en/software/junos/junos-getting-started/topics/task/remote-access.html); [Junos hardening checklist](https://www.juniper.net/assets/us/en/local/pdf/books/tw-hardening-junos-devices-checklist.pdf).

### [JUN-02] [JUNOS] `JunOSParser.get_services` — substring matching counts inactive/delete lines and HTTPS as HTTP

**Category:** 2
**Failure mode:** False positive
**Problem:** checks use `in` anywhere in a line. `inactive:`, `delete`, comments, and `set system services web-management https` all satisfy the positive strings.
**Example that breaks it:** `inactive: set system services telnet` or HTTPS-only J-Web sets the insecure Telnet/HTTP Boolean.
**Current behavior:** syntax state and secure subprotocol are ignored.
**Correct behavior:** parse active set/delete semantics and separate HTTP from HTTPS.
**Standard reference:** [Juniper remote access services](https://www.juniper.net/documentation/us/en/software/junos/junos-getting-started/topics/task/remote-access.html).

### [JUN-03] [JUNOS] `PluginJunOSChecks.check_broad_filters` — the check requires mutually separate Junos statements on one line

**Category:** 4
**Failure mode:** False negative
**Problem:** one line must contain `filter`, `term`, `source/destination-address`, and `then accept`. In display-set syntax, match conditions and actions are separate set lines.
**Example that breaks it:** `set firewall family inet filter F term T from source-address 0.0.0.0/0` plus `set ... term T then accept` never triggers.
**Current behavior:** only the repository's synthetic combined line fires.
**Correct behavior:** group statements by family/filter/term, then evaluate the assembled term and filter attachment.
**Standard reference:** [Juniper stateless firewall-filter components](https://www.juniper.net/documentation/us/en/software/junos/routing-policy/topics/concept/firewall-filter-components.html); [Juniper firewall-filter configuration](https://www.juniper.net/documentation/us/en/software/junos/routing-policy/topics/task/firewall-filter-qfx-series-cli.html).

### [JUN-04] [JUNOS] `PluginJunOSChecks.check_ssh_root` — inactive/delete syntax is treated as active root login

**Category:** 2
**Failure mode:** False positive
**Problem:** an unanchored substring search flags any line containing `set system services ssh root-login allow`.
**Example that breaks it:** `inactive: set system services ssh root-login allow` produces a finding.
**Current behavior:** configuration operation/state is not parsed.
**Correct behavior:** evaluate the final active candidate configuration and supported root-login modes.
**Standard reference:** [Juniper hardening checklist](https://www.juniper.net/assets/us/en/local/pdf/books/tw-hardening-junos-devices-checklist.pdf).

### [JUN-05] [JUNOS] `JunOSParser.get_users/get_version` — identity and release context are discarded

**Category:** 10
**Failure mode:** False negative
**Problem:** users always return empty and version always `?`.
**Example that breaks it:** root authentication, password/hash form, local class/permissions, and version-specific defaults cannot be audited.
**Current behavior:** missing parser capability looks like an empty secure result.
**Correct behavior:** parse local accounts/authentication/classes and release metadata, with explicit unknown when unavailable.
**Standard reference:** [Junos User Access guide](https://www.juniper.net/documentation/us/en/software/junos/user-access/user-access.pdf).

### [JUN-06] [JUNOS] plugin set — most Juniper hardening checklist items are absent

**Category:** 9
**Failure mode:** Coverage gap
**Problem:** missing checks include SSHv2/algorithms and access/rate limits, J-Web HTTPS certificate and permitted interfaces, idle/session limits, AAA, SNMPv3/read-only/trusted targets, authenticated redundant NTP, redundant syslog/enhanced timestamps/source address, banners, OOB management, redirects/source routing/proxy ARP/directed broadcast, LLDP scope, and unused ports.
**Example that breaks it:** SNMPv2c RW, unauthenticated NTP, no syslog, unrestricted management, and weak SSH algorithms produce no findings.
**Current behavior:** three narrow checks cover only Telnet/web, one impossible filter pattern, and root login.
**Correct behavior:** implement the current Juniper checklist over normalized hierarchy-aware models.
**Standard reference:** [Hardening Junos Devices checklist](https://www.juniper.net/assets/us/en/local/pdf/books/tw-hardening-junos-devices-checklist.pdf).

## ScreenOS findings

### [SCREEN-01] [SCREENOS] `PluginScreenOSChecks.check_insecure_services` — it searches synthetic global commands instead of interface management syntax

**Category:** 4
**Failure mode:** False negative
**Problem:** code looks for `set admin telnet enable` and `set admin web enable`; ScreenOS exposes these services per interface with `set interface <name> manage telnet|web`.
**Example that breaks it:** `set interface ethernet0/0 manage telnet` produces no finding.
**Current behavior:** the test fixture validates a command form not handled by the bundled original parser.
**Correct behavior:** parse per-interface manage/unmanage state and global HTTP-to-HTTPS redirection.
**Standard reference:** bundled original `reference/nipper-ng-original/libnipper-0.12.6/Juniper-ScreenOS/administration.cpp:78-114,173-215`.

### [SCREEN-02] [SCREENOS] `check_insecure_services` — interface/zone and manager-IP restrictions are absent

**Category:** 15
**Failure mode:** False negative
**Problem:** even the synthetic global Boolean contains no interface, zone, address, or `set admin manager-ip` context.
**Example that breaks it:** web management on Untrust without a manager-IP and Telnet on an isolated trusted interface cannot be distinguished.
**Current behavior:** real scope-sensitive exposure is not modeled.
**Correct behavior:** report effective services per interface/zone with configured management-source restrictions.
**Standard reference:** bundled original `reference/nipper-ng-original/libnipper-0.12.6/Juniper-ScreenOS/administration.cpp:75-114`.

### [SCREEN-03] [SCREENOS] `PluginScreenOSChecks.check_broad_policy_rules` — duplicated `any` test proves only one wildcard exists

**Category:** 13
**Failure mode:** False positive
**Problem:** the condition contains `"any" in line` twice, so it does not verify both source and destination. It also uses substring/case-sensitive text rather than policy fields.
**Example that breaks it:** `set policy id 1 from Trust to Untrust Any WebServer HTTP permit` can be flagged as any-to-any despite a specific destination (case handling depends on export).
**Current behavior:** one wildcard plus `permit` is labeled unrestricted.
**Correct behavior:** parse source, destination, service, action, enabled state, zones, and order as distinct fields.
**Standard reference:** bundled original `reference/nipper-ng-original/0.11.10/ScreenOS/process-policy.c`.

### [SCREEN-04] [SCREENOS] raw-line parser — policy continuations and disable/remove operations are not correlated

**Category:** 10
**Failure mode:** False negative
**Problem:** the parser returns raw lines only; the plugin cannot associate later `set policy id ...` modifiers or `unset` operations with the base policy.
**Example that breaks it:** a policy created on one line and later changed/disabled across policy-ID lines is judged only from whichever isolated line happens to contain keywords.
**Current behavior:** final effective policy state is not represented.
**Correct behavior:** build ordered policy objects keyed by ID and apply set/unset updates before analysis.
**Standard reference:** bundled original `reference/nipper-ng-original/0.11.10/ScreenOS/process-policy.c`.

### [SCREEN-05] [SCREENOS] `JuniperScreenOSParser` — hostname, version, users, and services are placeholders

**Category:** 10
**Failure mode:** False negative
**Problem:** fixed values (`juniper-device`, `?`, `[]`, all-false services) are returned for every input.
**Example that breaks it:** weak admin passwords, management services, and version-dependent defaults cannot be detected by shared checks or accurately reported.
**Current behavior:** unsupported data is represented as secure absence.
**Correct behavior:** parse actual admin, interface-management, version, and hostname commands or return explicit unknown.
**Standard reference:** bundled original ScreenOS processors under `reference/nipper-ng-original/0.11.10/ScreenOS/`.

### [SCREEN-06] [SCREENOS] plugin set — original Nipper coverage was reduced to two shallow checks

**Category:** 9
**Failure mode:** Coverage gap
**Problem:** missing original checks include password dictionary/strength, SNMP communities/access, default/no policy, policy semantics, admin timeout/access attempts/manager IP, HTTP redirect, SSH protocol version, auth servers, and interface management exposure.
**Example that breaks it:** SSHv1, weak admin credentials, no manager-IP, no policy, default-permit-all, and public SNMP pass.
**Current behavior:** only synthetic Telnet/web lines and a one-line policy substring are checked.
**Correct behavior:** restore normalized parity from actual ScreenOS syntax and effective state.
**Standard reference:** bundled original `reference/nipper-ng-original/0.11.10/ScreenOS/report.c:59-113`.

## HP ProCurve findings

### [HP-01] [HP PROCURVE] `HPProCurveParser.get_services` — WebAgent syntax and default state are wrong

**Category:** 5
**Failure mode:** False negative
**Problem:** code only enables HTTP for a line containing both `web-management` and `enable`, while AOS-S uses `web-management [plaintext]`; plaintext may be implied, and it is disabled with `no web-management` or `no web-management plaintext`.
**Example that breaks it:** `web-management plaintext` or an older default-enabled config without an explicit line yields `http=False`.
**Current behavior:** the test's `web-management enable` is synthetic.
**Correct behavior:** implement version/model-aware default and independent plaintext/SSL state.
**Standard reference:** [Aruba AOS-S Basic Operation Guide](https://www.arubanetworks.com/techdocs/AOS-Switch/16.10/Aruba%20Basic%20Operation%20Guide%20for%20AOS-S%20Switch%2016.10.pdf).

### [HP-02] [HP PROCURVE] `PluginHPChecks.check_snmp_communities` — two substrings stand in for SNMP security

**Category:** 1
**Failure mode:** False negative
**Problem:** only lower-case lines containing `snmp-server community public` or `private` are flagged. Token boundaries, case, access level, ACLs, SNMPv1/v2 restriction, and structural strength are ignored.
**Example that breaks it:** `snmp-server community a unrestricted` passes; `publiclyRandom` can be falsely flagged.
**Current behavior:** both false negatives and substring false positives are possible.
**Correct behavior:** parse community records and SNMPv3/restricted-access state, then evaluate permissions and secret strength.
**Standard reference:** bundled original `reference/nipper-ng-original/libnipper-0.12.6/HP-ProCurve/snmp-report.cpp:109-338`.

### [HP-03] [HP PROCURVE] `PluginHPChecks.check_ssh_hardening` — searched KEX command does not match AOS-S syntax

**Category:** 4
**Failure mode:** False positive
**Problem:** code looks for `ip ssh key-exchange`; AOS-S documents KEX selection under `ip ssh ... kex <algorithm>`.
**Example that breaks it:** a hardened `ip ssh kex ecdh-sha2-nistp384` configuration is reported “not hardened.”
**Current behavior:** real KEX configuration is invisible.
**Correct behavior:** parse the version-specific `ip ssh` cipher/MAC/KEX grammar.
**Standard reference:** [Aruba 2540 command guide](https://www.arubanetworks.com/techdocs/AOS-Switch/16.11/Aruba%202540%20IPv6%20Configuration%20Guide%20for%20AOS-S%2016.11.pdf).

### [HP-04] [HP PROCURVE] `check_ssh_hardening` — existence alone passes and disabled SSH is still required to harden KEX

**Category:** 14
**Failure mode:** False positive
**Problem:** any matching line would pass regardless of weak algorithms, while no line triggers even when SSH is disabled.
**Example that breaks it:** `no ip ssh` produces an SSH KEX finding; a hypothetical matching line selecting only weak group14-sha1 would pass.
**Current behavior:** service state and actual algorithm set are ignored.
**Correct behavior:** run algorithm checks only for enabled SSH and compare the effective set to a versioned policy.
**Standard reference:** [Aruba 2530 Access Security Guide](https://www.arubanetworks.com/techdocs/AOS-Switch/16.10/Aruba%202530%20Access%20Security%20Guide%20for%20ArubaOS-Switch%2016.10.pdf).

### [HP-05] [HP PROCURVE] `HPProCurveParser.get_services` — `no ip ssh` matches the positive SSH substring

**Category:** 2
**Failure mode:** False positive
**Problem:** `if "ip ssh" in line` sets SSH true even for the negated command.
**Example that breaks it:** `no ip ssh` yields `services["ssh"] == True`.
**Current behavior:** negation is ignored.
**Correct behavior:** parse anchored commands and final state in order.
**Standard reference:** [Aruba 2540 command guide](https://www.arubanetworks.com/techdocs/AOS-Switch/16.11/Aruba%202540%20IPv6%20Configuration%20Guide%20for%20AOS-S%2016.11.pdf).

### [HP-06] [HP PROCURVE] `HPProCurveParser.get_users/get_version` — users are unstructured and release context is unknown

**Category:** 10
**Failure mode:** False negative
**Problem:** user output contains only a raw manager-password line and version is always `?`; operator accounts, usernames, auth methods, password form, and model/version defaults are unavailable.
**Example that breaks it:** no manager password (the documented default on some models) cannot be reliably distinguished from external AAA-only secure access.
**Current behavior:** security policy cannot reason about identity or defaults.
**Correct behavior:** parse users/roles/password forms/AAA and firmware/model metadata.
**Standard reference:** [Aruba 2530 Access Security Guide](https://www.arubanetworks.com/techdocs/AOS-Switch/16.10/Aruba%202530%20Access%20Security%20Guide%20for%20ArubaOS-Switch%2016.10.pdf).

### [HP-07] [HP PROCURVE] plugin set — original and vendor hardening coverage is mostly missing

**Category:** 9
**Failure mode:** Coverage gap
**Problem:** missing checks include manager/operator password presence and structural strength, AAA/RADIUS/TACACS, SSH cipher/MAC/KEX sets, HTTPS certificate/plaintext independence, SNMP write/cleartext/dictionary/strength/access, logging, NTP, banners, session timeout, port access/unused ports, and configuration-file credential exposure.
**Example that breaks it:** no manager password, SNMPv2 RW, no syslog/NTP, and weak SSH ciphers can pass apart from the broken KEX finding.
**Current behavior:** four checks do not approach the bundled original's administration/authentication/SNMP coverage.
**Correct behavior:** implement model/version-aware AOS-S parsing and controls.
**Standard reference:** bundled `reference/nipper-ng-original/libnipper-0.12.6/HP-ProCurve/`; [Aruba 2530 Access Security Guide](https://www.arubanetworks.com/techdocs/AOS-Switch/16.10/Aruba%202530%20Access%20Security%20Guide%20for%20ArubaOS-Switch%2016.10.pdf).

## Check Point FW1 findings

### [CP-01] [CHECK POINT] `CheckPointFileParser._build_tree` — token order is retained but all field/rule semantics are destroyed

**Category:** 10
**Failure mode:** False negative
**Problem:** every token becomes `item_N` and every parenthesis becomes `sub_N`; original keys are not associated with values and repeated rule/member structure has no typed representation.
**Example that breaks it:** `:src`, `:dst`, `:services`, `:action`, `:disabled`, and `:track` survive only as unrelated leaf strings.
**Current behavior:** plugins can search token existence but cannot determine which field or rule a token belongs to.
**Correct behavior:** parse named Check Point S-expressions into typed objects, services, layers, and ordered rules.
**Standard reference:** bundled original `reference/nipper-ng-original/0.11.10/FW1/process-rules.c:94-317`.

### [CP-02] [CHECK POINT] `CheckPointFileParser._build_tree` — malformed parentheses crash or are silently accepted

**Category:** 10
**Failure mode:** Crash
**Problem:** an unmatched `)` pops the root stack and later access raises; unclosed `(` at EOF is never rejected. Quoted strings with whitespace are also split into separate tokens.
**Example that breaks it:** a file beginning with `)` causes stack underflow; `( :comment "allow admin only"` returns a plausible partial dict.
**Current behavior:** malformed exports are fatal or silently corrupted.
**Correct behavior:** use a quote-aware lexer and balanced-expression parser with line/column diagnostics.
**Standard reference:** [Check Point Security Management Administration Guide](https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_SecurityManagement_AdminGuide/CP_R82_SecurityManagement_AdminGuide.pdf); bundled original `reference/nipper-ng-original/0.11.10/FW1/process-rules.c`.

### [CP-03] [CHECK POINT] `PluginCheckPointChecks.check_insecure_objects` — any token named `any` is called an insecure object definition

**Category:** 13
**Failure mode:** False positive
**Problem:** recursive value search ignores keys, object type, case, comments, and usage. The built-in Any object or text containing a separate token can trigger even when no permissive rule uses it; `Any` can be missed due to case.
**Example that breaks it:** an unused built-in object/value `any` under objects produces “Insecure Object Definition.”
**Current behavior:** defining an object is conflated with allowing traffic.
**Correct behavior:** parse object identity/type and evaluate it only in the context of enabled rules and relevant fields.
**Standard reference:** [Check Point access-control best practices](https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_SecurityManagement_AdminGuide/CP_R82_SecurityManagement_AdminGuide.pdf).

### [CP-04] [CHECK POINT] `PluginCheckPointChecks.check_broad_filter_rules` — `accept` and `any` can come from different rules

**Category:** 13
**Failure mode:** False positive
**Problem:** two independent whole-file searches are ANDed. No same-rule association, source/destination/service distinction, disabled state, track, layer, install-on, or order is checked; real rulebases may live under the separately parsed `rulebases` key.
**Example that breaks it:** one narrow enabled accept rule plus a separate `Any` cleanup drop rule is reported as a broad accept.
**Current behavior:** unrelated tokens are synthesized into a rule that does not exist.
**Correct behavior:** evaluate each enabled ordered rule as a single object and require the intended wildcard dimensions/action in that rule.
**Standard reference:** [Check Point access-control best practices](https://sc1.checkpoint.com/documents/R80.40/WebAdminGuides/EN/CP_R80.40_SecurityManagement_AdminGuide/Topics-SECMG/Best-Practices-for-Access-Control-Rules.htm).

### [CP-05] [CHECK POINT] plugin set — original rule/object/service analysis and current policy controls are absent

**Category:** 9
**Failure mode:** Coverage gap
**Problem:** missing coverage includes ordered layers/rulebases, enabled state, source/destination/service/VPN/install-on/track, stealth and explicit cleanup rules, logging value, object/service/group resolution, shadowing/redundancy, and management policy context.
**Example that breaks it:** no stealth rule, no explicit logged cleanup rule, disabled broad rules, and enabled unlogged overly broad rules cannot be distinguished.
**Current behavior:** two global token searches replace the original typed rules engine.
**Correct behavior:** restore typed object/service/rulebase parsing and evaluate per-rule policy semantics.
**Standard reference:** bundled original `reference/nipper-ng-original/0.11.10/FW1/`; [Check Point R82 Security Management Guide](https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_SecurityManagement_AdminGuide/CP_R82_SecurityManagement_AdminGuide.pdf).

## SonicOS findings

### [SW-01] [SONICOS] `SonicOSParser` — parser dialect is incompatible with the original SonicOS export format

**Category:** 10
**Failure mode:** False negative
**Problem:** the parser expects line-oriented `set ...` commands. The bundled original consumes preference/export keys such as `firewallName`, `prefs_rule*`, and `policy*`; no format detection exists.
**Example that breaks it:** an original `.exp` containing `firewallName=...` and `prefs_ruleAction_*` yields default hostname, empty users, false services, and no policy visibility.
**Current behavior:** an unsupported real input format is accepted as securely empty.
**Correct behavior:** define supported SonicOS export/CLI formats, detect them, and parse the relevant format into typed policies/services.
**Standard reference:** bundled original `reference/nipper-ng-original/0.11.10/SonicOS/input.c:59-95` and `process-rules.c`.

### [SW-02] [SONICOS] `PluginSonicOSChecks.check_default_admin` — every administrator password line is flagged

**Category:** 1
**Failure mode:** False positive
**Problem:** after requiring `"set admin password" in line`, the second condition `"password" in line` is tautologically true because the prefix already contains that word. The password value is never parsed.
**Example that breaks it:** `set admin password A-very-long-random-secret` is reported as a potential default password.
**Current behavior:** strong and weak values are indistinguishable.
**Correct behavior:** parse credential type/value metadata and detect default/empty/plaintext/structural weakness without echoing secrets.
**Standard reference:** [SonicOS 7 release guidance for changing the default administrator password](https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7-0-0-0-release-notes/Content/title-and-intro.htm).

### [SW-03] [SONICOS] `SonicOSParser.get_services` / `check_http_management` — synthetic global service syntax ignores interface/zone access

**Category:** 4
**Failure mode:** False negative
**Problem:** only `set service http ... enable` is recognized. SonicOS management services are enabled on selected interfaces/zones and constrained by access rules; HTTPS/SSH/SNMP scope is not modeled.
**Example that breaks it:** HTTP enabled on a WAN interface through real SonicOS interface management configuration produces `http=False`.
**Current behavior:** the repository's synthetic fixture is the only proven dialect.
**Correct behavior:** parse real export/CLI interface management flags and source restrictions per zone/interface.
**Standard reference:** [SonicOS management access restriction](https://www.sonicwall.com/es-mx/support/knowledge-base/how-can-i-restrict-sonicwall-management-access-for-specific-ip-address-es-only/kA1VN0000000JM30AM).

### [SW-04] [SONICOS] `PluginSonicOSChecks.check_weak_vpn_encryption` — one invented line and case-sensitive substrings cover VPN crypto

**Category:** 4
**Failure mode:** False negative
**Problem:** only lines containing exact lower-case `set vpn encryption` and `des`/`3des` are inspected. Proposal suites, IKE/IPsec phases, case, disabled entries, authentication, DH/PFS, and TLS VPN settings are ignored.
**Example that breaks it:** a real export selecting DES/3DES through preference/policy keys or uppercase `3DES` passes.
**Current behavior:** most weak VPN configurations are invisible.
**Correct behavior:** parse real VPN proposal objects and evaluate complete enabled suites by protocol/version.
**Standard reference:** [SonicOS/X 7 IPsec VPN proposal configuration](https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7-0-0-0-ipsec_vpn/Content/site-to-site-vpns-proposals-tab-config.htm); bundled original `reference/nipper-ng-original/0.11.10/SonicOS/`.

### [SW-05] [SONICOS] `SonicOSParser.get_users/get_version` — identity and release state are placeholders

**Category:** 10
**Failure mode:** False negative
**Problem:** users always return empty and version always `?`.
**Example that breaks it:** default administrator state, role scope, password policy, MFA, and version-dependent crypto defaults cannot be checked.
**Current behavior:** unsupported information appears absent.
**Correct behavior:** parse user/admin settings and firmware/model version or return explicit unknown.
**Standard reference:** [SonicOS Device Settings guide](https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7-0-0-0-device_settings/Content/Topics/SNMP/enabling-configuring.htm).

### [SW-06] [SONICOS] plugin set — original policy/rule/service coverage and current hardening controls are absent

**Category:** 9
**Failure mode:** Coverage gap
**Problem:** missing checks include real ordered access rules/policies, rule enablement/zones/addresses/services/logging, management protocol/interface/source/TLS scope, login/password/MFA controls, SNMPv3, syslog, NTP, certificates, firmware, and security-service activation.
**Example that breaks it:** a WAN management service, SNMPv2c, no syslog, weak login constraints, and any-any enabled rules can produce no useful finding.
**Current behavior:** three synthetic substring checks replace the original rule/service analysis.
**Correct behavior:** implement a supported-format typed parser and scope-aware rule/management controls.
**Standard reference:** bundled original `reference/nipper-ng-original/0.11.10/SonicOS/`; [SonicOS 7 System Administration Guide](https://www.sonicwall.com/techdocs/pdf/sonicos-7-0-0-0-system.pdf).

## IOS-XE findings

### [XE-01] [IOS-XE] `PluginIOSXEChecks.check_macsec` — every interface is assumed to require MACsec

**Category:** 8
**Failure mode:** False positive
**Problem:** all interface blocks are checked, and the first without `mka policy` creates a finding. Loopbacks, shutdown ports, SVIs, tunnels, routed/WAN links, management ports, and links protected by other controls are not excluded.
**Example that breaks it:** `interface Loopback0` without MKA triggers “Layer 2 traffic not encrypted.”
**Current behavior:** MACsec is treated as universally mandatory.
**Correct behavior:** restrict the control to explicitly in-scope L2 links/roles and account for shutdown and alternative protections.
**Standard reference:** [Cisco IOS XE MACsec and MKA configuration guide](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/macsec/configuration/xe-3s/macsec-xe-3s-book.html).

### [XE-02] [IOS-XE] `check_macsec` — an `mka policy` child is accepted without resolving effectiveness

**Category:** 14
**Failure mode:** False negative
**Problem:** existence of a child string passes; policy definition, key chain, MACsec command/state, cipher, authentication, and attachment validity are not checked.
**Example that breaks it:** `mka policy MISSING` referencing no policy produces no finding.
**Current behavior:** a dangling or inactive reference is treated as working encryption.
**Correct behavior:** resolve the referenced MKA policy/key material and effective interface MACsec state.
**Standard reference:** [Cisco IOS XE MACsec and MKA configuration guide](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/macsec/configuration/xe-3s/macsec-xe-3s-book.html).

### [XE-03] [IOS-XE] `PluginIOSXEChecks.check_legacy_crypto` — crypto coverage is limited to two IKEv2 child substrings

**Category:** 4
**Failure mode:** False negative
**Problem:** only `encryption 3des` and `integrity md5` under IKEv2 proposals are detected. IKEv1 policies, IPsec transform sets, DES, weak DH groups/PRFs, SSH/TLS/SNMP algorithms, case/alternate forms, and inactive proposals are not evaluated.
**Example that breaks it:** `crypto isakmp policy 10` with `encryption des`, `hash md5`, `group 1` passes.
**Current behavior:** “Legacy Crypto” covers a tiny subset of legacy crypto.
**Correct behavior:** parse all relevant enabled proposal families and compare complete suites to a versioned policy.
**Standard reference:** [Cisco IOS-XE Software Hardening Guide](https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening).

### [XE-04] [IOS-XE] pipeline — IOS-XE bypasses every baseline IOS check

**Category:** 9
**Failure mode:** Coverage gap
**Problem:** `CiscoIOSXEParser` inherits the IOS parser, but `process_iosxe_conf()` runs only the MACsec and IKEv2 plugin. It does not run the IOS HTTP/SSH plugins, let alone missing AAA/SNMP/logging/NTP/control-plane checks.
**Example that breaks it:** `ip http server`, SSHv1, Telnet VTY, SNMPv2c RW, and no logging on IOS-XE produce only MACsec/legacy-IKE findings.
**Current behavior:** declaring the device IOS-XE reduces coverage below the IOS baseline.
**Correct behavior:** compose a shared IOS-family baseline plus IOS-XE-specific rules.
**Standard reference:** [Cisco IOS-XE Software Hardening Guide](https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening).

## Arista EOS findings

### [AR-01] [ARISTA EOS] `PluginAristaChecks.check_management_api` — HTTPS is searched globally instead of inside the eAPI block

**Category:** 15
**Failure mode:** False negative
**Problem:** any `protocol https` anywhere in the configuration suppresses the issue; parent/child association is not checked.
**Example that breaks it:** eAPI enables only HTTP, while an unrelated configuration block contains `protocol https`; the plugin reports nothing.
**Current behavior:** unrelated text is accepted as eAPI protection.
**Correct behavior:** inspect children of each `management api http-commands` block and model enabled protocols/VRFs/ACLs.
**Standard reference:** [Arista eAPI session-management commands](https://www.arista.com/en/um-eos/eos-session-management-commands?searchword=eos+section+10+6+ethernet+configuration+commands).

### [AR-02] [ARISTA EOS] `check_management_api` — block activation and simultaneous cleartext HTTP are ignored

**Category:** 14
**Failure mode:** False positive
**Problem:** merely declaring the parent without HTTPS is flagged even when the service lacks `no shutdown`; if both HTTP and HTTPS are enabled, the presence of HTTPS suppresses the cleartext finding.
**Example that breaks it:** a shutdown eAPI block is reported exposed; a live block with `protocol http` and `protocol https` passes.
**Current behavior:** definition, activation, and protocol coexistence are conflated.
**Correct behavior:** require effective activation and independently report each enabled insecure protocol.
**Standard reference:** [Arista eAPI session-management commands](https://www.arista.com/en/um-eos/eos-session-management-commands?searchword=eos+section+10+6+ethernet+configuration+commands).

### [AR-03] [ARISTA EOS] plugin set — one eAPI check omits the rest of EOS hardening

**Category:** 9
**Failure mode:** Coverage gap
**Problem:** missing checks include AAA authentication/authorization/accounting and unsafe `none` fallback, local roles/root, SSH, SNMP versions/auth/privacy/ACLs, logging/login-event logging, NTP, management VRFs/ACLs, other APIs (gNMI/gNOI), banners, unused services/interfaces, and control-plane protection.
**Example that breaks it:** AAA permits `none`, SNMPv1 is unrestricted, SSH is weak, and no remote logging exists; no finding is emitted if eAPI is absent.
**Current behavior:** EOS is labeled supported based on a single service check.
**Correct behavior:** create an EOS baseline from real EOS hierarchy and vendor controls, not inherited IOS assumptions alone.
**Standard reference:** [Arista EOS User Security](https://www.arista.com/en/um-eos/eos-user-security); [Arista EOS SNMP](https://www.arista.com/en/um-eos/eos-snmp).
