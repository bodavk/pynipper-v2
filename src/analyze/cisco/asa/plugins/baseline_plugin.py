import re

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.controls import ControlOutcome, record_control
from src.analyze.common.credentials import credential_policy_from_context, evaluate_credential
from src.analyze.common.issue import Finding, FindingBasis, Severity
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.cisco.asa import CiscoASAParser


CISCO_ASA_CONFIGURATION_GUIDES = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/"
    "general/asa-924-general-config.html",
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/"
    "firewall/asa-924-firewall-config.html",
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/"
    "vpn/asa-924-vpn-config.pdf",
)
CISCO_ASA_AAA_REFERENCE = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/"
    "A-H/asa-command-ref-A-H/aa-ac-commands.html",
)
CISCO_ASA_MANAGEMENT_REFERENCE = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/"
    "general/asa-924-general-config/admin-management.html",
)
CISCO_ASA_SSH_REFERENCE = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/"
    "S/asa-command-ref-S/so-st-commands.html",
)
CISCO_ASA_NTP_REFERENCE = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/"
    "I-R/asa-command-ref-I-R/n-commands.html",
)
CISCO_ASA_CERTIFICATE_REFERENCE = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/"
    "general/asa-916-general-config/basic-certs.html",
)
CISCO_ASA_FIREWALL_REFERENCE = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa91/configuration/"
    "firewall/asa_91_firewall_config/conns_connlimits.pdf",
)
CISCO_ASA_PASSWORD_POLICY_REFERENCE = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/"
    "I-R/asa-command-ref-I-R/pa-pn-commands.html",
)
CISCO_ASA_HTTP_TIMEOUT_REFERENCE = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/"
    "A-H/asa-command-ref-A-H/m_g-h.html",
)
CISCO_ASA_IKE_POLICY_REFERENCE = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/"
    "asa-cli-reference/A-H/asa-command-ref-A-H/crypto-a-to-crypto-ir-commands.html"
)
CISCO_ASA_CRYPTO_MAP_REFERENCE = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/A-H/"
    "asa-command-ref-A-H/crypto-is-cz-commands.html"
)
CISCO_ASA_WEBVPN_AUTH_REFERENCE = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/"
    "configuration/vpn/asa-916-vpn-config/vpn-groups.html"
)
NIST_CRYPTO_TRANSITIONS = "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final"
CISCO_ASA_AM_DISABLE_REFERENCE = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/A-H/asa-command-ref-A-H/"
    "crypto-a-to-crypto-ir-commands.html"
)
RFC_2409 = "https://www.rfc-editor.org/rfc/rfc2409"
RFC_8907 = "https://www.rfc-editor.org/rfc/rfc8907#section-4.5"
CISCO_ASA_LDAP_OVER_SSL_REFERENCE = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/I-R/asa-command-ref-I-R/m_l2-lof.html"
)
# SC-044 release-default sources (docs/agent_notes/INSECURE_DEFAULTS_BY_RELEASE.md).
CISCO_ASA_SYSOPT_REFERENCE = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/S/asa-command-ref-S/su-sz-commands.html",
)
CISCO_ASA_912_RELEASE_NOTES = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa912/release/notes/asarn912.html"
)
CISCO_ASA_ICMP_REFERENCE = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/I-R/asa-command-ref-I-R/ia-inr-commands.html",
)
CISCO_ASA_91_IKE_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa91/configuration/vpn/asa_91_vpn_config/vpn_ike.html"
)
CISCO_ASA_PASSWORD_RECOVERY_REFERENCE = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/S/asa-command-ref-S/sa-shov-commands.html"
)
CISCO_ASA_AUTO_UPDATE_REFERENCE = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/A-H/asa-command-ref-A-H/ar-az-commands.html"
)
CISCO_ASA_MASTER_PASSPHRASE_REFERENCE = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa918/configuration/general/"
    "asa-918-general-config/basic-hostname-pw.html"
)


class PluginASABaseline(BasePlugin):
    """Additional version-aware ASA management and platform baseline."""

    @staticmethod
    def _asa(parser: BaseDeviceParser) -> CiscoASAParser:
        if not isinstance(parser, CiscoASAParser):
            raise TypeError("PluginASABaseline requires an ASA parser")
        return parser

    def _lines(self, parser: BaseDeviceParser) -> list[str]:
        return [line.strip() for line in self._asa(parser).parser.ioscfg if line.strip()]

    @staticmethod
    def _finding(
        parser,
        rule_id,
        title,
        observation,
        impact,
        recommendation,
        severity,
        evidence,
        references=CISCO_ASA_CONFIGURATION_GUIDES,
        basis=None,
    ):
        return Finding(
            rule_id=rule_id,
            device=parser.device_type,
            title=title,
            observation=observation,
            impact=impact,
            exploitability="An attacker with management or data-plane reachability may exploit this condition.",
            recommendation=recommendation,
            severity=severity,
            evidence=evidence,
            references=references,
            basis=basis,
        )

    def check_aaa(self, parser: BaseDeviceParser) -> None:
        asa = self._asa(parser)
        active_protocols = {
            protocol
            for protocol in ("ssh", "telnet", "http")
            if asa.get_management_grants(protocol)
            and (protocol != "http" or asa.get_http_server_enabled())
        }
        bindings = {
            (item.binding_type, item.protocol): item
            for item in asa.get_administrative_aaa_bindings()
        }
        if not active_protocols:
            for control in ("cisco.asa.management-authentication", "cisco.asa.management-accounting"):
                record_control(parser, control, ControlOutcome.UNKNOWN,
                               "No explicit active management grant is supplied; service-domain completeness is unqualified.")
        for protocol in sorted(active_protocols):
            authentication = bindings.get(("authentication", protocol))
            control = "cisco.asa.management-authentication"
            if authentication is None:
                # The management grant for this protocol is in the export, so the
                # absent AAA binding is a feature that is simply not configured.
                record_control(parser, control, ControlOutcome.FINDING,
                               "Active management protocol has no AAA authentication binding configured.", instance=protocol)
                self.add_issue(self._finding(
                    parser, "cisco.asa.aaa.management_authentication",
                    "Management authentication is not configured",
                    (f"Active {protocol.upper()} management has no 'aaa authentication {protocol} console' binding. "
                     "The setting is omitted from the configuration, not set to a wrong value."),
                    "Management access does not use a defined local or central AAA authentication path.",
                    "Bind the protocol to LOCAL with a defined local user, or to a defined resilient AAA server group with an appropriate LOCAL fallback.",
                    Severity.HIGH,
                    (f"active {protocol} management grant; aaa authentication {protocol} console: not configured",),
                    CISCO_ASA_AAA_REFERENCE,
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                ))
            elif not authentication.resolved:
                record_control(parser, control, ControlOutcome.UNKNOWN, "Referenced AAA group is not supplied or cannot be resolved.", instance=protocol)
            else:
                record_control(parser, control, ControlOutcome.NO_FINDING, "Explicit authentication binding resolves to the supplied AAA state.", instance=protocol)
            if protocol not in {"ssh", "telnet"}:
                # ASA administrative-session accounting has no HTTP/ASDM keyword.
                continue
            accounting = bindings.get(("accounting", protocol))
            control = "cisco.asa.management-accounting"
            if accounting is None:
                record_control(parser, control, ControlOutcome.FINDING,
                               "Active management protocol has no session-accounting binding configured.", instance=protocol)
                self.add_issue(self._finding(
                    parser, "cisco.asa.aaa.management_accounting",
                    "Management session accounting is not configured",
                    (f"Active {protocol.upper()} management has no 'aaa accounting {protocol} console' binding. "
                     "The setting is omitted from the configuration, not set to a wrong value."),
                    "Administrative sessions may not be attributable in a central audit trail.",
                    "Configure administrative-session accounting to a defined RADIUS or TACACS+ server group for each supported protocol.",
                    Severity.MEDIUM,
                    (f"active {protocol} management grant; aaa accounting {protocol} console: not configured",),
                    CISCO_ASA_AAA_REFERENCE,
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                ))
            elif not accounting.resolved:
                record_control(parser, control, ControlOutcome.UNKNOWN,
                               "Referenced accounting server group is not in the export or cannot be resolved.", instance=protocol)
            else:
                record_control(parser, control, ControlOutcome.NO_FINDING,
                               "Explicit session-accounting binding resolves to a supplied group.", instance=protocol)

    def check_management_sessions_and_ssh(self, parser: BaseDeviceParser) -> None:
        asa = self._asa(parser)
        console_timeout = asa.get_console_timeout()
        record_control(parser, "cisco.asa.session-timeouts",
                       ControlOutcome.FINDING if console_timeout.value == 0 else
                       ControlOutcome.UNKNOWN if console_timeout.value is None else ControlOutcome.NO_FINDING,
                       "The effective console timeout is 0 (disabled)." if console_timeout.value == 0 else
                       "The console timeout value is invalid." if console_timeout.value is None else
                       f"The effective console timeout is {console_timeout.value} minutes.", instance="console")
        if console_timeout.value == 0:
            evidence = (
                (console_timeout.raw_line,)
                if console_timeout.raw_line
                else ("console timeout defaults to 0",)
            )
            self.add_issue(self._finding(
                parser,
                "cisco.asa.console.session_timeout",
                "ASA console session timeout is disabled",
                "The effective console timeout is 0 minutes, so authenticated serial or enable sessions do not time out.",
                "An unattended privileged console session can remain available indefinitely.",
                "Set a finite console timeout that meets the approved administrative-session policy.",
                Severity.MEDIUM,
                evidence,
                CISCO_ASA_MANAGEMENT_REFERENCE,
                basis=FindingBasis.EXPLICIT_VALUE if console_timeout.raw_line else FindingBasis.DOCUMENTED_DEFAULT,
            ))

        if not asa.get_management_grants("ssh"):
            record_control(parser, "cisco.asa.session-timeouts", ControlOutcome.NOT_APPLICABLE,
                           "No SSH management grant is configured.", instance="ssh")
            record_control(parser, "cisco.asa.ssh-settings", ControlOutcome.NOT_APPLICABLE,
                           "No SSH management grant is configured.")
            return
        ssh_timeout = asa.get_ssh_timeout()
        ssh_timeout_long = ssh_timeout.configured and ssh_timeout.value is not None and ssh_timeout.value > 10
        record_control(parser, "cisco.asa.session-timeouts",
                       ControlOutcome.FINDING if ssh_timeout_long else
                       ControlOutcome.UNKNOWN if ssh_timeout.value is None else ControlOutcome.NO_FINDING,
                       "The explicit SSH idle timeout exceeds ten minutes." if ssh_timeout_long else
                       "The SSH timeout value is invalid." if ssh_timeout.value is None else
                       f"The effective SSH idle timeout is {ssh_timeout.value} minutes.", instance="ssh")
        if ssh_timeout.configured and ssh_timeout.value is not None and ssh_timeout.value > 10:
            self.add_issue(self._finding(
                parser, "cisco.asa.ssh.idle_timeout_excessive",
                "ASA SSH administrative idle timeout is excessive",
                f"The explicitly configured SSH idle timeout is {ssh_timeout.value} minutes, above the project's ten-minute management target.",
                "An abandoned SSH session remains usable longer than intended.",
                "Set 'ssh timeout' to ten minutes or less after validating the operational requirement.",
                Severity.MEDIUM, (ssh_timeout.raw_line,), CISCO_ASA_MANAGEMENT_REFERENCE,
                basis=FindingBasis.EXPLICIT_VALUE,
            ))
        policy = asa.get_ssh_policy()
        record_control(parser, "cisco.asa.ssh-settings",
                       ControlOutcome.UNKNOWN if policy.version is None else
                       ControlOutcome.NO_FINDING if policy.version == "2" else ControlOutcome.FINDING,
                       "The SSH version is not explicit and the release default is not qualified." if policy.version is None else
                       f"The {policy.version_source} SSH protocol state is '{policy.version}'.", instance="version")
        if policy.version is not None and policy.version != "2":
            self.add_issue(self._finding(
                parser,
                "cisco.asa.ssh.protocol_version",
                "ASA SSH policy permits version 1",
                f"The {policy.version_source} SSH protocol state is '{policy.version}'.",
                "SSH version 1 has obsolete protocol and cryptographic design weaknesses.",
                "Restrict SSH to version 2; on releases where version 1 has been removed, retain the secure release default.",
                Severity.HIGH,
                tuple(item for item in policy.evidence) or (f"ASA {asa.get_version()} SSH default",),
                CISCO_ASA_SSH_REFERENCE,
                basis=(FindingBasis.EXPLICIT_VALUE if policy.version_source == "explicit"
                       else FindingBasis.DOCUMENTED_DEFAULT),
            ))
        # SC-044 ASA-06/ASA-08: default SSH algorithms. Command reference so-st:
        # '(9.10 and earlier) By default, the dh-group1-sha1 is used' (9.12(1) release
        # notes: new default group 14 SHA-256) and 'Medium is the default' encryption
        # level, which includes CBC-mode ciphers.
        _, release = asa.get_release()
        defaults = []
        if release is not None and policy.key_exchange is None and release < (9, 12, 1):
            defaults.append("key exchange: dh-group1-sha1 (default before 9.12(1))")
        if release is not None and policy.encryption is None:
            defaults.append("encryption: medium level with CBC-mode ciphers (default)")
        # ASA-07: 'ssh cipher integrity' history, '(9.10 and earlier) Medium is the
        # default' until 9.12(1); 9.13(1) lists hmac-sha1-96 in medium as insecure.
        if (release is not None and policy.integrity is None and release < (9, 12, 1)
                and (release >= (9, 4, 3) or (release[:2] == (9, 1) and release[2] >= 7))):
            defaults.append("integrity: medium level with hmac-sha1-96 (default before 9.12(1))")
        if defaults:
            self.add_issue(self._finding(
                parser,
                "cisco.asa.ssh.weak_algorithms",
                "ASA SSH relies on weak default algorithms",
                "SSH management is enabled and the export does not set these algorithms, so the documented defaults apply: "
                + "; ".join(defaults) + ".",
                "Diffie-Hellman group 1 (768-bit) and CBC-mode ciphers weaken the key exchange and confidentiality of administrative sessions.",
                "Set 'ssh key-exchange group ecdh-group14-sha256' or 'dh-group14-sha256' (or stronger) and 'ssh cipher encryption high'.",
                Severity.LOW,
                (f"ASA Version {asa.get_version()}", *defaults),
                CISCO_ASA_SSH_REFERENCE + (CISCO_ASA_912_RELEASE_NOTES,),
                basis=FindingBasis.DOCUMENTED_DEFAULT,
            ))

        weak = []
        if policy.encryption is not None:
            selected = sorted(set(policy.encryption) & {
                "all", "low", "des-cbc", "3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc",
            })
            if selected:
                weak.append("encryption: " + ", ".join(selected))
        if policy.integrity is not None:
            selected = sorted(set(policy.integrity) & {
                "all", "low", "medium", "hmac-md5", "hmac-md5-96", "hmac-sha1-96",
            })
            if selected:
                weak.append("integrity: " + ", ".join(selected))
        if policy.key_exchange in {"dh-group1-sha1", "dh-group14-sha1"}:
            weak.append("key exchange: " + policy.key_exchange)
        omitted = [name for name, value in (("key exchange", policy.key_exchange), ("encryption", policy.encryption),
                                            ("integrity", policy.integrity)) if value is None]
        integrity_default_unqualified = (
            release is not None and policy.integrity is None and release < (9, 12, 1)
            and not (release >= (9, 4, 3) or (release[:2] == (9, 1) and release[2] >= 7)))
        if defaults or weak:
            outcome, reason = ControlOutcome.FINDING, "SSH offers weak explicit or documented-default algorithms."
        elif release is None and omitted:
            outcome, reason = ControlOutcome.UNKNOWN, f"Omitted SSH {', '.join(omitted)} default is not qualified without an identified release."
        elif integrity_default_unqualified:
            outcome, reason = ControlOutcome.UNKNOWN, "The SSH integrity default is not qualified for this release."
        else:
            outcome, reason = ControlOutcome.NO_FINDING, "Explicit and release-default SSH algorithms are not weak."
        record_control(parser, "cisco.asa.ssh-settings", outcome, reason, instance="algorithms")
        if weak:
            self.add_issue(self._finding(
                parser,
                "cisco.asa.ssh.weak_algorithms",
                "ASA SSH policy explicitly permits weak algorithms",
                "The explicit SSH configuration includes " + "; ".join(weak) + ".",
                "Legacy SSH algorithms weaken confidentiality, integrity, or key-exchange strength.",
                "Use the release-supported high/custom encryption and integrity selections and a modern ECDH/Curve25519 key-exchange group.",
                Severity.HIGH,
                tuple(item for item in policy.evidence),
                CISCO_ASA_SSH_REFERENCE,
                basis=FindingBasis.EXPLICIT_VALUE,
            ))

    def check_local_users(self, parser: BaseDeviceParser) -> None:
        policy = credential_policy_from_context(parser.assessment_context)
        for credential in self._asa(parser).get_local_credentials():
            result = evaluate_credential(credential, policy)
            record_control(parser, "cisco.asa.stored-secrets",
                           ControlOutcome.FINDING if result.unsafe_storage else ControlOutcome.NO_FINDING,
                           f"Local user credential storage is '{result.storage_assessment.value}'.",
                           instance=f"user {credential.account}")
            if not result.unsafe_storage:
                continue
            self.add_issue(self._finding(
                parser, "cisco.asa.credentials.local_user_storage",
                "Local administrator credential storage is unsafe",
                (
                    f"Local user '{credential.account}' uses format '{credential.storage_type}', "
                    f"classified as '{result.storage_assessment.value}' under credential policy "
                    f"'{result.policy_version}'; the separate exact-default comparison is "
                    f"'{result.default_assessment.value}' and the blocklist comparison "
                    f"{result.blocklist_summary}. The credential is redacted."
                ),
                "Configuration disclosure can expose or accelerate compromise of a local administrative credential.",
                "Use supported PBKDF2 storage with unique credentials and prefer centralized AAA.",
                Severity.HIGH, tuple(item for item in credential.evidence),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))

    def check_http_management(self, parser: BaseDeviceParser) -> None:
        asa = self._asa(parser)
        lines = self._lines(parser)
        enabled = False
        for line in lines:
            if re.fullmatch(r"http server enable(?:\s+\d+)?", line):
                enabled = True
            elif line == "no http server enable":
                enabled = False
        if not enabled:
            for control in ("cisco.asa.http-source-restriction", "cisco.asa.https-certificate"):
                record_control(parser, control, ControlOutcome.NOT_APPLICABLE, "The HTTP server is not enabled.")
            record_control(parser, "cisco.asa.session-timeouts", ControlOutcome.NOT_APPLICABLE,
                           "The HTTP server is not enabled.", instance="asdm")
            return
        grants = asa.get_management_grants("http")
        if not grants:
            record_control(parser, "cisco.asa.http-source-restriction", ControlOutcome.FINDING,
                           "The HTTP server is enabled without an HTTP management source grant.")
            record_control(parser, "cisco.asa.session-timeouts", ControlOutcome.NOT_APPLICABLE,
                           "No HTTP management grant is configured.", instance="asdm")
            self.add_issue(self._finding(
                parser, "cisco.asa.management.http_sources",
                "ASDM/HTTPS management has no explicit source grant",
                "The HTTP server is enabled but no effective HTTP management source grant was parsed.",
                "Management reachability is uncertain and may rely on unintended configuration.",
                "Add narrow 'http <network> <mask> <interface>' grants or disable the HTTP server.",
                Severity.MEDIUM, ("http server enable",),
                basis=FindingBasis.REQUIRED_SETTING_MISSING,
            ))
        if grants:
            idle = asa.get_asdm_idle_policy()
            explicit_idle = idle.resolution_state == "explicit" and idle.minutes is not None
            record_control(parser, "cisco.asa.session-timeouts",
                           (ControlOutcome.FINDING if idle.minutes > 10 else ControlOutcome.NO_FINDING) if explicit_idle
                           else ControlOutcome.UNKNOWN,
                           f"The explicit {idle.source} is {idle.minutes:g} minutes." if explicit_idle else
                           f"ASDM idle timeout state is '{idle.resolution_state}'; the omitted default is not qualified.",
                           instance="asdm")
            if idle.resolution_state == "explicit" and idle.minutes is not None and idle.minutes > 10:
                self.add_issue(self._finding(
                    parser, "cisco.asa.asdm.idle_timeout_excessive",
                    "ASA ASDM administrative idle timeout is excessive",
                    f"The explicitly configured {idle.source} allows {idle.minutes:g} minutes of inactivity, above the project's ten-minute management target.",
                    "An abandoned ASDM session may remain usable longer than intended.",
                    "Set the effective HTTP/ASDM idle timeout to ten minutes or less.",
                    Severity.MEDIUM, tuple(item for item in idle.evidence),
                    CISCO_ASA_HTTP_TIMEOUT_REFERENCE,
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
        for grant in grants:
            record_control(parser, "cisco.asa.http-source-restriction",
                           ControlOutcome.FINDING if grant.is_any_source else ControlOutcome.NO_FINDING,
                           f"HTTP grant on '{grant.interface}' {'permits every source' if grant.is_any_source else 'is source restricted'}.",
                           instance=grant.raw_line)
            if grant.is_any_source:
                self.add_issue(self._finding(
                    parser, "cisco.asa.management.unrestricted_http",
                    "ASDM/HTTPS management source is unrestricted",
                    f"Every {grant.address_family} source is permitted to reach HTTP/ASDM on interface '{grant.interface}'.",
                    "The administrative web service is exposed to broad authentication and exploitation attempts.",
                    "Restrict HTTP management to dedicated administration networks.",
                    Severity.HIGH, (grant.raw_line,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
        certificate_bindings = asa.get_management_certificate_bindings()
        if not certificate_bindings:
            record_control(parser, "cisco.asa.https-certificate", ControlOutcome.FINDING,
                           "The HTTP server is enabled without an explicit SSL trustpoint assignment.")
            self.add_issue(self._finding(
                parser, "cisco.asa.management.certificate",
                "ASDM/HTTPS trustpoint is not explicitly assigned",
                "The management web server is enabled without an explicit SSL trustpoint assignment.",
                "Administrators may receive an untrusted or unintended device certificate.",
                "Enroll a managed certificate and assign it with 'ssl trust-point'.",
                Severity.MEDIUM, ("http server enable",),
                basis=FindingBasis.MISSING_EXPLICIT_SETTING,
            ))
            return
        for binding in certificate_bindings:
            evidence = tuple(item for item in binding.evidence)
            key = f"{binding.interface or 'default'}:{binding.trustpoint}"
            structural = (
                "The assigned trustpoint is not defined." if not binding.trustpoint_configured else
                "The assigned trustpoint has no identity certificate." if binding.certificate_chain_present
                and not binding.identity_certificate_present else
                "The identity certificate material is malformed." if binding.public_material_state == "malformed" else None)
            if structural:
                record_control(parser, "cisco.asa.https-certificate", ControlOutcome.FINDING, structural, instance=key)
            elif binding.assessment is None:
                record_control(parser, "cisco.asa.https-certificate", ControlOutcome.UNKNOWN,
                               "No assessable identity certificate is exported for the assigned trustpoint.", instance=key)
            if binding.assessment is not None:
                result = binding.assessment
                for aspect, state, bad, good in (
                    ("validity", result.validity_state, {"expired", "not-yet-valid"}, {"valid-at-assessment-time"}),
                    ("identity", result.identity_state, {"mismatch"}, {"match"}),
                    ("algorithm", result.algorithm_state, {"weak"}, {"acceptable"}),
                    ("trust", result.trust_state,
                     {"verification-failed"} if result.identity_state == "match"
                     and result.validity_state == "valid-at-assessment-time" else set(), {"trusted"}),
                ):
                    record_control(parser, "cisco.asa.https-certificate",
                                   ControlOutcome.FINDING if state in bad else
                                   ControlOutcome.NO_FINDING if state in good else ControlOutcome.UNKNOWN,
                                   f"Certificate {aspect} state is '{state}'.", instance=f"{key}/{aspect}")
            if not binding.trustpoint_configured:
                self.add_issue(self._finding(
                    parser, "cisco.asa.management.certificate_unresolved",
                    "ASDM/HTTPS trustpoint reference is unresolved",
                    f"SSL assigns trustpoint '{binding.trustpoint}'{f' on interface {binding.interface}' if binding.interface else ''}, but no matching crypto ca trustpoint object was parsed.",
                    "The supplied configuration does not establish the certificate identity served to administrators.",
                    "Define and enroll the referenced trustpoint, or supply the complete effective configuration containing it.",
                    Severity.MEDIUM, evidence,
                    CISCO_ASA_CERTIFICATE_REFERENCE,
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                ))
            elif binding.certificate_chain_present and not binding.identity_certificate_present:
                self.add_issue(self._finding(
                    parser, "cisco.asa.management.certificate_identity_missing",
                    "ASDM/HTTPS trustpoint has no identity certificate",
                    f"Assigned trustpoint '{binding.trustpoint}' has a certificate-chain section but no non-CA identity certificate entry.",
                    "A CA-only chain does not provide the device identity selected for HTTPS management.",
                    "Enroll or import the intended identity certificate into the assigned trustpoint and retain its issuing chain.",
                    Severity.MEDIUM, evidence,
                    CISCO_ASA_CERTIFICATE_REFERENCE,
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                ))
            elif binding.public_material_state == "malformed":
                self.add_issue(self._finding(
                    parser, "cisco.asa.management.certificate_material_malformed",
                    "ASDM/HTTPS identity certificate material is malformed",
                    f"Assigned trustpoint '{binding.trustpoint}' contains an identity-certificate entry whose exported hexadecimal DER cannot be parsed as X.509.",
                    "Malformed identity material cannot establish the intended HTTPS management identity.",
                    "Re-enroll or import the intended identity certificate and verify the complete trustpoint chain.",
                    Severity.MEDIUM, evidence,
                    CISCO_ASA_CERTIFICATE_REFERENCE,
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
            if binding.assessment is None:
                continue
            assessment = binding.assessment
            metadata = assessment.metadata
            if assessment.validity_state in {"expired", "not-yet-valid"}:
                self.add_issue(self._finding(
                    parser, "cisco.asa.management.certificate_validity",
                    "ASDM/HTTPS certificate is outside its validity period",
                    f"Trustpoint '{binding.trustpoint}' identity certificate is {assessment.validity_state} at the explicit assessment time; its validity interval is {metadata.not_before} through {metadata.not_after}.",
                    "Administrators cannot validate an endpoint certificate outside its declared validity interval.",
                    "Renew or replace the assigned identity certificate before its activation or expiration boundary.",
                    Severity.HIGH, evidence,
                    CISCO_ASA_CERTIFICATE_REFERENCE,
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
            if assessment.identity_state == "mismatch":
                self.add_issue(self._finding(
                    parser, "cisco.asa.management.certificate_identity",
                    "ASDM/HTTPS certificate does not match the intended identity",
                    f"Trustpoint '{binding.trustpoint}' identity certificate does not contain the explicitly declared management identity for interface '{binding.interface or 'default'}' in subjectAltName.",
                    "Clients validating the intended hostname or address will reject the management endpoint identity.",
                    "Enroll and assign a certificate whose subjectAltName contains the declared management DNS name or IP address.",
                    Severity.HIGH, evidence,
                    CISCO_ASA_CERTIFICATE_REFERENCE,
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
            if assessment.algorithm_state == "weak":
                self.add_issue(self._finding(
                    parser, "cisco.asa.management.certificate_algorithm",
                    "ASDM/HTTPS certificate uses a legacy key or signature",
                    f"Trustpoint '{binding.trustpoint}' identity certificate uses {metadata.public_key_algorithm} {metadata.public_key_size or 'intrinsic'} and signature hash {metadata.signature_hash_algorithm}.",
                    "Legacy public-key sizes or certificate signatures provide inadequate cryptographic assurance.",
                    "Replace the identity certificate with an organization-approved key and SHA-2-or-stronger signature supported by the ASA release.",
                    Severity.HIGH, evidence,
                    CISCO_ASA_CERTIFICATE_REFERENCE + (NIST_CRYPTO_TRANSITIONS,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
            if (
                assessment.trust_state == "verification-failed"
                and assessment.identity_state == "match"
                and assessment.validity_state == "valid-at-assessment-time"
            ):
                self.add_issue(self._finding(
                    parser, "cisco.asa.management.certificate_trust",
                    "ASDM/HTTPS certificate chain does not validate to an approved anchor",
                    f"Trustpoint '{binding.trustpoint}' certificate matches the intended identity and time boundary but cannot be validated to the explicitly approved exported trust-anchor fingerprint(s).",
                    "The supplied certificate chain does not establish trust under the selected assessment policy.",
                    "Install the correct issuing chain and approve only the intended root fingerprint after independent verification.",
                    Severity.HIGH, evidence,
                    CISCO_ASA_CERTIFICATE_REFERENCE,
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))

    def check_ntp(self, parser: BaseDeviceParser) -> None:
        asa = self._asa(parser)
        associations = asa.get_ntp_associations()
        if not associations:
            self.add_issue(self._finding(
                parser, "cisco.asa.ntp.servers", "NTP synchronization is not configured",
                "No NTP server is configured.",
                "Incorrect time weakens event correlation, certificate validation, and forensic timelines.",
                "Configure multiple trusted NTP servers.", Severity.MEDIUM,
                ("No ntp server command",),
                CISCO_ASA_NTP_REFERENCE,
                basis=FindingBasis.REQUIRED_SETTING_MISSING,
            ))
            record_control(parser, "cisco.asa.ntp-authentication", ControlOutcome.NOT_APPLICABLE,
                           "No NTP server is configured.")
            record_control(parser, "cisco.asa.ntp-servers", ControlOutcome.FINDING, "No NTP server is configured.")
            record_control(parser, "cisco.asa.ntp-key-algorithm", ControlOutcome.NOT_APPLICABLE,
                           "No NTP server is configured.")
            return
        record_control(parser, "cisco.asa.ntp-servers", ControlOutcome.NO_FINDING,
                       f"{len(associations)} NTP server(s) are configured.")
        release = asa._release_tuple(asa.get_version())
        for association in associations:
            evidence = tuple(item for item in association.evidence)
            record_control(
                parser, "cisco.asa.ntp-authentication",
                ControlOutcome.NO_FINDING if association.authentication_state == "authenticated" else ControlOutcome.FINDING,
                "NTP server is bound to a trusted authentication key."
                if association.authentication_state == "authenticated"
                else "NTP server lacks an effective trusted key binding.",
                instance=f"server {association.address}",
            )
            weak_digest = release is not None and release >= (9, 13) and association.algorithm in {"md5", "sha1"}
            record_control(
                parser, "cisco.asa.ntp-key-algorithm",
                ControlOutcome.NOT_APPLICABLE if association.authentication_state != "authenticated" else
                ControlOutcome.UNKNOWN if release is None else
                ControlOutcome.FINDING if weak_digest else ControlOutcome.NO_FINDING,
                "NTP server is not authenticated." if association.authentication_state != "authenticated" else
                "The release that decides stronger digest support is not identified." if release is None else
                f"NTP key algorithm is '{association.algorithm}'.",
                instance=f"server {association.address}",
            )
            if association.authentication_state != "authenticated":
                detail = (
                    "is not configured for authenticated NTP"
                    if association.authentication_state == "unauthenticated"
                    else f"references missing or untrusted key '{association.key_id}'"
                )
                self.add_issue(self._finding(
                    parser, "cisco.asa.ntp.authentication", "NTP authentication is incomplete",
                    f"NTP server '{association.address}' {detail}.",
                    "A spoofed time source can disrupt logging and time-dependent controls.",
                    "Enable NTP authentication and configure, trust, and bind a key for every server.",
                    Severity.MEDIUM, evidence,
                    CISCO_ASA_NTP_REFERENCE,
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                ))
            elif release is not None and release >= (9, 13) and association.algorithm in {"md5", "sha1"}:
                self.add_issue(self._finding(
                    parser, "cisco.asa.ntp.weak_algorithm", "NTP uses a legacy authentication algorithm",
                    f"NTP server '{association.address}' uses '{association.algorithm}' on an ASA release supporting stronger alternatives.",
                    "A legacy digest provides weaker protection against forged time updates.",
                    "Use SHA-256, SHA-512, or AES-CMAC according to the approved interoperability policy.",
                    Severity.MEDIUM, evidence,
                    CISCO_ASA_NTP_REFERENCE,
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))

    def check_threat_detection(self, parser: BaseDeviceParser) -> None:
        lines = self._lines(parser)
        enabled = "threat-detection basic-threat" in lines
        disabled = "no threat-detection basic-threat" in lines or not enabled
        record_control(parser, "cisco.asa.threat-detection",
                       ControlOutcome.FINDING if disabled else ControlOutcome.NO_FINDING,
                       "Basic threat detection is not enabled." if disabled else "Basic threat detection is enabled.")
        if "no threat-detection basic-threat" in lines or not enabled:
            self.add_issue(self._finding(
                parser, "cisco.asa.threat_detection.basic", "Basic threat detection is disabled",
                "The effective ASA configuration does not enable basic threat detection.",
                "Scanning, rate anomalies, and attack indicators may receive reduced local visibility.",
                "Enable and tune basic threat detection for the platform and traffic profile.",
                Severity.MEDIUM, ("threat-detection basic-threat absent or negated",),
                basis=FindingBasis.EXPLICIT_VALUE if "no threat-detection basic-threat" in lines else FindingBasis.MISSING_EXPLICIT_SETTING,
            ))

    def check_connection_limits(self, parser: BaseDeviceParser) -> None:
        asa = self._asa(parser)
        release = asa._release_tuple(asa.get_version())
        if release is None or release < (9, 1):
            record_control(parser, "cisco.asa.connection-limits", ControlOutcome.UNKNOWN,
                           "Connection-limit semantics are qualified only from ASA 9.1 on an identified release.")
            return
        policies = asa.get_connection_limit_policies()
        if not policies:
            record_control(parser, "cisco.asa.connection-limits", ControlOutcome.NOT_APPLICABLE,
                           "No attached policy class sets connection limits.")
        for policy in policies:
            unlimited = sorted(name for name, value in policy.limits if value == 0)
            record_control(parser, "cisco.asa.connection-limits",
                           ControlOutcome.FINDING if policy.invalid_values or unlimited else ControlOutcome.NO_FINDING,
                           "Attached connection limits are invalid or unlimited." if policy.invalid_values or unlimited
                           else "Attached connection limits are valid and bounded.",
                           instance=f"{policy.policy_name}/{policy.class_name}")
            evidence = tuple(item for item in policy.evidence)
            scope = ", ".join(policy.attachment_scopes)
            if policy.invalid_values:
                self.add_issue(self._finding(
                    parser,
                    "cisco.asa.control_plane.connection_limit_invalid",
                    "Attached ASA connection limit is invalid",
                    f"Policy '{policy.policy_name}' class '{policy.class_name}', attached at {scope}, contains invalid connection-limit value(s): {', '.join(policy.invalid_values)}.",
                    "An invalid or unresolved limit does not establish the intended connection-resource protection.",
                    "Configure supported integer connection limits from 1 through 2000000 after sizing them for the protected service and platform.",
                    Severity.HIGH,
                    evidence,
                    CISCO_ASA_FIREWALL_REFERENCE,
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
            if unlimited:
                self.add_issue(self._finding(
                    parser,
                    "cisco.asa.control_plane.connection_limit_unbounded",
                    "Attached ASA policy explicitly permits unlimited connections",
                    f"Policy '{policy.policy_name}' class '{policy.class_name}', attached at {scope}, explicitly sets {', '.join(unlimited)} to zero; ASA defines zero as unlimited.",
                    "An unbounded connection or embryonic-connection population can exhaust firewall or protected-service resources during a denial-of-service event.",
                    "Set traffic-appropriate nonzero limits based on platform capacity and observed workload; validate availability before deployment.",
                    Severity.HIGH if any("embryonic" in item for item in unlimited) else Severity.MEDIUM,
                    evidence,
                    CISCO_ASA_FIREWALL_REFERENCE,
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))

    def check_reverse_path(self, parser: BaseDeviceParser) -> None:
        lines = self._lines(parser)
        protected = {
            match.group(1)
            for line in lines
            if (match := re.fullmatch(r"ip verify reverse-path interface\s+(\S+)", line))
        }
        low_trust = False
        for interface in self._asa(parser).get_interfaces():
            name = interface["nameif"]
            if interface["security_level"] <= 10:
                low_trust = True
                record_control(parser, "cisco.asa.reverse-path",
                               ControlOutcome.NO_FINDING if name in protected else ControlOutcome.FINDING,
                               "Reverse-path verification is enabled." if name in protected else
                               "Low-trust interface has no reverse-path verification.", instance=name)
            if interface["security_level"] <= 10 and name not in protected:
                self.add_issue(self._finding(
                    parser, "cisco.asa.interface.reverse_path", "Reverse-path verification is missing",
                    f"Low-trust interface '{name}' does not have uRPF reverse-path verification enabled.",
                    "Spoofed source addresses may cross the firewall boundary without an interface-level routing check.",
                    "Configure 'ip verify reverse-path interface <nameif>' after validating asymmetric routing requirements.",
                    Severity.MEDIUM, (f"interface {name}",),
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                ))
        if not low_trust:
            record_control(parser, "cisco.asa.reverse-path", ControlOutcome.NOT_APPLICABLE,
                           "No named interface has security level 10 or lower.")

    def check_vpn_crypto(self, parser: BaseDeviceParser) -> None:
        native = parser.get_native_config()
        blocks = native.find_objects(r"^crypto (?:ikev1|isakmp) policy\s+")
        blocks += native.find_objects(r"^crypto ikev2 policy\s+")
        _, release = self._asa(parser).get_release()
        if not blocks:
            record_control(parser, "cisco.asa.ike-policy", ControlOutcome.NOT_APPLICABLE, "No IKE policy is configured.")
        for block in blocks:
            children = [child.text.strip().lower() for child in block.children]
            weak = [
                line for line in children
                if any(token in line.split() for token in ("des", "3des", "md5"))
                or re.fullmatch(r"group (?:1|2|5|14)", line)
                or line == "integrity sha"
            ]
            # SC-044 ASA-14: 9.1 VPN guide, IKEv1 policy defaults are 3DES and DH
            # group 2; by 9.17 they are AES-128 and group 14 (change release not
            # verified), so only releases up to 9.12 are decided.
            defaults = []
            if (release is not None and release < (9, 13)
                    and not block.text.strip().lower().startswith("crypto ikev2")):
                if not any(line.startswith("encryption ") for line in children):
                    defaults.append("encryption absent: default 3des")
                if not any(line.startswith("group ") for line in children):
                    defaults.append("group absent: default DH group 2")
            ikev2 = block.text.strip().lower().startswith("crypto ikev2")
            required = ("encryption ", "integrity ", "group ") if ikev2 else ("encryption ", "group ")
            omitted = [item.strip() for item in required if not any(line.startswith(item) for line in children)]
            record_control(
                parser, "cisco.asa.ike-policy",
                ControlOutcome.FINDING if defaults or weak else
                ControlOutcome.UNKNOWN if omitted else ControlOutcome.NO_FINDING,
                "IKE policy resolves to legacy explicit or documented-default values." if defaults or weak else
                f"Omitted {', '.join(omitted)} default is not qualified for this release." if omitted else
                "IKE policy sets explicit non-legacy values.", instance=block.text.strip())
            if defaults:
                self.add_issue(self._finding(
                    parser, "cisco.asa.crypto.legacy_vpn", "VPN policy uses legacy cryptography",
                    f"{block.text.strip()} omits parameters whose documented defaults on this release are weak: {'; '.join(defaults)}.",
                    "Weak VPN algorithms reduce confidentiality, integrity, or key-exchange strength.",
                    "Set AES-256 (or AES-GCM), SHA-256 or stronger and DH group 14 or stronger explicitly in every IKE policy.",
                    Severity.HIGH, (block.text.strip(), *weak, *defaults),
                    (CISCO_ASA_91_IKE_GUIDE,),
                    basis=FindingBasis.DOCUMENTED_DEFAULT,
                ))
                continue
            if weak:
                self.add_issue(self._finding(
                    parser, "cisco.asa.crypto.legacy_vpn", "VPN policy uses legacy cryptography",
                    f"{block.text.strip()} contains legacy encryption, integrity, or Diffie-Hellman selections.",
                    "Weak VPN algorithms reduce confidentiality, integrity, or key-exchange strength.",
                    "Use AES-GCM/AES-256, SHA-256 or stronger, and approved modern DH groups.",
                    Severity.HIGH, (block.text.strip(), *weak),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))

        approved_groups = parser.assessment_context.approved_asa_ike_dh_groups
        if approved_groups:
            for alternative in self._asa(parser).get_active_ike_dh_groups():
                outside = not (alternative.group in approved_groups or alternative.group in {"1", "2", "5", "14"})
                record_control(parser, "cisco.asa.ike-policy",
                               ControlOutcome.FINDING if outside else ControlOutcome.NO_FINDING,
                               "Enabled DH group is outside the approved profile." if outside else
                               "Enabled DH group is approved or covered by the legacy-group rule.",
                               instance=f"{alternative.version} policy {alternative.priority} group {alternative.group}")
                if (alternative.group in approved_groups
                        or alternative.group in {"1", "2", "5", "14"}):
                    continue  # Legacy groups have the existing finding; do not duplicate it.
                self.add_issue(self._finding(
                    parser, "cisco.asa.crypto.ike_dh_policy",
                    "Enabled ASA IKE policy offers a DH group outside the approved profile",
                    f"Enabled {alternative.version} policy {alternative.priority} offers group {alternative.group} on {', '.join(alternative.interfaces)}, outside the exact approved group set in assessment policy '{parser.assessment_context.policy_version}'.",
                    "A negotiable group outside the approved profile weakens policy consistency even when another allowed alternative exists.",
                    "Remove this DH alternative or revise the explicitly approved platform profile after review.",
                    Severity.MEDIUM,
                    tuple(item for item in alternative.evidence),
                    (CISCO_ASA_IKE_POLICY_REFERENCE,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
        lines = self._lines(parser)
        attached = any(re.fullmatch(r"crypto map \S+ interface \S+", line) for line in lines)
        transform_recorded = False
        if attached and any(re.fullmatch(r"crypto (?:dynamic-)?map \S+ \d+ set ikev2 ipsec-proposal .+", line) for line in lines):
            transform_recorded = True
            record_control(parser, "cisco.asa.ipsec-transforms", ControlOutcome.UNKNOWN,
                           "IKEv2 IPsec proposals referenced by crypto maps are not evaluated.", instance="ikev2-proposals")
        if attached and any(re.fullmatch(r"crypto (?:dynamic-)?map \S+ \d+ set pfs", line) for line in lines):
            transform_recorded = True
            record_control(parser, "cisco.asa.ipsec-transforms", ControlOutcome.UNKNOWN,
                           "'set pfs' without a group uses a release default that is not qualified.", instance="pfs-default")
        for binding in self._asa(parser).get_active_ipsec_transform_bindings():
            transform_recorded = True
            legacy = binding.declaration is not None and any(
                token in binding.declaration.lower().split() for token in ("esp-des", "esp-3des", "esp-md5-hmac", "esp-sha-hmac"))
            record_control(parser, "cisco.asa.ipsec-transforms",
                           ControlOutcome.FINDING if binding.declaration is None or legacy else ControlOutcome.NO_FINDING,
                           "Attached transform-set is not defined." if binding.declaration is None else
                           "Attached transform-set includes a legacy algorithm." if legacy else
                           "Attached transform-set uses no legacy algorithm.",
                           instance=f"{binding.interface}:{binding.transform_name}")
            if binding.declaration is None:
                self.add_issue(self._finding(
                    parser, "cisco.asa.crypto.unresolved_transform", "Attached IPsec transform-set is unresolved",
                    f"Crypto map on interface '{binding.interface}' references transform-set '{binding.transform_name}', but its definition is not present in this input.",
                    "The effective IPsec algorithms cannot be assessed from this configuration export.",
                    "Include the referenced transform-set definition in the export and validate the active crypto-map chain.",
                    Severity.MEDIUM, (binding.map_binding, binding.map_attachment),
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                ))
                continue
            if any(token in binding.declaration.lower().split() for token in ("esp-des", "esp-3des", "esp-md5-hmac", "esp-sha-hmac")):
                self.add_issue(self._finding(
                    parser, "cisco.asa.crypto.legacy_transform", "IPsec transform-set uses legacy cryptography",
                    f"An IPsec transform-set attached to interface '{binding.interface}' includes a legacy encryption or integrity algorithm.",
                    "Legacy transforms weaken protected VPN traffic.",
                    "Replace legacy transforms with AES and SHA-256 or authenticated encryption.",
                    Severity.HIGH, (binding.declaration, binding.map_binding, binding.map_attachment),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))

        for pfs in self._asa(parser).get_active_pfs_bindings():
            transform_recorded = True
            record_control(parser, "cisco.asa.ipsec-transforms",
                           ControlOutcome.FINDING if pfs.group in {"1", "2", "5", "14"} else ControlOutcome.NO_FINDING,
                           f"Explicit PFS group is {pfs.group}.", instance=f"pfs {pfs.interface} group {pfs.group}")
            if pfs.group not in {"1", "2", "5", "14"}:
                continue
            self.add_issue(self._finding(
                parser, "cisco.asa.crypto.legacy_pfs", "IPsec PFS uses a legacy Diffie-Hellman group",
                f"A crypto map attached to interface '{pfs.interface}' sets PFS to DH group {pfs.group}, which is in this project's legacy set (groups 1, 2, 5 and 14; groups 1, 2 and 5 were removed from ASA IKE in 9.15).",
                "New IPsec keys are derived with a weak key exchange, reducing forward secrecy for protected traffic.",
                "Set PFS to an approved modern group such as 19, 20 or 21, supported by the peer.",
                Severity.HIGH, tuple(pfs.evidence), (CISCO_ASA_CRYPTO_MAP_REFERENCE,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))
        if not transform_recorded:
            record_control(parser, "cisco.asa.ipsec-transforms", ControlOutcome.NOT_APPLICABLE,
                           "No attached crypto map references an IKEv1 transform-set or explicit PFS group.")

    def check_release_defaults(self, parser: BaseDeviceParser) -> None:
        """SC-044 ASA-01 and ASA-19: behaviour that applies unless the export turns it off."""
        asa = self._asa(parser)
        lines = self._lines(parser)
        vpn = [line for line in lines if re.fullmatch(r"crypto map \S+ interface \S+", line)
               or re.fullmatch(r"crypto (?:ikev1|ikev2|isakmp) enable \S+.*", line)]
        vpn += [f"webvpn enable {name}" for name in asa.get_ssl_service_policy().active_interfaces]
        permit_vpn = True
        for line in lines:
            if line == "no sysopt connection permit-vpn":
                permit_vpn = False
            elif line == "sysopt connection permit-vpn":
                permit_vpn = True
        record_control(parser, "cisco.asa.vpn-acl-bypass",
                       ControlOutcome.NOT_APPLICABLE if not vpn else
                       ControlOutcome.FINDING if permit_vpn else ControlOutcome.NO_FINDING,
                       "No VPN termination is configured." if not vpn else
                       "VPN traffic bypasses interface ACLs (sysopt connection permit-vpn)." if permit_vpn else
                       "'no sysopt connection permit-vpn' is configured.")
        if vpn and permit_vpn:
            explicit = "sysopt connection permit-vpn" in lines
            self.add_issue(self._finding(
                parser, "cisco.asa.vpn.sysopt_permit_vpn",
                "Decrypted VPN traffic bypasses interface access lists",
                "VPN termination is configured and 'no sysopt connection permit-vpn' is absent, so traffic from VPN tunnels "
                "is not checked by the interface access lists (enabled by default).",
                "A compromised VPN client or peer can reach every address its tunnel covers, regardless of the interface ACL.",
                "Configure 'no sysopt connection permit-vpn' and permit tunnel traffic in the outside ACL, or restrict each tunnel with a vpn-filter.",
                Severity.MEDIUM,
                tuple(vpn[:5]) + (("sysopt connection permit-vpn",) if explicit else ("no sysopt connection permit-vpn absent",)),
                CISCO_ASA_SYSOPT_REFERENCE,
                basis=FindingBasis.EXPLICIT_VALUE if explicit else FindingBasis.DOCUMENTED_DEFAULT,
            ))
        icmp_interfaces = {
            match.group(1).casefold()
            for line in lines
            if (match := re.fullmatch(r"icmp (?:permit|deny) .+ (\S+)", line))
        }
        outside = [interface for interface in asa.get_interfaces() if interface["security_level"] == 0]
        if not outside:
            record_control(parser, "cisco.asa.outside-icmp", ControlOutcome.NOT_APPLICABLE,
                           "No named interface has security level 0.")
        for interface in outside:
            restricted = interface["nameif"].casefold() in icmp_interfaces
            record_control(parser, "cisco.asa.outside-icmp",
                           ControlOutcome.NO_FINDING if restricted else ControlOutcome.FINDING,
                           "ICMP rules are configured for the interface." if restricted else
                           "No ICMP rule restricts ICMP to the interface.", instance=interface["nameif"])
        for interface in asa.get_interfaces():
            if interface["security_level"] != 0 or interface["nameif"].casefold() in icmp_interfaces:
                continue
            self.add_issue(self._finding(
                parser, "cisco.asa.interface.icmp_unrestricted",
                "All ICMP to the firewall is accepted on an outside interface",
                f"Interface {interface['nameif']} (security level 0) has no 'icmp' rules, so the ASA answers all ICMP "
                "sent to that interface (the documented default).",
                "Echo, timestamp and mask requests let anyone map and fingerprint the firewall and add to reconnaissance.",
                f"Add 'icmp permit' lines for the needed types (for example unreachable and time-exceeded) followed by 'icmp deny any {interface['nameif']}'.",
                Severity.LOW,
                (f"interface {interface['name']}", f"nameif {interface['nameif']}", "icmp rules absent"),
                CISCO_ASA_ICMP_REFERENCE,
                basis=FindingBasis.DOCUMENTED_DEFAULT,
            ))

    def check_remote_access_authentication(self, parser: BaseDeviceParser) -> None:
        control = "cisco.asa.ra-client-certificate"
        if not parser.assessment_context.asa_ra_require_client_certificate:
            record_control(parser, control, ControlOutcome.NOT_APPLICABLE,
                           "The assessment policy does not require remote-access client certificates.")
            return
        release = self._asa(parser)._release_tuple(self._asa(parser).get_version())
        if release is None or release < (9, 16):
            record_control(parser, control, ControlOutcome.UNKNOWN,
                           "Profile selection is qualified only from ASA 9.16 on an identified release.")
        profiles = self._asa(parser).get_selectable_webvpn_profiles()
        if release is not None and release >= (9, 16) and not profiles:
            record_control(parser, control, ControlOutcome.NOT_APPLICABLE,
                           "No remote-access profile is selectable on an enabled WebVPN listener.")
        for profile in profiles:
            record_control(parser, control,
                           ControlOutcome.FINDING if profile.authentication == "aaa" else
                           ControlOutcome.NO_FINDING if "certificate" in profile.authentication.split() else
                           ControlOutcome.UNKNOWN,
                           f"Profile authentication is '{profile.authentication}'.", instance=profile.name)
            if profile.authentication != "aaa":
                continue
            self.add_issue(self._finding(
                parser,
                "cisco.asa.remote_access.client_certificate_missing",
                "Selectable ASA remote-access profile requires only AAA authentication",
                f"WebVPN profile '{profile.name}' is selectable on enabled listener(s) {', '.join(profile.listener_interfaces)} and explicitly requires AAA but not a client certificate, contrary to assessment policy '{parser.assessment_context.policy_version}'.",
                "A password-only configured path does not meet this audit's explicit client-certificate requirement; external identity-provider MFA is not inferred from the export.",
                "Require certificate authentication for this profile or document and select a different approved authentication policy.",
                Severity.HIGH,
                tuple(item for item in profile.evidence)
                + ("assessment policy: ASA remote access client certificate required",),
                (CISCO_ASA_WEBVPN_AUTH_REFERENCE,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))

    def check_failover(self, parser: BaseDeviceParser) -> None:
        lines = self._lines(parser)
        failover = "failover" in lines and "no failover" not in lines
        if not failover:
            record_control(parser, "cisco.asa.failover-key", ControlOutcome.NOT_APPLICABLE, "Failover is not enabled.")
            return
        keyed = any(re.fullmatch(r"failover key\s+.+", line) for line in lines)
        record_control(parser, "cisco.asa.failover-key", ControlOutcome.NO_FINDING if keyed else ControlOutcome.FINDING,
                       "A failover key is configured." if keyed else "Failover is enabled without a failover key.")
        if not any(re.fullmatch(r"failover key\s+.+", line) for line in lines):
            self.add_issue(self._finding(
                parser, "cisco.asa.failover.authentication", "Failover link authentication is missing",
                "ASA failover is enabled without an explicit failover key.",
                "Unauthenticated failover communication can weaken the integrity of high-availability state exchange.",
                "Configure a strong failover key and protect the failover network.",
                Severity.HIGH, ("failover",),
                basis=FindingBasis.REQUIRED_SETTING_MISSING,
            ))

    def check_local_administrator_policy(self, parser: BaseDeviceParser) -> None:
        asa = self._asa(parser)
        release = asa._release_tuple(asa.get_version())
        if release is None or not asa.get_users():
            return
        bindings = {
            item.protocol: item
            for item in asa.get_administrative_aaa_bindings()
            if item.binding_type == "authentication"
        }
        local_paths = [
            protocol for protocol in ("ssh", "telnet", "http")
            if asa.get_management_grants(protocol)
            and (protocol != "http" or asa.get_http_server_enabled())
            and (binding := bindings.get(protocol)) is not None
            and binding.local_fallback
        ]
        if not local_paths:
            return
        lockout = asa.get_local_lockout_limit()
        # On releases before 9.17, privilege-15 users are exempt from this
        # control. Do not imply that a protected emergency administrator is
        # subject to lockout on older ASA releases.
        if release >= (9, 17) and lockout.raw_line.startswith(("no ", "default ")):
            self.add_issue(self._finding(
                parser, "cisco.asa.admin.local_lockout_disabled",
                "ASA local administrative login lockout is explicitly disabled",
                f"Local-database authentication is an active or fallback path for {', '.join(sorted(local_paths))}, while the maximum-failure limit is explicitly reset.",
                "Repeated guesses against a local administrative account are not limited by this configured control.",
                "Configure 'aaa local authentication attempts max-fail' to an approved value while retaining a tested emergency access path.",
                Severity.HIGH, (lockout.raw_line,), CISCO_ASA_AAA_REFERENCE,
                basis=FindingBasis.EXPLICIT_VALUE,
            ))
        minimum = asa.get_local_password_minimum()
        if (
            release >= (9, 1) and minimum.value is not None and minimum.value < 8
            and (minimum.configured or minimum.raw_line.startswith(("no ", "default ")))
        ):
            self.add_issue(self._finding(
                parser, "cisco.asa.admin.local_password_minimum",
                "ASA local administrator password minimum is below vendor guidance",
                f"The explicitly configured or reset local password policy permits {minimum.value}-character passwords, below Cisco's eight-character recommendation.",
                "New or changed local administrative passwords may be easier to guess; existing passwords are not retroactively changed by this setting.",
                "Set 'password-policy minimum-length' to at least eight or an approved stronger organizational value.",
                Severity.MEDIUM, (minimum.raw_line,), CISCO_ASA_PASSWORD_POLICY_REFERENCE,
                basis=FindingBasis.EXPLICIT_VALUE if minimum.configured else FindingBasis.DOCUMENTED_DEFAULT,
            ))

    def check_aaa_transport(self, parser: BaseDeviceParser) -> None:
        """SC-031: bound TACACS+ hosts without a key and LDAP hosts binding in clear text."""
        recorded = False
        for host in self._asa(parser).get_aaa_server_hosts():
            if host["bound"] and host["protocol"] in {"tacacs+", "ldap"}:
                recorded = True
                insecure = (not host["key"]) if host["protocol"] == "tacacs+" else (
                    not host["ldap_over_ssl"] and host["sasl"] in {None, "plain"})
                record_control(parser, "cisco.asa.aaa-server-transport",
                               ControlOutcome.FINDING if insecure else ControlOutcome.NO_FINDING,
                               f"Bound {host['protocol']} host {'sends credentials unprotected' if insecure else 'protects credentials in transit'}.",
                               instance=f"{host['group']} {host['address']}")
            if not host["bound"]:
                continue
            if host["protocol"] == "tacacs+" and not host["key"]:
                self.add_issue(self._finding(
                    parser, "cisco.asa.aaa.tacacs_key_missing",
                    "TACACS+ server without a shared key",
                    f"TACACS+ host {host['address']} in bound server group '{host['group']}' has no key.",
                    "Without a key TACACS+ packets are not obfuscated, so administrator and VPN user credentials cross the network in clear text.",
                    "Configure a long random 'key' for the host that matches the TACACS+ server, and protect it with the master passphrase.",
                    Severity.HIGH, (host["evidence"],), (RFC_8907, *CISCO_ASA_AAA_REFERENCE),
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                ))
            elif host["protocol"] == "ldap" and not host["ldap_over_ssl"] and host["sasl"] in {None, "plain"}:
                self.add_issue(self._finding(
                    parser, "cisco.asa.aaa.ldap_cleartext",
                    "LDAP authentication without SSL",
                    (f"LDAP host {host['address']} in bound server group '{host['group']}' does not enable "
                     "'ldap-over-ssl' and uses simple (plain) binds."),
                    "User and bind passwords are sent to the LDAP server in clear text and can be captured on the network path.",
                    "Configure 'ldap-over-ssl enable' for the host (LDAPS, TCP 636) and trust the LDAP server certificate.",
                    Severity.HIGH, (host["evidence"],), (CISCO_ASA_LDAP_OVER_SSL_REFERENCE,),
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                ))
        if not recorded:
            record_control(parser, "cisco.asa.aaa-server-transport", ControlOutcome.NOT_APPLICABLE,
                           "No bound TACACS+ or LDAP server host is configured.")

    def check_ike_aggressive_mode(self, parser: BaseDeviceParser) -> None:
        """SC-034: inbound IKEv1 aggressive mode accepted for pre-shared-key tunnel groups."""
        state = self._asa(parser).get_ikev1_aggressive_mode_state()
        record_control(parser, "cisco.asa.ike-aggressive-mode",
                       ControlOutcome.FINDING if state == "accepted" else
                       ControlOutcome.NO_FINDING if state == "disabled" else ControlOutcome.NOT_APPLICABLE,
                       {"accepted": "IKEv1 PSK termination accepts aggressive mode (documented default).",
                        "disabled": "IKEv1 aggressive mode is disabled."}.get(
                           state, "No IKEv1 pre-shared-key termination is configured."))
        accepted, evidence = self._asa(parser).get_ikev1_aggressive_mode()
        if not accepted:
            return
        self.add_issue(self._finding(
            parser, "cisco.asa.vpn.ike_aggressive_mode",
            "IKEv1 aggressive mode is accepted for pre-shared keys",
            ("IKEv1 is enabled on an interface with pre-shared-key tunnel groups and 'crypto ikev1 am-disable' is "
             "absent, so inbound aggressive-mode connections are accepted (the documented default)."),
            "Aggressive mode sends a hash derived from the pre-shared key before the peer is authenticated, so it can be captured and cracked offline.",
            ("Configure 'crypto ikev1 am-disable' (older releases: 'crypto isakmp am-disable'), prefer IKEv2 or "
             "certificates, and use long random pre-shared keys."),
            Severity.MEDIUM, evidence, (CISCO_ASA_AM_DISABLE_REFERENCE, RFC_2409),
            basis=FindingBasis.DOCUMENTED_DEFAULT,
        ))

    def check_service_key_storage(self, parser: BaseDeviceParser) -> None:
        """SC-035: clear-text tunnel-group and AAA server keys in the export."""
        labels = {
            "tunnel_group_pre_shared_key": "VPN tunnel-group pre-shared key",
            "aaa_server_key": "AAA server shared key",
        }
        for context, account, state, evidence in self._asa(parser).get_service_key_storage():
            record_control(parser, "cisco.asa.stored-secrets",
                           ControlOutcome.FINDING if state == "cleartext" else
                           ControlOutcome.NO_FINDING if state == "encrypted" else ControlOutcome.UNKNOWN,
                           {"cleartext": "Key is stored in clear text.", "encrypted": "Key is AES-encrypted (type 8).",
                            "masked": "Key is masked in this export; its storage is not visible."}.get(
                               state, "Key value is empty or not parsed."),
                           instance=f"{context} {account}")
            if state != "cleartext":
                continue
            self.add_issue(self._finding(
                parser, f"cisco.asa.credentials.{context}_storage",
                f"{labels[context]} is stored in clear text",
                (f"The {labels[context]} for '{account}' appears in clear text in this export, so the "
                 "master passphrase is not protecting it. The value is redacted."),
                "Anyone with a copy of this configuration can reuse the key to impersonate a VPN peer or authentication server.",
                ("Configure a master passphrase ('key config-key password-encryption' and "
                 "'password encryption aes') so stored keys are AES-encrypted, then rotate the exposed key."),
                Severity.HIGH, (evidence,), (CISCO_ASA_MASTER_PASSPHRASE_REFERENCE,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))

    def check_cis_follow_ups(self, parser: BaseDeviceParser) -> None:
        """SC-057: CIS ASA follow-ups (authorization, routing authentication, untrusted interfaces, hygiene)."""
        asa = self._asa(parser)
        blocks = asa.get_top_level_blocks()
        top = [" ".join(header.text.split()).lower() for header, _ in blocks]

        def has(*prefixes: str) -> bool:
            return any(line.startswith(prefix) for line in top for prefix in prefixes)

        # Authorization when management authentication uses a remote server group.
        remote_auth = [line for line in top if re.fullmatch(r"aaa authentication (ssh|telnet|http|enable|serial) console (\S+).*", line)
                       and line.split()[4] != "local"]
        if not remote_auth:
            record_control(parser, "cisco.asa.management-authorization", ControlOutcome.NOT_APPLICABLE,
                           "Management authentication does not use a remote server group.")
        if remote_auth:
            missing = [label for label, prefix in (("command authorization", "aaa authorization command"),
                                                   ("exec authorization", "aaa authorization exec"))
                       if not has(prefix)]
            record_control(parser, "cisco.asa.management-authorization",
                           ControlOutcome.FINDING if missing else ControlOutcome.NO_FINDING,
                           f"Not configured: {', '.join(missing)}." if missing else
                           "Command and exec authorization are configured.")
            if missing:
                self.add_issue(self._finding(
                    parser, "cisco.asa.aaa.management_authorization",
                    "Management authorization is not configured",
                    f"Management logins authenticate against a server group, but {' and '.join(missing)} is not configured.",
                    "Every authenticated administrator receives the privilege level configured locally instead of per-user, centrally controlled rights.",
                    "Configure 'aaa authorization command <group> LOCAL' and 'aaa authorization exec authentication-server' with appropriate server-side roles.",
                    Severity.MEDIUM, ("aaa authorization command/exec absent",),
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                ))

        # Routing protocol authentication.
        interfaces = {header.text.split()[1]: children for header, children in blocks
                      if header.text.lower().startswith("interface ") and len(header.text.split()) > 1}
        any_child = lambda pattern: any(re.search(pattern, child, re.IGNORECASE) for children in interfaces.values() for child in children)
        routing = []
        for header, children in blocks:
            text = header.text.lower()
            if text.startswith("router ospf ") and not any_child(r"^ospf authentication") and not any(
                    re.search(r"^area \S+ authentication", c, re.IGNORECASE) for c in children):
                routing.append(("ospf", header))
            elif text.startswith("router eigrp ") and not any_child(r"^authentication (mode|key) eigrp"):
                routing.append(("eigrp", header))
            elif text.startswith("router rip") and not any_child(r"^rip authentication mode md5"):
                routing.append(("rip", header))
            elif text.startswith("router bgp "):
                neighbors = {c.split()[1] for c in children if re.match(r"neighbor \S+ remote-as ", c, re.IGNORECASE)}
                secured = {c.split()[1] for c in children if re.match(r"neighbor \S+ password ", c, re.IGNORECASE)}
                if neighbors - secured:
                    routing.append(("bgp", header))
        flagged = {id(header) for _, header in routing}
        routers = [header for header, _ in blocks
                   if header.text.lower().startswith(("router ospf ", "router eigrp ", "router rip", "router bgp "))]
        if not routers:
            record_control(parser, "cisco.asa.routing-authentication", ControlOutcome.NOT_APPLICABLE,
                           "No OSPF, EIGRP, RIP or BGP process is configured.")
        for header in routers:
            record_control(parser, "cisco.asa.routing-authentication",
                           ControlOutcome.FINDING if id(header) in flagged else ControlOutcome.NO_FINDING,
                           "Routing process lacks authentication." if id(header) in flagged else
                           "Routing authentication is configured.", instance=header.text)
        for protocol, header in routing:
            self.add_issue(self._finding(
                parser, f"cisco.asa.routing.{protocol}.authentication",
                f"{protocol.upper()} on the ASA runs without authentication",
                (f"'{header.text}' is configured, but no {protocol.upper()} authentication was found "
                 + ("for at least one neighbor." if protocol == "bgp" else "on any interface or area.")),
                "A device that can reach the routing session can inject or withdraw routes on the firewall.",
                "Configure MD5 or key-chain authentication for the routing protocol on all neighbors (CIS ASA 9.x 2.1.x).",
                Severity.HIGH, (header,),
                basis=FindingBasis.REQUIRED_SETTING_MISSING,
            ))

        # Untrusted (assessed external) interfaces.
        context = parser.assessment_context
        external = []
        for name, children in interfaces.items():
            nameif = next((c.split()[1] for c in children if c.lower().startswith("nameif ") and len(c.split()) > 1), "")
            roles = {context.role_for_interface(name), context.role_for_interface(nameif)} if nameif else {context.role_for_interface(name)}
            if "external" in roles and nameif:
                level = next((c.split()[1] for c in children if c.lower().startswith("security-level ")), None)
                external.append((name, nameif, level))
        if not external:
            record_control(parser, "cisco.asa.external-interfaces", ControlOutcome.NOT_APPLICABLE,
                           "No named interface is classified external by the assessment policy.")
        else:
            record_control(parser, "cisco.asa.external-interfaces",
                           ControlOutcome.FINDING if has("no dns-guard") else ControlOutcome.NO_FINDING,
                           "'no dns-guard' is configured." if has("no dns-guard") else "DNS Guard is not disabled.",
                           instance="dns-guard")
        for name, nameif, level in external:
            dhcp = any(line == f"dhcpd enable {nameif.lower()}" for line in top)
            record_control(parser, "cisco.asa.external-interfaces",
                           ControlOutcome.FINDING if level not in (None, "0") or dhcp else ControlOutcome.NO_FINDING,
                           f"External interface security level is {level or 'omitted'}; DHCP server {'enabled' if dhcp else 'not enabled'}.",
                           instance=name)
            if level not in (None, "0"):
                self.add_issue(self._finding(
                    parser, "cisco.asa.interface.external_security_level",
                    "External interface has a non-zero security level",
                    f"Interface {name} (nameif {nameif}) is classified external but has security-level {level}.",
                    "A higher security level can allow traffic from the Internet-facing interface to lower-level interfaces without an explicit ACL.",
                    "Set 'security-level 0' on Internet-facing interfaces (CIS ASA 9.x 3.8).",
                    Severity.LOW, (f"interface {name} / security-level {level}",),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
            if any(line == f"dhcpd enable {nameif.lower()}" for line in top):
                self.add_issue(self._finding(
                    parser, "cisco.asa.services.external_dhcp_server",
                    "DHCP server is enabled on an external interface",
                    f"'dhcpd enable {nameif}' serves DHCP on an interface classified external.",
                    "Hosts on the untrusted network can obtain leases and probe the firewall's DHCP service.",
                    "Remove 'dhcpd enable' from untrusted interfaces (CIS ASA 9.x 2.4).",
                    Severity.MEDIUM, (f"dhcpd enable {nameif}",),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
        if external and has("no dns-guard"):
            self.add_issue(self._finding(
                parser, "cisco.asa.services.dns_guard_disabled",
                "DNS Guard is disabled",
                "'no dns-guard' is configured on a firewall with external interfaces.",
                "Without DNS Guard the ASA keeps DNS connections open for multiple responses, which helps DNS spoofing and cache-poisoning attempts.",
                "Remove 'no dns-guard' (CIS ASA 9.x 2.3).",
                Severity.LOW, ("no dns-guard",),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))

        # Lower-priority hygiene, reported once.
        size = next((int(line.split()[2]) for line in top if re.fullmatch(r"logging buffer-size \d+", line)), 0)
        unused = [name for name, children in interfaces.items()
                  if not any(c.lower().startswith("nameif ") for c in children)
                  and "shutdown" not in [c.lower() for c in children]
                  and "." not in name and not name.lower().startswith("management")]
        items = [
            ("1.2.1", "domain-name", not has("domain-name ")),
            ("1.2.4", f"shut down unused interfaces ({', '.join(unused[:5])})", bool(unused)),
            ("1.5.1", "banner asdm", not has("banner asdm")),
            ("1.5.2", "banner exec", not has("banner exec")),
            ("1.5.3", "banner login", not has("banner login")),
            ("1.5.4", "banner motd", not has("banner motd")),
            ("1.10.2", "disable logging to monitor", has("logging monitor")),
            ("1.10.4", "logging device-id", not has("logging device-id")),
            ("1.10.5", "logging history (level 5 or higher)", not has("logging history")),
            ("1.10.6", "logging timestamp", not has("logging timestamp")),
            ("1.10.7", "logging buffer-size >= 524288", size < 524288),
            ("1.10.8", "logging buffered (level 3 or higher)", not has("logging buffered")),
            ("1.11.4", "snmp-server enable traps", has("snmp-server host") and not has("snmp-server enable traps")),
        ]
        missing = [f"CIS {ref}: {label}" for ref, label, gap in items if gap]
        if missing:
            self.add_issue(self._finding(
                parser, "cisco.asa.hardening.cis_hygiene",
                "CIS hardening items not configured",
                f"{len(missing)} lower-priority CIS hardening item(s) are not configured: " + "; ".join(missing) + ".",
                "Each item is minor on its own; together they reduce accountability, log quality and attack-surface hygiene.",
                "Review the listed items against the organization's baseline and configure those that apply.",
                Severity.INFORMATIONAL, (f"{len(missing)} CIS hygiene item(s) absent; see observation",),
                basis=FindingBasis.REQUIRED_SETTING_MISSING,
            ))

    def check_password_recovery(self, parser: BaseDeviceParser) -> None:
        """SC-057 (CIS ASA 9.x 1.1.4): password recovery through ROMMON."""
        enabled, evidence = self._asa(parser).get_password_recovery()
        record_control(parser, "cisco.asa.password-recovery",
                       ControlOutcome.FINDING if enabled else ControlOutcome.NO_FINDING,
                       "Password recovery is enabled." if enabled else "'no service password-recovery' is configured.")
        if not enabled:
            return
        self.add_issue(self._finding(
            parser, "cisco.asa.platform.password_recovery",
            "Password recovery is enabled",
            ("'service password-recovery' is explicitly configured." if evidence else
             "'no service password-recovery' is not configured; the ASA command reference documents that password recovery is enabled by default."),
            "Anyone with console access can boot into ROMMON, bypass the startup configuration and reset the administrator passwords.",
            "Configure 'no service password-recovery' if console access is not otherwise controlled, and keep a documented recovery procedure.",
            Severity.LOW, (evidence,) if evidence else ("service password-recovery absent: documented default enabled",),
            (CISCO_ASA_PASSWORD_RECOVERY_REFERENCE,),
            basis=FindingBasis.EXPLICIT_VALUE if evidence else FindingBasis.DOCUMENTED_DEFAULT,
        ))

    def check_url_credentials_and_updates(self, parser: BaseDeviceParser) -> None:
        """SC-036 URL credentials and Auto Update Server certificate verification."""
        asa = self._asa(parser)
        url_credentials = asa.get_url_credentials()
        record_control(parser, "cisco.asa.stored-secrets",
                       ControlOutcome.FINDING if url_credentials else ControlOutcome.NO_FINDING,
                       f"{len(url_credentials)} URL(s) embed a password." if url_credentials else
                       "No URL embeds a 'user:password@' credential.", instance="urls")
        for evidence in url_credentials:
            self.add_issue(self._finding(
                parser, "cisco.asa.credentials.url_storage",
                "Password is embedded in a URL",
                "A URL in the configuration contains a 'user:password@' credential; the password is redacted.",
                "Anyone with a copy of the configuration can reuse the account, and the credential is not protected by the master passphrase.",
                "Remove the credential from the URL, use certificate-based or separately stored authentication, and rotate the exposed password.",
                Severity.MEDIUM, (evidence,), (CISCO_ASA_AUTO_UPDATE_REFERENCE,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))
        _, release = asa.get_release()
        servers = asa.get_auto_update_servers()
        if not servers:
            record_control(parser, "cisco.asa.auto-update-authentication", ControlOutcome.NOT_APPLICABLE,
                           "No Auto Update Server is configured.")
        for scheme, keyword, evidence in servers:
            unverified = (scheme == "http" or keyword == "no-verification"
                          or (keyword is None and release is not None and release < (9, 2, 0)))
            record_control(parser, "cisco.asa.auto-update-authentication",
                           ControlOutcome.FINDING if unverified else
                           ControlOutcome.UNKNOWN if scheme != "https" or (keyword is None and release is None) else
                           ControlOutcome.NO_FINDING,
                           "The Auto Update Server is not authenticated." if unverified else
                           "The URL scheme or the release default for certificate verification is not qualified."
                           if scheme != "https" or (keyword is None and release is None) else
                           "HTTPS with certificate verification (explicit or the 9.2(1)+ default).",
                           instance=evidence.text)
            if scheme == "http":
                reason, basis = "uses plain HTTP, so updates are neither encrypted nor authenticated", FindingBasis.EXPLICIT_VALUE
            elif keyword == "no-verification":
                reason, basis = "sets no-verification, so the server certificate is not checked", FindingBasis.EXPLICIT_VALUE
            elif keyword is None and release is not None and release < (9, 2, 0):
                reason, basis = ("omits verify-certificate on a release before 9.2(1), where the documented default "
                                 "is not to verify the certificate"), FindingBasis.DOCUMENTED_DEFAULT
            else:
                continue
            self.add_issue(self._finding(
                parser, "cisco.asa.update.server_unverified",
                "Auto Update Server is not authenticated",
                f"The Auto Update Server entry {reason}.",
                "An attacker who can intercept the connection can impersonate the server and push configuration or software images to the firewall.",
                "Use an https:// Auto Update Server URL with 'verify-certificate' and a trusted CA certificate.",
                Severity.HIGH, (evidence,), (CISCO_ASA_AUTO_UPDATE_REFERENCE,),
                basis=basis,
            ))

    # Controls recorded by this plugin; all are unknown when the plugin cannot run.
    BASELINE_CONTROLS = (
        "cisco.asa.management-authentication", "cisco.asa.management-accounting", "cisco.asa.ntp-authentication",
        "cisco.asa.session-timeouts", "cisco.asa.ssh-settings", "cisco.asa.stored-secrets",
        "cisco.asa.http-source-restriction", "cisco.asa.https-certificate", "cisco.asa.ntp-servers",
        "cisco.asa.ntp-key-algorithm", "cisco.asa.threat-detection", "cisco.asa.connection-limits",
        "cisco.asa.reverse-path", "cisco.asa.ike-policy", "cisco.asa.ipsec-transforms",
        "cisco.asa.vpn-acl-bypass", "cisco.asa.outside-icmp", "cisco.asa.ra-client-certificate",
        "cisco.asa.failover-key", "cisco.asa.aaa-server-transport", "cisco.asa.ike-aggressive-mode",
        "cisco.asa.management-authorization", "cisco.asa.routing-authentication", "cisco.asa.external-interfaces",
        "cisco.asa.password-recovery", "cisco.asa.auto-update-authentication",
    )

    def analyze(self, parser: BaseDeviceParser) -> None:
        if parser.device_type != "ASA" or self._asa(parser).get_version() == "?":
            for control in self.BASELINE_CONTROLS:
                record_control(parser, control, ControlOutcome.UNKNOWN,
                               "No 'ASA Version' header; the baseline checks did not run.", instance="baseline")
            return
        self.check_aaa(parser)
        self.check_management_sessions_and_ssh(parser)
        self.check_local_administrator_policy(parser)
        self.check_local_users(parser)
        self.check_service_key_storage(parser)
        self.check_url_credentials_and_updates(parser)
        self.check_password_recovery(parser)
        self.check_cis_follow_ups(parser)
        self.check_ike_aggressive_mode(parser)
        self.check_aaa_transport(parser)
        self.check_http_management(parser)
        self.check_ntp(parser)
        self.check_threat_detection(parser)
        self.check_connection_limits(parser)
        self.check_reverse_path(parser)
        self.check_vpn_crypto(parser)
        self.check_remote_access_authentication(parser)
        self.check_failover(parser)
        self.check_release_defaults(parser)
