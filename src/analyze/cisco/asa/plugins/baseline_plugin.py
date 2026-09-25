import re

from src.analyze.common.base_plugin import BasePlugin
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
        for protocol in sorted(active_protocols):
            authentication = bindings.get(("authentication", protocol))
            if authentication is None or not authentication.resolved:
                detail = (
                    "is missing"
                    if authentication is None
                    else f"references undefined server group '{authentication.server_group}'"
                )
                self.add_issue(self._finding(
                    parser, "cisco.asa.aaa.management_authentication",
                    "Management authentication binding is unresolved",
                    f"Active {protocol.upper()} management {detail} for its AAA authentication binding.",
                    "Management access may rely on an unintended authentication path or an unavailable server group.",
                    "Bind the protocol to LOCAL with a defined local user, or to a defined resilient AAA server group with an appropriate LOCAL fallback.",
                    Severity.HIGH,
                    (authentication.raw_line,) if authentication else (f"active {protocol} management grant",),
                    CISCO_ASA_AAA_REFERENCE,
                ))
            if protocol not in {"ssh", "telnet"}:
                # ASA administrative-session accounting has no HTTP/ASDM keyword.
                continue
            accounting = bindings.get(("accounting", protocol))
            if accounting is None or not accounting.resolved:
                detail = (
                    "is missing"
                    if accounting is None
                    else f"references undefined server group '{accounting.server_group}'"
                )
                self.add_issue(self._finding(
                    parser, "cisco.asa.aaa.management_accounting",
                    "Management accounting binding is unresolved",
                    f"Active {protocol.upper()} management {detail} for its AAA session-accounting binding.",
                    "Administrative sessions may not be attributable in a central audit trail.",
                    "Configure administrative-session accounting to a defined RADIUS or TACACS+ server group for each supported protocol.",
                    Severity.MEDIUM,
                    (accounting.raw_line,) if accounting else (f"active {protocol} management grant",),
                    CISCO_ASA_AAA_REFERENCE,
                ))

    def check_management_sessions_and_ssh(self, parser: BaseDeviceParser) -> None:
        asa = self._asa(parser)
        console_timeout = asa.get_console_timeout()
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
            ))

        if not asa.get_management_grants("ssh"):
            return
        ssh_timeout = asa.get_ssh_timeout()
        if ssh_timeout.configured and ssh_timeout.value is not None and ssh_timeout.value > 10:
            self.add_issue(self._finding(
                parser, "cisco.asa.ssh.idle_timeout_excessive",
                "ASA SSH administrative idle timeout is excessive",
                f"The explicitly configured SSH idle timeout is {ssh_timeout.value} minutes, above the project's ten-minute management target.",
                "An abandoned SSH session remains usable longer than intended.",
                "Set 'ssh timeout' to ten minutes or less after validating the operational requirement.",
                Severity.MEDIUM, (ssh_timeout.raw_line,), CISCO_ASA_MANAGEMENT_REFERENCE,
            ))
        policy = asa.get_ssh_policy()
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
            ))

    def check_local_users(self, parser: BaseDeviceParser) -> None:
        policy = credential_policy_from_context(parser.assessment_context)
        for credential in self._asa(parser).get_local_credentials():
            result = evaluate_credential(credential, policy)
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
            return
        grants = asa.get_management_grants("http")
        if not grants:
            self.add_issue(self._finding(
                parser, "cisco.asa.management.http_sources",
                "ASDM/HTTPS management has no explicit source grant",
                "The HTTP server is enabled but no effective HTTP management source grant was parsed.",
                "Management reachability is uncertain and may rely on unintended configuration.",
                "Add narrow 'http <network> <mask> <interface>' grants or disable the HTTP server.",
                Severity.MEDIUM, ("http server enable",),
            ))
        if grants:
            idle = asa.get_asdm_idle_policy()
            if idle.resolution_state == "explicit" and idle.minutes is not None and idle.minutes > 10:
                self.add_issue(self._finding(
                    parser, "cisco.asa.asdm.idle_timeout_excessive",
                    "ASA ASDM administrative idle timeout is excessive",
                    f"The explicitly configured {idle.source} allows {idle.minutes:g} minutes of inactivity, above the project's ten-minute management target.",
                    "An abandoned ASDM session may remain usable longer than intended.",
                    "Set the effective HTTP/ASDM idle timeout to ten minutes or less.",
                    Severity.MEDIUM, tuple(item for item in idle.evidence),
                    CISCO_ASA_HTTP_TIMEOUT_REFERENCE,
                ))
        for grant in grants:
            if grant.is_any_source:
                self.add_issue(self._finding(
                    parser, "cisco.asa.management.unrestricted_http",
                    "ASDM/HTTPS management source is unrestricted",
                    f"Every {grant.address_family} source is permitted to reach HTTP/ASDM on interface '{grant.interface}'.",
                    "The administrative web service is exposed to broad authentication and exploitation attempts.",
                    "Restrict HTTP management to dedicated administration networks.",
                    Severity.HIGH, (grant.raw_line,),
                ))
        certificate_bindings = asa.get_management_certificate_bindings()
        if not certificate_bindings:
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
            if not binding.trustpoint_configured:
                self.add_issue(self._finding(
                    parser, "cisco.asa.management.certificate_unresolved",
                    "ASDM/HTTPS trustpoint reference is unresolved",
                    f"SSL assigns trustpoint '{binding.trustpoint}'{f' on interface {binding.interface}' if binding.interface else ''}, but no matching crypto ca trustpoint object was parsed.",
                    "The supplied configuration does not establish the certificate identity served to administrators.",
                    "Define and enroll the referenced trustpoint, or supply the complete effective configuration containing it.",
                    Severity.MEDIUM, evidence,
                    CISCO_ASA_CERTIFICATE_REFERENCE,
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
            return
        release = asa._release_tuple(asa.get_version())
        for association in associations:
            evidence = tuple(item for item in association.evidence)
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
                ))
            elif release is not None and release >= (9, 13) and association.algorithm in {"md5", "sha1"}:
                self.add_issue(self._finding(
                    parser, "cisco.asa.ntp.weak_algorithm", "NTP uses a legacy authentication algorithm",
                    f"NTP server '{association.address}' uses '{association.algorithm}' on an ASA release supporting stronger alternatives.",
                    "A legacy digest provides weaker protection against forged time updates.",
                    "Use SHA-256, SHA-512, or AES-CMAC according to the approved interoperability policy.",
                    Severity.MEDIUM, evidence,
                    CISCO_ASA_NTP_REFERENCE,
                ))

    def check_threat_detection(self, parser: BaseDeviceParser) -> None:
        lines = self._lines(parser)
        enabled = "threat-detection basic-threat" in lines
        if "no threat-detection basic-threat" in lines or not enabled:
            self.add_issue(self._finding(
                parser, "cisco.asa.threat_detection.basic", "Basic threat detection is disabled",
                "The effective ASA configuration does not enable basic threat detection.",
                "Scanning, rate anomalies, and attack indicators may receive reduced local visibility.",
                "Enable and tune basic threat detection for the platform and traffic profile.",
                Severity.MEDIUM, ("threat-detection basic-threat absent or negated",),
            ))

    def check_connection_limits(self, parser: BaseDeviceParser) -> None:
        asa = self._asa(parser)
        release = asa._release_tuple(asa.get_version())
        if release is None or release < (9, 1):
            return
        for policy in asa.get_connection_limit_policies():
            unlimited = sorted(name for name, value in policy.limits if value == 0)
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
                ))

    def check_reverse_path(self, parser: BaseDeviceParser) -> None:
        lines = self._lines(parser)
        protected = {
            match.group(1)
            for line in lines
            if (match := re.fullmatch(r"ip verify reverse-path interface\s+(\S+)", line))
        }
        for interface in self._asa(parser).get_interfaces():
            name = interface["nameif"]
            if interface["security_level"] <= 10 and name not in protected:
                self.add_issue(self._finding(
                    parser, "cisco.asa.interface.reverse_path", "Reverse-path verification is missing",
                    f"Low-trust interface '{name}' does not have uRPF reverse-path verification enabled.",
                    "Spoofed source addresses may cross the firewall boundary without an interface-level routing check.",
                    "Configure 'ip verify reverse-path interface <nameif>' after validating asymmetric routing requirements.",
                    Severity.MEDIUM, (f"interface {name}",),
                ))

    def check_vpn_crypto(self, parser: BaseDeviceParser) -> None:
        native = parser.get_native_config()
        blocks = native.find_objects(r"^crypto (?:ikev1|isakmp) policy\s+")
        blocks += native.find_objects(r"^crypto ikev2 policy\s+")
        for block in blocks:
            children = [child.text.strip().lower() for child in block.children]
            weak = [
                line for line in children
                if any(token in line.split() for token in ("des", "3des", "md5"))
                or re.fullmatch(r"group (?:1|2|5|14)", line)
                or line == "integrity sha"
            ]
            if weak:
                self.add_issue(self._finding(
                    parser, "cisco.asa.crypto.legacy_vpn", "VPN policy uses legacy cryptography",
                    f"{block.text.strip()} contains legacy encryption, integrity, or Diffie-Hellman selections.",
                    "Weak VPN algorithms reduce confidentiality, integrity, or key-exchange strength.",
                    "Use AES-GCM/AES-256, SHA-256 or stronger, and approved modern DH groups.",
                    Severity.HIGH, (block.text.strip(), *weak),
                ))

        approved_groups = parser.assessment_context.approved_asa_ike_dh_groups
        if approved_groups:
            for alternative in self._asa(parser).get_active_ike_dh_groups():
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
                ))
        for binding in self._asa(parser).get_active_ipsec_transform_bindings():
            if binding.declaration is None:
                self.add_issue(self._finding(
                    parser, "cisco.asa.crypto.unresolved_transform", "Attached IPsec transform-set is unresolved",
                    f"Crypto map on interface '{binding.interface}' references transform-set '{binding.transform_name}', but its definition is not present in this input.",
                    "The effective IPsec algorithms cannot be assessed from this configuration export.",
                    "Include the referenced transform-set definition in the export and validate the active crypto-map chain.",
                    Severity.MEDIUM, (binding.map_binding, binding.map_attachment),
                ))
                continue
            if any(token in binding.declaration.lower().split() for token in ("esp-des", "esp-3des", "esp-md5-hmac", "esp-sha-hmac")):
                self.add_issue(self._finding(
                    parser, "cisco.asa.crypto.legacy_transform", "IPsec transform-set uses legacy cryptography",
                    f"An IPsec transform-set attached to interface '{binding.interface}' includes a legacy encryption or integrity algorithm.",
                    "Legacy transforms weaken protected VPN traffic.",
                    "Replace legacy transforms with AES and SHA-256 or authenticated encryption.",
                    Severity.HIGH, (binding.declaration, binding.map_binding, binding.map_attachment),
                ))

        for pfs in self._asa(parser).get_active_pfs_bindings():
            if pfs.group not in {"1", "2", "5", "14"}:
                continue
            self.add_issue(self._finding(
                parser, "cisco.asa.crypto.legacy_pfs", "IPsec PFS uses a legacy Diffie-Hellman group",
                f"A crypto map attached to interface '{pfs.interface}' sets PFS to DH group {pfs.group}, which is in this project's legacy set (groups 1, 2, 5 and 14; groups 1, 2 and 5 were removed from ASA IKE in 9.15).",
                "New IPsec keys are derived with a weak key exchange, reducing forward secrecy for protected traffic.",
                "Set PFS to an approved modern group such as 19, 20 or 21, supported by the peer.",
                Severity.HIGH, tuple(pfs.evidence), (CISCO_ASA_CRYPTO_MAP_REFERENCE,),
            ))

    def check_remote_access_authentication(self, parser: BaseDeviceParser) -> None:
        if not parser.assessment_context.asa_ra_require_client_certificate:
            return
        for profile in self._asa(parser).get_selectable_webvpn_profiles():
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
            ))

    def check_failover(self, parser: BaseDeviceParser) -> None:
        lines = self._lines(parser)
        failover = "failover" in lines and "no failover" not in lines
        if not failover:
            return
        if not any(re.fullmatch(r"failover key\s+.+", line) for line in lines):
            self.add_issue(self._finding(
                parser, "cisco.asa.failover.authentication", "Failover link authentication is missing",
                "ASA failover is enabled without an explicit failover key.",
                "Unauthenticated failover communication can weaken the integrity of high-availability state exchange.",
                "Configure a strong failover key and protect the failover network.",
                Severity.HIGH, ("failover",),
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
            ))

    def analyze(self, parser: BaseDeviceParser) -> None:
        if parser.device_type != "ASA" or self._asa(parser).get_version() == "?":
            return
        self.check_aaa(parser)
        self.check_management_sessions_and_ssh(parser)
        self.check_local_administrator_policy(parser)
        self.check_local_users(parser)
        self.check_http_management(parser)
        self.check_ntp(parser)
        self.check_threat_detection(parser)
        self.check_connection_limits(parser)
        self.check_reverse_path(parser)
        self.check_vpn_crypto(parser)
        self.check_remote_access_authentication(parser)
        self.check_failover(parser)
