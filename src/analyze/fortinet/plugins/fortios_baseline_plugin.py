"""VDOM-aware FortiOS management, monitoring, and policy hardening checks."""

from collections import defaultdict
from dataclasses import replace
import re

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.issue import Finding, FindingBasis, Severity
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.common.policy_semantics import (
    ProofState,
    network_covers,
    service_covers,
    static_values_cover,
)
from src.devices.fortinet.fortios import FortiDict, FortiOSParser


FORTINET_HARDENING = (
    "https://docs.fortinet.com/document/fortigate/7.2.0/best-practices/"
    "555436/hardening"
)
FORTINET_ADMIN_GUIDE = (
    "https://docs.fortinet.com/document/fortigate/7.2.11/administration-guide/14906/"
    "administrator-account-options"
)
FORTINET_ADMIN_REFERENCE = (
    "https://docs.fortinet.com/document/fortigate/7.2.0/cli-reference/16620/"
    "config-system-admin"
)
FORTINET_GLOBAL_REFERENCE = (
    "https://docs.fortinet.com/document/fortigate/7.2.2/cli-reference/1620/"
    "config-system-global"
)
FORTINET_PASSWORD_REFERENCE = (
    "https://docs.fortinet.com/document/fortigate/7.2.11/cli-reference/127236326/"
    "config-system-password-policy"
)
FORTINET_CRYPTO_GUIDE = (
    "https://docs.fortinet.com/document/fortigate/7.2.2/administration-guide/484445/"
    "system-administrator-best-practices"
)
FORTINET_SNMP_REFERENCE = (
    "https://docs.fortinet.com/document/fortigate/7.2.13/cli-reference/292257317/"
    "config-system-snmp-user"
)
FORTINET_NTP_GUIDE = (
    "https://docs.fortinet.com/document/fortigate/7.2.11/administration-guide/512210/"
    "setting-the-system-time"
)
FORTINET_NTP_AUTH_GUIDE = (
    "https://docs.fortinet.com/document/fortigate/7.2.11/administration-guide/336196/"
    "cryptographic-hash-function-authentication-support"
)
FORTINET_AUTOUPDATE_GUIDE = (
    "https://docs.fortinet.com/document/fortigate/7.2.0/administration-guide/547335/"
    "automatic-updates"
)
FORTINET_FIRMWARE_GUIDE = (
    "https://docs.fortinet.com/document/fortigate/7.2.10/administration-guide/369092/"
    "enabling-automatic-firmware-updates"
)
FORTINET_DOS_GUIDE = (
    "https://docs.fortinet.com/document/fortigate/7.2.11/administration-guide/771644/"
    "configuring-a-dos-policy"
)
FORTINET_CONFIGURATION_BACKUP_GUIDE = (
    "https://docs.fortinet.com/document/fortigate/7.6.5/administration-guide/"
    "702257/configuration-backups-and-reset"
)
FORTINET_LOCAL_CERTIFICATE_REFERENCE = (
    "https://docs.fortinet.com/document/fortigate/7.0.19/cli-reference/"
    "556354036/config-vpn-certificate-local"
)
FORTINET_CA_CERTIFICATE_REFERENCE = (
    "https://docs.fortinet.com/document/fortigate/7.6.6/cli-reference/"
    "144962638/config-vpn-certificate-ca"
)
NIST_CRYPTO_TRANSITIONS = "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final"
FORTINET_AUTO_SCRIPT_REFERENCE = (
    "https://docs.fortinet.com/document/fortigate/7.4.1/cli-reference/64620/"
    "config-system-auto-script"
)
FORTINET_INSPECTION_GUIDE = (
    "https://docs.fortinet.com/document/fortigate/7.2.0/administration-guide/721410/"
    "inspection-modes"
)
FORTINET_PROFILE_GROUP_REFERENCE = (
    "https://docs.fortinet.com/document/fortigate/7.2.6/cli-reference/283620/"
    "config-firewall-profile-group"
)
FORTINET_SYSLOG_TRANSPORT_REFERENCE = (
    "https://docs.fortinet.com/document/fortigate/7.4.5/cli-reference/141516630/"
    "config-log-syslogd-setting"
)
FORTINET_ADDRESS_REFERENCE = (
    "https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/306021697/"
    "config-firewall-address"
)
FORTINET_ADDRESS_GROUP_REFERENCE = (
    "https://docs.fortinet.com/document/fortigate/7.6.0/cli-reference/301511994/"
    "config-firewall-addrgrp"
)
FORTINET_SERVICE_REFERENCE = (
    "https://docs.fortinet.com/document/fortigate/7.6.6/cli-reference/198499981/"
    "config-firewall-service-custom"
)
FORTINET_SERVICE_GROUP_REFERENCE = (
    "https://docs.fortinet.com/document/fortigate/7.6.3/cli-reference/242456538/"
    "config-firewall-service-group"
)
FORTINET_IPS_REFERENCE = (
    "https://docs.fortinet.com/document/fortigate/7.2.0/cli-reference/407620/"
    "config-ips-sensor"
)
FORTINET_IPS_ORDER_REFERENCE = (
    "https://docs.fortinet.com/document/fortigate/6.4.10/administration-guide/"
    "213498/signature-based-defense"
)
FORTINET_RADSEC_GUIDE = (
    "https://docs.fortinet.com/document/fortigate/7.6.5/administration-guide/"
    "729374/configuring-a-radsec-client"
)
FORTINET_RADIUS_GUIDE = (
    "https://docs.fortinet.com/document/fortigate/7.6.5/administration-guide/"
    "759080/configuring-a-radius-server"
)
FORTINET_LOCAL_IN_REFERENCE = (
    "https://docs.fortinet.com/document/fortigate/7.2.1/cli-reference/328620/"
    "config-firewall-local-in-policy"
)
FORTINET_PHASE1_REFERENCE = (
    "https://docs.fortinet.com/document/fortigate/7.2.0/cli-reference/365620/"
    "config-vpn-ipsec-phase1"
)
FORTINET_PHASE2_REFERENCE = (
    "https://docs.fortinet.com/document/fortigate/7.2.2/cli-reference/372620/"
    "config-vpn-ipsec-phase2-interface"
)
IETF_IKEV2_ALGORITHM_GUIDANCE = "https://www.rfc-editor.org/rfc/rfc8247.html"


class PluginFortiOSBaseline(BasePlugin):
    """Evaluate explicit FortiOS state and infer defaults only for known releases."""

    _UNRESTRICTED_TRUST = {
        "0.0.0.0 0.0.0.0",
        "0.0.0.0/0",
        "::/0",
        "0:0:0:0:0:0:0:0/0",
    }
    _MFA_METHODS = {"email", "fortitoken", "fortitoken-cloud", "sms"}
    _WEAK_SSH = {
        "ssh-enc-algo": {
            "3des-cbc",
            "aes128-cbc",
            "aes192-cbc",
            "aes256-cbc",
            "blowfish-cbc",
            "arcfour",
        },
        "ssh-kex-algo": {
            "diffie-hellman-group1-sha1",
            "diffie-hellman-group14-sha1",
            "diffie-hellman-group-exchange-sha1",
        },
        "ssh-mac-algo": {
            "hmac-md5",
            "hmac-md5-96",
            "hmac-sha1",
            "hmac-sha1-96",
        },
    }

    @staticmethod
    def _fortios(parser: BaseDeviceParser) -> FortiOSParser:
        if not isinstance(parser, FortiOSParser):
            raise TypeError("PluginFortiOSBaseline requires a FortiOS parser")
        return parser

    @staticmethod
    def _values(settings: FortiDict, key: str) -> list[str]:
        value = settings.get(key)
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item) for item in value]
        return [str(value)]

    @staticmethod
    def _text(value: object, default: str = "") -> str:
        if isinstance(value, list):
            return " ".join(str(item) for item in value)
        return str(value) if value is not None else default

    @staticmethod
    def _enabled(settings: FortiDict) -> bool:
        return PluginFortiOSBaseline._text(settings.get("status"), "enable").lower() != "disable"

    @staticmethod
    def _supports_default_inference(parser: FortiOSParser) -> bool:
        """Limit absence/default findings to the documented FortiOS 7.x model."""

        numbers = re.findall(r"\d+", parser.get_version())
        if len(numbers) < 2:
            return False
        return (int(numbers[0]), int(numbers[1])) >= (7, 0)

    @staticmethod
    def _finding(
        parser: BaseDeviceParser,
        rule_id: str,
        title: str,
        observation: str,
        impact: str,
        recommendation: str,
        severity: Severity,
        evidence: tuple[str, ...],
        references: tuple[str, ...],
        basis=None,
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            device=parser.device_type,
            title=title,
            observation=observation,
            impact=impact,
            exploitability=(
                "An attacker with reachability or administrative access may exploit "
                "the effective weakness."
            ),
            recommendation=recommendation,
            severity=severity,
            evidence=evidence,
            references=references,
            basis=basis,
        )

    @staticmethod
    def _evidence(fortios: FortiOSParser, path: tuple[str, ...], fallback: str) -> tuple[str, ...]:
        return tuple(item for item in fortios.field_evidence(path)) or (fallback,)

    def check_administrators(self, parser: BaseDeviceParser) -> None:
        fortios = self._fortios(parser)
        privileged_local = []
        roles = {
            (role.scope, role.administrator): role
            for role in fortios.get_administrator_roles()
        }
        for scope, username, settings, path in fortios.iter_administrators():
            if not self._enabled(settings):
                continue
            profile = self._text(settings.get("accprofile"), "super_admin").lower()
            role = roles.get((scope, username))
            privileged = role is not None and role.privileged_state == "privileged"
            role_description = (
                "super_admin account" if profile == "super_admin"
                else f"privileged account using profile '{profile}'"
            )
            trusts = [
                " ".join(self._values(settings, key)).lower()
                for key in settings
                if str(key).lower().startswith(("trusthost", "ip6-trusthost"))
            ]
            restricted = bool(trusts) and all(
                trust not in self._UNRESTRICTED_TRUST for trust in trusts
            )
            if privileged and not restricted:
                self.add_issue(
                    self._finding(
                        parser,
                        "fortinet.fortios.admin.trusted_hosts",
                        "Privileged administrator is not source restricted",
                        f"Enabled {role_description} '{username}' in scope '{scope}' has no effective trusted-host restriction.",
                        "Unrestricted administrator source addresses broaden the management-plane attack surface.",
                        "Configure restrictive trusthost and ip6-trusthost entries for the administrator.",
                        Severity.HIGH,
                        self._evidence(fortios, path, f"system admin {username}"),
                        (FORTINET_ADMIN_GUIDE, FORTINET_ADMIN_REFERENCE),
                    )
                )

            remote = self._text(settings.get("remote-auth"), "disable").lower() == "enable"
            peer = self._text(settings.get("peer-auth"), "disable").lower() == "enable"
            if privileged and remote and not self._text(settings.get("remote-group")):
                self.add_issue(
                    self._finding(
                        parser,
                        "fortinet.fortios.admin.remote_group",
                        "Remote administrator lacks a group binding",
                        f"Remote-authenticated administrator '{username}' in scope '{scope}' has no remote-group.",
                        "An incomplete remote authorization binding can produce unintended or unusable administrative access.",
                        "Bind the account to a narrowly authorized remote group and test fallback access.",
                        Severity.HIGH,
                        self._evidence(fortios, path, f"system admin {username}"),
                        (FORTINET_ADMIN_REFERENCE,),
                    )
                )
            if privileged and not remote and not peer:
                privileged_local.append((scope, username, path))
                mfa = self._text(settings.get("two-factor"), "disable").lower()
                if mfa not in self._MFA_METHODS:
                    self.add_issue(
                        self._finding(
                            parser,
                            "fortinet.fortios.admin.mfa",
                            "Privileged local administrator lacks MFA",
                            f"Local {role_description} '{username}' in scope '{scope}' has no enabled two-factor method.",
                            "A stolen password alone may be sufficient for privileged access.",
                            "Enable an approved FortiToken, email, SMS, or organization-approved federated MFA method.",
                            Severity.HIGH,
                            self._evidence(fortios, path, f"system admin {username}"),
                            (FORTINET_ADMIN_GUIDE, FORTINET_ADMIN_REFERENCE),
                        )
                    )

        if self._supports_default_inference(fortios) and privileged_local:
            remote_privileged = any(
                self._enabled(settings)
                and (roles.get((scope, username)) is not None
                     and roles[(scope, username)].privileged_state == "privileged")
                and self._text(settings.get("remote-auth"), "disable").lower() == "enable"
                and bool(self._text(settings.get("remote-group")))
                for scope, username, settings, _ in fortios.iter_administrators()
            )
            if not remote_privileged:
                self.add_issue(
                    self._finding(
                        parser,
                        "fortinet.fortios.admin.centralized_authentication",
                        "Privileged authentication is local only",
                        (
                            "No enabled super_admin account is bound to remote authentication."
                            if all(
                                roles.get((scope, username)) is not None
                                and roles[(scope, username)].profile.casefold() == "super_admin"
                                for scope, username, _ in privileged_local
                            ) else "No enabled privileged account is bound to remote authentication."
                        ),
                        "Local-only privileged authentication reduces centralized control and accountability.",
                        "Configure a tested remote administrator group and retain only a protected emergency local account.",
                        Severity.MEDIUM,
                        tuple(
                            text
                            for _, username, path in privileged_local
                            for text in self._evidence(fortios, path, f"system admin {username}")
                        ),
                        (FORTINET_HARDENING, FORTINET_ADMIN_REFERENCE),
                    )
                )

    def check_password_and_session_policy(self, parser: BaseDeviceParser) -> None:
        fortios = self._fortios(parser)
        policies = list(fortios.iter_scoped_sections("system password-policy"))
        if self._supports_default_inference(fortios) and not policies:
            self.add_issue(
                self._finding(
                    parser,
                    "fortinet.fortios.password_policy.disabled",
                    "Administrator password policy is not enabled",
                    "No system password-policy section is present; on the identified FortiOS release its status defaults to disabled.",
                    "Locally managed credentials may accept weak or repeatedly reused passwords.",
                    "Enable the password policy for admin-password with organization-approved complexity and reuse controls.",
                    Severity.HIGH,
                    ("system password-policy absent",),
                    (FORTINET_PASSWORD_REFERENCE,),
                    basis=FindingBasis.DOCUMENTED_DEFAULT,
                )
            )
        for scope, settings, path in policies:
            if not self._enabled(settings):
                self.add_issue(
                    self._finding(
                        parser,
                        "fortinet.fortios.password_policy.disabled",
                        "Administrator password policy is not enabled",
                        f"The password policy in scope '{scope}' is explicitly disabled.",
                        "Locally managed credentials may accept weak or repeatedly reused passwords.",
                        "Enable the password policy for admin-password with organization-approved complexity and reuse controls.",
                        Severity.HIGH,
                        self._evidence(fortios, path + ("status",), "set status disable"),
                        (FORTINET_PASSWORD_REFERENCE,),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )
                continue
            weak = []
            numeric_targets = {
                # NEEDS_HUMAN_REVIEW: 12 is the project baseline; the Fortinet
                # reference documents the field/range but does not prescribe 12.
                "minimum-length": 12,
                "min-lower-case-letter": 1,
                "min-upper-case-letter": 1,
                "min-non-alphanumeric": 1,
                "min-number": 1,
            }
            for field, target in numeric_targets.items():
                value = self._text(settings.get(field))
                if value.isdigit() and int(value) < target:
                    weak.append(f"{field} is {value or 'not configured'} (target {target}+)" )
                elif not value and self._supports_default_inference(fortios):
                    weak.append(f"{field} is not configured (target {target}+)" )
            apply_to = {value.lower() for value in self._values(settings, "apply-to")}
            if apply_to and "admin-password" not in apply_to:
                weak.append("apply-to omits admin-password")
            reuse = self._text(settings.get("reuse-password")).lower()
            if reuse == "enable" or (not reuse and self._supports_default_inference(fortios)):
                weak.append("password reuse is permitted")
            if weak:
                self.add_issue(
                    self._finding(
                        parser,
                        "fortinet.fortios.password_policy.weak",
                        "Administrator password policy is weak",
                        f"Scope '{scope}' has: {'; '.join(weak)}.",
                        "Insufficient complexity or reuse protection makes password compromise more likely.",
                        "Require at least 12 characters, each character class, admin-password scope, and disable password reuse.",
                        Severity.MEDIUM,
                        self._evidence(fortios, path, "system password-policy"),
                        (FORTINET_PASSWORD_REFERENCE,),
                    )
                )

        for scope, settings, path in fortios.iter_scoped_sections("system global"):
            threshold = self._text(settings.get("admin-lockout-threshold"))
            duration = self._text(settings.get("admin-lockout-duration"))
            weak = []
            if threshold.isdigit() and (int(threshold) == 0 or int(threshold) > 3):
                weak.append(f"threshold {threshold}")
            if duration.isdigit() and int(duration) < 60:
                weak.append(f"duration {duration} seconds")
            if weak:
                self.add_issue(
                    self._finding(
                        parser,
                        "fortinet.fortios.admin.lockout",
                        "Administrative lockout settings are weak",
                        f"Scope '{scope}' explicitly configures {', '.join(weak)}; the documented FortiOS defaults are three attempts and 60 seconds.",
                        "Additional or uninterrupted password guesses increase exposure to online attacks.",
                        "Use no more than three failed attempts and a lockout duration of at least 60 seconds.",
                        Severity.MEDIUM,
                        self._evidence(fortios, path, "system global lockout settings"),
                        (FORTINET_GLOBAL_REFERENCE,),
                    )
                )
            timeout = self._text(settings.get("admintimeout"))
            if timeout.isdigit() and (int(timeout) == 0 or int(timeout) > 10):
                self.add_issue(
                    self._finding(
                        parser,
                        "fortinet.fortios.admin.session_timeout",
                        "Administrative session timeout is excessive",
                        f"Scope '{scope}' sets admintimeout to {timeout} minutes; this rule permits at most 10 minutes.",
                        "An unattended authenticated session remains usable for longer than necessary.",
                        "Set admintimeout to 10 minutes or less, subject to operational policy.",
                        Severity.MEDIUM,
                        self._evidence(fortios, path + ("admintimeout",), f"set admintimeout {timeout}"),
                        (FORTINET_GLOBAL_REFERENCE,),
                    )
                )

    def check_management_crypto(self, parser: BaseDeviceParser) -> None:
        fortios = self._fortios(parser)
        https_enabled = any(
            "https" in {value.lower() for value in self._values(settings, "allowaccess")}
            and self._enabled(settings)
            for _, _, settings, _ in fortios.iter_interfaces()
        )
        globals_ = list(fortios.iter_scoped_sections("system global"))
        for scope, settings, path in globals_:
            explicit_weak = {
                "strong-crypto": "disable",
                "ssl-static-key-ciphers": "enable",
                "admin-ssh-v1": "enable",
                "ssh-cbc-cipher": "enable",
            }
            for field, weak_value in explicit_weak.items():
                if self._text(settings.get(field)).lower() != weak_value:
                    continue
                self.add_issue(
                    self._finding(
                        parser,
                        f"fortinet.fortios.crypto.{field.replace('-', '_')}",
                        "Weak management-plane cryptography is enabled",
                        f"Scope '{scope}' explicitly sets {field} to {weak_value}.",
                        "Legacy protocol or cipher support weakens administrative channel protection.",
                        f"Set {field} to {'enable' if weak_value == 'disable' else 'disable'} and test administrative clients.",
                        Severity.HIGH,
                        self._evidence(fortios, path + (field,), f"set {field} {weak_value}"),
                        (FORTINET_HARDENING, FORTINET_CRYPTO_GUIDE),
                    )
                )
            dh_params = self._text(settings.get("dh-params"))
            if dh_params.isdigit() and int(dh_params) < 2048:
                self.add_issue(
                    self._finding(
                        parser,
                        "fortinet.fortios.crypto.dh_parameters",
                        "Weak Diffie-Hellman parameters are configured",
                        f"Scope '{scope}' sets dh-params to {dh_params} bits; this rule requires at least 2048 bits.",
                        "Small finite-field groups reduce the strength of negotiated TLS key exchange.",
                        "Configure dh-params of at least 2048 bits; Fortinet's hardening example uses 8192.",
                        Severity.HIGH,
                        self._evidence(fortios, path + ("dh-params",), f"set dh-params {dh_params}"),
                        (FORTINET_HARDENING,),
                    )
                )
            for field, weak_values in self._WEAK_SSH.items():
                configured = {value.lower() for value in self._values(settings, field)}
                weak = sorted(configured.intersection(weak_values))
                if weak:
                    self.add_issue(
                        self._finding(
                            parser,
                            f"fortinet.fortios.ssh.weak_{field[4:].replace('-', '_')}",
                            "Weak SSH algorithms are explicitly enabled",
                            f"Scope '{scope}' includes weak {field} values: {', '.join(weak)}.",
                            "Legacy SSH algorithms weaken confidentiality, integrity, or key exchange.",
                            "Remove the listed algorithms and retain only organization-approved modern values.",
                            Severity.HIGH,
                            self._evidence(fortios, path + (field,), f"set {field} {' '.join(weak)}"),
                            (FORTINET_CRYPTO_GUIDE,),
                        )
                    )

        if https_enabled and self._supports_default_inference(fortios):
            certificates = [
                self._text(settings.get("admin-server-cert"))
                for _, settings, _ in globals_
                if self._text(settings.get("admin-server-cert"))
            ]
            if not certificates or any(value == "Fortinet_GUI_Server" for value in certificates):
                self.add_issue(
                    self._finding(
                        parser,
                        "fortinet.fortios.https.management_certificate",
                        "Administrative HTTPS uses the factory certificate",
                        "HTTPS management is enabled but no non-default admin-server-cert is configured.",
                        "Clients cannot reliably authenticate the appliance when a generic factory certificate is used.",
                        "Install and select a trusted, device-specific administrative server certificate.",
                        Severity.MEDIUM,
                        tuple(certificates) or ("admin-server-cert absent",),
                        (FORTINET_GLOBAL_REFERENCE, FORTINET_HARDENING),
                    )
                )

    def check_management_certificates(self, parser: BaseDeviceParser) -> None:
        fortios = self._fortios(parser)
        if not any(
            self._enabled(settings)
            and "https" in {value.casefold() for value in self._values(settings, "allowaccess")}
            for _, _, settings, _ in fortios.iter_interfaces()
        ):
            return
        references = (
            FORTINET_GLOBAL_REFERENCE,
            FORTINET_LOCAL_CERTIFICATE_REFERENCE,
            FORTINET_CA_CERTIFICATE_REFERENCE,
        )
        for binding in fortios.get_management_certificate_bindings():
            evidence = tuple(item for item in binding.evidence) or (
                f"admin-server-cert {binding.certificate}",
            )
            if binding.reference_state == "unavailable":
                continue
            if binding.reference_state != "resolved":
                self.add_issue(self._finding(
                    parser,
                    "fortinet.fortios.https.certificate_unresolved",
                    "Administrative HTTPS certificate reference is unresolved",
                    f"Scope '{binding.scope}' selects admin-server-cert '{binding.certificate}', but no matching supplied local-certificate object is resolved.",
                    "The configuration export does not establish the certificate identity selected for administrative HTTPS.",
                    "Include the referenced local-certificate object in the export or correct admin-server-cert to select the intended installed certificate.",
                    Severity.MEDIUM,
                    evidence,
                    references,
                ))
                continue
            if binding.public_material_state == "malformed":
                self.add_issue(self._finding(
                    parser,
                    "fortinet.fortios.https.certificate_material_malformed",
                    "Administrative HTTPS certificate material is malformed",
                    f"The exported public material for admin-server-cert '{binding.certificate}' in scope '{binding.scope}' cannot be parsed as X.509.",
                    "The supplied export cannot establish the selected certificate's identity, validity, or cryptographic strength.",
                    "Re-import or renew the intended certificate and verify that a complete public certificate is present in the audit export.",
                    Severity.HIGH,
                    evidence,
                    references,
                ))
                continue
            if binding.assessment is None or binding.metadata is None:
                continue

            assessment = binding.assessment
            metadata = binding.metadata
            if assessment.validity_state in {"expired", "not-yet-valid"}:
                self.add_issue(self._finding(
                    parser,
                    "fortinet.fortios.https.certificate_validity",
                    "Administrative HTTPS certificate is outside its validity period",
                    f"Certificate '{binding.certificate}' is {assessment.validity_state} at the explicit assessment time; its interval is {metadata.not_before} through {metadata.not_after}.",
                    "Administrators cannot validate an endpoint certificate outside its declared validity interval.",
                    "Renew or replace the selected certificate before its activation or expiration boundary.",
                    Severity.HIGH,
                    evidence,
                    references,
                ))
            if assessment.identity_state == "mismatch":
                self.add_issue(self._finding(
                    parser,
                    "fortinet.fortios.https.certificate_identity",
                    "Administrative HTTPS certificate does not match the intended identity",
                    f"Certificate '{binding.certificate}' does not contain the explicitly declared management identity for scope '{binding.scope}' in subjectAltName.",
                    "Administrators can receive hostname or IP identity errors and may learn to bypass certificate warnings.",
                    "Enroll and select a certificate whose subjectAltName contains the declared management DNS name or IP address.",
                    Severity.HIGH,
                    evidence,
                    references,
                ))
            if assessment.algorithm_state == "weak":
                self.add_issue(self._finding(
                    parser,
                    "fortinet.fortios.https.certificate_algorithm",
                    "Administrative HTTPS certificate uses a legacy key or signature",
                    f"Certificate '{binding.certificate}' uses {metadata.public_key_algorithm} {metadata.public_key_size or 'intrinsic'} and signature hash {metadata.signature_hash_algorithm}.",
                    "Legacy public-key sizes or certificate signatures provide inadequate cryptographic assurance.",
                    "Replace the certificate with an organization-approved key and SHA-2-or-stronger signature supported by the FortiOS release.",
                    Severity.HIGH,
                    evidence,
                    references + (NIST_CRYPTO_TRANSITIONS,),
                ))
            if assessment.trust_state == "verification-failed":
                self.add_issue(self._finding(
                    parser,
                    "fortinet.fortios.https.certificate_trust",
                    "Administrative HTTPS certificate chain does not validate to an approved anchor",
                    f"Certificate '{binding.certificate}' matches the declared identity and time boundary but cannot be validated to the explicitly approved exported trust-anchor fingerprint(s).",
                    "The supplied public certificate set does not establish trust under the selected assessment policy.",
                    "Supply the complete issuing chain and approved anchor, or replace the certificate with one chaining to the approved PKI.",
                    Severity.HIGH,
                    evidence,
                    references,
                ))

    def check_snmp(self, parser: BaseDeviceParser) -> None:
        fortios = self._fortios(parser)
        snmp_interfaces = [
            (scope, name, path)
            for scope, name, settings, path in fortios.iter_interfaces()
            if self._enabled(settings)
            and "snmp" in {value.lower() for value in self._values(settings, "allowaccess")}
        ]
        agent_disabled_scopes = {
            scope
            for scope, settings, _ in fortios.iter_scoped_sections("system snmp sysinfo")
            if self._text(settings.get("status"), "disable").lower() == "disable"
        }
        if "global" in agent_disabled_scopes:
            return
        snmp_interfaces = [
            item for item in snmp_interfaces if item[0] not in agent_disabled_scopes
        ]
        if not snmp_interfaces:
            return
        for scope, section, path in fortios.iter_scoped_sections("system snmp community"):
            if scope in agent_disabled_scopes:
                continue
            for name, settings in section.items():
                if isinstance(settings, dict) and self._enabled(settings):
                    community_evidence = tuple(
                        replace(item, text=item.text.replace(str(name), "<redacted>"))
                        for item in fortios.field_evidence(path + (str(name),))
                    ) or ("system snmp community <redacted>",)
                    self.add_issue(
                        self._finding(
                            parser,
                            "fortinet.fortios.snmp.legacy_community",
                            "Legacy SNMP community is enabled",
                            f"An enabled SNMPv1/v2c community is configured in scope '{scope}'; its name is redacted.",
                            "Community-based SNMP lacks modern per-user authentication and privacy.",
                            "Migrate managers to SNMPv3 authPriv and remove the community configuration.",
                            Severity.HIGH,
                            community_evidence,
                            (FORTINET_SNMP_REFERENCE, FORTINET_HARDENING),
                        )
                    )

        secure_users: set[str] = set()
        for scope, section, path in fortios.iter_scoped_sections("system snmp user"):
            if scope in agent_disabled_scopes:
                continue
            for username, settings in section.items():
                if not isinstance(settings, dict) or not self._enabled(settings):
                    continue
                security = self._text(settings.get("security-level"), "no-auth-no-priv").lower()
                auth = self._text(settings.get("auth-proto"), "sha").lower()
                privacy = self._text(settings.get("priv-proto"), "aes").lower()
                has_credentials = bool(self._text(settings.get("auth-pwd"))) and bool(
                    self._text(settings.get("priv-pwd"))
                )
                secure = (
                    security == "auth-priv"
                    and auth not in {"md5"}
                    and privacy not in {"des"}
                    and has_credentials
                )
                if secure:
                    secure_users.add(scope)
                    continue
                self.add_issue(
                    self._finding(
                        parser,
                        "fortinet.fortios.snmp.v3_security",
                        "SNMPv3 user protection is incomplete",
                        f"SNMP user '{username}' in scope '{scope}' uses security-level {security}, auth-proto {auth}, priv-proto {privacy}, and {'complete' if has_credentials else 'incomplete'} credential fields.",
                        "Weak or absent authentication and privacy can expose management data and operations.",
                        "Require auth-priv with supported SHA authentication and AES privacy.",
                        Severity.HIGH,
                        self._evidence(fortios, path + (str(username),), f"system snmp user {username}"),
                        (FORTINET_SNMP_REFERENCE,),
                    )
                )

        for scope, interface, path in snmp_interfaces:
            applicable_scopes = {scope, "global"}
            if scope == "root":
                applicable_scopes.add("root")
            if not secure_users.intersection(applicable_scopes):
                self.add_issue(
                    self._finding(
                        parser,
                        "fortinet.fortios.snmp.secure_user_missing",
                        "SNMP service lacks a secure SNMPv3 user",
                        f"Interface '{interface}' in scope '{scope}' permits SNMP, but no applicable authPriv user was found.",
                        "The exposed SNMP service may rely only on weak communities or incomplete user protection.",
                        "Configure a source-restricted SNMPv3 authPriv user before permitting SNMP on the interface.",
                        Severity.HIGH,
                        self._evidence(fortios, path + ("allowaccess",), f"{interface}: allowaccess snmp"),
                        (FORTINET_SNMP_REFERENCE, FORTINET_HARDENING),
                    )
                )

    def check_ntp(self, parser: BaseDeviceParser) -> None:
        fortios = self._fortios(parser)
        sections = list(fortios.iter_scoped_sections("system ntp"))
        if self._supports_default_inference(fortios) and not sections:
            self.add_issue(
                self._finding(
                    parser,
                    "fortinet.fortios.ntp.synchronization",
                    "NTP synchronization is not configured",
                    "No system ntp section is present in the identified FortiOS configuration.",
                    "Incorrect time undermines event correlation and time-dependent controls.",
                    "Enable NTP synchronization with multiple trusted FortiGuard or custom servers.",
                    Severity.MEDIUM,
                    ("system ntp absent",),
                    (FORTINET_NTP_GUIDE,),
                )
            )
        for scope, settings, path in sections:
            if self._text(settings.get("ntpsync"), "disable").lower() != "enable":
                self.add_issue(
                    self._finding(
                        parser,
                        "fortinet.fortios.ntp.synchronization",
                        "NTP synchronization is not configured",
                        f"NTP synchronization is disabled in scope '{scope}'.",
                        "Incorrect time undermines event correlation and time-dependent controls.",
                        "Set ntpsync enable and configure trusted time sources.",
                        Severity.MEDIUM,
                        self._evidence(fortios, path + ("ntpsync",), "set ntpsync disable"),
                        (FORTINET_NTP_GUIDE,),
                    )
                )
                continue
            if self._text(settings.get("type"), "fortiguard").lower() != "custom":
                continue
            servers = settings.get("ntpserver")
            enabled_servers = []
            if isinstance(servers, dict):
                enabled_servers = [
                    (str(name), server)
                    for name, server in servers.items()
                    if isinstance(server, dict) and self._enabled(server)
                ]
            if not enabled_servers:
                self.add_issue(
                    self._finding(
                        parser,
                        "fortinet.fortios.ntp.custom_server_missing",
                        "Custom NTP mode has no enabled server",
                        f"Scope '{scope}' selects custom NTP but contains no enabled ntpserver object.",
                        "The appliance may not obtain a trustworthy time source.",
                        "Configure multiple enabled custom NTP servers or use FortiGuard NTP.",
                        Severity.MEDIUM,
                        self._evidence(fortios, path, "system ntp"),
                        (FORTINET_NTP_GUIDE,),
                    )
                )
            for name, server in enabled_servers:
                authentication = self._text(server.get("authentication"), "disable").lower()
                key_type = self._text(
                    server.get("key-type"),
                    self._text(
                        settings.get("key-type"),
                        "md5" if self._supports_default_inference(fortios) else "",
                    ),
                ).lower()
                has_key = bool(self._text(server.get("key"))) and bool(self._text(server.get("key-id")))
                if authentication != "enable" or not has_key:
                    detail = "authentication disabled" if authentication != "enable" else "key binding incomplete"
                    self.add_issue(
                        self._finding(
                            parser,
                            "fortinet.fortios.ntp.authentication",
                            "Custom NTP server authentication is weak",
                            f"NTP server '{name}' in scope '{scope}' has {detail}; key material is redacted.",
                            "An unauthenticated or weakly authenticated time source can spoof device time.",
                            "Enable NTPv4 authentication with a complete SHA-256 key binding where supported.",
                            Severity.MEDIUM,
                            self._evidence(fortios, path + ("ntpserver", name), f"ntpserver {name}"),
                            (FORTINET_NTP_GUIDE, FORTINET_NTP_AUTH_GUIDE),
                        )
                    )
                if authentication == "enable" and has_key and key_type in {"md5", "sha1"}:
                    self.add_issue(
                        self._finding(
                            parser,
                            "fortinet.fortios.ntp.weak_algorithm",
                            "Custom NTP server uses a legacy algorithm",
                            f"NTP server '{name}' in scope '{scope}' uses legacy {key_type} authentication; key material is redacted.",
                            "A legacy digest provides weaker protection against forged time updates.",
                            "Use SHA-256 NTPv4 authentication where supported by the exact FortiOS release.",
                            Severity.MEDIUM,
                            self._evidence(fortios, path + ("ntpserver", name), f"ntpserver {name}"),
                            (FORTINET_NTP_GUIDE, FORTINET_NTP_AUTH_GUIDE),
                        )
                    )

    def check_logging_and_policy_profiles(self, parser: BaseDeviceParser) -> None:
        fortios = self._fortios(parser)
        inspections = {
            (inspection.scope, inspection.policy_name): inspection
            for inspection in fortios.get_security_inspection()
        }
        wan_by_scope: dict[str, set[str]] = defaultdict(set)
        for scope, name, settings, _ in fortios.iter_interfaces():
            if self._enabled(settings) and (
                self._text(settings.get("role")).lower() == "wan" or name.lower().startswith("wan")
            ):
                wan_by_scope[scope].add(name.lower())

        for scope, _, name, settings, path in fortios.iter_firewall_policies():
            if not self._enabled(settings) or self._text(settings.get("action"), "deny").lower() != "accept":
                continue
            destinations = {value.lower() for value in self._values(settings, "dstintf")}
            outbound = bool(destinations.intersection(wan_by_scope.get(scope, set()))) or any(
                value.startswith("wan") for value in destinations
            )
            if not outbound:
                continue
            if self._text(settings.get("logtraffic"), "disable").lower() not in {"all", "utm"}:
                self.add_issue(
                    self._finding(
                        parser,
                        "fortinet.fortios.policy.logging",
                        "Internet-bound policy logging is disabled",
                        f"Enabled accept policy '{name}' in scope '{scope}' reaches a WAN interface but logtraffic is not all or utm.",
                        "Unlogged permitted traffic reduces detection and investigation visibility.",
                        "Enable logtraffic all or utm according to the policy's inspection design.",
                        Severity.MEDIUM,
                        self._evidence(fortios, path + ("logtraffic",), f"firewall policy {name}: logtraffic disable"),
                        (FORTINET_HARDENING,),
                    )
                )
            utm_enabled = self._text(settings.get("utm-status"), "disable").lower() == "enable"
            group_attached = (
                self._text(settings.get("profile-type"), "single").lower() == "group"
                and bool(self._text(settings.get("profile-group")))
            )
            individual_attached = any(
                self._text(settings.get(field))
                for field in fortios.inspection_profile_fields()
            )
            has_profile = utm_enabled and (group_attached or individual_attached)
            if not has_profile:
                self.add_issue(
                    self._finding(
                        parser,
                        "fortinet.fortios.policy.security_profiles",
                        "Internet-bound policy lacks security inspection",
                        f"Enabled accept policy '{name}' in scope '{scope}' reaches a WAN interface without UTM or a referenced security profile.",
                        "Uninspected allowed traffic can carry malware, exploits, or prohibited applications.",
                        "Enable the required inspection mode and attach appropriate IPS, antivirus, web, application, DNS, and SSL/SSH profiles.",
                        Severity.HIGH,
                        self._evidence(fortios, path, f"firewall policy {name}"),
                        (FORTINET_INSPECTION_GUIDE, FORTINET_HARDENING),
                    )
                )
                continue

            inspection = inspections.get((scope, name))
            if inspection is None:
                continue
            policy_evidence = self._evidence(fortios, path, f"firewall policy {name}")
            attachment_evidence = policy_evidence + (
                f"{scope}: {inspection.attachment_mode} {inspection.attachment_name}",
            )
            if inspection.resolution_state == "unresolved":
                self.add_issue(
                    self._finding(
                        parser,
                        "fortinet.fortios.policy.security_profile_unresolved",
                        "Internet-bound policy references an unresolved profile group",
                        f"Enabled accept policy '{name}' in scope '{scope}' references profile group '{inspection.attachment_name}', but no same-VDOM, global, or root definition is present.",
                        "The static export does not prove that the intended UTM controls can be applied.",
                        "Attach an existing profile group in the applicable VDOM or global scope and verify its members.",
                        Severity.HIGH,
                        attachment_evidence,
                        (FORTINET_PROFILE_GROUP_REFERENCE, FORTINET_INSPECTION_GUIDE),
                    )
                )
                continue
            if inspection.resolution_state == "empty":
                self.add_issue(
                    self._finding(
                        parser,
                        "fortinet.fortios.policy.security_profile_ineffective",
                        "Internet-bound policy uses an empty profile group",
                        f"Enabled accept policy '{name}' in scope '{scope}' references group '{inspection.attachment_name}', but the resolved group contains no supported threat-inspection profile members.",
                        "An empty group does not provide the threat inspection implied by its attachment.",
                        "Populate the group with reviewed IPS, antivirus, web, application, DNS, file, or other required inspection profiles.",
                        Severity.HIGH,
                        attachment_evidence,
                        (FORTINET_PROFILE_GROUP_REFERENCE, FORTINET_HARDENING),
                    )
                )

            for profile in inspection.profiles:
                profile_evidence = policy_evidence + tuple(
                    item for item in profile.evidence
                ) + (f"{scope}: {profile.profile_type} profile {profile.name}",)
                if profile.resolution_state == "unresolved":
                    self.add_issue(
                        self._finding(
                            parser,
                            "fortinet.fortios.policy.security_profile_unresolved",
                            "Internet-bound policy references an unresolved security profile",
                            f"Enabled accept policy '{name}' in scope '{scope}' references {profile.profile_type} '{profile.name}', but no same-VDOM, global, root, or known built-in definition is present.",
                            "The static export does not prove that this inspection function can be applied.",
                            f"Attach an existing {profile.profile_type} in the applicable scope.",
                            Severity.HIGH,
                            profile_evidence,
                            (FORTINET_INSPECTION_GUIDE, FORTINET_PROFILE_GROUP_REFERENCE),
                        )
                    )
                elif profile.content_state in {"empty", "nonblocking"}:
                    reason = (
                        "has no exported inspection settings"
                        if profile.content_state == "empty"
                        else "contains only explicitly non-blocking actions: "
                        + ", ".join(profile.actions)
                    )
                    self.add_issue(
                        self._finding(
                            parser,
                            "fortinet.fortios.policy.security_profile_ineffective",
                            "Internet-bound policy uses an ineffective security profile",
                            f"Enabled accept policy '{name}' in scope '{scope}' uses {profile.profile_type} '{profile.name}', which {reason}.",
                            "The attached profile does not block the threats its name may imply.",
                            f"Configure '{profile.name}' with reviewed blocking actions appropriate to the protected traffic.",
                            Severity.HIGH,
                            profile_evidence,
                            (FORTINET_IPS_REFERENCE, FORTINET_HARDENING),
                        )
                    )

        destination_filters = (
            ("log syslogd setting", "log syslogd filter"),
            ("log syslogd2 setting", "log syslogd2 filter"),
            ("log syslogd3 setting", "log syslogd3 filter"),
            ("log syslogd4 setting", "log syslogd4 filter"),
            ("log fortianalyzer setting", "log fortianalyzer filter"),
            ("log fortianalyzer2 setting", "log fortianalyzer2 filter"),
            ("log fortianalyzer3 setting", "log fortianalyzer3 filter"),
            ("log fortiguard setting", "log fortiguard filter"),
            ("log disk setting", "log disk filter"),
            ("log memory setting", "log memory filter"),
        )
        disabled_events = {"anomaly", "forward-traffic", "local-traffic", "system", "user"}
        for destination_name, filter_name in destination_filters:
            enabled_scopes = {
                scope
                for scope, settings, _ in fortios.iter_scoped_sections(destination_name)
                if self._text(settings.get("status")).lower() == "enable"
            }
            for scope, settings, path in fortios.iter_scoped_sections(filter_name):
                if scope not in enabled_scopes:
                    continue
                disabled = sorted(
                    field
                    for field in disabled_events
                    if self._text(settings.get(field)).lower() == "disable"
                )
                if disabled:
                    self.add_issue(
                        self._finding(
                            parser,
                            "fortinet.fortios.logging.events_filtered",
                            "Central log destination filters security events",
                            f"Enabled destination '{destination_name}' in scope '{scope}' explicitly disables: {', '.join(disabled)}.",
                            "Filtering security-relevant events creates monitoring and investigation blind spots.",
                            "Enable the required traffic, anomaly, local, system, and user event categories.",
                            Severity.MEDIUM,
                            self._evidence(fortios, path, filter_name),
                            (FORTINET_HARDENING,),
                        )
                    )

    def check_syslog_transport(self, parser: BaseDeviceParser) -> None:
        """Reliable TCP is not evidence that exported syslog is TLS protected."""
        fortios = self._fortios(parser)
        for sink in fortios.get_syslog_sinks():
            if sink.transport_state == "explicit-cleartext":
                self.add_issue(self._finding(
                    parser,
                    "fortinet.fortios.logging.remote_cleartext",
                    "Enabled FortiOS remote syslog explicitly disables TLS",
                    f"Enabled {sink.name} in scope '{sink.scope}' sends to '{sink.server}' with "
                    f"'enc-algorithm disable'; mode '{sink.mode or 'unspecified'}' does not establish encryption.",
                    "Remote audit events may be readable or modified in transit even when reliable delivery is selected.",
                    "Use a protected syslog transport with an approved TLS configuration, or document an equivalent protected path.",
                    Severity.MEDIUM,
                    tuple(item for item in sink.evidence),
                    (FORTINET_SYSLOG_TRANSPORT_REFERENCE,),
                ))
            elif sink.transport_state == "explicit-weak-tls":
                self.add_issue(self._finding(
                    parser,
                    "fortinet.fortios.logging.remote_weak_tls",
                    "Enabled FortiOS remote syslog permits weak TLS settings",
                    f"Enabled {sink.name} in scope '{sink.scope}' sends to '{sink.server}' "
                    f"with encryption level '{sink.encryption}' and minimum TLS version "
                    f"'{sink.tls_minimum or 'inherited'}'.",
                    "Weak ciphers or obsolete TLS versions can reduce the confidentiality and integrity of remote audit events.",
                    "Use high-strength encryption and a minimum of TLS 1.2 or a stronger approved setting.",
                    Severity.MEDIUM,
                    tuple(item for item in sink.evidence),
                    (FORTINET_SYSLOG_TRANSPORT_REFERENCE, NIST_CRYPTO_TRANSITIONS),
                ))

    def check_ips_selector_actions(self, parser: BaseDeviceParser) -> None:
        """Report only a proven first broad passing high/critical IPS filter."""
        fortios = self._fortios(parser)
        for inspection in fortios.get_security_inspection():
            for profile in inspection.profiles:
                if (profile.profile_type != "ips-sensor"
                        or profile.resolution_state != "resolved"
                        or profile.content_state != "configured"):
                    continue
                weak: list[str] = []
                evidence: list[str] = []
                exempted: list[str] = []
                exemption_evidence: list[str] = []
                for target in ("critical", "high"):
                    first = next((
                        selector for selector in profile.ips_selectors
                        if selector.active_state != "disable"
                        and selector.broad_match
                        and (not selector.severities or target in selector.severities
                             or "all" in selector.severities)
                    ), None)
                    if (first is not None and first.severities
                            and first.active_state == "enable"
                            and first.action in {"pass", "monitor", "allow"}):
                        weak.append(target)
                        evidence.extend(item for item in first.evidence)
                    if (first is not None and first.severities
                            and first.active_state == "enable"
                            and first.action == "block" and first.exemptions):
                        exempted.append(target)
                        exemption_evidence.extend(item for item in first.evidence + first.exemptions)
                if weak:
                    self.add_issue(self._finding(
                        parser,
                        "fortinet.fortios.policy.ips_selector_nonblocking",
                        "Attached FortiOS IPS sensor passes selected high-severity signatures",
                        f"Active accept policy '{inspection.policy_name}' in scope '{inspection.scope}' "
                        f"uses IPS sensor '{profile.name}' whose first broad, explicitly enabled "
                        f"selector for {', '.join(weak)} severity is set to pass/monitor.",
                        "Matching critical or high-severity signatures may be logged or allowed instead of blocked.",
                        "Review the IPS entry order and set an approved blocking action for these severities.",
                        Severity.HIGH,
                        tuple(item for item in inspection.evidence + profile.evidence)
                        + tuple(dict.fromkeys(evidence)),
                        (FORTINET_IPS_REFERENCE, FORTINET_IPS_ORDER_REFERENCE),
                    ))
                if exempted:
                    self.add_issue(self._finding(
                        parser,
                        "fortinet.fortios.policy.ips_selector_exempt_ip",
                        "Attached FortiOS IPS sensor exempts traffic from high-severity signatures",
                        f"Active accept policy '{inspection.policy_name}' in scope '{inspection.scope}' "
                        f"uses IPS sensor '{profile.name}' whose first broad blocking selector "
                        f"for {', '.join(exempted)} severity has an explicit IP exemption.",
                        "Traffic matching the exemption is not inspected by the affected signatures.",
                        "Remove the exemption or narrowly justify and review its source/destination scope.",
                        Severity.HIGH,
                        tuple(item for item in inspection.evidence + profile.evidence)
                        + tuple(dict.fromkeys(exemption_evidence)),
                        (FORTINET_IPS_REFERENCE, FORTINET_IPS_ORDER_REFERENCE),
                    ))

    def check_policy_effectiveness(self, parser: BaseDeviceParser) -> None:
        """Report independent hygiene and only statically proven first-match effects."""

        fortios = self._fortios(parser)
        prior_by_scope: dict[tuple[str, str], list] = defaultdict(list)
        references = (
            FORTINET_HARDENING,
            FORTINET_ADDRESS_REFERENCE,
            FORTINET_ADDRESS_GROUP_REFERENCE,
            FORTINET_SERVICE_REFERENCE,
            FORTINET_SERVICE_GROUP_REFERENCE,
        )
        for policy in fortios.get_firewall_policy_semantics():
            evidence = tuple(item for item in policy.evidence) or (
                f"firewall policy {policy.name}",
            )
            if not policy.enabled:
                if (
                    policy.action == "accept"
                    and policy.source_networks.any
                    and policy.destination_networks.any
                    and policy.services.any
                    and policy.schedule.casefold() == "always"
                    and not policy.source_negated
                    and not policy.destination_negated
                    and not policy.service_negated
                ):
                    self.add_issue(self._finding(
                        parser,
                        "fortinet.fortios.policy.disabled_permissive_rule",
                        "Disabled permissive firewall policy remains configured",
                        f"Disabled {policy.family} policy '{policy.name}' at position {policy.position} in scope '{policy.scope}' retains an all-address, all-service accept action.",
                        "Stale permissive policy obscures intent and can create broad exposure if re-enabled.",
                        "Remove the obsolete policy or narrow and document it before reactivation.",
                        Severity.LOW,
                        evidence,
                        references,
                    ))
                continue

            if (
                policy.action == "accept"
                and policy.services.any
                and not (policy.source_networks.any and policy.destination_networks.any)
            ):
                self.add_issue(self._finding(
                    parser,
                    "fortinet.fortios.policy.broad_service",
                    "Firewall policy is unrestricted by service",
                    f"Enabled {policy.family} accept policy '{policy.name}' at position {policy.position} in scope '{policy.scope}' permits all services within its address and interface scope.",
                    "Unnecessary protocols and destination ports can cross the policy boundary.",
                    "Replace ALL with the smallest required service objects or a reviewed service group.",
                    Severity.MEDIUM,
                    evidence,
                    references,
                ))

            key = (policy.scope.casefold(), policy.family)
            if not policy.proof_eligible:
                continue
            for earlier in prior_by_scope[key]:
                if not all(
                    state == ProofState.PROVEN
                    for state in (
                        static_values_cover(
                            earlier.source_interfaces,
                            policy.source_interfaces,
                            any_value="any",
                        ),
                        static_values_cover(
                            earlier.destination_interfaces,
                            policy.destination_interfaces,
                            any_value="any",
                        ),
                        network_covers(earlier.source_networks, policy.source_networks),
                        network_covers(
                            earlier.destination_networks, policy.destination_networks
                        ),
                        service_covers(earlier.services, policy.services),
                    )
                ):
                    continue
                same_action = earlier.action == policy.action
                if same_action and earlier.behavior_signature != policy.behavior_signature:
                    continue
                self.add_issue(self._finding(
                    parser,
                    (
                        "fortinet.fortios.policy.redundant_rule"
                        if same_action
                        else "fortinet.fortios.policy.shadowed_rule"
                    ),
                    "Firewall policy is redundant" if same_action else "Firewall policy is shadowed",
                    f"{'IPv6' if policy.family == 'ipv6' else 'IPv4'} policy '{policy.name}' at position {policy.position} in scope '{policy.scope}' is fully covered by earlier policy '{earlier.name}' at position {earlier.position} with {'equivalent behavior' if same_action else 'a different terminal action'}.",
                    "The later policy cannot alter first-match enforcement for the statically proven traffic scope and obscures policy intent.",
                    "Remove or reorder the policy after validating VDOM scope, NAT/inspection behavior and operational intent.",
                    Severity.LOW if same_action else Severity.HIGH,
                    evidence + tuple(item for item in earlier.evidence),
                    references,
                ))
                break
            prior_by_scope[key].append(policy)

    def check_configuration_backups(self, parser: BaseDeviceParser) -> None:
        fortios = self._fortios(parser)
        backups = fortios.get_configuration_backups()
        complete = [
            backup
            for backup in backups
            if backup.schedule_state == "effective"
            and backup.destination
            and backup.transport_security != "unknown"
        ]
        incomplete_automatic = [
            backup
            for backup in backups
            if backup.start_mode == "auto" and backup not in complete
        ]

        for backup in incomplete_automatic:
            gaps = []
            if not backup.destination or backup.transport_security == "unknown":
                gaps.append("no supported destination")
            if backup.schedule_state != "effective":
                gaps.append(f"schedule state '{backup.schedule_state}'")
            self.add_issue(self._finding(
                parser,
                "fortinet.fortios.configuration.backup_incomplete",
                "Automatic configuration backup script is incomplete",
                f"Auto-script '{backup.name}' in scope '{backup.scope}' has "
                + " and ".join(gaps)
                + ".",
                "The configured automation cannot provide continuing configuration checkpoints as intended.",
                "Configure an automatic backup script with a positive interval, repeat 0, and a supported destination, or use a documented external backup process.",
                Severity.MEDIUM,
                tuple(item for item in backup.evidence),
                (FORTINET_CONFIGURATION_BACKUP_GUIDE, FORTINET_AUTO_SCRIPT_REFERENCE),
            ))

        if (
            parser.assessment_context.configuration_backup_scope == "on-device-required"
            and not complete
            and not incomplete_automatic
            and self._supports_default_inference(fortios)
        ):
            self.add_issue(self._finding(
                parser,
                "fortinet.fortios.configuration.backup_required",
                "Required recurring on-device configuration backup is absent",
                "The assessment policy requires an on-device schedule, but no complete recurring FortiOS backup auto-script is configured.",
                "The device lacks the policy-required configuration checkpoints for recovery.",
                "Configure a recurring secure backup auto-script or change the assessment scope only when an external managed backup process is evidenced.",
                Severity.MEDIUM,
                ("assessment policy: on-device configuration backup required",),
                (FORTINET_CONFIGURATION_BACKUP_GUIDE, FORTINET_AUTO_SCRIPT_REFERENCE),
            ))

        for backup in backups:
            if backup.transport_security != "insecure":
                continue
            self.add_issue(self._finding(
                parser,
                "fortinet.fortios.configuration.backup_transport",
                "Configuration backup script uses an insecure transport",
                f"Backup auto-script '{backup.name}' in scope '{backup.scope}' sends configuration data to '{backup.destination or 'an unresolved destination'}' using {backup.protocol.upper()}.",
                "Configuration backups can expose credentials, addressing, and security policy in transit.",
                "Use SFTP or a protected management station and secure the stored backup independently.",
                Severity.HIGH,
                tuple(item for item in backup.evidence),
                (FORTINET_CONFIGURATION_BACKUP_GUIDE,),
            ))

    def check_updates_and_unused_services(self, parser: BaseDeviceParser) -> None:
        fortios = self._fortios(parser)
        for scope, settings, path in fortios.iter_scoped_sections("system autoupdate schedule"):
            disabled = self._text(settings.get("status")).lower() == "disable"
            manual = self._text(settings.get("frequency")).lower() == "manual"
            if disabled or manual:
                self.add_issue(
                    self._finding(
                        parser,
                        "fortinet.fortios.fortiguard.automatic_updates",
                        "Automatic FortiGuard updates are disabled",
                        f"Scope '{scope}' explicitly configures automatic-update status '{self._text(settings.get('status'), 'default')}' and frequency '{self._text(settings.get('frequency'), 'default')}'.",
                        "Delayed security-service updates reduce protection against newly identified threats.",
                        "Enable automatic FortiGuard updates at a suitable interval.",
                        Severity.HIGH,
                        self._evidence(fortios, path, "system autoupdate schedule"),
                        (FORTINET_AUTOUPDATE_GUIDE, FORTINET_HARDENING),
                    )
                )

        centrally_managed = any(
            self._text(settings.get("type")).lower() == "fortimanager"
            for _, settings, _ in fortios.iter_scoped_sections("system central-management")
        )
        if not centrally_managed:
            for scope, settings, path in fortios.iter_scoped_sections("system fortiguard"):
                if self._text(settings.get("auto-firmware-upgrade")).lower() == "disable":
                    self.add_issue(
                        self._finding(
                            parser,
                            "fortinet.fortios.firmware.automatic_updates",
                            "Automatic firmware upgrades are explicitly disabled",
                            f"Scope '{scope}' disables auto-firmware-upgrade and no FortiManager control was identified.",
                            "Security fixes may be delayed unless a separate managed upgrade process exists.",
                            "Enable automatic firmware upgrades where supported, or document and monitor the managed patch process.",
                            Severity.MEDIUM,
                            self._evidence(fortios, path + ("auto-firmware-upgrade",), "set auto-firmware-upgrade disable"),
                            (FORTINET_FIRMWARE_GUIDE, FORTINET_HARDENING),
                        )
                    )

        policy_interfaces: dict[str, set[str]] = defaultdict(set)
        for scope, _, _, settings, _ in fortios.iter_firewall_policies():
            policy_interfaces[scope].update(value.lower() for value in self._values(settings, "srcintf"))
            policy_interfaces[scope].update(value.lower() for value in self._values(settings, "dstintf"))
        member_interfaces: set[str] = set()
        for section_name in ("system interface", "system switch-interface", "system zone", "system virtual-switch"):
            for _, section, _ in fortios.iter_scoped_sections(section_name):
                for settings in section.values():
                    if isinstance(settings, dict):
                        member_interfaces.update(value.lower() for value in self._values(settings, "member"))

        for scope, name, settings, path in fortios.iter_interfaces():
            service_values = {value.lower() for value in self._values(settings, "allowaccess")}
            role = self._text(settings.get("role")).lower()
            auxiliary = service_values.intersection({"capwap", "fabric", "fgfm"})
            if centrally_managed:
                auxiliary.discard("fgfm")
            if auxiliary and (role == "wan" or name.lower().startswith("wan")):
                self.add_issue(
                    self._finding(
                        parser,
                        "fortinet.fortios.management.auxiliary_services",
                        "Auxiliary management service is exposed on WAN",
                        f"Interface '{name}' in scope '{scope}' permits: {', '.join(sorted(auxiliary))}.",
                        "Unneeded fabric, access-point, or manager services expand the WAN attack surface.",
                        "Remove services not required by the documented topology and restrict required manager access upstream.",
                        Severity.MEDIUM,
                        self._evidence(fortios, path + ("allowaccess",), f"{name}: allowaccess"),
                        (FORTINET_HARDENING,),
                    )
                )
            if self._text(settings.get("status")).lower() != "up":
                continue
            no_address = not self._values(settings, "ip") or set(self._values(settings, "ip")) <= {"0.0.0.0"}
            dynamic = self._text(settings.get("mode")).lower() in {"dhcp", "pppoe"}
            if (
                no_address
                and not dynamic
                and not service_values
                and name.lower() not in policy_interfaces.get(scope, set())
                and name.lower() not in member_interfaces
                and not any(field in settings for field in ("vlanid", "interface", "aggregate"))
            ):
                self.add_issue(
                    self._finding(
                        parser,
                        "fortinet.fortios.interface.unused_enabled",
                        "Apparently unused interface is explicitly enabled",
                        f"Interface '{name}' in scope '{scope}' is explicitly up, has no address or management service, and is not referenced by parsed policies or interface groups.",
                        "Unused enabled ports can provide an unintended physical or logical attachment point.",
                        "Disable the interface, or document and configure its intended role before use.",
                        Severity.LOW,
                        self._evidence(fortios, path + ("status",), f"{name}: set status up"),
                        (FORTINET_HARDENING,),
                    )
                )

    def check_dos_policies(self, parser: BaseDeviceParser) -> None:
        fortios = self._fortios(parser)
        wan_by_scope: dict[str, dict[str, tuple[str, ...]]] = defaultdict(dict)
        for scope, name, settings, path in fortios.iter_interfaces():
            if self._enabled(settings) and (
                self._text(settings.get("role")).lower() == "wan" or name.lower().startswith("wan")
            ):
                wan_by_scope[scope][name.lower()] = self._evidence(fortios, path, f"system interface {name}")

        configured: dict[str, set[str]] = defaultdict(set)
        for policy in fortios.get_dos_policies():
            if not policy.enabled:
                continue
            active = [anomaly for anomaly in policy.anomalies if anomaly.enabled]
            if active:
                configured[policy.scope].update(interface.casefold() for interface in policy.interfaces)
            monitor_only = [anomaly.name for anomaly in active if anomaly.action != "block"]
            blocking = [anomaly.name for anomaly in active if anomaly.action == "block"]
            evidence = tuple(item for item in policy.evidence) or (
                f"firewall DoS-policy{('6' if policy.family == 'ipv6' else '')} {policy.name}",
            )
            if not blocking or monitor_only:
                detail = (
                    f"monitor-only or non-blocking anomalies: {', '.join(monitor_only)}"
                    if monitor_only
                    else "no enabled anomalies"
                )
                self.add_issue(
                    self._finding(
                        parser,
                        "fortinet.fortios.dos.no_blocking_anomaly",
                        "DoS policy includes unprotected anomaly coverage",
                        f"Enabled {policy.family} DoS policy '{policy.name}' in scope '{policy.scope}' has {detail}.",
                        "A pass-only or disabled detector records threshold events without mitigating that flood class.",
                        "Set applicable anomalies to block after tuning and validating thresholds for the protected workload.",
                        Severity.MEDIUM,
                        evidence,
                        (FORTINET_DOS_GUIDE,),
                    )
                )
            unlogged = [anomaly.name for anomaly in active if not anomaly.logging]
            if unlogged:
                self.add_issue(
                    self._finding(
                        parser,
                        "fortinet.fortios.dos.logging",
                        "DoS anomaly logging is disabled",
                        f"DoS policy '{policy.name}' in scope '{policy.scope}' has unlogged enabled anomalies: {', '.join(unlogged)}.",
                        "Unlogged flood detections reduce monitoring and tuning visibility.",
                        "Enable logging for each active anomaly and forward those events centrally.",
                        Severity.MEDIUM,
                        evidence,
                        (FORTINET_DOS_GUIDE,),
                    )
                )
            invalid_thresholds = [anomaly.name for anomaly in active if anomaly.threshold_state == "invalid"]
            if invalid_thresholds:
                self.add_issue(
                    self._finding(
                        parser,
                        "fortinet.fortios.dos.threshold_invalid",
                        "DoS anomaly threshold is invalid",
                        f"DoS policy '{policy.name}' in scope '{policy.scope}' has invalid explicit thresholds for: {', '.join(invalid_thresholds)}.",
                        "The intended detector cannot be proven to trigger at a valid configured threshold.",
                        "Configure a valid positive threshold and tune its adequacy against observed workload baselines.",
                        Severity.HIGH,
                        evidence,
                        (FORTINET_DOS_GUIDE,),
                    )
                )

        if self._supports_default_inference(fortios):
            for scope, interfaces in wan_by_scope.items():
                for interface, evidence in interfaces.items():
                    if interface in configured.get(scope, set()):
                        continue
                    self.add_issue(
                        self._finding(
                            parser,
                            "fortinet.fortios.dos.wan_policy_missing",
                            "WAN interface lacks an active DoS policy",
                            f"Enabled WAN interface '{interface}' in scope '{scope}' has no active DoS policy with an enabled anomaly.",
                            "The Internet-facing interface lacks configured threshold-based flood detection or blocking.",
                            "Create and tune an IPv4 and, where applicable, IPv6 DoS policy for the WAN interface.",
                            Severity.MEDIUM,
                            evidence,
                            (FORTINET_DOS_GUIDE, FORTINET_HARDENING),
                        )
                    )

    def check_aaa_transport(self, parser: BaseDeviceParser) -> None:
        """Assess only active administrative RADIUS bindings with known 7.4+ semantics."""

        fortios = self._fortios(parser)
        for profile in fortios.get_aaa_server_profiles():
            if not profile.is_bound_for_administration or not profile.radsec_supported:
                continue
            binding = (
                f"administrators {', '.join(profile.administrators)} through group(s) "
                f"{', '.join(profile.administrator_groups)}"
            )
            evidence = tuple(item for item in profile.evidence) or (
                f"config user radius / edit {profile.name}",
            )

            if profile.transport == "tls":
                identity_gaps = []
                if not profile.ca_certificate:
                    identity_gaps.append("no CA trust-anchor reference")
                if profile.server_identity_check == "disable":
                    identity_gaps.append("server identity checking is explicitly disabled")
                if identity_gaps:
                    self.add_issue(
                        self._finding(
                            parser,
                            "fortinet.fortios.aaa.radsec_server_identity",
                            "RadSec server identity validation is incomplete",
                            f"RADIUS profile '{profile.name}' in scope '{profile.scope}' uses TLS for {binding}, but has {', and '.join(identity_gaps)}.",
                            "A TLS channel without an anchored and verified server identity can be terminated by an unintended or impersonating endpoint.",
                            "Import the issuing CA, reference it with ca-cert, and keep server-identity-check enabled; ensure the configured server name or IP is present in the certificate identity.",
                            Severity.HIGH,
                            evidence,
                            (FORTINET_RADSEC_GUIDE,),
                        )
                    )

                minimum = (profile.tls_minimum_version or "default").lower()
                if minimum in {"sslv3", "tlsv1", "tlsv1-1"}:
                    self.add_issue(
                        self._finding(
                            parser,
                            "fortinet.fortios.aaa.radsec_tls_version",
                            "RadSec permits a legacy TLS version",
                            f"RADIUS profile '{profile.name}' in scope '{profile.scope}' uses tls-min-proto-version '{profile.tls_minimum_version}' for {binding}.",
                            "Legacy TLS versions weaken the confidentiality and integrity of administrative authentication traffic.",
                            "Set tls-min-proto-version to TLSv1-2 or TLSv1-3 as supported by both peers.",
                            Severity.HIGH,
                            evidence,
                            (FORTINET_RADSEC_GUIDE,),
                        )
                    )
                continue

            if (
                profile.transport in {"udp", "tcp"}
                and profile.require_message_authenticator == "disable"
            ):
                path = "a separately declared protected path" if profile.protected_path else "an unknown network path"
                self.add_issue(
                    self._finding(
                        parser,
                        "fortinet.fortios.aaa.radius_message_authenticator",
                        "RADIUS message-authenticator validation is disabled",
                        f"RADIUS profile '{profile.name}' in scope '{profile.scope}' uses {profile.transport.upper()} over {path} for {binding} and explicitly disables require-message-authenticator.",
                        "Forged or modified RADIUS responses may be accepted when protocol message validation is disabled.",
                        "Enable require-message-authenticator and confirm the RADIUS server supports and emits the attribute; use RadSec or an explicitly protected path where transport confidentiality is required.",
                        Severity.HIGH,
                        evidence,
                        (FORTINET_RADIUS_GUIDE,),
                    )
                )

    def check_local_in_policy(self, parser: BaseDeviceParser) -> None:
        fortios = self._fortios(parser)
        sensitive_services = {
            "all",
            "ftp",
            "http",
            "https",
            "snmp",
            "ssh",
            "telnet",
        }
        wildcards = {
            "ipv4": {"0.0.0.0/0", "all", "all_ipv4"},
            "ipv6": {"::/0", "0::/0", "all", "all6", "all_ipv6"},
        }
        for policy in fortios.get_local_in_policies():
            if not policy.enabled or policy.action != "accept":
                continue
            if policy.source_negated or policy.service_negated:
                continue
            sources = {value.casefold() for value in policy.sources}
            services = {value.casefold() for value in policy.services}
            if not sources.intersection(wildcards[policy.family]):
                continue
            if not services.intersection(sensitive_services):
                continue
            if policy.schedule.casefold() != "always":
                continue
            evidence = tuple(item for item in policy.evidence) or (
                f"firewall local-in-policy{'' if policy.family == 'ipv4' else '6'} {policy.name}",
            )
            self.add_issue(
                self._finding(
                    parser,
                    "fortinet.fortios.local_in.unrestricted_management",
                    "Local-in policy permits unrestricted management traffic",
                    f"Enabled {policy.family} local-in policy '{policy.name}' at position {policy.position} in scope '{policy.scope}' accepts unrestricted sources for sensitive service(s) {', '.join(sorted(services.intersection(sensitive_services)))} on interface '{policy.interface}' with the always schedule.",
                    "A broad local-device rule exposes administrative or monitoring services beyond an explicitly trusted source set.",
                    "Replace the wildcard source with approved management networks and retain an explicit deny policy after required local services.",
                    Severity.HIGH,
                    evidence,
                    (FORTINET_HARDENING, FORTINET_LOCAL_IN_REFERENCE),
                )
            )

    @staticmethod
    def _weak_ipsec_proposal(value: str) -> bool:
        proposal = value.casefold()
        return (
            proposal.startswith(("des-", "3des-", "null-"))
            or "-md5" in proposal
            or "-sha1" in proposal
            or proposal.endswith("-null")
        )

    def check_ipsec_tunnels(self, parser: BaseDeviceParser) -> None:
        for tunnel in self._fortios(parser).get_ipsec_tunnels():
            if not tunnel.active:
                continue
            evidence = tuple(item for item in tunnel.evidence) or (
                f"vpn ipsec phase2 {tunnel.name} -> {tunnel.phase1_name or '<missing>'}",
            )
            if tunnel.resolution_state == "unresolved":
                self.add_issue(
                    self._finding(
                        parser,
                        "fortinet.fortios.vpn.unresolved",
                        "Enabled IPsec phase2 has an unresolved phase1 binding",
                        f"Enabled phase2 '{tunnel.name}' in scope '{tunnel.scope}' references phase1 '{tunnel.phase1_name or '<missing>'}', which is not defined in the same scope.",
                        "The configured tunnel cannot establish the intended protected path through a valid local phase1 definition.",
                        "Reference an enabled phase1 definition in the same VDOM and review its peer identity and cryptographic policy.",
                        Severity.HIGH,
                        evidence,
                        (FORTINET_PHASE1_REFERENCE, FORTINET_PHASE2_REFERENCE),
                    )
                )
                continue

            weaknesses = []
            weak_phase1 = sorted(
                value for value in tunnel.phase1_proposals if self._weak_ipsec_proposal(value)
            )
            weak_phase2 = sorted(
                value for value in tunnel.phase2_proposals if self._weak_ipsec_proposal(value)
            )
            weak_dh = sorted(
                {value for value in tunnel.phase1_dh_groups + tunnel.phase2_dh_groups if value in {"1", "2", "5", "22", "23", "24"}}
            )
            if weak_phase1:
                weaknesses.append("weak phase1 proposal(s) " + ", ".join(weak_phase1))
            if weak_phase2:
                weaknesses.append("weak phase2 proposal(s) " + ", ".join(weak_phase2))
            if weak_dh:
                weaknesses.append("legacy DH group(s) " + ", ".join(weak_dh))
            if tunnel.pfs == "disable":
                weaknesses.append("PFS explicitly disabled")
            if tunnel.replay == "disable":
                weaknesses.append("anti-replay explicitly disabled")
            if not weaknesses:
                continue
            self.add_issue(
                self._finding(
                    parser,
                    "fortinet.fortios.vpn.weak_proposal",
                    "Enabled IPsec tunnel uses weak cryptographic settings",
                    f"Phase2 '{tunnel.name}' bound to phase1 '{tunnel.phase1_name}' in scope '{tunnel.scope}' has: {'; '.join(weaknesses)}.",
                    "Legacy algorithms, small Diffie-Hellman groups, missing forward secrecy, or disabled replay protection weaken tunnel confidentiality and integrity.",
                    "Use AES-GCM or AES with SHA-256 or stronger, DH group 14 or an approved stronger group, PFS, and anti-replay according to peer compatibility and policy.",
                    Severity.HIGH,
                    evidence,
                    (
                        FORTINET_PHASE1_REFERENCE,
                        FORTINET_PHASE2_REFERENCE,
                        IETF_IKEV2_ALGORITHM_GUIDANCE,
                    ),
                )
            )

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_administrators(parser)
        self.check_management_crypto(parser)
        self.check_management_certificates(parser)
        self.check_snmp(parser)
        self.check_logging_and_policy_profiles(parser)
        self.check_syslog_transport(parser)
        self.check_ips_selector_actions(parser)
        self.check_policy_effectiveness(parser)
        self.check_configuration_backups(parser)
        self.check_updates_and_unused_services(parser)
        self.check_password_and_session_policy(parser)
        self.check_ntp(parser)
        self.check_dos_policies(parser)
        self.check_aaa_transport(parser)
        self.check_local_in_policy(parser)
        self.check_ipsec_tunnels(parser)


__all__ = ["PluginFortiOSBaseline"]
