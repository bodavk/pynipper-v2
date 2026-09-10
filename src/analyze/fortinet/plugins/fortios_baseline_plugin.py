"""VDOM-aware FortiOS management, monitoring, and policy hardening checks."""

from collections import defaultdict
import re

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.issue import Finding, Severity
from src.devices.common.base_parser import BaseDeviceParser
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
FORTINET_INSPECTION_GUIDE = (
    "https://docs.fortinet.com/document/fortigate/7.2.0/administration-guide/721410/"
    "inspection-modes"
)


class PluginFortiOSBaseline(BasePlugin):
    """Evaluate explicit FortiOS state and infer defaults only for known releases."""

    _UNRESTRICTED_TRUST = {
        "0.0.0.0 0.0.0.0",
        "0.0.0.0/0",
        "::/0",
        "0:0:0:0:0:0:0:0/0",
    }
    _MFA_METHODS = {"email", "fortitoken", "fortitoken-cloud", "sms"}
    _PROFILE_FIELDS = {
        "application-list",
        "av-profile",
        "dnsfilter-profile",
        "file-filter-profile",
        "ips-sensor",
        "profile-group",
        "ssl-ssh-profile",
        "webfilter-profile",
    }
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
        )

    @staticmethod
    def _evidence(fortios: FortiOSParser, path: tuple[str, ...], fallback: str) -> tuple[str, ...]:
        return tuple(item.text for item in fortios.field_evidence(path)) or (fallback,)

    def check_administrators(self, parser: BaseDeviceParser) -> None:
        fortios = self._fortios(parser)
        privileged_local = []
        for scope, username, settings, path in fortios.iter_administrators():
            if not self._enabled(settings):
                continue
            profile = self._text(settings.get("accprofile"), "super_admin").lower()
            privileged = profile == "super_admin"
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
                        f"Enabled super_admin account '{username}' in scope '{scope}' has no effective trusted-host restriction.",
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
                            f"Local super_admin account '{username}' in scope '{scope}' has no enabled two-factor method.",
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
                and self._text(settings.get("accprofile"), "super_admin").lower() == "super_admin"
                and self._text(settings.get("remote-auth"), "disable").lower() == "enable"
                and bool(self._text(settings.get("remote-group")))
                for _, _, settings, _ in fortios.iter_administrators()
            )
            if not remote_privileged:
                self.add_issue(
                    self._finding(
                        parser,
                        "fortinet.fortios.admin.centralized_authentication",
                        "Privileged authentication is local only",
                        "No enabled super_admin account is bound to remote authentication.",
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
                        item.text.replace(str(name), "<redacted>")
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
                if authentication != "enable" or not has_key or key_type in {"md5", "sha1"}:
                    detail = "authentication disabled" if authentication != "enable" else "key binding incomplete"
                    if key_type in {"md5", "sha1"}:
                        detail = f"legacy {key_type} authentication"
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

    def check_logging_and_policy_profiles(self, parser: BaseDeviceParser) -> None:
        fortios = self._fortios(parser)
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
            has_profile = self._text(settings.get("utm-status"), "disable").lower() == "enable" and any(
                self._text(settings.get(field)) for field in self._PROFILE_FIELDS
            )
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
        for section_name in ("firewall DoS-policy", "firewall DoS-policy6"):
            for scope, section, path in fortios.iter_scoped_sections(section_name):
                for name, settings in section.items():
                    if not isinstance(settings, dict) or not self._enabled(settings):
                        continue
                    interface = self._text(settings.get("interface")).lower()
                    if interface:
                        configured[scope].add(interface)
                    anomalies = settings.get("anomaly")
                    blocking_anomalies = []
                    unlogged = []
                    if isinstance(anomalies, dict):
                        for anomaly_name, anomaly in anomalies.items():
                            if not isinstance(anomaly, dict) or not self._enabled(anomaly):
                                continue
                            if self._text(anomaly.get("action"), "pass").lower() == "block":
                                blocking_anomalies.append(str(anomaly_name))
                            if self._text(anomaly.get("log"), "disable").lower() != "enable":
                                unlogged.append(str(anomaly_name))
                    if not blocking_anomalies:
                        self.add_issue(
                            self._finding(
                                parser,
                                "fortinet.fortios.dos.no_blocking_anomaly",
                                "DoS policy has no blocking anomaly",
                                f"Enabled {section_name} '{name}' in scope '{scope}' has no enabled anomaly with action block.",
                                "A policy without an active blocking detector does not provide threshold-based flood mitigation.",
                                "Enable and tune applicable anomaly detectors with action block and tested thresholds.",
                                Severity.MEDIUM,
                                self._evidence(fortios, path + (str(name),), f"{section_name} {name}"),
                                (FORTINET_DOS_GUIDE,),
                            )
                        )
                    elif unlogged:
                        self.add_issue(
                            self._finding(
                                parser,
                                "fortinet.fortios.dos.logging",
                                "DoS anomaly logging is disabled",
                                f"DoS policy '{name}' in scope '{scope}' has unlogged enabled anomalies: {', '.join(unlogged)}.",
                                "Unlogged flood detections reduce monitoring and tuning visibility.",
                                "Enable logging for each active anomaly and forward those events centrally.",
                                Severity.MEDIUM,
                                self._evidence(fortios, path + (str(name),), f"{section_name} {name}"),
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

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_administrators(parser)
        self.check_management_crypto(parser)
        self.check_snmp(parser)
        self.check_logging_and_policy_profiles(parser)
        self.check_updates_and_unused_services(parser)
        self.check_password_and_session_policy(parser)
        self.check_ntp(parser)
        self.check_dos_policies(parser)


__all__ = ["PluginFortiOSBaseline"]
