"""Effective-state ArubaOS-Switch/HP ProCurve hardening checks."""

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.controls import ControlOutcome as CO, record_control
from src.analyze.common.issue import Finding, FindingBasis, Severity
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.common.models import ConfigurationState
from src.devices.hp.procurve import HPFeature, HPProCurveParser


AOS_SWITCH_SECURITY_GUIDE = (
    "https://www.arubanetworks.com/techdocs/AOS-Switch/16.10/"
    "Aruba%202530%20Access%20Security%20Guide%20for%20ArubaOS-Switch%2016.10.pdf"
)
AOS_SWITCH_SNTP_GUIDE = (
    "https://arubanetworking.hpe.com/techdocs/AOS-S/16.11/MCG/KB/content/kb/"
    "snt-ser.htm"
)
AOS_SWITCH_LOGGING_GUIDE = (
    "https://arubanetworking.hpe.com/techdocs/AOS-S/16.11/MCG/KB/content/kb/"
    "cnf-sev-lev-eve-log.htm"
)
AOS_SWITCH_DEBUG_GUIDE = (
    "https://arubanetworking.hpe.com/techdocs/AOS-S/16.11/MCG/YC/content/"
    "common%20files/cnf-deb-ope.htm"
)
AOS_SWITCH_SNMPV3_GUIDE = (
    "https://arubanetworking.hpe.com/techdocs/AOS-S/16.11/MCG/WC/content/"
    "common%20files/snm-use-com.htm"
)
AOS_SWITCH_LAYER2_GUIDE = (
    "https://arubanetworking.hpe.com/techdocs/AOS-Switch/16.11/"
    "Aruba%203810M5400R%20Access%20Security%20Guide%20for%20AOS-S%2016.11.pdf"
)
AOS_SWITCH_PORT_ACCESS_GUIDE = (
    "https://arubanetworking.hpe.com/techdocs/AOS-S/16.10/ASG/WC/content/common%20files/"
    "rec-set-por-acc-16.-16..htm"
)
AOS_SWITCH_BPDU_PROTECTION_GUIDE = (
    "https://arubanetworking.hpe.com/techdocs/AOS-S/16.10/ATMG/KB/content/kb/ena-dis-bpd-pro.htm"
)
AOS_SWITCH_BPDU_FILTER_GUIDE = (
    "https://arubanetworking.hpe.com/techdocs/AOS-S/16.10/ATMG/WB/content/common%20files/cnf-bpd-fil.htm"
)
AOS_SWITCH_BASIC_OPERATION_GUIDE = (
    "https://arubanetworking.hpe.com/techdocs/AOS-Switch/16.11/"
    "Aruba%20Basic%20Operation%20Guide%20for%20AOS-S%2016.11.pdf"
)
AOS_SWITCH_PASSWORD_GUIDE = (
    "https://arubanetworking.hpe.com/techdocs/AOS-S/16.11/ASG/YC/content/"
    "common%20files/cnf-pas-sec.htm"
)
AOS_SWITCH_AUTHENTICATION_GUIDE = (
    "https://arubanetworking.hpe.com/techdocs/AOS-S/16.10/ASG/YC/content/"
    "common%20files/cnf-swi-aut-met.htm"
)


class PluginHPChecks(BasePlugin):
    """Assess AOS-S 16.x defaults and explicit commands without substring guesses."""

    _WEAK_SSH = {
        "cipher": {"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "rijndael-cbc@lysator.liu.se"},
        "kex": {"diffie-hellman-group14-sha1"},
        "mac": {"hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96"},
    }

    @staticmethod
    def _hp(parser: BaseDeviceParser) -> HPProCurveParser:
        if not isinstance(parser, HPProCurveParser):
            raise TypeError("PluginHPChecks requires an HPProCurveParser")
        return parser

    @staticmethod
    def _evidence(feature: HPFeature) -> tuple[str, ...]:
        return tuple(item for item in feature.evidence)

    def check_management(self, parser: BaseDeviceParser) -> None:
        hp = self._hp(parser)
        states = hp.get_service_states()
        for protocol, rule_id, title in (
            ("telnet", "hp.procurve.management.telnet", "Telnet management is enabled"),
            ("http", "hp.procurve.management.http", "Clear-text WebAgent is enabled"),
        ):
            feature = states[protocol]
            record_control(
                parser, "hp.procurve.cleartext-management",
                CO.FINDING if feature.state == ConfigurationState.ENABLED
                else CO.NO_FINDING if feature.state == ConfigurationState.DISABLED else CO.UNKNOWN,
                f"{protocol.upper()} management is enabled (explicit or documented release default)."
                if feature.state == ConfigurationState.ENABLED
                else f"{protocol.upper()} management is explicitly disabled."
                if feature.state == ConfigurationState.DISABLED
                else f"{protocol.upper()} state: {feature.detail or 'release default not qualified'}.",
                instance=protocol,
            )
            if feature.state != ConfigurationState.ENABLED:
                continue
            self.add_issue(
                Finding(
                    rule_id=rule_id,
                    device=parser.device_type,
                    title=title,
                    observation=f"{protocol.upper()} management is enabled by the effective AOS-S configuration.",
                    impact="Administrative credentials and sessions can be exposed or altered in transit.",
                    exploitability="An attacker with management-path access can intercept or attempt the clear-text service.",
                    recommendation=(
                        "Disable Telnet with 'no telnet-server' and use SSH."
                        if protocol == "telnet"
                        else "Disable HTTP with 'no web-management' and, if needed, enable 'web-management ssl'."
                    ),
                    severity=Severity.HIGH,
                    evidence=self._evidence(feature),
                    references=(AOS_SWITCH_SECURITY_GUIDE,),
                    basis=(
                        FindingBasis.DOCUMENTED_DEFAULT if "default" in feature.detail
                        else FindingBasis.EXPLICIT_VALUE
                    ),
                )
            )

        exposed_secure = [
            protocol
            for protocol in ("ssh", "https")
            if states[protocol].state == ConfigurationState.ENABLED
        ]
        managers = hp.has_authorized_managers()
        if exposed_secure:
            record_control(
                parser, "hp.procurve.management-source-restriction",
                CO.NO_FINDING if managers else CO.FINDING,
                "Enabled SSH/HTTPS management is limited by active authorized managers." if managers
                else "Enabled SSH/HTTPS management has no active authorized-manager restriction.",
            )
        elif all(states[name].state == ConfigurationState.DISABLED for name in ("ssh", "https")):
            record_control(parser, "hp.procurve.management-source-restriction", CO.NOT_APPLICABLE,
                           "SSH and HTTPS management are disabled.")
        elif managers:
            record_control(parser, "hp.procurve.management-source-restriction", CO.NO_FINDING,
                           "Active authorized managers restrict management sources.")
        else:
            record_control(parser, "hp.procurve.management-source-restriction", CO.UNKNOWN,
                           "SSH/HTTPS state is not qualified for this release and no authorized managers are configured.")
        if exposed_secure and not managers:
            self.add_issue(
                Finding(
                    rule_id="hp.procurve.management.source_restriction",
                    device=parser.device_type,
                    title="Management services lack authorized-manager restrictions",
                    observation=f"{', '.join(name.upper() for name in exposed_secure)} is enabled without an active 'ip authorized-managers' source restriction.",
                    impact="Every routed source that can reach the switch may probe the management plane.",
                    exploitability="A reachable attacker can attempt authentication or exploit a management-service flaw.",
                    recommendation="Restrict management access with explicit authorized IP managers and network controls.",
                    severity=Severity.MEDIUM,
                    evidence=tuple(
                        evidence
                        for name in exposed_secure
                        for evidence in states[name].evidence
                    ),
                    references=(AOS_SWITCH_SECURITY_GUIDE,),
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                )
            )

    def check_snmp(self, parser: BaseDeviceParser) -> None:
        hp = self._hp(parser)
        communities = hp.get_snmp_communities()
        if not communities:
            record_control(parser, "hp.procurve.snmp-community", CO.NOT_APPLICABLE,
                           "No SNMP community is configured.")
            record_control(parser, "hp.procurve.snmpv3-secure-user", CO.NOT_APPLICABLE,
                           "No community-based SNMP access is configured.")
        for number, community in enumerate(communities, 1):
            evidence = tuple(item for item in community.evidence)
            default_name = community.name.casefold() in {"public", "private"}
            broad = community.access == "manager" or not community.restricted
            record_control(
                parser, "hp.procurve.snmp-community",
                CO.FINDING if default_name or broad else CO.NO_FINDING,
                ("Community uses a default name and/or has manager or unrestricted access."
                 if default_name or broad else "Community is non-default, operator-level and restricted."),
                instance=f"community #{number}",
            )
            if community.name.casefold() in {"public", "private"}:
                self.add_issue(
                    Finding(
                        rule_id="hp.procurve.snmp.default_community",
                        device=parser.device_type,
                        title="Default SNMP community is configured",
                        observation=f"The exact default SNMP community name '{community.name}' is active.",
                        impact="Widely known community names facilitate unauthorized SNMP access.",
                        exploitability="A reachable attacker can use the known string if network controls permit SNMP.",
                        recommendation="Remove the default community and migrate management to authenticated, encrypted SNMPv3.",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        references=(AOS_SWITCH_SECURITY_GUIDE,),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )
            if community.access == "manager" or not community.restricted:
                self.add_issue(
                    Finding(
                        rule_id="hp.procurve.snmp.community_access",
                        device=parser.device_type,
                        title="SNMP community has broad or write-capable access",
                        observation=f"Community '{community.name}' has {community.access} access and is {'restricted' if community.restricted else 'unrestricted'}.",
                        impact="SNMPv1/v2c community disclosure may permit broad read access or configuration changes.",
                        exploitability="An attacker requires SNMP reachability and the community value.",
                        recommendation="Remove community-based management or limit it to read-only restricted access during SNMPv3 migration.",
                        severity=Severity.HIGH if community.access == "manager" else Severity.MEDIUM,
                        evidence=evidence,
                        references=(AOS_SWITCH_SECURITY_GUIDE,),
                        basis=(
                            FindingBasis.EXPLICIT_VALUE if community.access == "manager"
                            else FindingBasis.MISSING_EXPLICIT_SETTING
                        ),
                    )
                )

        if communities:
            strong_users = [
                user
                for user in hp.get_snmpv3_users()
                if user.authentication in {"sha", "sha256", "sha384", "sha512"}
                and user.privacy in {"aes", "aes128", "aes192", "aes256"}
            ]
            record_control(
                parser, "hp.procurve.snmpv3-secure-user",
                CO.NO_FINDING if strong_users else CO.FINDING,
                "An SNMPv3 user with SHA authentication and AES privacy is configured." if strong_users
                else "Community SNMP is active without an SNMPv3 SHA/AES user.",
            )
            if not strong_users:
                self.add_issue(
                    Finding(
                        rule_id="hp.procurve.snmp.secure_user_missing",
                        device=parser.device_type,
                        title="No authenticated and private SNMPv3 user is configured",
                        observation="Community-based SNMP is active without a parsed SNMPv3 user using SHA authentication and AES privacy.",
                        impact="SNMP management may rely on reusable clear-text community credentials.",
                        exploitability="A network-positioned attacker can capture or guess a community and query the device.",
                        recommendation="Configure an SNMPv3 user with authentication and privacy, then disable SNMPv1/v2c access.",
                        severity=Severity.MEDIUM,
                        evidence=tuple(item for community in communities for item in community.evidence),
                        references=(AOS_SWITCH_SECURITY_GUIDE,),
                        basis=FindingBasis.REQUIRED_SETTING_MISSING,
                    )
                )

        if hp.get_snmpv3_agent_state() is False:
            for control in ("hp.procurve.snmpv3-user-protection", "hp.procurve.snmpv3-source-restriction"):
                record_control(parser, control, CO.NOT_APPLICABLE, "The SNMPv3 agent is explicitly disabled.")
            return
        if not hp.get_snmpv3_users():
            for control in ("hp.procurve.snmpv3-user-protection", "hp.procurve.snmpv3-source-restriction"):
                record_control(parser, control, CO.NOT_APPLICABLE, "No SNMPv3 user is configured.")
        for user in hp.get_snmpv3_users():
            evidence = tuple(item for item in user.evidence)
            instance = f"snmpv3 user {user.name}"
            undetermined = {"unknown", "default-unknown"}
            protection_fires = (
                user.authentication == "none" or user.privacy == "none"
                or user.authentication == "md5" or user.privacy == "des"
            )
            record_control(
                parser, "hp.procurve.snmpv3-user-protection",
                CO.FINDING if protection_fires
                else CO.UNKNOWN if user.authentication in undetermined or user.privacy in undetermined
                else CO.NO_FINDING,
                f"Authentication '{user.authentication}', privacy '{user.privacy}'"
                + (" (algorithm omitted or unrecognized; release default not qualified)."
                   if not protection_fires and (user.authentication in undetermined or user.privacy in undetermined)
                   else "."),
                instance=instance,
            )
            record_control(
                parser, "hp.procurve.snmpv3-source-restriction",
                CO.NO_FINDING if hp.has_authorized_managers() else CO.FINDING,
                "Active authorized managers restrict SNMPv3 sources." if hp.has_authorized_managers()
                else "No active authorized-manager restriction.",
                instance=instance,
            )
            missing = []
            if user.authentication == "none":
                missing.append("authentication")
            if user.privacy == "none":
                missing.append("privacy")
            if missing:
                self.add_issue(
                    Finding(
                        rule_id="hp.procurve.snmp.v3_protection",
                        device=parser.device_type,
                        title="SNMPv3 user lacks complete protection",
                        observation=f"SNMPv3 user '{user.name}' lacks {' and '.join(missing)}.",
                        impact="SNMP management traffic may lack origin authentication or confidentiality.",
                        exploitability="A reachable or on-path attacker can target an under-protected SNMP identity.",
                        recommendation="Configure SHA authentication and AES privacy for this user.",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        references=(AOS_SWITCH_SNMPV3_GUIDE,),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )
            weak = []
            if user.authentication == "md5":
                weak.append("MD5 authentication")
            if user.privacy == "des":
                weak.append("DES privacy")
            if weak:
                self.add_issue(
                    Finding(
                        rule_id="hp.procurve.snmp.v3_weak_algorithm",
                        device=parser.device_type,
                        title="SNMPv3 user uses weak algorithms",
                        observation=f"SNMPv3 user '{user.name}' uses {', '.join(weak)}.",
                        impact="Legacy SNMPv3 algorithms provide inadequate cryptographic protection.",
                        exploitability="A traffic observer can target weaknesses in the configured algorithms.",
                        recommendation="Use the platform-supported SHA authentication and AES privacy options.",
                        severity=Severity.MEDIUM,
                        evidence=evidence,
                        references=(AOS_SWITCH_SNMPV3_GUIDE,),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )
            if not hp.has_authorized_managers():
                self.add_issue(
                    Finding(
                        rule_id="hp.procurve.snmp.v3_access_scope",
                        device=parser.device_type,
                        title="SNMPv3 access lacks a manager source restriction",
                        observation=f"SNMPv3 user '{user.name}' is configured without an active authorized-manager restriction.",
                        impact="Every routed source that can reach the agent may attempt SNMPv3 authentication.",
                        exploitability="A reachable attacker can probe or password-guess the SNMP agent.",
                        recommendation="Restrict management access to approved NMS networks with authorized managers and network controls.",
                        severity=Severity.MEDIUM,
                        evidence=evidence,
                        references=(AOS_SWITCH_SNMPV3_GUIDE,),
                        basis=FindingBasis.REQUIRED_SETTING_MISSING,
                    )
                )

    def check_ssh_crypto(self, parser: BaseDeviceParser) -> None:
        hp = self._hp(parser)
        ssh = hp.get_service_states()["ssh"]
        if ssh.state != ConfigurationState.ENABLED:
            record_control(
                parser, "hp.procurve.ssh-algorithms",
                CO.NOT_APPLICABLE if ssh.state == ConfigurationState.DISABLED else CO.UNKNOWN,
                "SSH is disabled." if ssh.state == ConfigurationState.DISABLED
                else "SSH state is not qualified for this release.",
            )
            return
        algorithms = hp.get_ssh_algorithms()
        weak = {
            kind: sorted(set(algorithms[kind]) & values)
            for kind, values in self._WEAK_SSH.items()
            if isinstance(algorithms[f"{kind}_state"], HPFeature)
            and algorithms[f"{kind}_state"].state != ConfigurationState.UNKNOWN
            and set(algorithms[kind]) & values
        }
        if not weak:
            unqualified = [
                kind for kind in self._WEAK_SSH
                if not isinstance(algorithms[f"{kind}_state"], HPFeature)
                or algorithms[f"{kind}_state"].state == ConfigurationState.UNKNOWN
                or (not hp.has_supported_default_release()
                    and not self._weak_ssh_explicitly_removed(kind, algorithms[f"{kind}_state"]))
            ]
            record_control(
                parser, "hp.procurve.ssh-algorithms", CO.UNKNOWN if unqualified else CO.NO_FINDING,
("The effective SSH " + ", ".join(unqualified) + " list is not qualified: no documented release default"
                 " and the listed legacy algorithms are not all explicitly removed.")
                if unqualified else "The effective SSH cipher, KEX and MAC lists contain no listed legacy algorithm.",
            )
            return
        record_control(parser, "hp.procurve.ssh-algorithms", CO.FINDING,
                       "The effective SSH suite includes legacy algorithms.")
        summary = "; ".join(f"{kind}: {', '.join(values)}" for kind, values in weak.items())
        evidence = list(self._evidence(ssh))
        for kind in weak:
            evidence.extend(item for item in algorithms[f"{kind}_state"].evidence)
        self.add_issue(
            Finding(
                rule_id="hp.procurve.ssh.weak_algorithms",
                device=parser.device_type,
                title="SSH permits legacy cryptographic algorithms",
                observation=f"The effective SSH suite includes {summary}.",
                impact="Legacy CBC/3DES, SHA-1, or MD5 choices weaken transport protection.",
                exploitability="A capable network attacker may exploit downgrade or weaknesses when a client negotiates an allowed legacy suite.",
                recommendation="Disable the listed algorithms with the documented 'no ip ssh cipher|kex|mac' commands and retain modern CTR/SHA-2/ECDH choices.",
                severity=Severity.MEDIUM,
                evidence=tuple(dict.fromkeys(evidence)),
                references=(AOS_SWITCH_SECURITY_GUIDE,),
                basis=(
                    FindingBasis.EXPLICIT_VALUE
                    if any(
                        value in item.text.casefold()
                        for kind, values in weak.items()
                        for value in values
                        for item in algorithms[f"{kind}_state"].evidence
                    )
                    else FindingBasis.DOCUMENTED_DEFAULT
                ),
            )
        )

    @classmethod
    def _weak_ssh_explicitly_removed(cls, kind: str, state: HPFeature) -> bool:
        """True when the last command for every listed legacy algorithm of this kind removes it."""
        last: dict[str, bool] = {}
        for item in state.evidence:
            tokens = item.text.casefold().split()
            if tokens and tokens[-1] in cls._WEAK_SSH[kind]:
                last[tokens[-1]] = tokens[0] == "no"
        return all(last.get(value) for value in cls._WEAK_SSH[kind])

    def check_operational_baseline(self, parser: BaseDeviceParser) -> None:
        hp = self._hp(parser)
        states = hp.get_service_states()
        service_enabled = any(feature.state == ConfigurationState.ENABLED for feature in states.values())
        remote = hp.get_remote_authentication()
        if remote:
            record_control(parser, "hp.procurve.centralized-authentication", CO.NO_FINDING,
                           "Management login uses " + ", ".join(remote) + ".")
        elif service_enabled:
            record_control(parser, "hp.procurve.centralized-authentication", CO.FINDING,
                           "An enabled management service has no RADIUS or TACACS authentication method.")
        elif all(feature.state == ConfigurationState.DISABLED for feature in states.values()):
            record_control(parser, "hp.procurve.centralized-authentication", CO.NOT_APPLICABLE,
                           "Telnet, SSH, HTTP and HTTPS management are disabled.")
        else:
            record_control(parser, "hp.procurve.centralized-authentication", CO.UNKNOWN,
                           "Management-service state is not qualified for this release.")
        if any(
            feature.state == ConfigurationState.ENABLED
            for feature in states.values()
        ) and not hp.get_remote_authentication():
            self.add_issue(
                Finding(
                    rule_id="hp.procurve.authentication.centralized",
                    device=parser.device_type,
                    title="Management authentication is not centralized",
                    observation="An enabled management service has no parsed RADIUS or TACACS authentication method.",
                    impact="Local-only accounts reduce centralized revocation, policy enforcement, and auditability.",
                    exploitability="Compromise of a local credential can provide access independently of central identity controls.",
                    recommendation="Configure RADIUS or TACACS+ for management login with a documented emergency local fallback.",
                    severity=Severity.MEDIUM,
                    evidence=tuple(
                        evidence
                        for feature in states.values()
                        for evidence in feature.evidence
                    ),
                    references=(AOS_SWITCH_SECURITY_GUIDE,),
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                )
            )

    def check_administrative_policy(self, parser: BaseDeviceParser) -> None:
        hp = self._hp(parser)
        policies = hp.get_administrative_authentication_policies()
        credentials = {
            item.role: item for item in hp.get_local_administrator_credentials()
        }

        local_is_applicable = any(
            policy.applicable is True
            and "local" in {policy.primary, policy.secondary}
            for policy in policies
        )
        manager = credentials["manager"]
        if local_is_applicable:
            record_control(
                parser, "hp.procurve.manager-credential",
                CO.FINDING if manager.state == ConfigurationState.DISABLED
                else CO.NO_FINDING if manager.state == ConfigurationState.ENABLED else CO.UNKNOWN,
                "Local authentication is effective and the manager credential is absent."
                if manager.state == ConfigurationState.DISABLED
                else "Local authentication is effective and a manager credential is configured."
                if manager.state == ConfigurationState.ENABLED
                else "Credentials are not included in the export (no include-credentials).",
            )
        elif any(
            policy.applicable is not False and (
                policy.resolution_state in {"unknown-release", "invalid"}
                or (policy.applicable is None and "local" in {policy.primary, policy.secondary})
            )
            for policy in policies
        ):
            record_control(parser, "hp.procurve.manager-credential", CO.UNKNOWN,
                           "Administrative authentication methods or channel state are not qualified.")
        else:
            record_control(parser, "hp.procurve.manager-credential", CO.NOT_APPLICABLE,
                           "No applicable administrative channel uses local authentication.")
        if local_is_applicable and manager.state == ConfigurationState.DISABLED:
            operator = credentials["operator"]
            observation = "Local authentication is effective for an administrative channel, but manager password protection is explicitly absent."
            if operator.state == ConfigurationState.ENABLED:
                observation += " Only an operator credential is exported; AOS-S documents that this condition permits full manager privilege."
            self.add_issue(Finding(
                rule_id="hp.procurve.admin.manager_credential_missing",
                device=parser.device_type,
                title="Local administrative fallback lacks manager protection",
                observation=observation,
                impact="An administrative channel can reach read-write manager access without the intended manager-level credential boundary.",
                exploitability="A user who reaches a locally authenticated management channel may obtain full configuration privileges.",
                recommendation="Configure a unique manager credential and retain local fallback only as a controlled emergency-access path.",
                severity=Severity.HIGH,
                evidence=tuple(item for item in manager.evidence) + tuple(
                    item.text
                    for policy in policies
                    if policy.applicable is True and "local" in {policy.primary, policy.secondary}
                    for item in policy.evidence
                ),
                references=(AOS_SWITCH_PASSWORD_GUIDE,),
                basis=(
                    FindingBasis.REQUIRED_SETTING_MISSING
                    if any(item.text.startswith("include-credentials") for item in manager.evidence)
                    else FindingBasis.EXPLICIT_VALUE
                ),
            ))

        for policy in policies:
            authorized = "authorized" in {policy.primary, policy.secondary}
            record_control(
                parser, "hp.procurve.admin-authentication-methods",
                CO.FINDING if policy.applicable is True and authorized
                else CO.NOT_APPLICABLE if policy.applicable is False
                else CO.UNKNOWN if policy.applicable is None or policy.resolution_state in {"unknown-release", "invalid"}
                else CO.NO_FINDING,
                f"Methods '{policy.primary} {policy.secondary}' ({policy.resolution_state})"
                + ("; channel disabled." if policy.applicable is False
                   else "; channel state not qualified." if policy.applicable is None else "."),
                instance=f"{policy.channel} {policy.access_level}",
            )
            if policy.applicable is not True or "authorized" not in {policy.primary, policy.secondary}:
                continue
            self.add_issue(Finding(
                rule_id="hp.procurve.admin.unauthenticated_method",
                device=parser.device_type,
                title="Administrative channel permits an unauthenticated method",
                observation=(
                    f"The {policy.channel} {policy.access_level} policy uses "
                    f"'{policy.primary} {policy.secondary}', including the documented no-authentication 'authorized' method."
                ),
                impact="The configured fallback can grant administrative access without validating a credential.",
                exploitability="A user who can reach the affected management service may be admitted when that method is selected.",
                recommendation="Replace 'authorized' with a validated primary method and either a controlled local fallback or fail-closed 'none'.",
                severity=Severity.CRITICAL if policy.access_level == "enable" else Severity.HIGH,
                evidence=tuple(item for item in policy.evidence),
                references=(AOS_SWITCH_AUTHENTICATION_GUIDE,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))

        banner = hp.get_login_banner_policy()
        banner_fires = banner.state == ConfigurationState.DISABLED and banner.resolution_state != "unknown-release"
        record_control(
            parser, "hp.procurve.login-banner",
            CO.FINDING if banner_fires else CO.NO_FINDING if banner.state == ConfigurationState.ENABLED else CO.UNKNOWN,
            "No effective 'banner motd' is configured." if banner_fires
            else "A 'banner motd' notice is configured." if banner.state == ConfigurationState.ENABLED
            else f"Banner state not qualified ({banner.resolution_state}).",
        )
        if banner.state == ConfigurationState.DISABLED and banner.resolution_state != "unknown-release":
            self.add_issue(Finding(
                rule_id="hp.procurve.admin.login_banner",
                device=parser.device_type,
                title="Pre-login administrative notice is not configured",
                observation="The supported AOS-S export has no effective 'banner motd' configuration.",
                impact="Users are not shown the organization's authorization and monitoring notice at administrative access.",
                exploitability="This is primarily a governance and legal-notice control rather than a direct technical exploit.",
                recommendation="Configure an approved message with 'banner motd' and validate its presentation on each enabled management channel.",
                severity=Severity.LOW,
                evidence=tuple(item for item in banner.evidence) or ("banner motd absent from supported AOS-S export",),
                references=(AOS_SWITCH_BASIC_OPERATION_GUIDE,),
                basis=FindingBasis.REQUIRED_SETTING_MISSING,
            ))

        for session in hp.get_administrative_session_policies():
            if session.applicable is False:
                outcome, reason = CO.NOT_APPLICABLE, "The management channel is disabled."
            elif session.applicable is None:
                outcome, reason = CO.UNKNOWN, "The management channel state is not qualified for this release."
            elif session.resolution_state in {"invalid", "unknown-release"} or session.timeout_seconds is None:
                outcome, reason = CO.UNKNOWN, f"Idle timeout is not qualified ({session.resolution_state})."
            elif 0 < session.timeout_seconds <= 600:
                outcome, reason = CO.NO_FINDING, f"Idle timeout is {session.timeout_seconds} seconds ({session.resolution_state})."
            else:
                outcome, reason = CO.FINDING, f"Idle timeout is {session.timeout_seconds or 'disabled'} ({session.resolution_state})."
            record_control(parser, "hp.procurve.idle-timeout", outcome, reason, instance=session.channel)
            if (
                session.applicable is not True
                or session.resolution_state in {"invalid", "unknown-release"}
                or session.timeout_seconds is None
                or 0 < session.timeout_seconds <= 600
            ):
                continue
            label = {
                "remote-cli": "remote CLI",
                "serial-usb": "serial/USB console",
                "web": "WebAgent",
            }[session.channel]
            disabled = session.timeout_seconds == 0
            rule_id = {
                "remote-cli": "hp.procurve.admin.remote_cli_idle_timeout",
                "serial-usb": "hp.procurve.admin.serial_idle_timeout",
                "web": "hp.procurve.admin.web_idle_timeout",
            }[session.channel]
            command = {
                "remote-cli": "console idle-timeout 600",
                "serial-usb": "console idle-timeout serial-usb 600",
                "web": "web-management idle-timeout 600",
            }[session.channel]
            self.add_issue(Finding(
                rule_id=rule_id,
                device=parser.device_type,
                title=f"{label.capitalize()} idle timeout is {'disabled' if disabled else 'excessive'}",
                observation=(
                    f"The effective {label} idle timeout is disabled."
                    if disabled else f"The effective {label} idle timeout is {session.timeout_seconds} seconds, above the 600-second project target."
                ),
                impact="An unattended authenticated administrative session can remain usable longer than intended.",
                exploitability="A person or process with access to an abandoned management session can inherit its privileges.",
                recommendation=f"Set a timeout of at most 600 seconds (for example, '{command}').",
                severity=Severity.MEDIUM,
                evidence=tuple(item for item in session.evidence),
                references=(AOS_SWITCH_BASIC_OPERATION_GUIDE,),
                basis=(
                    FindingBasis.DOCUMENTED_DEFAULT
                    if session.resolution_state.startswith("documented-default")
                    else FindingBasis.EXPLICIT_VALUE
                ),
            ))

    def check_advanced_baseline(self, parser: BaseDeviceParser) -> None:
        hp = self._hp(parser)
        remote_authentication = hp.get_remote_authentication()
        if remote_authentication:
            accounting = hp.has_management_accounting()
            record_control(
                parser, "hp.procurve.management-accounting", CO.NO_FINDING if accounting else CO.FINDING,
                "An active AAA accounting target is configured." if accounting
                else "Centralized authentication is used without an active AAA accounting target.",
            )
        else:
            record_control(parser, "hp.procurve.management-accounting", CO.NOT_APPLICABLE,
                           "Management login does not use RADIUS or TACACS.")
        if remote_authentication and not hp.has_management_accounting():
            self.add_issue(
                Finding(
                    rule_id="hp.procurve.authentication.accounting",
                    device=parser.device_type,
                    title="Centralized management authentication lacks accounting",
                    observation=f"Management login uses {', '.join(remote_authentication)} but no active exec, command, system, or network accounting target was parsed.",
                    impact="Successful sessions and administrative activity may not be recorded by a centralized service.",
                    exploitability="A compromised administrator account can make changes with reduced independent audit evidence.",
                    recommendation="Configure appropriate AAA exec and command accounting to RADIUS or protected syslog.",
                    severity=Severity.MEDIUM,
                    evidence=("centralized management authentication without aaa accounting",),
                    references=(AOS_SWITCH_SECURITY_GUIDE,),
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                )
            )

        password_control = hp.get_password_configuration_control()
        if hp.get_users():
            record_control(
                parser, "hp.procurve.password-complexity",
                CO.FINDING if password_control.state == ConfigurationState.DISABLED
                else CO.NO_FINDING if password_control.state == ConfigurationState.ENABLED else CO.UNKNOWN,
                "Password configuration-control is disabled." if password_control.state == ConfigurationState.DISABLED
                else "Password configuration-control is enabled." if password_control.state == ConfigurationState.ENABLED
                else password_control.detail or "Password configuration-control is not qualified for this release.",
            )
        elif any(item.state == ConfigurationState.UNKNOWN for item in hp.get_local_administrator_credentials()):
            record_control(parser, "hp.procurve.password-complexity", CO.UNKNOWN,
                           "Local credentials are not included in the export (no include-credentials).")
        else:
            record_control(parser, "hp.procurve.password-complexity", CO.NOT_APPLICABLE,
                           "No local manager or operator credential is configured.")
        if hp.get_users() and password_control.state == ConfigurationState.DISABLED:
            self.add_issue(
                Finding(
                    rule_id="hp.procurve.credentials.password_complexity",
                    device=parser.device_type,
                    title="Local password complexity control is disabled",
                    observation="A local manager or operator credential is configured while password configuration-control is disabled.",
                    impact="New local passwords are not subject to the switch password-complexity policy.",
                    exploitability="Weak local credentials are more susceptible to guessing and reuse attacks.",
                    recommendation="Disable incompatible WebUI/REST access where necessary, set the documented password parameters, and enable 'password configuration-control'.",
                    severity=Severity.HIGH,
                    evidence=self._evidence(password_control),
                    references=(AOS_SWITCH_SECURITY_GUIDE,),
                    basis=(
                        FindingBasis.DOCUMENTED_DEFAULT if "default" in password_control.detail
                        else FindingBasis.EXPLICIT_VALUE
                    ),
                )
            )

        configured_vlans = set(hp.get_configured_vlans()) - {1}
        if not configured_vlans:
            record_control(parser, "hp.procurve.dhcp-snooping", CO.NOT_APPLICABLE,
                           "No non-default VLAN is configured.")
        elif not hp.has_supported_default_release():
            snooped = set(hp.get_dhcp_snooping_vlans())
            for vlan in sorted(configured_vlans):
                record_control(
                    parser, "hp.procurve.dhcp-snooping", CO.NO_FINDING if vlan in snooped else CO.UNKNOWN,
                    "DHCP snooping is explicitly enabled for this VLAN." if vlan in snooped
                    else "The release is outside the qualified AOS-S default table.",
                    instance=f"vlan {vlan}",
                )
        else:
            snooped = set(hp.get_dhcp_snooping_vlans())
            for vlan in sorted(configured_vlans):
                record_control(
                    parser, "hp.procurve.dhcp-snooping", CO.NO_FINDING if vlan in snooped else CO.FINDING,
                    "DHCP snooping is enabled for this VLAN." if vlan in snooped
                    else "DHCP snooping is not configured for this VLAN.",
                    instance=f"vlan {vlan}",
                )
        if (
            configured_vlans
            and hp.has_supported_default_release()
        ):
            missing = sorted(configured_vlans - set(hp.get_dhcp_snooping_vlans()))
            if missing:
                self.add_issue(
                    Finding(
                        rule_id="hp.procurve.layer2.dhcp_snooping",
                        device=parser.device_type,
                        title="Configured client VLAN lacks DHCP snooping",
                        observation="DHCP snooping is absent for configured non-default VLANs: " + ", ".join(map(str, missing)) + ".",
                        impact="Rogue DHCP servers can distribute attacker-controlled addressing, gateway, or DNS information on those VLANs.",
                        exploitability="An attacker connected to an affected Layer-2 segment can answer client DHCP requests.",
                        recommendation="Enable DHCP snooping on client VLANs and trust only validated DHCP-server or uplink ports.",
                        severity=Severity.MEDIUM,
                        evidence=tuple(f"vlan {vlan} without dhcp-snooping" for vlan in missing),
                        references=(AOS_SWITCH_SECURITY_GUIDE,),
                        basis=FindingBasis.REQUIRED_SETTING_MISSING,
                    )
                )

        self._check_observability(parser)

    def check_edge_protections(self, parser: BaseDeviceParser) -> None:
        hp = self._hp(parser)
        ports = hp.get_port_protections() if hp.has_supported_layer2_release() else ()
        edge_controls = (
            "hp.procurve.access-edge-vlan-trust", "hp.procurve.access-edge-dot1x",
            "hp.procurve.access-edge-bpdu-protection", "hp.procurve.access-edge-spoofing-protection",
        )
        edge_roles = any(role == "access-edge" for _, role in parser.assessment_context.interface_roles)
        if not edge_roles:
            for control in edge_controls:
                record_control(parser, control, CO.NOT_APPLICABLE,
                               "No port is classified access-edge by the assessment policy.")
        elif not hp.has_supported_layer2_release():
            for control in edge_controls:
                record_control(parser, control, CO.UNKNOWN,
                               "The release is outside the qualified AOS-S 16.10/16.11 Layer-2 grammar.")
        elif not any(port.active and port.role == "access-edge" for port in ports):
            for control in edge_controls:
                record_control(parser, control, CO.NOT_APPLICABLE,
                               "No active port is classified access-edge by the assessment policy.")
        for port in ports:
            if not port.active or port.role != "access-edge":
                continue
            evidence = tuple(item for item in port.evidence) + (
                f"assessment policy: port {port.port} role access-edge",
            )
            if port.tagged:
                record_control(parser, "hp.procurve.access-edge-vlan-trust", CO.FINDING,
                               "The access-edge port has tagged VLAN membership.", instance=f"port {port.port}")
                for control in edge_controls[1:]:
                    record_control(parser, control, CO.UNKNOWN,
                                   "The port carries tagged VLANs; per-port access-edge protections were not evaluated.",
                                   instance=f"port {port.port}")
                self.add_issue(Finding(
                    rule_id="hp.procurve.layer2.access_edge_trunk",
                    device=parser.device_type,
                    title="Access-edge port carries tagged VLANs",
                    observation=f"Port {port.port} is explicitly classified access-edge but has tagged VLAN membership {list(port.vlans)}.",
                    impact="An unintended tagged path can expose multiple VLANs to an endpoint and weaken segmentation.",
                    exploitability="A connected endpoint may send tagged traffic into VLANs not intended for that access port.",
                    recommendation="Use untagged client VLAN membership, or reclassify and document the port as an approved uplink.",
                    severity=Severity.HIGH,
                    evidence=evidence,
                    references=(AOS_SWITCH_LAYER2_GUIDE,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
                continue
            trusted = [
                label for label, enabled in (
                    ("DHCP snooping", port.dhcp_trusted),
                    ("ARP protection", port.arp_trusted),
                ) if enabled
            ]
            record_control(
                parser, "hp.procurve.access-edge-vlan-trust", CO.FINDING if trusted else CO.NO_FINDING,
                ("The port is trusted for " + ", ".join(trusted) + ".") if trusted
                else "Untagged membership only and no DHCP-snooping/ARP trust.",
                instance=f"port {port.port}",
            )
            record_control(
                parser, "hp.procurve.access-edge-dot1x",
                CO.FINDING if port.dot1x_control == "authorized"
                else CO.NOT_APPLICABLE if port.dot1x_control is None else CO.NO_FINDING,
                "No 802.1X authenticator port control is configured on this port." if port.dot1x_control is None
                else f"802.1X authenticator control is '{port.dot1x_control}'.",
                instance=f"port {port.port}",
            )
            record_control(
                parser, "hp.procurve.access-edge-bpdu-protection",
                CO.FINDING if port.bpdu_protection is False or (port.bpdu_protection is True and port.bpdu_filter is True)
                else CO.NO_FINDING,
                "BPDU protection is explicitly disabled." if port.bpdu_protection is False
                else "BPDU protection is combined with BPDU filtering." if port.bpdu_protection and port.bpdu_filter
                else "BPDU protection is enabled without filtering." if port.bpdu_protection
                else "BPDU protection is not configured for this port (omitted); the check reports only explicit disablement or filter bypass.",
                instance=f"port {port.port}",
            )
            lacking = [
                label for label, present, applies in (
                    ("Dynamic ARP protection", port.arp_protected, bool(port.vlans)),
                    ("Dynamic IP Lockdown", port.source_lockdown, True),
                    ("port security", port.port_security, True),
                ) if applies and not present
            ]
            record_control(
                parser, "hp.procurve.access-edge-spoofing-protection", CO.FINDING if lacking else CO.NO_FINDING,
                ("The port lacks " + ", ".join(lacking) + ".") if lacking
                else "ARP protection, IP lockdown and port security are configured.",
                instance=f"port {port.port}",
            )
            if trusted:
                self.add_issue(Finding(
                    rule_id="hp.procurve.layer2.access_edge_trust",
                    device=parser.device_type,
                    title="Access-edge port is trusted by spoofing protections",
                    observation=f"Port {port.port} is explicitly classified access-edge but is trusted for {', '.join(trusted)}.",
                    impact="Trust bypasses validation intended to block rogue DHCP or forged ARP messages from endpoint-facing ports.",
                    exploitability="A connected endpoint can originate server or ARP traffic that would otherwise be validated or dropped.",
                    recommendation="Remove trust from this access edge and reserve it for explicitly classified server/uplink ports.",
                    severity=Severity.HIGH,
                    evidence=evidence,
                    references=(AOS_SWITCH_LAYER2_GUIDE,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
            if port.dot1x_control == "authorized":
                self.add_issue(Finding(
                    rule_id="hp.procurve.layer2.access_edge.dot1x_force_authorized",
                    device=parser.device_type,
                    title="Access-edge 802.1X port is forced authorized",
                    observation=f"Port {port.port} is an assessed access edge with 802.1X authenticator control set to authorized (force authorized).",
                    impact="Any connected device gets network access without 802.1X authentication.",
                    exploitability="A person with physical access to the port can connect an unauthenticated device.",
                    recommendation="Set the authenticator port control to auto, or document an approved exception for this port.",
                    severity=Severity.HIGH,
                    evidence=evidence,
                    references=(AOS_SWITCH_PORT_ACCESS_GUIDE,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
            if port.bpdu_protection is False:
                self.add_issue(Finding(
                    rule_id="hp.procurve.layer2.access_edge.bpdu_guard_ineffective",
                    device=parser.device_type,
                    title="Access-edge port has BPDU protection explicitly disabled",
                    observation=f"Port {port.port} is an assessed access edge and BPDU protection is explicitly disabled for it.",
                    impact="A connected device can send BPDUs without the port being disabled, potentially affecting spanning-tree topology.",
                    exploitability="A user or attacker on the access port can connect a bridge or send crafted BPDUs.",
                    recommendation="Enable 'spanning-tree <port> bpdu-protection' on this access edge.",
                    severity=Severity.MEDIUM,
                    evidence=evidence,
                    references=(AOS_SWITCH_BPDU_PROTECTION_GUIDE,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
            elif port.bpdu_protection is True and port.bpdu_filter is True:
                self.add_issue(Finding(
                    rule_id="hp.procurve.layer2.access_edge.bpdu_filter_bypass",
                    device=parser.device_type,
                    title="Access-edge BPDU filtering can bypass protection",
                    observation=f"Port {port.port} has BPDU protection but also BPDU filtering, which makes the port ignore incoming BPDUs.",
                    impact="The filter can prevent BPDU protection from seeing the BPDU that should disable the port.",
                    exploitability="A bridge connected to the access port may go undetected.",
                    recommendation="Remove BPDU filtering from the assessed access edge and keep BPDU protection.",
                    severity=Severity.MEDIUM,
                    evidence=evidence,
                    references=(AOS_SWITCH_BPDU_PROTECTION_GUIDE, AOS_SWITCH_BPDU_FILTER_GUIDE),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
            for suffix, present, label in (
                ("arp_protection", port.arp_protected, "Dynamic ARP protection on its VLAN"),
                ("source_lockdown", port.source_lockdown, "Dynamic IP Lockdown"),
                ("port_security", port.port_security, "port security"),
            ):
                if present or (suffix == "arp_protection" and not port.vlans):
                    continue
                self.add_issue(Finding(
                    rule_id=f"hp.procurve.layer2.access_edge.{suffix}",
                    device=parser.device_type,
                    title=f"Access-edge port lacks {label}",
                    observation=f"Port {port.port} is explicitly classified access-edge but lacks {label}.",
                    impact="A connected endpoint may spoof IP/MAC bindings or exceed the intended endpoint identity policy.",
                    exploitability="An attacker with physical or Layer-2 access may inject forged traffic on the client segment.",
                    recommendation=f"Enable and validate {label} for this access edge, preserving DHCP snooping prerequisites and server/uplink trust boundaries.",
                    severity=Severity.MEDIUM,
                    evidence=evidence,
                    references=(AOS_SWITCH_LAYER2_GUIDE,),
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                ))
    def _check_observability(self, parser: BaseDeviceParser) -> None:
        hp = self._hp(parser)
        logging = hp.get_remote_logging_policy()
        destinations = hp.get_logging_destinations()
        record_control(
            parser, "hp.procurve.remote-logging", CO.NO_FINDING if destinations else CO.FINDING,
            "An active remote syslog destination is configured." if destinations
            else "No active remote syslog destination is configured.",
        )
        if not destinations:
            record_control(parser, "hp.procurve.remote-event-logging", CO.NOT_APPLICABLE,
                           "No active remote syslog destination is configured.")
        elif not hp.has_supported_administrative_release():
            record_control(parser, "hp.procurve.remote-event-logging", CO.UNKNOWN,
                           "The release is outside the qualified AOS-S 16.10/16.11 logging defaults.")
        elif logging.event_enabled is False:
            record_control(parser, "hp.procurve.remote-event-logging", CO.FINDING,
                           "'no debug event' suppresses Event Log forwarding.")
        elif logging.severity_state == "explicit" and logging.severity == "major":
            record_control(parser, "hp.procurve.remote-event-logging", CO.FINDING,
                           "The explicit 'major' severity filter excludes error events.")
        elif logging.severity_state == "invalid" or logging.event_enabled is None:
            record_control(parser, "hp.procurve.remote-event-logging", CO.UNKNOWN,
                           "The Event Log forwarding state or severity filter is not recognized.")
        else:
            record_control(parser, "hp.procurve.remote-event-logging", CO.NO_FINDING,
                           f"Event Log forwarding is enabled with severity filter {logging.severity or 'not set'}.")
        if not destinations:
            self.add_issue(
                Finding(
                    rule_id="hp.procurve.logging.remote_destination",
                    device=parser.device_type,
                    title="No effective remote syslog destination",
                    observation=(
                        "Configured syslog servers are inactive because remote debug logging is explicitly disabled."
                        if logging.destinations and logging.destination_enabled is False else
                        "No active AOS-S remote syslog destination was found."
                    ),
                    impact="Security events may be lost with local log rollover or device compromise.",
                    exploitability="An attacker who gains device access can benefit from reduced external evidence.",
                    recommendation=(
                        "Re-enable the configured remote syslog destination with 'debug destination logging'."
                        if logging.destinations and logging.destination_enabled is False else
                        "Configure at least one protected remote syslog destination."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=(tuple(item for item in logging.control_evidence)
                              if logging.destinations and logging.destination_enabled is False
                              else ("remote logging destination absent",)),
                    references=(AOS_SWITCH_SECURITY_GUIDE,),
                    basis=(
                        FindingBasis.EXPLICIT_VALUE
                        if logging.destinations and logging.destination_enabled is False
                        else FindingBasis.REQUIRED_SETTING_MISSING
                    ),
                )
            )
        if destinations and hp.has_supported_administrative_release():
            if logging.event_enabled is False:
                self.add_issue(Finding(
                    rule_id="hp.procurve.logging.remote_event_disabled",
                    device=parser.device_type,
                    title="AOS-S Event Log forwarding is disabled",
                    observation="Remote syslog servers are configured, but 'no debug event' suppresses switch Event Log messages to them.",
                    impact="Security-relevant switch events may be absent from central retention even though other debug messages can still be sent.",
                    exploitability="An attacker with device access may benefit from missing centrally retained events.",
                    recommendation="Enable Event Log forwarding with 'debug event' and verify the remote logging destination.",
                    severity=Severity.MEDIUM,
                    evidence=tuple(item for item in logging.event_evidence)
                    + tuple(item for destination in destinations for item in destination.evidence),
                    references=(AOS_SWITCH_DEBUG_GUIDE,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
            elif logging.severity_state == "explicit" and logging.severity == "major":
                self.add_issue(Finding(
                    rule_id="hp.procurve.logging.remote_severity_excludes_errors",
                    device=parser.device_type,
                    title="AOS-S remote logging excludes error events",
                    observation="The explicit 'major' filter forwards fatal events but excludes error-severity Event Log messages from configured syslog servers.",
                    impact="Error-severity switch events may be absent from central monitoring; the local Event Log is unaffected by this filter.",
                    exploitability="A fault or hostile action recorded at error severity may not reach the remote collector.",
                    recommendation="Set remote Event Log severity to 'error' or a more inclusive approved level.",
                    severity=Severity.MEDIUM,
                    evidence=tuple(item for item in logging.severity_evidence)
                    + tuple(item for destination in destinations for item in destination.evidence),
                    references=(AOS_SWITCH_LOGGING_GUIDE,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
        associations = hp.get_sntp_associations()
        record_control(
            parser, "hp.procurve.ntp-servers", CO.NO_FINDING if associations else CO.FINDING,
            "An SNTP server is configured." if associations else "No active SNTP server is configured.",
        )
        if not associations:
            record_control(parser, "hp.procurve.ntp-authentication", CO.NOT_APPLICABLE,
                           "No SNTP server is configured.")
        elif not hp.has_supported_sntp_release():
            record_control(parser, "hp.procurve.ntp-authentication", CO.UNKNOWN,
                           "The release is outside the qualified AOS-S 16.10/16.11 SNTP defaults.")
        else:
            for association in associations:
                record_control(
                    parser, "hp.procurve.ntp-authentication",
                    CO.FINDING if association.authentication_state in {"unauthenticated", "unresolved"}
                    else CO.NO_FINDING if association.authentication_state == "authenticated" else CO.UNKNOWN,
                    f"SNTP authentication state: {association.authentication_state}.",
                    instance=f"sntp server {association.address}",
                )
        if not associations:
            self.add_issue(
                Finding(
                    rule_id="hp.procurve.ntp.servers",
                    device=parser.device_type,
                    title="No SNTP time source is configured",
                    observation="No active 'sntp server' entry was found.",
                    impact="Inaccurate timestamps hinder event correlation and certificate or authentication troubleshooting.",
                    exploitability="Poor time consistency reduces the reliability of forensic timelines.",
                    recommendation="Configure redundant trusted SNTP servers and the appropriate time synchronization mode.",
                    severity=Severity.LOW,
                    evidence=("SNTP server absent",),
                    references=(AOS_SWITCH_SNTP_GUIDE,),
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                )
            )
        elif hp.has_supported_sntp_release():
            for association in associations:
                if association.authentication_state == "unauthenticated":
                    self.add_issue(
                        Finding(
                            rule_id="hp.procurve.ntp.authentication",
                            device=parser.device_type,
                            title="SNTP association is unauthenticated",
                            observation=f"SNTP server '{association.address}' does not have effective client authentication and a per-server key binding.",
                            impact="Unauthenticated time responses can corrupt log chronology and time-dependent security behavior.",
                            exploitability="A network-positioned attacker may spoof SNTP responses if routing and filtering permit it.",
                            recommendation="Enable SNTP authentication and associate a configured trusted key with every unicast server.",
                            severity=Severity.MEDIUM,
                            evidence=tuple(item for item in association.evidence),
                            references=(AOS_SWITCH_SNTP_GUIDE,),
                            basis=FindingBasis.REQUIRED_SETTING_MISSING,
                        )
                    )
                elif association.authentication_state == "unresolved":
                    self.add_issue(
                        Finding(
                            rule_id="hp.procurve.ntp.key_resolution",
                            device=parser.device_type,
                            title="SNTP server key binding is unresolved",
                            observation=f"SNTP server '{association.address}' references key ID '{association.key_id or 'missing'}', but the key is missing, incomplete, or not trusted.",
                            impact="The switch cannot establish the intended authenticated time association from the exported configuration.",
                            exploitability="Authentication failure can cause loss of synchronization or fallback to an unintended time source.",
                            recommendation="Define the referenced MD5 key with secret material, mark it trusted, and retain its per-server binding.",
                            severity=Severity.MEDIUM,
                            evidence=tuple(item for item in association.evidence),
                            references=(AOS_SWITCH_SNTP_GUIDE,),
                            basis=FindingBasis.EXPLICIT_VALUE,
                        )
                    )

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_management(parser)
        self.check_snmp(parser)
        self.check_ssh_crypto(parser)
        self.check_operational_baseline(parser)
        self.check_administrative_policy(parser)
        self.check_advanced_baseline(parser)
        self.check_edge_protections(parser)
