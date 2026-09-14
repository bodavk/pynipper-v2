"""Effective-state ArubaOS-Switch/HP ProCurve hardening checks."""

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.issue import Finding, Severity
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
AOS_SWITCH_SNMPV3_GUIDE = (
    "https://arubanetworking.hpe.com/techdocs/AOS-S/16.11/MCG/WC/content/"
    "common%20files/snm-use-com.htm"
)
AOS_SWITCH_LAYER2_GUIDE = (
    "https://arubanetworking.hpe.com/techdocs/AOS-Switch/16.11/"
    "Aruba%203810M5400R%20Access%20Security%20Guide%20for%20AOS-S%2016.11.pdf"
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
        return tuple(item.text for item in feature.evidence)

    def check_management(self, parser: BaseDeviceParser) -> None:
        hp = self._hp(parser)
        states = hp.get_service_states()
        for protocol, rule_id, title in (
            ("telnet", "hp.procurve.management.telnet", "Telnet management is enabled"),
            ("http", "hp.procurve.management.http", "Clear-text WebAgent is enabled"),
        ):
            feature = states[protocol]
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
                )
            )

        exposed_secure = [
            protocol
            for protocol in ("ssh", "https")
            if states[protocol].state == ConfigurationState.ENABLED
        ]
        if exposed_secure and not hp.has_authorized_managers():
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
                        evidence.text
                        for name in exposed_secure
                        for evidence in states[name].evidence
                    ),
                    references=(AOS_SWITCH_SECURITY_GUIDE,),
                )
            )

    def check_snmp(self, parser: BaseDeviceParser) -> None:
        hp = self._hp(parser)
        communities = hp.get_snmp_communities()
        for community in communities:
            evidence = tuple(item.text for item in community.evidence)
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
                    )
                )

        if communities:
            strong_users = [
                user
                for user in hp.get_snmpv3_users()
                if user.authentication in {"sha", "sha256", "sha384", "sha512"}
                and user.privacy in {"aes", "aes128", "aes192", "aes256"}
            ]
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
                        evidence=tuple(item.text for community in communities for item in community.evidence),
                        references=(AOS_SWITCH_SECURITY_GUIDE,),
                    )
                )

        if hp.get_snmpv3_agent_state() is False:
            return
        for user in hp.get_snmpv3_users():
            evidence = tuple(item.text for item in user.evidence)
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
                    )
                )

    def check_ssh_crypto(self, parser: BaseDeviceParser) -> None:
        hp = self._hp(parser)
        ssh = hp.get_service_states()["ssh"]
        if ssh.state != ConfigurationState.ENABLED:
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
            return
        summary = "; ".join(f"{kind}: {', '.join(values)}" for kind, values in weak.items())
        evidence = list(self._evidence(ssh))
        for kind in weak:
            evidence.extend(item.text for item in algorithms[f"{kind}_state"].evidence)
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
            )
        )

    def check_operational_baseline(self, parser: BaseDeviceParser) -> None:
        hp = self._hp(parser)
        states = hp.get_service_states()
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
                        evidence.text
                        for feature in states.values()
                        for evidence in feature.evidence
                    ),
                    references=(AOS_SWITCH_SECURITY_GUIDE,),
                )
            )

    def check_advanced_baseline(self, parser: BaseDeviceParser) -> None:
        hp = self._hp(parser)
        remote_authentication = hp.get_remote_authentication()
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
                )
            )

        password_control = hp.get_password_configuration_control()
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
                )
            )

        configured_vlans = set(hp.get_configured_vlans()) - {1}
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
                    )
                )

        self._check_observability(parser)

    def check_edge_protections(self, parser: BaseDeviceParser) -> None:
        hp = self._hp(parser)
        ports = hp.get_port_protections() if hp.has_supported_layer2_release() else ()
        for port in ports:
            if not port.active or port.role != "access-edge":
                continue
            evidence = tuple(item.text for item in port.evidence) + (
                f"assessment policy: port {port.port} role access-edge",
            )
            if port.tagged:
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
                ))
                continue
            trusted = [
                label for label, enabled in (
                    ("DHCP snooping", port.dhcp_trusted),
                    ("ARP protection", port.arp_trusted),
                ) if enabled
            ]
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
                ))
    def _check_observability(self, parser: BaseDeviceParser) -> None:
        hp = self._hp(parser)
        if not hp.get_logging_destinations():
            self.add_issue(
                Finding(
                    rule_id="hp.procurve.logging.remote_destination",
                    device=parser.device_type,
                    title="No remote syslog destination is configured",
                    observation="No active AOS-S 'logging <address>' destination was found.",
                    impact="Security events may be lost with local log rollover or device compromise.",
                    exploitability="An attacker who gains device access can benefit from reduced external evidence.",
                    recommendation="Configure at least one protected remote syslog destination.",
                    severity=Severity.MEDIUM,
                    evidence=("remote logging destination absent",),
                    references=(AOS_SWITCH_SECURITY_GUIDE,),
                )
            )
        associations = hp.get_sntp_associations()
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
                            evidence=tuple(item.text for item in association.evidence),
                            references=(AOS_SWITCH_SNTP_GUIDE,),
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
                            evidence=tuple(item.text for item in association.evidence),
                            references=(AOS_SWITCH_SNTP_GUIDE,),
                        )
                    )

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_management(parser)
        self.check_snmp(parser)
        self.check_ssh_crypto(parser)
        self.check_operational_baseline(parser)
        self.check_advanced_baseline(parser)
        self.check_edge_protections(parser)
