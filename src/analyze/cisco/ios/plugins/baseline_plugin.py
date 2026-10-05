import re

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.credentials import credential_policy_from_context, evaluate_credential
from src.analyze.common.controls import ControlOutcome as CO, record_control, record_manual_review
from src.analyze.common.issue import Finding, FindingBasis, Severity
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.common.policy_semantics import ProofState, network_covers, service_covers
from src.devices.cisco.ios import CiscoIOSParser, ConfigurationState
from src.devices.common.models import DefaultCredentialAssessment


CISCO_IOS_HARDENING_GUIDE = (
    "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
)
CISCO_XE_SECURITY_WARNINGS = (
    "https://www.cisco.com/c/en/us/about/trust-center/resilient-infrastructure/"
    "resilient-infrastructure-security-warnings-reference.html"
)
CISCO_XE_TLS_SYSLOG = (
    "https://www.cisco.com/c/en/us/support/docs/routers/xe-sd-wan-routers/"
    "222665-sdwan-cisco-ios-xe-tls-syslog-configurat.html"
)
CISCO_IOS_LDAP_GUIDE = (
    "https://www.cisco.com/en/US/docs/ios-xml/ios/sec_usr_ldap/configuration/15-2mt/sec_conf_ldap.html"
)
RFC_3193_L2TP_IPSEC = "https://www.rfc-editor.org/rfc/rfc3193"
CISCO_PPTP_IOS_GUIDE = (
    "https://www.cisco.com/c/en/us/support/docs/ip/point-to-point-tunneling-protocol-pptp/29781-pptp-ios.html"
)
CISCO_PAP_GUIDE = (
    "https://www.cisco.com/c/en/us/support/docs/wan/point-to-point-protocol-ppp/10313-config-pap.html"
)
CISCO_SMART_INSTALL_ADVISORY = (
    "https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-20180409-smi.html"
)
CISCO_SMART_INSTALL_MISUSE = (
    "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/"
    "cisco-sa-20170214-smi"
)
CISCO_IOS_FILE_TRANSFER_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/syst-mgmt/b-system-management/"
    "m_ifs-file-trans-0.html"
)
CISCO_IOSXE_GNMI_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/prog/configuration/179/b_179_programmability_cg/"
    "m_178_prog_gnmi.html"
)
CISCO_IOSXE_SERVICE_ACL_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/prog/configuration/179/"
    "b_179_programmability_cg/m_179_prog_service-level_acls.html"
)
CISCO_IOSXE_SECURITY_WARNINGS = (
    "https://www.cisco.com/c/en/us/about/trust-center/resilient-infrastructure/"
    "resilient-infrastructure-security-warnings-reference.html"
)
CISCO_FHRP_COMMAND_REFERENCE = (
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipapp_fhrp/command/fhp-cr-book/fhp-s2.html"
)
CISCO_HSRP_GUIDE = (
    "https://www.cisco.com/c/en/us/support/docs/ip/hot-standby-router-protocol-hsrp/9234-hsrpguidetoc.html"
)
CISCO_NTP_ACCESS_GROUP_REFERENCE = (
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/bsm/command/bsm-cr-book/bsm-cr-n1.html"
)
_TYPE6_KEY_CONTEXTS = frozenset({"tacacs_key", "isakmp_pre_shared_key", "keyring_pre_shared_key"})
CISCO_TYPE6_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/sec-vpn/b-security-vpn/"
    "m_sec-encrypt-preshare-0.html"
)
CISCO_PASSWORD_ENCRYPTION_FACTS = (
    "https://www.cisco.com/c/en/us/support/docs/security-vpn/"
    "remote-authentication-dial-user-service-radius/107614-64.html"
)
CISCO_IOS_AGGRESSIVE_MODE_REFERENCE = (
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/a1/sec-a1-cr-book/sec-cr-c4.html"
)
RFC_2409 = "https://www.rfc-editor.org/rfc/rfc2409"
RFC_8907 = "https://www.rfc-editor.org/rfc/rfc8907#section-4.5"
CISCO_IOS_TACACS_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_tacacs/configuration/xe-16/"
    "sec-usr-tacacs-xe-16-book/sec-cfg-tacacs.html"
)
CISCO_IOS_SSH_ALGORITHM_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/security-vpn/"
    "security-vpn/m_sec-secure-shell-algorithm-ccc.html"
)
CISCO_IOS_SNMPV3_GUIDE = (
    "https://www.cisco.com/c/en/us/support/docs/ip/"
    "simple-network-management-protocol-snmp/20370-snmpsecurity-20370.html"
)
CISCO_IOS_ROUTING_HARDENING_GUIDE = (
    "https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening"
)
CISCO_IOS_OSPF_AUTH_GUIDE = (
    "https://www.cisco.com/c/en/us/support/docs/ip/"
    "open-shortest-path-first-ospf/13697-25.html"
)
CISCO_IOS_DISCOVERY_GUIDE = CISCO_IOS_HARDENING_GUIDE
CISCO_IOS_COPP_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/quality-of-service/"
    "quality-of-service/m_qos-plcshp-ctrl-pln-plc-0.html"
)
CISCO_IOS_CHANGE_LOG_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/system-management/"
    "system-management/m_cm-config-logger-0.html"
)
CISCO_IOS_ARCHIVE_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/system-management/"
    "system-management/m_cm-config-versioning.html"
)
CISCO_IOS_AUTHORIZATION_GUIDE = (
    "https://www.cisco.com/c/dam/en/us/td/docs/ios/security/configuration/guide/12_4t/sec_12_4t_book.pdf"
)
CISCO_IOS_ACCOUNTING_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/ios/sec_user_services/configuration/guide/convert/aaa/sec_cfg_accountg.html"
)
CISCO_IOS_AAA_GROUP_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/security-vpn/security-vpn/m_sec-rad-aaa-server-groups.html"
)
CISCO_IOS_IPV6_FHS_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/"
    "configuration_guide/sec/b_1712_sec_9300_cg/configuring_ipv6_first_hop_security.html"
)
RFC_9099 = "https://www.rfc-editor.org/rfc/rfc9099.html"
CISCO_IOS_DOT1X_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_8021x/"
    "configuration/xe-3e/sec-usr-8021x-xe-3e-book/config-ieee-802x-pba.html"
)
CISCO_IOS_OPEN_AUTH_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_8021x/"
    "configuration/xe-3e/sec-usr-8021x-xe-3e-book/sec-ieee-open-auth.html"
)
CISCO_IOS_BPDU_GUARD_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/lanswitch/"
    "command/lsw-cr-book/lsw-s2.html"
)
CISCO_IOS_RIP_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/ios/"
    "iproute_rip/command/reference/irr_book/irr_rip.html"
)
CISCO_IOS_ISIS_AUTH_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_isis/"
    "configuration/xe-3e/irs-xe-3e-book/rs-scty-0.html"
)
CISCO_IOS_EIGRP_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/"
    "iproute_eigrp/command/ire-cr-book/ire-i1.html"
)
CISCO_IOS_BGP_PREFIX_FILTER_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/"
    "ip-routing/b-ip-routing/m_irg-external-sp-0.html"
)
CISCO_IOS_ROUTE_MAP_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/"
    "ip-routing/b-ip-routing/m_iri-iprouting.html"
)
CISCO_IOS_AS_PATH_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/ios/"
    "iproute_bgp/command/reference/irg_book/irg_bgp2.html"
)
CISCO_IOS_BOOT_CONFIG_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/ios/ios_xe/fundamentals/"
    "configuration/guide/TIPs_conversion/config_mgmt_xe_3s_Book/cf_config-files_xe.html"
)
CISCO_IOS_CNS_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/cns/configuration/xe-16/"
    "cns-xe-16-book/cns-config-agent.html"
)
CISCO_IOS_KEY_LIFETIME_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/ios/"
    "iproute_pi/command/reference/iri_book/iri_pi2.html"
)
# SC-044 release-default sources (docs/agent_notes/INSECURE_DEFAULTS_BY_RELEASE.md).
CISCO_ESM_CR = "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/esm/command/esm-cr-book/esm-cr-a1.html"
CISCO_CAT9200_SSH_1712 = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/"
    "configuration_guide/sec/b_1712_sec_9200_cg/secure_shell_version_2_support.html"
)
CISCO_TERMINAL_SERVICES_CR = (
    "https://www.cisco.com/c/en/us/td/docs/ios/termserv/command/reference/tsv_book/tsv_s1.html"
)
CISCO_IP_ADDRESSING_CR = (
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipaddr/command/ipaddr-cr-book/ipaddr-i4.html"
)
CISCO_IP_ADDRESSING_CR_I3 = (
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipaddr/command/ipaddr-cr-book/ipaddr-i3.html"
)
CISCO_IP_APP_SERVICES_CR = (
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipapp/command/iap-cr-book/iap-i1.html"
)
CISCO_WAN_CR = "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/wan/command/wan-cr-book/wan-s1.html"
CISCO_FUNDAMENTALS_CR_FK = (
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/cf_command_ref/F_through_K.html"
)
CISCO_FUNDAMENTALS_CR_RS = (
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/cf_command_ref/R_through_setup.html"
)
CISCO_INTERFACE_CR_L2 = (
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/interface/command/ir-cr-book/ir-l2.html"
)
CISCO_SECURITY_CR_E1 = (
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/d1/sec-d1-cr-book/sec-cr-e1.html"
)
CISCO_FLEXVPN_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_conn_ike2vpn/configuration/xe-16-10/"
    "sec-flex-vpn-xe-16-10-book/sec-cfg-ikev2-flex.html"
)
CISCO_VTP_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-13/"
    "configuration_guide/vlan/b_1713_vlan_9300_cg/configuring_vtp.html"
)
CISCO_INSECURE_FEATURE_RESTRICTIONS = (
    "https://www.cisco.com/c/en/us/about/trust-center/resilient-infrastructure/"
    "insecure-feature-restrictions-on-ios-xe.html"
)
CISCO_IOS_HTTPS_TRUSTPOINT_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/https/"
    "command/nm-https-cr-book/nm-https-cr-cl-sh.html"
)


class PluginIOSBaseline(BasePlugin):
    """Version-gated IOS hardening baseline beyond HTTP and SSH."""

    @staticmethod
    def _ios(parser: BaseDeviceParser) -> CiscoIOSParser:
        if not isinstance(parser, CiscoIOSParser):
            raise TypeError("PluginIOSBaseline requires an IOS-family parser")
        return parser

    @staticmethod
    def _children(parent) -> list[str]:
        return [child.text.strip() for child in parent.children]

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
        references: tuple[str, ...] = (CISCO_IOS_HARDENING_GUIDE,),
        basis=None,
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            device=parser.device_type,
            title=title,
            observation=observation,
            impact=impact,
            exploitability="An attacker with management-plane or configuration access may exploit this weakness.",
            recommendation=recommendation,
            severity=severity,
            evidence=evidence,
            references=references,
            basis=basis,
        )

    def _global_lines(self, parser: BaseDeviceParser) -> list[str]:
        return self._ios(parser)._global_lines()

    @staticmethod
    def _effective_toggle(lines: list[str], positive: str, negative: str) -> bool:
        state = False
        for line in lines:
            if re.fullmatch(positive, line):
                state = True
            elif re.fullmatch(negative, line):
                state = False
        return state

    def _applicable(self, parser: BaseDeviceParser) -> bool:
        # Defaults and syntax vary by train. Unknown software is explicitly not
        # treated as proof that a baseline control is absent.
        return self._ios(parser).get_version() != "?"

    def check_aaa(self, parser: BaseDeviceParser) -> None:
        lines = self._global_lines(parser)
        aaa_enabled = self._effective_toggle(lines, r"aaa new-model", r"no aaa new-model")
        if not aaa_enabled:
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.aaa.new_model",
                    "Centralized AAA is not enabled",
                    "The effective configuration does not enable 'aaa new-model'.",
                    "Authentication, authorization, and accounting policy may be inconsistent and locally controlled.",
                    "Enable AAA new-model and define a tested local fallback before applying it to management lines.",
                    Severity.HIGH,
                    ("aaa new-model not present or negated",),
                )
            )
            return
        if not any(re.fullmatch(r"aaa authentication login\s+\S+\s+.+", line) for line in lines):
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.aaa.login_authentication",
                    "AAA login authentication method list is missing",
                    "AAA is enabled but no login authentication method list is configured.",
                    "Management lines may fall back to an unintended authentication behavior.",
                    "Configure an 'aaa authentication login' method list with an appropriate local fallback.",
                    Severity.HIGH,
                    ("aaa new-model",),
                )
            )
        if not any(re.fullmatch(r"aaa accounting (?:exec|commands)\s+.+", line) for line in lines):
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.aaa.accounting",
                    "Administrative AAA accounting is missing",
                    "AAA is enabled but no EXEC or command accounting method is configured.",
                    "Administrative activity may not be attributable or centrally auditable.",
                    "Configure start-stop EXEC and command accounting to a resilient AAA service.",
                    Severity.MEDIUM,
                    ("aaa new-model",),
                )
            )

    def check_management_lines(self, parser: BaseDeviceParser) -> None:
        ios = self._ios(parser)
        aaa_enabled = self._effective_toggle(
            self._global_lines(parser), r"aaa new-model", r"no aaa new-model"
        )
        has_local_users = any(
            item.context == "local_user" for item in ios.get_credential_metadata()
        )
        aaa_server_groups = ios.get_aaa_server_groups()

        def login_backend_resolves(item) -> bool:
            if "none" in item.methods or ("local" in item.methods and not has_local_users):
                return False
            for index, method in enumerate(item.methods):
                if method != "group":
                    continue
                if index + 1 >= len(item.methods):
                    return False
                group = item.methods[index + 1]
                if group not in {"radius", "tacacs+"} and group not in aaa_server_groups:
                    return False
            return bool(item.methods)

        login_lists = {
            item.name for item in ios.get_aaa_method_lists()
            if item.service == "login_authentication" and login_backend_resolves(item)
        }

        def authentication_resolves(line) -> bool:
            if line.login_kind == "local":
                return has_local_users
            if aaa_enabled and line.login_kind == "aaa" and line.login_list:
                return line.login_list in login_lists
            return False

        for timeout in ios.get_effective_line_timeouts():
            if (
                timeout.active is not True
                or not timeout.timeout_configured
                or timeout.timeout_parse_error
                or timeout.timeout_minutes is None
                or timeout.timeout_seconds is None
            ):
                continue
            evidence = tuple(item for item in timeout.evidence)
            total_seconds = timeout.timeout_minutes * 60 + timeout.timeout_seconds
            if total_seconds == 0:
                rule_scope = "auxiliary" if timeout.line_type == "aux" else timeout.line_type
                self.add_issue(self._finding(
                    parser,
                    f"cisco.ios.{rule_scope}.session_timeout",
                    f"{timeout.line_type.upper()} session timeout is disabled",
                    f"{timeout.line} uses an unlimited exec-timeout.",
                    "Abandoned authenticated sessions can remain usable indefinitely.",
                    "Configure a finite 'exec-timeout' of ten minutes or less.",
                    Severity.MEDIUM,
                    evidence,
                ))
            elif total_seconds > 600:
                self.add_issue(self._finding(
                    parser,
                    "cisco.ios.line.session_timeout_excessive",
                    "Interactive line idle timeout is excessive",
                    f"{timeout.line} permits {timeout.timeout_minutes} minutes and {timeout.timeout_seconds} seconds of inactivity before logout.",
                    "An unattended authenticated session remains available longer than the documented ten-minute baseline.",
                    "Set 'exec-timeout' to ten minutes or less after validating the operational requirement.",
                    Severity.MEDIUM,
                    evidence,
                ))

        # SC-044 IOS-03: Terminal Services CR, 'transport input all' was the default
        # before 15.4(3)M4, so trains up to 15.3 accept Telnet when the line is absent.
        train = ios.get_train()
        legacy_vty_default = bool(train and train < (15, 4) and not ios.is_iosxe())
        for line in ios.get_management_lines("vty"):
            evidence = tuple(item for item in line.evidence)
            if line.transports is None or any(
                token in line.transports for token in ("telnet", "all")
            ):
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.vty.telnet",
                        "VTY permits clear-text Telnet",
                        f"{line.line} does not explicitly restrict inbound transport to SSH.",
                        "Remote administrative credentials and commands may traverse the network without encryption.",
                        "Configure 'transport input ssh' on every VTY range.",
                        Severity.HIGH,
                        (evidence or (line.line,)) + (
                            (f"version {ios.get_version()}: default 'transport input all' before 15.4(3)M4",)
                            if line.transports is None and legacy_vty_default else ()
                        ),
                        references=(
                            (CISCO_IOS_HARDENING_GUIDE, CISCO_TERMINAL_SERVICES_CR)
                            if line.transports is None and legacy_vty_default
                            else (CISCO_IOS_HARDENING_GUIDE,)
                        ),
                        basis=(
                            (FindingBasis.DOCUMENTED_DEFAULT if legacy_vty_default
                             else FindingBasis.MISSING_EXPLICIT_SETTING)
                            if line.transports is None
                            else FindingBasis.EXPLICIT_VALUE
                        ),
                    )
                )
            if line.output_transports and any(
                item in {"telnet", "rlogin", "all"} for item in line.output_transports
            ):
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.vty.insecure_output_transport",
                        "VTY permits insecure outbound terminal transport",
                        f"{line.line} explicitly permits an insecure outbound transport.",
                        "An administrator can initiate clear-text reverse terminal sessions through the device.",
                        "Set 'transport output ssh' or 'transport output none'.",
                        Severity.MEDIUM,
                        evidence or (line.line,),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )

        self.check_effective_vty_aaa(parser)

        for console in ios.get_management_lines("console"):
            evidence = tuple(item for item in console.evidence)
            if not authentication_resolves(console):
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.console.authentication",
                        "Console authentication is not explicitly secured",
                        f"{console.line} lacks a resolvable local or AAA login binding.",
                        "Physical or terminal-server access may reach an unintended authentication path.",
                        "Bind the console to a tested AAA login method with an appropriate local recovery path.",
                        Severity.HIGH,
                        evidence or (console.line,),
                    )
                )

        for auxiliary in ios.get_management_lines("aux"):
            evidence = tuple(item for item in auxiliary.evidence)
            fully_disabled = (
                auxiliary.exec_enabled is False
                and auxiliary.transports == ("none",)
                and auxiliary.output_transports == ("none",)
            )
            if fully_disabled:
                continue
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.auxiliary.enabled",
                    "Auxiliary management line is not fully disabled",
                    f"{auxiliary.line} does not combine 'no exec', 'transport input none', and 'transport output none'.",
                    "An unused AUX port can provide an additional local, modem, or reverse-terminal management path.",
                    "Disable the AUX line using the complete Cisco hardening sequence unless it has an approved operational use.",
                    Severity.HIGH,
                    evidence or (auxiliary.line,),
                )
            )
            if auxiliary.exec_enabled is not False and not authentication_resolves(auxiliary):
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.auxiliary.authentication",
                        "Active auxiliary line lacks resolved authentication",
                        f"{auxiliary.line} is not disabled and lacks a resolvable local or AAA login binding.",
                        "A reachable AUX session may use an unintended or line-password authentication path.",
                        "Disable the line or bind it to a tested AAA login method.",
                        Severity.HIGH,
                        evidence or (auxiliary.line,),
                )
            )

    def check_effective_vty_aaa(self, parser: BaseDeviceParser) -> None:
        ios = self._ios(parser)
        aaa_enabled = self._effective_toggle(
            self._global_lines(parser), r"aaa new-model", r"no aaa new-model"
        )
        has_local_users = any(
            item.context == "local_user" for item in ios.get_credential_metadata()
        )
        methods = {
            (item.service, item.name, item.privilege_level): item
            for item in ios.get_aaa_method_lists()
        }
        accounting = {
            (item.service, item.name, item.privilege_level): item
            for item in ios.get_aaa_accounting_lists()
        }
        groups = {}
        for item in ios.get_aaa_server_group_records():
            groups.setdefault(item.name, []).append(item)

        def referenced_groups(tokens: tuple[str, ...]) -> tuple[str, ...]:
            return tuple(
                tokens[index + 1] for index, token in enumerate(tokens[:-1])
                if token.casefold() == "group"
            )

        def valid(item, *, authentication: bool = False) -> bool:
            if item is None or not item.methods:
                return False
            if item.methods[-1].casefold() == "group":
                return False
            if any(
                group.casefold() not in {"radius", "tacacs+"} and group not in groups
                for group in referenced_groups(item.methods)
            ):
                return False
            if authentication and (
                "none" in item.methods or ("local" in item.methods and not has_local_users)
            ):
                return False
            return True

        for line in ios.get_effective_vty_aaa():
            if not line.active:
                continue
            evidence = tuple(item for item in line.evidence)
            login = methods.get(("login_authentication", line.login_list, None))
            authenticated = (
                line.login_kind == "local" and has_local_users
                or aaa_enabled and line.login_kind == "aaa" and valid(login, authentication=True)
            )
            if not authenticated:
                reason = (
                    f"references undefined AAA login list '{line.login_list}'"
                    if line.login_kind == "aaa" and login is None
                    else "lacks a resolvable local or AAA login binding"
                )
                self.add_issue(self._finding(
                    parser, "cisco.ios.vty.authentication",
                    "VTY authentication is not explicitly bound",
                    f"{line.line} {reason}.",
                    "The line may use an unintended password-only or default authentication path.",
                    "Bind each VTY range to a named AAA login method or explicit local authentication.",
                    Severity.HIGH, evidence or (line.line,),
                ))

            if not aaa_enabled:
                continue
            exec_name = line.exec_authorization_list or "default"
            command_name = line.command_authorization_list or "default"
            exec_method = methods.get(("exec_authorization", exec_name, None))
            command_method = methods.get(("command_authorization", command_name, 15))
            missing = []
            if not valid(exec_method):
                missing.append("EXEC authorization")
            if not valid(command_method):
                missing.append("privilege-15 command authorization")
            if missing:
                self.add_issue(self._finding(
                    parser, "cisco.ios.vty.authorization",
                    "VTY administrative authorization is incomplete",
                    f"{line.line} lacks resolved {', '.join(missing)}.",
                    "Authenticated administrators may receive unintended EXEC access or execute commands without centralized authorization.",
                    "Define and bind resolved AAA EXEC and privilege-15 command authorization method lists.",
                    Severity.HIGH, evidence or (line.line,),
                ))

            bypass = [
                service for service, item in (("EXEC", exec_method), ("privilege-15 commands", command_method))
                if item is not None and any(
                    method.casefold() in {"none", "if-authenticated"} for method in item.methods
                )
            ]
            if bypass:
                self.add_issue(self._finding(
                    parser, "cisco.ios.vty.authorization_bypass",
                    "VTY authorization has an explicit bypass method",
                    f"{line.line} binds {', '.join(bypass)} to an authorization list containing 'none' or 'if-authenticated'.",
                    "A configured fallback can allow access without a server-backed or local privilege decision; this does not imply unauthenticated login.",
                    "Replace the bypass method with an approved server-backed or local authorization fallback.",
                    Severity.HIGH,
                    evidence + tuple(item.evidence for item in (exec_method, command_method) if item is not None),
                    (CISCO_IOS_AUTHORIZATION_GUIDE,),
                ))

            selected_accounting = []
            missing_explicit = []
            for service, level, explicit in (
                ("exec", None, line.exec_accounting_list),
                ("commands", 15, line.command_accounting_list),
            ):
                name = explicit or "default"
                item = accounting.get((service, name, level))
                if item is not None:
                    selected_accounting.append(item)
                elif explicit:
                    missing_explicit.append(f"{service} list '{explicit}'")
            disabled_accounting = [
                item for item in selected_accounting if item.record_type == "none"
            ]
            if missing_explicit or (accounting and not any(
                item.record_type != "none" and valid(item) for item in selected_accounting
            ) and not disabled_accounting):
                self.add_issue(self._finding(
                    parser, "cisco.ios.vty.accounting_unbound",
                    "Administrative accounting list is not effective on VTY",
                    (
                        f"{line.line} references undefined {', '.join(missing_explicit)}."
                        if missing_explicit else
                        f"{line.line} has no effective EXEC or privilege-15 command accounting list despite configured accounting declarations."
                    ),
                    "Administrative actions on this line may not generate central accounting records.",
                    "Bind a usable named accounting list to the line or define an effective default list.",
                    Severity.MEDIUM,
                    evidence + tuple(item.evidence for item in selected_accounting),
                    (CISCO_IOS_ACCOUNTING_GUIDE,),
                ))
            if disabled_accounting:
                self.add_issue(self._finding(
                    parser, "cisco.ios.vty.accounting_disabled",
                    "VTY accounting is explicitly disabled",
                    f"{line.line} selects an EXEC or privilege-15 command accounting list with record type 'none'.",
                    "That selected accounting service does not create administrative activity records.",
                    "Use an approved start-stop or stop-only accounting method on this line.",
                    Severity.MEDIUM,
                    evidence + tuple(item.evidence for item in disabled_accounting),
                    (CISCO_IOS_ACCOUNTING_GUIDE,),
                ))

            bound_lists = tuple(
                item for item in (login, exec_method, command_method, *selected_accounting)
                if item is not None
            )
            unusable = sorted({
                group for item in bound_lists for group in referenced_groups(item.methods)
                if group.casefold() not in {"radius", "tacacs+"}
                and (group not in groups or not any(record.members for record in groups[group]))
            })
            if unusable:
                self.add_issue(self._finding(
                    parser, "cisco.ios.vty.aaa_server_group_unusable",
                    "Bound AAA list references an unusable server group",
                    f"{line.line} references an undefined or explicitly empty AAA server group: {', '.join(unusable)}.",
                    "Remote AAA cannot use the named group as configured; a separate local fallback may still work.",
                    "Define the referenced group with qualified server members or remove the unusable method.",
                    Severity.HIGH,
                    evidence + tuple(record.evidence for name in unusable
                                     for record in groups.get(name, ())),
                    (CISCO_IOS_AAA_GROUP_GUIDE,),
                ))

    def check_ssh_policy(self, parser: BaseDeviceParser) -> None:
        ios = self._ios(parser)
        if ios.get_ssh_state().value != "enabled":
            return
        weak_algorithms = {
            "encryption": {"des", "3des", "3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc"},
            "mac": {"hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96"},
            "kex": {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"},
            "hostkey": {"ssh-dss", "ssh-rsa"},
        }
        weak = []
        evidence = []
        for policy in ios.get_ssh_server_algorithms():
            if policy.algorithms is None:
                continue
            selected = sorted(set(policy.algorithms) & weak_algorithms[policy.category])
            if selected:
                weak.append(f"{policy.category}: {', '.join(selected)}")
                evidence.extend(item for item in policy.evidence)
        if weak:
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.ssh.weak_algorithms",
                    "SSH server explicitly permits weak algorithms",
                    "The explicit SSH server policy includes " + "; ".join(weak) + ".",
                    "Legacy SSH algorithms weaken confidentiality, integrity, key exchange, or host authentication.",
                    "Restrict the SSH server to release-supported AES-CTR/GCM, SHA-2/EtM, modern KEX, and SHA-2/EdDSA host-key algorithms.",
                    Severity.HIGH,
                    tuple(evidence),
                    (CISCO_IOS_SSH_ALGORITHM_GUIDE,),
                )
            )
        # SC-044 IOS-17: Catalyst 9200 17.12 SSH guide, 'Starting from Cisco IOS XE
        # Release 17.10, the following Key Exchange and MAC algorithms are removed from
        # the default list': diffie-hellman-group14-sha1 and hmac-sha1 (plus sha2 non-EtM).
        train = ios.get_train()
        configured = {policy.category for policy in ios.get_ssh_server_algorithms() if policy.algorithms is not None}
        if ios.is_iosxe() and train and (16, 0) <= train < (17, 10):
            defaults = []
            if "kex" not in configured:
                defaults.append("kex: default list includes diffie-hellman-group14-sha1")
            if "mac" not in configured:
                defaults.append("mac: default list includes hmac-sha1")
            if defaults:
                self.add_issue(self._finding(
                    parser,
                    "cisco.ios.ssh.weak_algorithms",
                    "SSH server uses default algorithm lists that include SHA-1",
                    f"IOS XE {train[0]}.{train[1]} has no 'ip ssh server algorithm' line for "
                    + " and ".join(item.split(":")[0] for item in defaults)
                    + "; before 17.10 the default lists still offer SHA-1 key exchange and MACs.",
                    "SHA-1 based key exchange and integrity are deprecated and weaken administrative sessions.",
                    "Set 'ip ssh server algorithm kex ecdh-sha2-nistp256 ...' and 'ip ssh server algorithm mac hmac-sha2-256-etm@openssh.com ...', or upgrade to 17.10 or later.",
                    Severity.LOW,
                    tuple(defaults),
                    (CISCO_IOS_SSH_ALGORITHM_GUIDE, CISCO_CAT9200_SSH_1712),
                    basis=FindingBasis.DOCUMENTED_DEFAULT,
                ))
        key = ios.get_ssh_rsa_key_modulus()
        if key.configured and key.value is not None and key.value < 2048:
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.ssh.weak_host_key",
                    "Explicit SSH RSA host key is undersized",
                    f"The recorded RSA key-generation command specifies a {key.value}-bit modulus.",
                    "An undersized host key provides inadequate resistance to key recovery.",
                    "Generate a release-supported RSA key of at least 2048 bits or a stronger supported host-key type.",
                    Severity.HIGH,
                    (key.raw_line,),
                    (CISCO_IOS_SSH_ALGORITHM_GUIDE,),
                )
            )

    def check_acl_effectiveness(self, parser: BaseDeviceParser) -> None:
        """Report only same-attachment first-match relationships proven statically."""
        earlier_by_scope = {}
        for rule in self._ios(parser).get_attached_acl_semantics():
            if not rule.proof_eligible:
                continue
            earlier_rules = earlier_by_scope.setdefault(rule.scope.casefold(), [])
            for earlier in earlier_rules:
                if earlier.family != rule.family or not all(
                    state == ProofState.PROVEN
                    for state in (
                        network_covers(earlier.source_networks, rule.source_networks),
                        network_covers(
                            earlier.destination_networks, rule.destination_networks
                        ),
                        service_covers(earlier.services, rule.services),
                    )
                ):
                    continue
                same_action = earlier.action == rule.action
                if same_action and earlier.behavior_signature != rule.behavior_signature:
                    continue
                self.add_issue(self._finding(
                    parser,
                    (
                        "cisco.ios.acl.redundant_rule"
                        if same_action
                        else "cisco.ios.acl.shadowed_rule"
                    ),
                    "Attached IOS ACL rule is redundant" if same_action else "Attached IOS ACL rule is shadowed",
                    f"ACL entry '{rule.name}' at position {rule.position} in attachment '{rule.scope}' is fully covered by earlier entry '{earlier.name}' at position {earlier.position} with {'equivalent behavior' if same_action else 'a different terminal action'}.",
                    "The later entry cannot alter first-match filtering for the statically proven traffic scope; a conflicting shadowed entry can give reviewers a false impression of enforced access control.",
                    "Remove or reorder the entry after validating interface direction, address/service scope, logging and operational intent.",
                    Severity.LOW if same_action else Severity.HIGH,
                    tuple(item for item in rule.evidence + earlier.evidence),
                    (CISCO_IOS_HARDENING_GUIDE,),
                ))
                break
            earlier_rules.append(rule)

    def check_credentials(self, parser: BaseDeviceParser) -> None:
        policy = credential_policy_from_context(parser.assessment_context)
        for credential in (*parser.get_credential_metadata(), *self._ios(parser).get_additional_credential_metadata()):
            result = evaluate_credential(credential, policy)
            if credential.default_assessment == DefaultCredentialAssessment.MATCH and credential.storage_type == "0":
                self.add_issue(self._finding(
                    parser,
                    "cisco.ios.credentials.known_default_value",
                    "Known weak plaintext credential value",
                    f"The {credential.context.replace('_', ' ')} credential at '{credential.account}' matches the exact known-default list under policy '{result.policy_version}'. The value is redacted.",
                    "A widely known credential can permit direct administrative access.",
                    "Replace it with a unique strong value and prefer centralized AAA.",
                    Severity.HIGH,
                    tuple(item for item in credential.evidence),
                ))
            if not result.unsafe_storage:
                continue
            if credential.context == "local_user":
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.credentials.local_storage",
                        "Local credential uses weak storage",
                        (
                            f"User '{credential.account}' uses '{credential.method}' storage type "
                            f"'{credential.storage_type}', classified as "
                            f"'{result.storage_assessment.value}' under credential policy "
                            f"'{result.policy_version}'; the separate blocklist comparison "
                            f"{result.blocklist_summary}. The credential is redacted."
                        ),
                        "Plaintext, reversible, or legacy hashes are more readily recovered from a configuration disclosure.",
                        "Use a supported strong secret algorithm and migrate administrative authentication to AAA.",
                        Severity.HIGH,
                        tuple(item for item in credential.evidence),
                    )
                )
            elif credential.context == "enable":
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.credentials.enable_storage",
                        "Enable credential uses weak storage",
                        (
                            f"The enable credential uses storage type '{credential.storage_type}', "
                            f"classified as '{result.storage_assessment.value}' under credential policy "
                            f"'{result.policy_version}'; the separate blocklist comparison "
                            f"{result.blocklist_summary}. Its value is redacted."
                        ),
                        "Configuration disclosure can expose or accelerate recovery of the privileged credential.",
                        "Replace it with a strong 'enable secret' algorithm and remove the enable password.",
                        Severity.HIGH,
                        tuple(item for item in credential.evidence),
                    )
                )
            elif credential.context in {"radius_key", "line_password", *_TYPE6_KEY_CONTEXTS}:
                self.add_issue(self._finding(
                    parser,
                    f"cisco.ios.credentials.{credential.context}_storage",
                    "Shared or line credential uses unsafe storage",
                    f"The {credential.context.replace('_', ' ')} at '{credential.account}' uses storage type '{credential.storage_type}', classified as '{result.storage_assessment.value}' under policy '{result.policy_version}'. The value is redacted.",
                    "Configuration disclosure can expose or permit recovery of the credential.",
                    ("Store the key as type 6 (AES) where the release supports it: configure "
                     "'key config-key password-encrypt' and 'password encryption aes', then rotate the "
                     "exposed value."
                     if credential.context in _TYPE6_KEY_CONTEXTS
                     else "Use supported protected storage and rotate the exposed value."),
                    Severity.HIGH,
                    tuple(item for item in credential.evidence),
                    references=(
                        (CISCO_TYPE6_GUIDE, CISCO_PASSWORD_ENCRYPTION_FACTS)
                        if credential.context in _TYPE6_KEY_CONTEXTS
                        else (CISCO_IOS_HARDENING_GUIDE,)
                    ),
                    basis=FindingBasis.EXPLICIT_VALUE if credential.context in _TYPE6_KEY_CONTEXTS else None,
                ))

    def check_snmp(self, parser: BaseDeviceParser) -> None:
        for community, access, evidence in self._ios(parser).get_snmp_community_metadata():
            problems = ["community-based SNMP"]
            if community.casefold() in {"public", "private"}:
                problems.append("an exact default community")
                self.add_issue(self._finding(
                    parser,
                    "cisco.ios.snmp.default_community",
                    "Known default SNMP community is configured",
                    "An active SNMPv1/v2c community matches the exact default-community list; its value is redacted.",
                    "Widely known community strings can allow unauthorized SNMP access.",
                    "Replace the community with a unique value, restrict managers, and migrate to SNMPv3 authPriv.",
                    Severity.HIGH,
                    (evidence,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
            if access == "rw":
                problems.append("read-write access")
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.snmp.legacy_community",
                    "Legacy SNMP community configured",
                    f"An SNMPv1/v2c community uses {', '.join(problems)}. The value is redacted.",
                    "Community-based SNMP lacks modern per-user authentication and privacy protections.",
                    "Migrate to SNMPv3 authPriv, restrict managers, and remove v1/v2c communities.",
                    Severity.HIGH if access == "rw" else Severity.MEDIUM,
                    (evidence,),
                )
            )

        views, groups, users = self._ios(parser).get_snmpv3_relationships()
        view_map = {view.name.casefold(): view for view in views}
        group_map = {group.name.casefold(): group for group in groups}
        for user in users:
            evidence = tuple(item for item in user.evidence)
            if not user.group_resolved or (user.read_view and not user.read_view_resolved):
                unresolved = (
                    f"group '{user.group}'"
                    if not user.group_resolved
                    else f"read view '{user.read_view}'"
                )
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.snmp.v3_reference",
                        "SNMPv3 user references an unresolved access object",
                        f"SNMPv3 user '{user.name}' references unresolved {unresolved}.",
                        "An unresolved group or view prevents the configuration from proving the intended SNMP access policy.",
                        "Create the referenced SNMPv3 group/view or bind the user to an existing least-privileged object.",
                        Severity.MEDIUM,
                        evidence,
                        (CISCO_IOS_SNMPV3_GUIDE,),
                    )
                )
                continue

            protection_gaps = []
            if user.group_security_level != "priv":
                protection_gaps.append(
                    f"group security level is '{user.group_security_level or 'unknown'}'"
                )
            if not user.authentication:
                protection_gaps.append("authentication is not configured")
            if not user.privacy:
                protection_gaps.append("privacy is not configured")
            if protection_gaps:
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.snmp.v3_protection",
                        "SNMPv3 user lacks authPriv protection",
                        f"SNMPv3 user '{user.name}' has " + "; ".join(protection_gaps) + ".",
                        "SNMP management data may lack strong origin authentication or confidentiality.",
                        "Use a v3 priv group and configure the user with supported authentication and AES privacy.",
                        Severity.HIGH,
                        evidence,
                        (CISCO_IOS_SNMPV3_GUIDE,),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )

            weak = []
            if user.authentication == "md5":
                weak.append("MD5 authentication")
            if user.privacy in {"des", "des56", "3des"}:
                weak.append(f"{user.privacy.upper()} privacy")
            if weak:
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.snmp.v3_weak_algorithm",
                        "SNMPv3 user uses a weak algorithm",
                        f"SNMPv3 user '{user.name}' uses {', '.join(weak)}.",
                        "Legacy SNMP authentication or privacy algorithms provide inadequate cryptographic strength.",
                        "Use a supported SHA-family authentication algorithm and AES privacy; validate SHA-2 availability for the exact IOS XE platform and release.",
                        Severity.MEDIUM,
                        evidence,
                        (CISCO_IOS_SNMPV3_GUIDE,),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )

            view = view_map.get(user.read_view.casefold()) if user.read_view else None
            broad_view = not user.read_view or bool(
                view
                and set(view.included_subtrees) & {"iso", "internet", "1", "1.3.6.1"}
                and not view.excluded_subtrees
            )
            group = group_map.get(user.group.casefold())
            access_gaps = []
            if not user.source_restricted:
                access_gaps.append("no user or group source ACL")
            if broad_view:
                access_gaps.append("the default or an unrestricted read view")
            if group and group.write_view:
                access_gaps.append(f"write view '{group.write_view}'")
            if access_gaps:
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.snmp.v3_access_scope",
                        "SNMPv3 user has broad access scope",
                        f"SNMPv3 user '{user.name}' has " + "; ".join(access_gaps) + ".",
                        "A compromised monitoring identity may query excessive MIB data, reach the agent from unintended networks, or modify managed objects.",
                        "Apply a restrictive read view and source ACL; remove write access unless explicitly required.",
                        Severity.HIGH if group and group.write_view else Severity.MEDIUM,
                        evidence,
                        (CISCO_IOS_SNMPV3_GUIDE,),
                    )
                )

    def check_logging(self, parser: BaseDeviceParser) -> None:
        lines = self._global_lines(parser)
        hosts = [
            line
            for line in lines
            if re.fullmatch(r"logging host\s+\S+\s+\S+(?:\s+.*)?", line)
            or re.fullmatch(r"logging host\s+\S+", line)
            or re.fullmatch(r"logging\s+\d+(?:\.\d+){3}", line)
        ]
        if not hosts:
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.logging.remote_destination",
                    "Remote logging destination is missing",
                    "No active remote syslog destination is configured.",
                    "Events may be lost during compromise or device failure and unavailable to central monitoring.",
                    "Configure one or more protected remote logging hosts.",
                    Severity.MEDIUM,
                    ("No logging host command",),
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                )
            )
            return
        # SC-032: ESM command reference, 'transport (Optional) Method of transport to be
        # used. UDP is the default.' Only BEEP with TLS (or 'transport tls') protects it.
        cleartext = [line for line in hosts if not re.search(r"\btransport\s+(?:beep\b.*\btls\b|tls\b)", line)]
        if cleartext:
            explicit = [line for line in cleartext if re.search(r"\btransport\s+(?:udp|tcp|beep)\b", line)]
            self.add_issue(Finding(
                rule_id="cisco.ios.logging.remote_cleartext",
                device=parser.device_type,
                title="Remote syslog is sent in clear text",
                observation=(f"{len(cleartext)} remote logging host(s) use "
                             + ("an unencrypted transport" if explicit and len(explicit) == len(cleartext)
                                else "the default transport (UDP 514)") + " without TLS."),
                impact="Log messages, which can include user names, addresses and configuration changes, can be read or forged on the path to the collector.",
                exploitability="An attacker on the logging path can capture events or inject false ones to hide activity.",
                recommendation="Send syslog over a protected path (management network or VPN) or use TLS where the platform supports it ('logging host <ip> transport tls' / BEEP with TLS and a trustpoint).",
                severity=Severity.LOW,
                evidence=tuple(cleartext),
                references=(CISCO_ESM_CR,),
                basis=FindingBasis.EXPLICIT_VALUE if len(explicit) == len(cleartext) else FindingBasis.DOCUMENTED_DEFAULT,
            ))
        trap = next((line for line in reversed(lines) if line.startswith("logging trap ")), "")
        levels = {
            "emergencies": 0, "alerts": 1, "critical": 2, "errors": 3,
            "warnings": 4, "notifications": 5, "informational": 6, "debugging": 7,
        }
        value = trap.split()[-1].lower() if trap else ""
        numeric = int(value) if value.isdigit() else levels.get(value)
        if numeric is None or numeric < 6:
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.logging.severity",
                    "Remote logging severity is insufficient",
                    f"The remote logging threshold is '{value or 'not configured'}'.",
                    "Administrative and security-relevant informational events may not be centralized.",
                    "Configure 'logging trap informational' unless policy explicitly requires a different threshold.",
                    Severity.LOW,
                    tuple(hosts) + ((trap,) if trap else ()),
                )
            )

    def check_configuration_management(self, parser: BaseDeviceParser) -> None:
        state = self._ios(parser).get_configuration_management()
        evidence = tuple(item for item in state.evidence)
        if not state.change_logging:
            self.add_issue(self._finding(
                parser,
                "cisco.ios.configuration.change_logging",
                "Configuration-change logging is disabled",
                "The effective archive log-config state does not enable configuration-change logging.",
                "Administrative changes can lack a local per-user, per-session command history.",
                "Enable 'archive / log config / logging enable', suppress keys, and notify syslog.",
                Severity.MEDIUM,
                evidence or ("archive log config logging enable absent",),
                (CISCO_IOS_CHANGE_LOG_GUIDE,),
            ))
        else:
            if not state.hide_keys:
                self.add_issue(self._finding(
                    parser,
                    "cisco.ios.configuration.change_logging_secrets",
                    "Configuration log does not suppress secret values",
                    "Configuration-change logging is enabled without effective 'hidekeys'.",
                    "Credentials entered in configuration commands can be retained in the local change log.",
                    "Enable 'hidekeys' under archive log config and protect any existing log records.",
                    Severity.HIGH,
                    evidence,
                    (CISCO_IOS_CHANGE_LOG_GUIDE,),
                ))
            if not state.notify_syslog:
                self.add_issue(self._finding(
                    parser,
                    "cisco.ios.configuration.change_notification",
                    "Configuration changes are not sent to syslog",
                    "Configuration-change logging is enabled without effective 'notify syslog'.",
                    "The change history remains only on the device and can be lost or altered during compromise.",
                    "Enable 'notify syslog' and verify delivery through the separately configured remote logging path.",
                    Severity.MEDIUM,
                    evidence,
                    (CISCO_IOS_CHANGE_LOG_GUIDE,),
                ))

        archive_complete = bool(state.destination) and state.schedule_state == "effective"
        if state.archive_configured and not archive_complete:
            gaps = []
            if not state.destination:
                gaps.append("no effective archive destination")
            if state.schedule_state != "effective":
                gaps.append(f"schedule state '{state.schedule_state}'")
            self.add_issue(self._finding(
                parser,
                "cisco.ios.configuration.archive_incomplete",
                "Configuration archive is incomplete",
                "The configured archive has " + " and ".join(gaps) + ".",
                "The on-box archive cannot automatically produce usable configuration checkpoints as intended.",
                "Configure a valid path and at least one effective trigger: time-period or write-memory.",
                Severity.MEDIUM,
                evidence,
                (CISCO_IOS_ARCHIVE_GUIDE,),
            ))
        elif (
            parser.assessment_context.configuration_backup_scope == "on-device-required"
            and not archive_complete
        ):
            self.add_issue(self._finding(
                parser,
                "cisco.ios.configuration.archive_required",
                "Required on-device configuration archive is absent",
                "The assessment policy requires on-device configuration archiving, but no complete scheduled archive is configured.",
                "The device lacks the policy-required local or remote configuration checkpoints for rollback.",
                "Configure an archive destination and an effective time-period or write-memory trigger.",
                Severity.MEDIUM,
                evidence or ("assessment policy: on-device configuration backup required",),
                (CISCO_IOS_ARCHIVE_GUIDE,),
            ))
        if state.destination and state.transport_security == "insecure":
            self.add_issue(self._finding(
                parser,
                "cisco.ios.configuration.archive_transport",
                "Configuration archive uses an insecure transport",
                f"The archive destination uses '{state.protocol}' transport: {state.destination}.",
                "Configuration backups can expose credentials, addressing, and security policy in transit.",
                "Use an approved encrypted transfer mechanism or protected local storage supported by the exact platform.",
                Severity.HIGH,
                evidence,
                (CISCO_IOS_ARCHIVE_GUIDE,),
            ))

    def check_ntp(self, parser: BaseDeviceParser) -> None:
        associations = self._ios(parser).get_ntp_associations()
        if not associations:
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.ntp.servers",
                    "NTP synchronization is not configured",
                    "No NTP server or peer is configured.",
                    "Inaccurate time undermines event correlation, certificates, and forensic timelines.",
                    "Configure multiple trusted NTP servers.",
                    Severity.MEDIUM,
                    ("No ntp server or peer command",),
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                )
            )
            return
        for association in associations:
            if association.authentication_state == "authenticated":
                continue
            detail = (
                "has no effective authenticated key binding"
                if association.authentication_state == "unauthenticated"
                else f"references missing or untrusted key '{association.key_id}'"
            )
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.ntp.authentication",
                    "NTP authentication is incomplete",
                    f"NTP {association.role} '{association.address}' in VRF '{association.vrf}' {detail}.",
                    "A spoofed time source can disrupt logs and time-dependent security controls.",
                    "Enable NTP authentication and configure, trust, and bind a key for this association.",
                    Severity.MEDIUM,
                    tuple(item for item in association.evidence),
                )
            )

    def check_banner(self, parser: BaseDeviceParser) -> None:
        lines = self._global_lines(parser)
        if not any(re.match(r"banner (?:login|motd)\s+", line) for line in lines):
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.banner.login",
                    "Login warning banner is missing",
                    "No login or message-of-the-day warning banner is configured.",
                    "Users may not receive the organization's required authorized-use and monitoring notice.",
                    "Configure an approved legal warning with 'banner login'.",
                    Severity.LOW,
                    ("No banner login or banner motd command",),
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                )
            )

    def check_unnecessary_services(self, parser: BaseDeviceParser) -> None:
        ios = self._ios(parser)
        services = ios.get_legacy_services()
        if services:
            names = sorted({name for name, _ in services})
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.services.unnecessary",
                    "Unnecessary legacy services are enabled",
                    f"Explicit legacy service commands are active: {', '.join(names)}.",
                    "Unneeded listeners increase management-plane attack surface.",
                    "Disable every service that is not operationally required using its 'no' form.",
                    Severity.MEDIUM,
                    tuple(evidence for _, evidence in services),
                )
            )
        defaults = ios.get_legacy_default_services()
        if defaults:
            self.add_issue(Finding(
                rule_id="cisco.ios.services.legacy_default",
                device=parser.device_type,
                title="Legacy services are on by default in this old release",
                observation=("The export does not disable services that this IOS train enables by default: "
                             + "; ".join(f"{name} ({reason})" for name, reason in defaults) + "."),
                impact="Finger discloses logged-in users and the small servers (echo, chargen, discard, daytime) can be abused for reflection or denial of service.",
                exploitability="Any host that can reach the device can query these services.",
                recommendation="Add 'no service finger' and 'no service tcp-small-servers' / 'no service udp-small-servers', and plan an upgrade from this unsupported release.",
                severity=Severity.MEDIUM,
                evidence=(f"version {ios.get_version()}",),
                references=(CISCO_IOS_HARDENING_GUIDE, CISCO_IOS_ROUTING_HARDENING_GUIDE),
                basis=FindingBasis.DOCUMENTED_DEFAULT,
            ))
        servers = ios.get_file_and_shell_servers()
        shells = [evidence for kind, evidence in servers if kind in {"rsh", "rcp"}]
        if shells:
            self.add_issue(Finding(
                rule_id="cisco.ios.services.remote_shell",
                device=parser.device_type,
                title="rsh/rcp server is enabled",
                observation="The router accepts remote shell (rsh) or remote copy (rcp) requests.",
                impact="rsh and rcp send commands, files and usernames in clear text and authenticate by remote username and host address, which can be spoofed.",
                exploitability="An attacker who can reach TCP 514 from an allowed host address or spoof one can run commands or copy files, including the configuration.",
                recommendation="Disable with 'no ip rcmd rsh-enable' and 'no ip rcmd rcp-enable' and use SSH/SCP instead.",
                severity=Severity.HIGH,
                evidence=tuple(shells),
                references=(CISCO_IOS_FILE_TRANSFER_GUIDE,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))
        tftp = [evidence for kind, evidence in servers if kind == "tftp"]
        if tftp:
            self.add_issue(Finding(
                rule_id="cisco.ios.services.tftp_server",
                device=parser.device_type,
                title="TFTP server is enabled on the device",
                observation="The device serves files over TFTP ('tftp-server').",
                impact="TFTP has no authentication or encryption; anyone allowed by the optional access list can download the served files.",
                exploitability="An attacker who can reach UDP 69 can download software images or other served files and learn the exact release.",
                recommendation="Remove 'tftp-server' when it is not needed, or restrict it with an access list and use SCP instead.",
                severity=Severity.MEDIUM,
                evidence=tuple(tftp),
                references=(CISCO_IOS_FILE_TRANSFER_GUIDE,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))
        gnmi = ios.get_gnmi_insecure_server()
        if gnmi:
            self.add_issue(Finding(
                rule_id="cisco.ios.management.insecure_protocol",
                device=parser.device_type,
                title="gNMI is enabled without TLS",
                observation="'gnxi server' starts the insecure gNMI server (default port 50052) without TLS.",
                impact="gNMI usernames, passwords and configuration data cross the network in clear text.",
                exploitability="An attacker on the path can capture credentials and read or change the configuration through gNMI.",
                recommendation="Use only 'gnxi secure-server' with a trustpoint and remove 'gnxi server'; Cisco documents insecure mode for day-zero setup only.",
                severity=Severity.HIGH,
                evidence=(gnmi,),
                references=(CISCO_IOSXE_GNMI_GUIDE,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))

    def check_pptp_dialin(self, parser: BaseDeviceParser) -> None:
        """SC-013: explicitly configured PPTP dial-in; reachability and logins are not proven."""
        groups = self._ios(parser).get_pptp_dialin_groups()
        record_control(parser, "cisco.ios.pptp-dialin", CO.FINDING if groups else CO.NO_FINDING,
                       "A VPDN group accepts PPTP dial-in." if groups
                       else "No VPDN group accepts PPTP dial-in while 'vpdn enable' is in effect.")
        for group in groups:
            template = (f"Virtual-Template{group.virtual_template}" if group.virtual_template
                        else "no virtual-template")
            if group.authentication:
                auth = f" The template's PPP authentication order is {' '.join(group.authentication)}"
                auth += (", which permits PAP (cleartext passwords inside the tunnel)." if "pap" in group.authentication
                         else ".")
            else:
                auth = " No explicit PPP authentication method was resolved on the template."
            self.add_issue(Finding(
                rule_id="cisco.ios.vpn.pptp_gateway",
                device=parser.device_type,
                title="Legacy PPTP VPN dial-in is enabled",
                observation=(f"VPDN is enabled and vpdn-group '{group.group}' accepts PPTP dial-in using {template}."
                             + auth + " External reachability and successful client authentication are not established by this export."),
                impact="PPTP relies on MS-CHAP/MPPE or weaker methods; captured sessions can be cracked offline and the protocol is deprecated.",
                exploitability="A client that can reach TCP 1723 and GRE on the router may negotiate the legacy protocol.",
                recommendation="Migrate remote access to IKEv2/IPsec or another supported VPN and remove 'protocol pptp' from the VPDN group (or 'no vpdn enable').",
                severity=Severity.HIGH,
                evidence=group.evidence,
                references=(CISCO_PPTP_IOS_GUIDE, CISCO_PAP_GUIDE),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))

    def check_l2tp_dialin(self, parser: BaseDeviceParser) -> None:
        """SC-013: L2TP dial-in on a router with no IPsec configuration at all."""
        ios = self._ios(parser)
        groups = ios.get_l2tp_dialin_groups()
        if groups and ios.has_ipsec_configuration():
            record_manual_review(parser, "L2TP dial-in with IPsec configuration present",
                                 "Whether the L2TP sessions are protected by the configured IPsec policy is not evaluated.")
        if not groups or ios.has_ipsec_configuration():
            return
        for group in groups:
            auth = (f" The template's PPP authentication order is {' '.join(group.authentication)}."
                    if group.authentication else "")
            self.add_issue(Finding(
                rule_id="cisco.ios.vpn.l2tp_without_ipsec",
                device=parser.device_type,
                title="L2TP dial-in without IPsec on this router",
                observation=(f"vpdn-group '{group.group}' accepts L2TP dial-in and the configuration contains no crypto map, "
                             "IPsec profile or transform set, so the router itself does not protect the tunnel." + auth
                             + " Protection by another device on the path is not visible in this export."),
                impact="L2TP provides no confidentiality; PPP authentication and user traffic inside the tunnel can be read or altered in transit.",
                exploitability="Requires the ability to observe or intercept traffic between clients and the router.",
                recommendation="Run L2TP only inside IPsec (L2TP/IPsec, RFC 3193) or migrate to an IKEv2/IPsec remote-access VPN.",
                severity=Severity.MEDIUM,
                evidence=group.evidence,
                references=(RFC_3193_L2TP_IPSEC, CISCO_PPTP_IOS_GUIDE),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))

    def check_ppp_pap(self, parser: BaseDeviceParser) -> None:
        """SC-013: PAP sends passwords in clear text across the PPP link (Cisco PAP guide)."""
        for record in self._ios(parser).get_ppp_pap_interfaces():
            parts = []
            if record.methods:
                position = ("as the first method" if record.methods[0] == "pap"
                            else "as a fallback after " + ", ".join(record.methods[:record.methods.index("pap")]))
                parts.append(f"accepts PAP {position} (ppp authentication {' '.join(record.methods)})")
            if record.sends_pap:
                parts.append("sends its own PAP credentials to the peer (ppp pap sent-username)")
            first = bool(record.methods) and record.methods[0] == "pap"
            self.add_issue(Finding(
                rule_id="cisco.ios.ppp.pap_authentication",
                device=parser.device_type,
                title="PPP link uses cleartext PAP authentication",
                observation=(f"Active PPP interface {record.interface} " + " and ".join(parts)
                             + ". Whether the underlying link or access network is otherwise protected is not established by this export."),
                impact="PAP passwords cross the link in clear text with no protection against replay or guessing, so anyone able to observe the link or access network can capture them.",
                exploitability="Requires the ability to observe or intercept traffic on the PPP link or the PPPoE/access network.",
                recommendation="Use CHAP (or EAP) for PPP authentication and remove PAP from the method list and 'ppp pap sent-username', unless the provider requires PAP and the path is otherwise protected.",
                severity=Severity.MEDIUM if first or record.sends_pap else Severity.LOW,
                evidence=record.evidence,
                references=(CISCO_PAP_GUIDE,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))

    def check_xe_security_warnings(self, parser: BaseDeviceParser) -> None:
        """Explicit settings Cisco's IOS XE security-warnings reference flags as insecure."""
        ios = self._ios(parser)
        for record in ios.get_logging_tls_profiles():
            weak = ", ".join(record.weak_versions + record.weak_ciphers)
            self.add_issue(self._finding(
                parser, "cisco.ios.logging.remote_weak_tls",
                "Syslog TLS profile allows weak TLS settings",
                f"Syslog destination {record.host} uses TLS profile '{record.profile}', which permits: {weak}.",
                "TLS 1.0/1.1 and CBC-mode SHA-1 suites are deprecated and weaken the protection of log records in transit.",
                "Set 'tls-version TLSv1.2' (or TLSv1.3) and only GCM/TLS 1.3 cipher suites in the logging TLS profile.",
                Severity.MEDIUM, record.evidence,
                (CISCO_XE_SECURITY_WARNINGS, CISCO_XE_TLS_SYSLOG),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))
        if ios.is_iosxe():
            for association in ios.get_ntp_associations():
                if association.authentication_state != "authenticated" or association.algorithm != "md5":
                    continue
                self.add_issue(self._finding(
                    parser, "cisco.ios.ntp.weak_algorithm",
                    "NTP authentication uses MD5",
                    f"NTP {association.role} '{association.address}' in VRF '{association.vrf}' is authenticated with MD5 key '{association.key_id}'.",
                    "MD5 is cryptographically weak; Cisco IOS XE flags MD5 NTP keys as insecure, and manipulated time affects certificates and log timestamps.",
                    "Replace the key with an hmac-sha2-256 (or other SHA-2) NTP authentication key and re-bind the association.",
                    Severity.LOW, association.evidence, (CISCO_XE_SECURITY_WARNINGS,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
        if ios.is_iosxe():
            servers = ios.get_aaa_servers_without_tls()
            if servers:
                summary = ", ".join(f"{len(items)} {protocol}" for protocol, items in servers.items())
                evidence = tuple(item for items in servers.values() for item in items)
                self.add_issue(self._finding(
                    parser, "cisco.ios.aaa.servers_without_tls",
                    "AAA servers are defined without TLS",
                    f"{summary} server definition(s) have no TLS/DTLS (LDAP: no 'mode secure'). Cisco IOS XE flags these "
                    "as insecure; protection then relies on the protocol's shared-secret obfuscation and the network path.",
                    "AAA traffic is not encrypted end to end. This is a hardening gap for the assessor to weigh, not an exploitable flaw by itself.",
                    "Where the AAA servers support it, move to RADIUS over DTLS/TLS (RadSec), TACACS+ over TLS and LDAP 'mode secure'.",
                    Severity.INFORMATIONAL, evidence[:6], (CISCO_XE_SECURITY_WARNINGS,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
        found = ios.get_xe_insecure_feature_lines()
        specs = {
            "router odr": ("cisco.ios.routing.odr_enabled", "On-Demand Routing (ODR) is enabled",
                           "ODR accepts routes learned from unauthenticated, unencrypted CDP messages, so a neighbour can inject routes.",
                           "Remove 'router odr' and use a routing protocol with authentication.", Severity.MEDIUM),
            "secure-webauth-disable": ("cisco.ios.webauth.insecure_http", "Web authentication over plain HTTP is allowed",
                                       "Web-authentication credentials can be sent over unencrypted HTTP and captured on the network.",
                                       "Remove 'secure-webauth-disable' and serve web authentication over HTTPS with a trusted certificate.",
                                       Severity.HIGH),
            "key-hash md5": ("cisco.ios.ssh.weak_pubkey_hash", "SSH public keys are pinned by MD5 hash",
                             "Administrator SSH public keys are identified by MD5 fingerprints, which are vulnerable to collision attacks.",
                             "Re-enter the keys with 'key-string' so IOS XE stores a SHA-2 hash.", Severity.LOW),
        }
        for command, evidence in found.items():
            rule, title, impact, recommendation, severity = specs[command]
            self.add_issue(self._finding(
                parser, rule, title,
                f"The configuration contains {len(evidence)} explicit '{command}' setting(s) that Cisco's IOS XE security-warnings reference marks as insecure.",
                impact, recommendation, severity, evidence, (CISCO_XE_SECURITY_WARNINGS,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))

    def check_cis_follow_ups(self, parser: BaseDeviceParser) -> None:
        """SC-056: CIS IOS/IOS-XE follow-ups.

        Login lockout gets its own finding; lower-priority hardening items that are simply
        not configured are collected into one informational finding so the report stays short.
        Absence here means the feature is not configured; no default value is inferred.
        """
        lines = self._global_lines(parser)
        folded = [" ".join(line.split()).lower() for line in lines]

        def has(*prefixes: str) -> bool:
            return any(line.startswith(prefix) for line in folded for prefix in prefixes)

        ios = self._ios(parser)
        aaa = has("aaa new-model")
        if not has("login block-for"):
            self.add_issue(self._finding(
                parser, "cisco.ios.authentication.login_lockout",
                "Login attempts are not rate limited",
                "'login block-for' is not configured, so repeated failed logins do not trigger a quiet period.",
                "Password-guessing attacks against SSH, Telnet or HTTP logins are not slowed down.",
                "Configure 'login block-for <seconds> attempts <n> within <seconds>' with a 'login quiet-mode access-class' for management hosts.",
                Severity.LOW, ("login block-for absent",),
                (CISCO_XE_SECURITY_WARNINGS,),
                basis=FindingBasis.REQUIRED_SETTING_MISSING,
            ))
        http_enabled = ConfigurationState.ENABLED in (ios.get_http_server_state(), ios.get_https_server_state())
        snmp = has("snmp-server community", "snmp-server group", "snmp-server user")
        logging_host = has("logging host") or any(re.fullmatch(r"logging \d+(?:\.\d+){3}", line) for line in folded)
        items = [
            ("1.1.3", "aaa authentication enable default", aaa and not has("aaa authentication enable default")),
            ("1.1.9", "aaa accounting network", aaa and not has("aaa accounting network")),
            ("1.1.10", "aaa accounting system", aaa and not has("aaa accounting system")),
            ("1.2.9", "ip http max-connections", http_enabled and not has("ip http max-connections")),
            ("1.2.10", "ip http timeout-policy", http_enabled and not has("ip http timeout-policy")),
            ("1.3.1", "banner exec", not has("banner exec")),
            ("1.5.7", "snmp-server host", snmp and not has("snmp-server host")),
            ("1.5.8", "snmp-server enable traps snmp", snmp and not has("snmp-server enable traps snmp", "snmp-server enable traps")),
            ("2.1.1.1.1", "non-default hostname", not any(line.startswith("hostname ") and line.split()[1] not in {"router", "switch"} for line in folded)),
            ("2.1.1.1.2", "ip domain name", not has("ip domain-name", "ip domain name")),
            ("2.2.2", "logging buffered <size>", not any(re.fullmatch(r"logging buffered \d+.*", line) for line in folded)),
            ("2.2.3", "logging console critical (or no logging console)", not has("logging console critical", "no logging console")),
            ("2.2.6", "service timestamps debug datetime", not has("service timestamps debug datetime")),
            ("2.2.7", "logging source-interface", logging_host and not has("logging source-interface")),
            ("2.2.8", "login on-success/on-failure log", not (has("login on-success log") and has("login on-failure log"))),
            ("2.4.2", "AAA server source-interface", aaa and has("tacacs", "radius") and not has("ip tacacs source-interface", "ip radius source-interface")),
            ("2.4.3", "ntp source", has("ntp server") and not has("ntp source")),
            ("IOS XE 1.0 2.1.8", "ip cef (CEF disabled)", has("no ip cef")),
        ]
        missing = [f"CIS {ref}: {label}" for ref, label, gap in items if gap]
        if missing:
            self.add_issue(self._finding(
                parser, "cisco.ios.hardening.cis_hygiene",
                "CIS hardening items not configured",
                f"{len(missing)} lower-priority CIS hardening item(s) are not configured: " + "; ".join(missing) + ".",
                "Each item is minor on its own; together they reduce accountability, log quality and resilience against brute force.",
                "Review the listed items against the organization's baseline and configure those that apply.",
                Severity.INFORMATIONAL, (f"{len(missing)} CIS hygiene item(s) absent; see observation",),
                (CISCO_XE_SECURITY_WARNINGS,),
                basis=FindingBasis.REQUIRED_SETTING_MISSING,
            ))

    def check_smart_install(self, parser: BaseDeviceParser) -> None:
        """SC-025: Smart Install accepts unauthenticated configuration and image changes."""
        state, evidence = self._ios(parser).get_smart_install()
        if state is False:
            record_control(parser, "cisco.ios.smart-install", CO.NO_FINDING, "'no vstack' is configured.")
        elif state is None:
            record_control(parser, "cisco.ios.smart-install", CO.UNKNOWN,
                           "Neither 'vstack' nor 'no vstack' appears; older releases do not show the state.")
        if state is not True:
            return
        record_control(parser, "cisco.ios.smart-install", CO.FINDING, "'vstack' is configured.")
        self.add_issue(Finding(
            rule_id="cisco.ios.services.smart_install",
            device=parser.device_type,
            title="Smart Install (vstack) is enabled",
            observation="The running configuration contains 'vstack', so the Smart Install service listens on TCP 4786.",
            impact="Smart Install has no authentication: anyone who can reach TCP 4786 can replace the configuration, load a different software image or run privileged commands.",
            exploitability="Exposed Smart Install clients are widely scanned for and have been abused in mass attacks; no credentials are needed.",
            recommendation="Run 'no vstack' once deployment is complete. If Smart Install is required, block TCP 4786 from untrusted networks with an interface ACL.",
            severity=Severity.HIGH,
            evidence=evidence,
            references=(CISCO_SMART_INSTALL_ADVISORY, CISCO_SMART_INSTALL_MISUSE),
            basis=FindingBasis.EXPLICIT_VALUE,
        ))

    def check_programmability_api_acls(self, parser: BaseDeviceParser) -> None:
        """SC-026: attached NETCONF/RESTCONF ACLs that provably admit every source."""
        ios = self._ios(parser)
        for api in ios.get_programmability_apis():
            for family, name in (("ipv4", api.ipv4_acl), ("ipv6", api.ipv6_acl)):
                if not name:
                    continue
                acl = (ios.get_management_ipv4_acl(name, allow_extended=True)
                       if family == "ipv4" else ios.get_management_ipv6_acl(name))
                if acl.state != "permit-all":
                    continue
                if api.service == "RESTCONF":
                    shared_name = (ios.get_http_access_class() if family == "ipv4"
                                   else ios.get_http_ipv6_access_class())
                    if shared_name:
                        shared = (ios.get_management_ipv4_acl(shared_name)
                                  if family == "ipv4" else ios.get_management_ipv6_acl(shared_name))
                        if shared.state != "permit-all":
                            # A restrictive WebUI ACL may protect the HTTPS process.
                            # Unresolved/unsupported shared ACLs also prevent proof.
                            continue
                service = api.service.casefold()
                family_label = "IPv4" if family == "ipv4" else "IPv6"
                rule_id = (f"cisco.ios.management.{service}_unrestricted_sources"
                           if family == "ipv4" else
                           f"cisco.ios.management.{service}_ipv6_unrestricted_sources")
                self.add_issue(Finding(
                    rule_id=rule_id,
                    device=parser.device_type,
                    title=f"{api.service} service ACL permits every {family_label} source",
                    observation=(f"The active {api.service} {api.transport} service binds {family_label} "
                                 f"ACL '{name}', whose effective first-match rules permit every source."),
                    impact="The attached service ACL does not restrict management API clients in this address family.",
                    exploitability="A client still needs network reachability and valid authentication; upstream or interface restrictions are not proven by this export.",
                    recommendation=f"Restrict the {api.service} service ACL to approved management sources.",
                    severity=Severity.HIGH,
                    evidence=api.evidence + acl.evidence,
                    references=(CISCO_IOSXE_SERVICE_ACL_GUIDE,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))

    def check_https_public_certificate(self, parser: BaseDeviceParser) -> None:
        binding = self._ios(parser).get_https_selected_public_certificate()
        if binding is None:
            return
        result = binding.assessment
        metadata = binding.metadata
        evidence = tuple(item for item in binding.evidence)
        if result.validity_state in {"expired", "not-yet-valid"}:
            self.add_issue(self._finding(
                parser, "cisco.ios.management.https_certificate_validity",
                "HTTPS management certificate is outside its validity period",
                f"Selected trustpoint '{binding.trustpoint}' identity certificate is {result.validity_state} at the explicit assessment time.",
                "Clients validating the management endpoint may reject an expired or not-yet-valid certificate.",
                "Renew or replace the selected HTTPS identity certificate.",
                Severity.HIGH, evidence, (CISCO_IOS_HTTPS_TRUSTPOINT_GUIDE,),
            ))
        if result.identity_state == "mismatch":
            self.add_issue(self._finding(
                parser, "cisco.ios.management.https_certificate_identity",
                "HTTPS management certificate identity does not match",
                f"Selected trustpoint '{binding.trustpoint}' certificate does not match the explicitly declared IOS HTTPS management identity in subjectAltName.",
                "Clients validating the intended hostname or address will reject this endpoint identity.",
                "Select a certificate with the approved management DNS name or IP address in subjectAltName.",
                Severity.HIGH, evidence, (CISCO_IOS_HTTPS_TRUSTPOINT_GUIDE,),
            ))
        if result.algorithm_state == "weak":
            self.add_issue(self._finding(
                parser, "cisco.ios.management.https_certificate_algorithm",
                "HTTPS management certificate uses a legacy key or signature",
                f"Selected trustpoint '{binding.trustpoint}' certificate uses {metadata.public_key_algorithm} {metadata.public_key_size or 'intrinsic'} and signature hash {metadata.signature_hash_algorithm}.",
                "Legacy public-key sizes or signatures reduce certificate assurance.",
                "Replace the selected certificate with an approved key and signature algorithm supported by this release.",
                Severity.HIGH, evidence, (CISCO_IOS_HTTPS_TRUSTPOINT_GUIDE,),
            ))
        if (result.trust_state == "verification-failed"
                and result.identity_state == "match"
                and result.validity_state == "valid-at-assessment-time"):
            self.add_issue(self._finding(
                parser, "cisco.ios.management.https_certificate_trust",
                "HTTPS management certificate chain does not validate to an approved anchor",
                f"Selected trustpoint '{binding.trustpoint}' certificate matches identity and time but cannot be validated to the explicitly approved exported anchor.",
                "The supplied chain does not establish trust under the selected assessment policy.",
                "Install the intended issuing chain and independently approve its root fingerprint.",
                Severity.HIGH, evidence, (CISCO_IOS_HTTPS_TRUSTPOINT_GUIDE,),
            ))

    def check_boot_config_retrieval(self, parser: BaseDeviceParser) -> None:
        if parser.assessment_context.device_lifecycle != "commissioned":
            return
        for retrieval in self._ios(parser).get_explicit_boot_config_retrievals():
            if retrieval.protocol != "tftp":
                continue
            self.add_issue(self._finding(
                parser,
                "cisco.ios.services.tftp_boot_config",
                "Commissioned device fetches boot configuration over TFTP",
                f"Explicit boot {retrieval.kind} configuration retrieval uses unauthenticated TFTP on an assessed commissioned device.",
                "An attacker able to influence the boot-time path or server could supply altered configuration.",
                "Remove the TFTP boot-configuration fetch or use an approved authenticated provisioning process with verified trust boundaries.",
                Severity.HIGH,
                tuple(item for item in retrieval.evidence)
                + ("assessment policy: device lifecycle commissioned",),
                (CISCO_IOS_BOOT_CONFIG_GUIDE,),
            ))
        for retrieval in self._ios(parser).get_cns_config_retrievals():
            if retrieval.protocol != "http":
                continue
            self.add_issue(self._finding(
                parser,
                "cisco.ios.services.cns_config_cleartext",
                "Commissioned device retrieves CNS configuration without encryption",
                f"The {retrieval.kind} configuration agent is configured without the 'encrypt' keyword, so it retrieves configuration over HTTP on an assessed commissioned device.",
                "An attacker able to observe or influence the path to the CNS server could read or alter configuration pushed to the device.",
                "Remove the CNS configuration agent from commissioned devices, or add 'encrypt' and use an approved authenticated configuration server.",
                Severity.HIGH,
                tuple(item for item in retrieval.evidence)
                + ("assessment policy: device lifecycle commissioned",),
                (CISCO_IOS_CNS_GUIDE,),
            ))

    def check_interface_protections(self, parser: BaseDeviceParser) -> None:
        lines = self._global_lines(parser)
        train = self._ios(parser).get_train()
        if "no ip source-route" not in lines:
            # SC-044 IOS-06: IP Addressing CR, Command Default "Enabled"; the IOS XE
            # hardening guide states it is enabled in all IOS XE releases.
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.ip.source_route",
                    "IP source routing is not explicitly disabled",
                    "The configuration does not contain 'no ip source-route', so IP source routing is enabled (the documented default).",
                    "Source-routed packets can bypass expected routing paths and trust boundaries.",
                    "Configure 'no ip source-route'.",
                    Severity.MEDIUM,
                    ("no ip source-route absent",),
                    references=(CISCO_IOS_HARDENING_GUIDE, CISCO_IP_ADDRESSING_CR, CISCO_IOS_ROUTING_HARDENING_GUIDE),
                    basis=FindingBasis.DOCUMENTED_DEFAULT,
                )
            )
        proxy_arp_disabled = self._effective_toggle(lines, r"ip arp proxy disable", r"no ip arp proxy disable")
        for interface in parser.get_native_config().find_objects(r"^interface\s+"):
            children = self._children(interface)
            if "shutdown" in children or not any(line.startswith("ip address ") for line in children):
                continue
            missing = []
            if "no ip redirects" not in children:
                missing.append("no ip redirects")
            if "no ip proxy-arp" not in children and not proxy_arp_disabled:
                missing.append("no ip proxy-arp")
            # SC-044 IOS-07: IP Application Services CR, directed broadcasts are
            # dropped by default only from 12.0.
            if train and train < (12, 0) and "no ip directed-broadcast" not in children:
                missing.append("no ip directed-broadcast")
            if missing:
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.interface.ip_hardening",
                        "Layer-3 interface hardening is incomplete",
                        f"{interface.text.strip()} lacks {', '.join(missing)}, so the documented defaults (enabled) apply.",
                        "Redirects, proxy ARP or directed broadcasts can enable traffic redirection, reflection attacks and weaken local network trust assumptions.",
                        "Disable redirects and proxy ARP (and directed broadcasts on releases before 12.0) on routed interfaces unless explicitly required.",
                        Severity.MEDIUM,
                        (interface.text.strip(), *missing),
                        references=(CISCO_IOS_HARDENING_GUIDE, CISCO_IP_ADDRESSING_CR, CISCO_IP_APP_SERVICES_CR),
                        basis=FindingBasis.DOCUMENTED_DEFAULT,
                    )
                )

    def check_control_plane(self, parser: BaseDeviceParser) -> None:
        policies = [
            policy for policy in self._ios(parser).get_control_plane_policies()
            if policy.direction == "input"
        ]
        if not policies:
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.control_plane.copp",
                    "Control-plane policing is not attached",
                    "No input service policy is attached under control-plane configuration.",
                    "Unrestricted control-plane traffic can contribute to CPU exhaustion and management outages.",
                    "Deploy a validated Control Plane Policing policy appropriate for the platform role.",
                    Severity.MEDIUM,
                    ("No control-plane service-policy input",),
                    (CISCO_IOS_COPP_GUIDE,),
                )
            )
            return

        for policy in policies:
            evidence = tuple(item for item in policy.evidence)
            scope = policy.scope.replace("-", " ")
            if policy.protection_state == "platform-managed":
                # Several Catalyst IOS-XE families expose the system-generated
                # classes operationally even when the static export contains
                # only this well-known attachment. Rate adequacy remains unknown.
                continue
            if not policy.policy_resolved:
                self.add_issue(self._finding(
                    parser,
                    "cisco.ios.control_plane.policy_reference",
                    "Control-plane policy attachment is unresolved",
                    f"The {scope} control plane references undefined policy map '{policy.name}'.",
                    "An unresolved attachment cannot classify or police host-bound traffic as intended.",
                    "Define the attached policy map and verify its classes and actions before deployment.",
                    Severity.HIGH,
                    evidence,
                    (CISCO_IOS_COPP_GUIDE,),
                ))
                continue
            if policy.protection_state == "empty-policy":
                self.add_issue(self._finding(
                    parser,
                    "cisco.ios.control_plane.policy_empty",
                    "Attached control-plane policy is empty",
                    f"Policy map '{policy.name}' is attached to the {scope} input control plane but contains no classes.",
                    "The attachment does not classify or constrain any control-plane traffic.",
                    "Add validated control-plane classes and explicit policing or drop behavior.",
                    Severity.HIGH,
                    evidence,
                    (CISCO_IOS_COPP_GUIDE,),
                ))
                continue

            for policy_class in policy.classes:
                if policy_class.selector_resolution in {"resolved", "implicit-all"}:
                    continue
                self.add_issue(self._finding(
                    parser,
                    "cisco.ios.control_plane.class_reference",
                    "Control-plane class selector is unresolved",
                    f"Class '{policy_class.name}' in attached policy '{policy.name}' has selector state '{policy_class.selector_resolution}'.",
                    "An undefined class map, empty class map, or missing ACL can prevent the intended traffic classification.",
                    "Define the class map and every referenced ACL with the intended control-plane traffic selectors.",
                    Severity.HIGH,
                    tuple(item for item in policy_class.evidence) or evidence,
                    (CISCO_IOS_COPP_GUIDE,),
                ))

            resolved_classes = [
                item for item in policy.classes
                if item.selector_resolution in {"resolved", "implicit-all"}
            ]
            if policy.protection_state == "no-enforcement" and resolved_classes:
                self.add_issue(self._finding(
                    parser,
                    "cisco.ios.control_plane.policy_no_enforcement",
                    "Attached control-plane policy has no effective policing or drop action",
                    f"Policy map '{policy.name}' has resolved classes but no valid police rate or explicit drop action.",
                    "Classification without an enforcing action does not constrain traffic sent to the route processor.",
                    "Add platform-tested police or drop actions; choose rates from device capacity and operational traffic evidence.",
                    Severity.HIGH,
                    evidence,
                    (CISCO_IOS_COPP_GUIDE,),
                ))

    def check_tacacs_keys(self, parser: BaseDeviceParser) -> None:
        """SC-031: TACACS+ servers used by AAA method lists without a shared key."""
        ios = self._ios(parser)
        used_all = False
        used_groups: set[str] = set()
        for method_list in ios.get_aaa_method_lists():
            tokens = list(method_list.methods)
            for index, token in enumerate(tokens[:-1]):
                if token.casefold() == "group":
                    target = tokens[index + 1]
                    if target.casefold() == "tacacs+":
                        used_all = True
                    else:
                        used_groups.add(target)
        members: set[str] = set()
        for group in ios.get_aaa_server_group_records():
            if group.protocol == "tacacs+" and group.name in used_groups:
                members.update(member.casefold() for member in group.members)
        if not used_all and not members:
            return
        global_key, servers = ios.get_tacacs_servers()
        if global_key:
            return
        for name, address, has_key, evidence in servers:
            if has_key:
                continue
            if not used_all and name.casefold() not in members and address.casefold() not in members:
                continue
            self.add_issue(Finding(
                rule_id="cisco.ios.aaa.tacacs_key_missing",
                device=parser.device_type,
                title="TACACS+ server without a shared key",
                observation=(f"TACACS+ server '{name}' is used by an AAA method list but neither the server nor "
                             "a global 'tacacs-server key' defines a shared key."),
                impact="Without a key TACACS+ packets are not obfuscated, so administrator usernames, passwords and commands cross the network in clear text.",
                exploitability="An attacker on the path to the TACACS+ server can read administrator credentials from captured packets.",
                recommendation="Configure a long random key on the server ('key 6 ...' under 'tacacs server') matching the TACACS+ server, and prefer TACACS+ over TLS where supported.",
                severity=Severity.HIGH,
                evidence=(evidence,),
                references=(CISCO_IOS_TACACS_GUIDE, RFC_8907),
                basis=FindingBasis.REQUIRED_SETTING_MISSING,
            ))

    def check_ldap_transport(self, parser: BaseDeviceParser) -> None:
        """SC-031: LDAP servers used by AAA method lists without 'mode secure' (TLS)."""
        ios = self._ios(parser)
        servers, groups = ios.get_ldap_servers()
        if not servers:
            record_control(parser, "cisco.ios.ldap-transport", CO.NOT_APPLICABLE, "No LDAP server is defined.")
            return
        used: dict[str, str] = {}
        for method_list in ios.get_aaa_method_lists():
            tokens = list(method_list.methods)
            for index, token in enumerate(tokens[:-1]):
                if token.casefold() != "group":
                    continue
                target = tokens[index + 1]
                if target.casefold() == "ldap":
                    for server in servers:
                        used.setdefault(server.name.casefold(), "the global 'group ldap' method")
                elif target in groups:
                    for member in groups[target]:
                        used.setdefault(member.casefold(), f"server group '{target}'")
        if not any(server.name.casefold() in used for server in servers):
            record_control(parser, "cisco.ios.ldap-transport", CO.NOT_APPLICABLE,
                           "LDAP servers are defined but no AAA method list uses them.")
        for server in servers:
            via = used.get(server.name.casefold())
            if via is None:
                continue
            if server.secure:
                record_control(parser, "cisco.ios.ldap-transport", CO.NO_FINDING, "Used LDAP servers set 'mode secure'.")
                continue
            if server.port == "636":
                record_control(parser, "cisco.ios.ldap-transport", CO.UNKNOWN,
                               "A used LDAP server uses port 636 without 'mode secure'; implicit LDAPS is not documented.")
                record_manual_review(parser, f"LDAP server '{server.name}' on port 636",
                                     "Port 636 without 'mode secure' may be implicit LDAPS; verify on the device.")
                continue
            record_control(parser, "cisco.ios.ldap-transport", CO.FINDING, "A used LDAP server has no 'mode secure'.")
            self.add_issue(Finding(
                rule_id="cisco.ios.aaa.ldap_cleartext",
                device=parser.device_type,
                title="LDAP authentication server is used without TLS",
                observation=(f"LDAP server '{server.name}' is used by an AAA method list through {via} "
                             "and has no 'mode secure', so the router does not initiate TLS to it."),
                impact="LDAP binds carry the authenticating user's password (and the router's bind credentials) in clear text.",
                exploitability="An attacker on the path to the LDAP server can capture administrator or user passwords.",
                recommendation="Configure 'mode secure' with a trusted CA certificate on the LDAP server definition, or move to an authentication method protected end to end.",
                severity=Severity.HIGH,
                evidence=server.evidence,
                references=(CISCO_IOS_LDAP_GUIDE, CISCO_XE_SECURITY_WARNINGS),
                basis=FindingBasis.REQUIRED_SETTING_MISSING,
            ))

    def check_fhrp_authentication(self, parser: BaseDeviceParser) -> None:
        """SC-028: HSRP/VRRPv2/GLBP groups without MD5 authentication."""
        for group in self._ios(parser).get_fhrp_groups():
            if group["auth"] == "md5":
                continue
            name = group["protocol"].upper()
            explicit = group["auth"] == "text"
            self.add_issue(Finding(
                rule_id="cisco.ios.fhrp.authentication",
                device=parser.device_type,
                title=f"{name} group without MD5 authentication",
                observation=(f"{name} group {group['group']} on {group['interface']} "
                             + ("uses plain-text authentication, which is sent unencrypted in every hello."
                                if explicit else "has no MD5 authentication configured.")),
                impact="Any host on the segment can send hellos with a higher priority and become the active default gateway.",
                exploitability="An attacker on the same VLAN can take over the virtual gateway address and intercept or drop the segment's traffic.",
                recommendation=f"Configure '{group['protocol']} {group['group']} authentication md5 key-chain <name>' (or key-string) on every group member.",
                severity=Severity.MEDIUM,
                evidence=tuple(group["evidence"]) + ((group["auth_evidence"],) if group["auth_evidence"] else ()),
                references=(CISCO_FHRP_COMMAND_REFERENCE, CISCO_HSRP_GUIDE),
                basis=FindingBasis.EXPLICIT_VALUE if explicit else FindingBasis.MISSING_EXPLICIT_SETTING,
            ))

    def check_ntp_access(self, parser: BaseDeviceParser) -> None:
        """SC-033: NTP runs without any access group, so anyone may query or peer."""
        exposed, evidence = self._ios(parser).get_ntp_service_exposure()
        if not exposed:
            return
        self.add_issue(Finding(
            rule_id="cisco.ios.ntp.server_exposed",
            device=parser.device_type,
            title="NTP service has no access control",
            observation="NTP is configured and no 'ntp access-group' exists; by default full access (time requests and control queries) is granted to all systems.",
            impact="Any host that can reach UDP 123 can query the device's NTP service, including control queries that reveal information and can be used for reflection traffic.",
            exploitability="Attackers scan for NTP services that answer control queries and use them for amplification or reconnaissance.",
            recommendation="Add 'ntp access-group peer <acl>' for the time sources and 'ntp access-group serve-only <acl>' for clients, and block UDP 123 from untrusted networks.",
            severity=Severity.LOW,
            evidence=evidence,
            references=(CISCO_NTP_ACCESS_GROUP_REFERENCE,),
            basis=FindingBasis.DOCUMENTED_DEFAULT,
        ))

    def check_http_tls(self, parser: BaseDeviceParser) -> None:
        """SC-027: explicit legacy TLS versions or weak cipher suites on the HTTPS server."""
        settings = self._ios(parser).get_http_tls_settings()
        if not settings["https"]:
            return
        version = str(settings.get("tls_version", ""))
        if version.casefold() in {"tlsv1.0", "tlsv1.1"}:
            self.add_issue(Finding(
                rule_id="cisco.ios.tls.minimum_version",
                device=parser.device_type,
                title="HTTPS management accepts TLS below 1.2",
                observation=f"'ip http tls-version {version}' allows TLS versions older than 1.2 on the HTTPS server.",
                impact="Legacy TLS versions have known weaknesses that can expose administrator sessions.",
                exploitability="An attacker on the path can force or exploit a weak TLS version when a client supports it.",
                recommendation="Set 'ip http tls-version TLSv1.2' (or TLSv1.3 where supported).",
                severity=Severity.MEDIUM,
                evidence=(settings["tls_evidence"],),
                references=(CISCO_IOSXE_SECURITY_WARNINGS,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))
        weak = settings.get("weak_suites") or []
        if weak:
            self.add_issue(Finding(
                rule_id="cisco.ios.tls.weak_cipher",
                device=parser.device_type,
                title="HTTPS management allows weak cipher suites",
                observation=f"'ip http secure-ciphersuite' includes {', '.join(weak)} (SHA-1, DES/3DES, RC4 or MD5 based).",
                impact="Weak cipher suites reduce the protection of administrator sessions.",
                exploitability="An attacker on the path benefits when a client negotiates one of these suites.",
                recommendation="Limit 'ip http secure-ciphersuite' to AES-GCM or TLS 1.3 suites such as tls13-aes256-gcm-sha384.",
                severity=Severity.MEDIUM,
                evidence=(settings["suite_evidence"],),
                references=(CISCO_IOSXE_SECURITY_WARNINGS,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))

    def check_snmp_notifications(self, parser: BaseDeviceParser) -> None:
        """SC-037: SNMPv1/v2c trap or inform targets send the community in clear text."""
        legacy = [evidence for _, version, evidence in self._ios(parser).get_snmp_notification_hosts()
                  if version in {"1", "2c"}]
        if not legacy:
            return
        self.add_issue(Finding(
            rule_id="cisco.ios.snmp.legacy_version",
            device=parser.device_type,
            title="SNMP notifications use SNMPv1/v2c",
            observation="SNMP trap or inform targets use version 1 or 2c (version 1 is the default when none is given).",
            impact="Each notification carries the community string in clear text and has no integrity protection.",
            exploitability="An attacker on the path can read the community and reuse it if the same string grants SNMP access.",
            recommendation="Send notifications with 'snmp-server host <address> version 3 priv <user>' and remove v1/v2c targets.",
            severity=Severity.MEDIUM,
            evidence=tuple(legacy),
            references=(CISCO_IOSXE_SECURITY_WARNINGS, CISCO_IOS_SNMPV3_GUIDE),
            basis=FindingBasis.EXPLICIT_VALUE,
        ))

    def check_embedded_credentials(self, parser: BaseDeviceParser) -> None:
        """SC-036: clear-text FTP/HTTP client passwords and credentials in URLs."""
        labels = {"ftp_client": "FTP client password ('ip ftp password')",
                  "http_client": "HTTP client password ('ip http client password')",
                  "url": "password embedded in a URL"}
        for kind, evidence in self._ios(parser).get_embedded_credentials():
            self.add_issue(Finding(
                rule_id=f"cisco.ios.credentials.{kind}_storage",
                device=parser.device_type,
                title="Clear-text credential outside the credential store",
                observation=f"The configuration contains a {labels[kind]}. The value is redacted.",
                impact="The password is readable by anyone with the configuration and is sent over clear-text FTP/HTTP when used.",
                exploitability="An attacker who obtains a configuration backup or captures the transfer can reuse the account on the file server.",
                recommendation="Use SCP/SFTP or HTTPS with a dedicated low-privilege account and remove stored FTP/HTTP passwords and URL credentials.",
                severity=Severity.MEDIUM,
                evidence=(evidence,),
                references=(CISCO_IOSXE_SECURITY_WARNINGS,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))

    def check_ike_aggressive_mode(self, parser: BaseDeviceParser) -> None:
        """SC-034: IKEv1 aggressive mode accepted for pre-shared-key peers."""
        accepted, evidence = self._ios(parser).get_ikev1_aggressive_mode()
        if not accepted:
            return
        self.add_issue(Finding(
            rule_id="cisco.ios.vpn.ike_aggressive_mode",
            device=parser.device_type,
            title="IKEv1 aggressive mode is accepted for pre-shared keys",
            observation=("IKEv1 pre-shared keys are configured and 'crypto isakmp aggressive-mode disable' is absent, "
                         "so the router processes incoming aggressive-mode requests (the documented default)."),
            impact="Aggressive mode sends a hash derived from the pre-shared key before the peer is authenticated, so it can be captured and cracked offline.",
            exploitability="An attacker who can reach UDP 500 can request an aggressive-mode exchange and brute-force a weak key offline.",
            recommendation=("Configure 'crypto isakmp aggressive-mode disable' unless Easy VPN clients with pre-shared keys "
                            "need it, prefer IKEv2 or certificates, and use long random pre-shared keys."),
            severity=Severity.MEDIUM,
            evidence=evidence,
            references=(CISCO_IOS_AGGRESSIVE_MODE_REFERENCE, RFC_2409),
            basis=FindingBasis.DOCUMENTED_DEFAULT,
        ))

    def check_crypto(self, parser: BaseDeviceParser) -> None:
        native = parser.get_native_config()
        ios = self._ios(parser)
        # SC-044 IOS-23: Security CR c4, an ISAKMP policy defaults to 56-bit DES and
        # 768-bit DH group 1. Classic IOS only: the IOS-XE plugin already treats
        # missing parameters as weak.
        classic = not ios.is_iosxe() and ios.get_train() is not None
        for policy in native.find_objects(r"^crypto (?:isakmp|ikev1) policy\s+"):
            children = self._children(policy)
            weak = [
                line for line in children
                if re.fullmatch(r"encryption (?:des|3des)", line)
                or re.fullmatch(r"hash (?:md5|sha)", line)
                or re.fullmatch(r"group (?:1|2|5|14)", line)
            ]
            defaults = []
            if classic:
                if not any(line.startswith("encryption ") for line in children):
                    defaults.append("encryption absent: default 56-bit DES")
                if not any(line.startswith("group ") for line in children):
                    defaults.append("group absent: default DH group 1 (768-bit)")
            if defaults:
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.crypto.legacy_ike",
                        "IKE policy uses legacy algorithms",
                        f"{policy.text.strip()} omits parameters whose documented defaults are weak: {'; '.join(defaults)}.",
                        "Weak encryption, hashing, or Diffie-Hellman groups reduce VPN security.",
                        "Set 'encryption aes 256', 'hash sha256' or stronger and 'group 19' or stronger explicitly in every ISAKMP policy.",
                        Severity.HIGH,
                        (policy.text.strip(), *weak, *defaults),
                        references=(CISCO_IOS_AGGRESSIVE_MODE_REFERENCE,),
                        basis=FindingBasis.DOCUMENTED_DEFAULT,
                    )
                )
                continue
            if weak:
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.crypto.legacy_ike",
                        "IKE policy uses legacy algorithms",
                        f"{policy.text.strip()} contains legacy cryptographic selections.",
                        "Weak encryption, hashing, or Diffie-Hellman groups reduce VPN security.",
                        "Use AES-256 or AES-GCM, SHA-256 or stronger, and an approved modern DH group.",
                        Severity.HIGH,
                        (policy.text.strip(), *weak),
                    )
                )
        for transform in native.find_objects(r"^crypto ipsec transform-set\s+"):
            weak = [token for token in transform.text.lower().split() if token in {"esp-des", "esp-3des", "esp-md5-hmac", "esp-sha-hmac"}]
            if weak:
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.crypto.legacy_ipsec",
                        "IPsec transform-set uses legacy algorithms",
                        f"Transform-set '{transform.text.split()[3]}' contains legacy algorithms.",
                        "Legacy transforms weaken VPN confidentiality or integrity.",
                        "Replace the transform-set with AES and SHA-256 or an authenticated-encryption suite.",
                        Severity.HIGH,
                        (transform.text.strip(),),
                    )
                )

    def _ikev1_in_use(self, parser: BaseDeviceParser) -> tuple[str, ...]:
        evidence = []
        for line in self._global_lines(parser):
            folded = re.sub(r"\s+", " ", line.casefold())
            if re.match(r"crypto (?:isakmp key |keyring |isakmp profile |isakmp client configuration group )", folded) \
                    or re.match(r"crypto map \S+ \d+ ipsec-isakmp", folded):
                evidence.append(re.sub(r"(?i)^(crypto isakmp key)\s+(?:\d\s+)?\S+", r"\1 <redacted>", line))
        return tuple(evidence)

    def check_release_defaults(self, parser: BaseDeviceParser) -> None:
        """SC-044: settings whose documented IOS default is insecure and that the export leaves at default."""
        ios = self._ios(parser)
        lines = self._global_lines(parser)
        folded = [re.sub(r"\s+", " ", line.casefold()) for line in lines]
        train = ios.get_train()

        services = ios.get_default_enabled_services()
        if services:
            self.add_issue(Finding(
                rule_id="cisco.ios.services.default_enabled",
                device=parser.device_type,
                title="Unneeded services are left at their enabled default",
                observation="The export does not disable services that IOS enables by default: "
                            + "; ".join(f"{name} ({reason})" for name, reason in services) + ".",
                impact="PAD, BOOTP and MOP are legacy services that are rarely needed; each listener adds attack surface and BOOTP can hand out boot files to anyone who asks.",
                exploitability="A host on an attached network can reach the default-enabled service without credentials.",
                recommendation="Configure 'no service pad', 'no ip bootp server' and 'no mop enabled' on Ethernet interfaces unless a documented need exists.",
                severity=Severity.LOW,
                evidence=tuple(f"{name}: {reason}" for name, reason in services),
                references=(CISCO_IOS_HARDENING_GUIDE, CISCO_WAN_CR, CISCO_FUNDAMENTALS_CR_FK, CISCO_INTERFACE_CR_L2),
                basis=FindingBasis.DOCUMENTED_DEFAULT,
            ))

        lookup = self._effective_toggle(folded, r"ip domain[ -]lookup(?: .*)?", r"no ip domain[ -]lookup")
        if not any(re.fullmatch(r"(?:no )?ip domain[ -]lookup(?: .*)?", line) for line in folded):
            lookup = True  # IOS-12: IP Addressing CR i3, DNS lookup is enabled by default
        if lookup and train:
            self.add_issue(Finding(
                rule_id="cisco.ios.services.dns_lookup",
                device=parser.device_type,
                title="DNS lookup of mistyped commands is enabled",
                observation="'no ip domain lookup' is absent, so DNS-based host name translation is enabled (the documented default).",
                impact="A mistyped exec command is treated as a host name, which delays the session and sends DNS queries (broadcast when no name server is set) that reveal typed text.",
                exploitability="Low: only disclosure of mistyped words to hosts that can see the DNS queries.",
                recommendation="Configure 'no ip domain lookup' unless the device resolves names, or set 'transport preferred none' on the lines.",
                severity=Severity.INFORMATIONAL,
                evidence=("ip domain lookup: default enabled",),
                references=(CISCO_IP_ADDRESSING_CR_I3,),
                basis=FindingBasis.DOCUMENTED_DEFAULT,
            ))

        if train and not self._effective_toggle(folded, r"service tcp-keepalives-in", r"no service tcp-keepalives-in"):
            self.add_issue(Finding(
                rule_id="cisco.ios.services.tcp_keepalives",
                device=parser.device_type,
                title="TCP keepalives for incoming sessions are disabled",
                observation="'service tcp-keepalives-in' is absent; the documented default is disabled.",
                impact="Sessions whose remote end disappears are not detected, so orphaned management sessions keep VTY lines busy.",
                exploitability="An attacker who opens and abandons sessions can exhaust the VTY lines and lock out administrators.",
                recommendation="Configure 'service tcp-keepalives-in' (and 'service tcp-keepalives-out').",
                severity=Severity.LOW,
                evidence=("service tcp-keepalives-in absent",),
                references=(CISCO_FUNDAMENTALS_CR_RS, CISCO_IOS_HARDENING_GUIDE),
                basis=FindingBasis.DOCUMENTED_DEFAULT,
            ))

        # IOS-21: Security CR e1, without enable credentials the console password acts
        # as the enable password for all VTY sessions.
        credentials = (*parser.get_credential_metadata(), *ios.get_additional_credential_metadata())
        console = [item for item in credentials
                   if item.context == "line_password" and item.account.casefold().startswith("line con")]
        aaa = self._effective_toggle(lines, r"aaa new-model", r"no aaa new-model")
        if console and not aaa and not any(item.context == "enable" for item in credentials):
            self.add_issue(Finding(
                rule_id="cisco.ios.credentials.enable_missing",
                device=parser.device_type,
                title="No enable secret: the console password grants privileged mode",
                observation="Neither 'enable secret' nor 'enable password' is configured and the console line has a password, "
                            "so that console password serves as the enable password for all VTY sessions (documented behaviour).",
                impact="Anyone who knows the console password can reach privileged EXEC remotely; console passwords are often shared and weakly stored.",
                exploitability="An attacker with a VTY login and the console password gets full control.",
                recommendation="Configure a unique 'enable algorithm-type scrypt secret' or central AAA with privilege control.",
                severity=Severity.MEDIUM,
                evidence=tuple(item for credential in console for item in credential.evidence) + ("enable secret/password absent",),
                references=(CISCO_SECURITY_CR_E1,),
                basis=FindingBasis.DOCUMENTED_DEFAULT,
            ))

        # IOS-22: Security CR c4, eight built-in ISAKMP policies (some with 3DES, MD5
        # and DH group 2) apply when no policy is configured. Introduced in 12.4(20)T,
        # so only trains from 15.x are decided.
        ikev1 = self._ikev1_in_use(parser)
        if (ikev1 and train and (train >= (15, 0) or ios.is_iosxe())
                and not parser.get_native_config().find_objects(r"^crypto (?:isakmp|ikev1) policy\s+")
                and "no crypto isakmp default policy" not in folded):
            self.add_issue(self._finding(
                parser,
                "cisco.ios.crypto.legacy_ike",
                "IKEv1 relies on the built-in default ISAKMP policies",
                "IKEv1 is configured, no 'crypto isakmp policy' exists and the default policies are not disabled, "
                "so the eight built-in policies apply, including 3DES, MD5/SHA-1 and DH group 2 proposals.",
                "Weak encryption, hashing, or Diffie-Hellman groups reduce VPN security.",
                "Configure explicit ISAKMP policies with AES-256, SHA-256 or stronger and DH group 19 or stronger, and add 'no crypto isakmp default policy'.",
                Severity.HIGH,
                ikev1[:5] + ("crypto isakmp policy absent", "no crypto isakmp default policy absent"),
                references=(CISCO_IOS_AGGRESSIVE_MODE_REFERENCE,),
                basis=FindingBasis.DOCUMENTED_DEFAULT,
            ))

        # IOS-25: FlexVPN guide, IKEv2 smart defaults apply when no proposal is
        # configured and are not shown in 'show running-config'.
        native = parser.get_native_config()
        if (native.find_objects(r"^crypto ikev2 profile\s+")
                and not native.find_objects(r"^crypto ikev2 proposal\s+")
                and "no crypto ikev2 proposal default" not in folded):
            self.add_issue(self._finding(
                parser,
                "cisco.ios.crypto.ikev2_default_proposal",
                "IKEv2 uses the built-in default proposal",
                "An IKEv2 profile exists but no 'crypto ikev2 proposal' is configured, so the smart-default proposal is used; "
                "on documented releases it includes DH group 5 and SHA-1 based transforms.",
                "Legacy Diffie-Hellman groups and SHA-1 weaken the key exchange and integrity of the tunnel.",
                "Configure an explicit IKEv2 proposal (AES-GCM or AES-256, SHA-256 or stronger, DH group 19 or stronger) and a policy that references it; add 'no crypto ikev2 proposal default'.",
                Severity.LOW,
                tuple(obj.text.strip() for obj in native.find_objects(r"^crypto ikev2 profile\s+"))[:5]
                + ("crypto ikev2 proposal absent",),
                references=(CISCO_FLEXVPN_GUIDE,),
                basis=FindingBasis.DOCUMENTED_DEFAULT,
            ))

        # IOS-27: VTP server is the default mode; only transparent/off are saved.
        if parser.device_type in {"IOS_SWITCH", "IOS_CATALYST"}:
            modes = [line for line in folded if line.startswith("vtp mode ")]
            mode = modes[-1].split()[2] if modes else "server"
            if mode not in {"transparent", "off"}:
                self.add_issue(self._finding(
                    parser,
                    "cisco.ios.vtp.mode",
                    "Switch takes part in VTP",
                    f"VTP mode is {mode}" + (" (the documented default; only transparent or off mode is saved in the configuration)." if not modes else "."),
                    "A switch with a higher configuration revision in the same VTP domain can overwrite or delete the VLAN database of every server and client switch.",
                    "Use 'vtp mode transparent' or 'vtp mode off' unless VTP is managed deliberately (VTPv3 with a primary server and password).",
                    Severity.LOW,
                    tuple(line for line in lines if line.casefold().startswith("vtp ") and "password" not in line.casefold())
                    or ("vtp mode absent: default server",),
                    references=(CISCO_VTP_GUIDE,),
                    basis=FindingBasis.EXPLICIT_VALUE if modes else FindingBasis.DOCUMENTED_DEFAULT,
                ))

        # IOS-30: IOS-XE 26.1.1+ writes 'system mode insecure' to keep deprecated features.
        insecure = [line for line in lines if re.fullmatch(r"system mode insecure", line.strip(), re.I)]
        if insecure:
            self.add_issue(self._finding(
                parser,
                "cisco.ios.system.insecure_mode",
                "Insecure feature restrictions are switched off",
                "'system mode insecure' is configured, so features that IOS XE 26.1.1 and later block by default "
                "(clear-text and deprecated protocols and algorithms) remain available.",
                "Deprecated protocols such as Telnet, HTTP and weak SSH or SNMP algorithms can still be enabled.",
                "Remove the insecure features the device still uses, then remove 'system mode insecure'.",
                Severity.LOW,
                tuple(insecure),
                references=(CISCO_INSECURE_FEATURE_RESTRICTIONS,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))

    def check_routing(self, parser: BaseDeviceParser) -> None:
        ios = self._ios(parser)
        ipv4_prefix_lists = ios.get_bgp_ipv4_prefix_list_effects()
        route_maps = ios.get_bgp_route_map_effects()
        as_path_filters = ios.get_bgp_as_path_filter_effects()
        key_lifetimes = ios.get_routing_key_lifetime_states()

        def report_unusable_key_lifetime(scope: str, key_reference: str, evidence: tuple[str, ...]) -> None:
            lifetime = key_lifetimes.get(key_reference.casefold()) if key_reference else None
            if lifetime is None or lifetime[0] != "unusable":
                return
            self.add_issue(self._finding(
                parser,
                "cisco.ios.routing.key_lifetime_unusable",
                "Routing key chain has no currently usable authentication key",
                f"{scope} binds key chain '{key_reference}', but every exported key is outside its send or accept lifetime at the supplied assessment time.",
                "The configuration cannot use this key chain to send and accept authenticated routing updates at the assessed time.",
                "Renew or rotate the key chain with overlapping valid send and accept lifetimes, then verify adjacency state.",
                Severity.HIGH,
                evidence + tuple(item for item in lifetime[1])
                + (f"assessment policy time: {parser.assessment_context.assessment_time}",),
                (CISCO_IOS_KEY_LIFETIME_GUIDE,),
            ))
        for peer in ios.get_bgp_neighbors():
            if not peer.active or peer.inheritance_unknown:
                continue
            scope = f"neighbor {peer.address} in {peer.address_family}, VRF {peer.vrf}"
            evidence = tuple(item for item in peer.evidence)
            if peer.authentication_state in {"unauthenticated", "unresolved"}:
                detail = "has no authentication" if peer.authentication_state == "unauthenticated" else "has an unresolved authentication reference"
                self.add_issue(self._finding(
                    parser,
                    "cisco.ios.routing.bgp.authentication",
                    "BGP neighbor authentication is incomplete",
                    f"BGP {scope} {detail}.",
                    "An unauthenticated routing adjacency can permit spoofed session establishment or route injection from a reachable attacker.",
                    "Configure peer authentication using a mechanism supported by the exact IOS/IOS XE release and the remote peer.",
                    Severity.HIGH,
                    evidence,
                    (CISCO_IOS_ROUTING_HARDENING_GUIDE,),
                ))
            if peer.peer_role != "external":
                continue
            if peer.address_family == "ipv4 unicast":
                for direction in ("in", "out"):
                    direction_label = "inbound" if direction == "in" else "outbound"
                    bindings = [
                        (kind, name) for bound_direction, kind, name in peer.policy_references
                        if bound_direction == direction
                    ]
                    for kind, name in bindings:
                        if kind not in {"prefix-list", "route-map", "filter-list"}:
                            continue
                        effect = (
                            ipv4_prefix_lists.get(name.casefold()) if kind == "prefix-list"
                            else route_maps.get(name.casefold()) if kind == "route-map"
                            else as_path_filters.get(name)
                        )
                        policy_label = {
                            "prefix-list": "prefix list", "route-map": "route map",
                            "filter-list": "AS-path filter list",
                        }[kind]
                        reference = {
                            "prefix-list": CISCO_IOS_BGP_PREFIX_FILTER_GUIDE,
                            "route-map": CISCO_IOS_ROUTE_MAP_GUIDE,
                            "filter-list": CISCO_IOS_AS_PATH_GUIDE,
                        }[kind]
                        if effect is None:
                            self.add_issue(self._finding(
                                parser,
                                f"cisco.ios.routing.bgp.missing_{kind.replace('-', '_')}",
                                f"BGP neighbor references an undefined {policy_label}",
                                f"External BGP {scope} has {direction_label} {policy_label} '{name}' attached, but no definition is exported.",
                                "The configured route boundary cannot be validated from this export.",
                                f"Define the intended {policy_label} and verify its effective neighbor binding.",
                                Severity.MEDIUM,
                                evidence,
                                (reference,),
                            ))
                        elif effect[0] == "permit-all" and len(bindings) == 1:
                            self.add_issue(self._finding(
                                parser,
                                f"cisco.ios.routing.bgp.permit_all_{kind.replace('-', '_')}",
                                f"BGP neighbor {policy_label} permits every IPv4 route",
                                (f"External BGP {scope} uses {direction_label} prefix-list '{name}' whose sole rule permits 0.0.0.0/0 le 32."
                                 if kind == "prefix-list" else
                                 f"External BGP {scope} uses {direction_label} route map '{name}' whose sole permit clause has no match condition."
                                 if kind == "route-map" else
                                 f"External BGP {scope} uses {direction_label} AS-path filter list '{name}' whose sole rule permits every AS path."),
                                f"The attached {policy_label} does not restrict IPv4 route exchange in this direction.",
                                "Replace the permit-all clause with approved prefix boundaries.",
                                Severity.HIGH,
                                evidence + tuple(item for item in effect[1]),
                                (reference,),
                            ))
            for direction, present in (("inbound", peer.inbound_policy), ("outbound", peer.outbound_policy)):
                if present:
                    continue
                self.add_issue(self._finding(
                    parser,
                    f"cisco.ios.routing.bgp.{direction}_policy",
                    f"External BGP neighbor lacks an {direction} route policy",
                    f"External BGP {scope} has no explicit {direction} route-map, prefix-list, filter-list, or distribute-list.",
                    "Unrestricted route exchange can admit or advertise unintended prefixes across a routing trust boundary.",
                    f"Apply an explicit least-privilege {direction} route policy appropriate to this peer.",
                    Severity.HIGH,
                    evidence,
                    (CISCO_IOS_ROUTING_HARDENING_GUIDE,),
                ))
            if not peer.prefix_limit:
                self.add_issue(self._finding(
                    parser,
                    "cisco.ios.routing.bgp.prefix_limit",
                    "External BGP neighbor has no maximum-prefix safeguard",
                    f"External BGP {scope} has no explicit maximum-prefix control; no numeric threshold is inferred.",
                    "An unexpectedly large route advertisement can consume routing resources or disrupt forwarding.",
                    "Configure a peer-specific maximum-prefix value based on the documented expected route volume.",
                    Severity.MEDIUM,
                    evidence,
                    (CISCO_IOS_ROUTING_HARDENING_GUIDE,),
                ))

        for interface in ios.get_ospf_interfaces():
            if (not interface.shutdown and not interface.passive
                    and interface.authentication_state == "authenticated"):
                report_unusable_key_lifetime(
                    f"OSPF process {interface.process_id} on {interface.interface}",
                    interface.key_reference, tuple(item for item in interface.evidence),
                )
            if interface.shutdown or interface.passive or interface.authentication_state in {"authenticated", "unknown"}:
                continue
            evidence = tuple(item for item in interface.evidence)
            if interface.authentication_state == "weak":
                title = "OSPF interface uses simple-password authentication"
                observation = f"OSPF process {interface.process_id}, interface {interface.interface}, area {interface.area} uses clear-text simple authentication."
                recommendation = "Use message-digest or a supported key-chain algorithm consistently across the adjacency."
                rule_id = "cisco.ios.routing.ospf.weak_authentication"
            else:
                title = "OSPF interface authentication is incomplete"
                observation = f"OSPF process {interface.process_id}, interface {interface.interface}, area {interface.area} is {interface.authentication_state}."
                recommendation = "Configure and validate OSPF authentication consistently across the adjacency."
                rule_id = "cisco.ios.routing.ospf.authentication"
            self.add_issue(self._finding(
                parser, rule_id, title, observation,
                "An unprotected routing adjacency can accept forged protocol packets from a reachable attacker.",
                recommendation, Severity.HIGH if interface.authentication_state != "weak" else Severity.MEDIUM,
                evidence, (CISCO_IOS_OSPF_AUTH_GUIDE,),
            ))

        for interface in ios.get_rip_interfaces():
            state = interface.authentication_state
            if interface.send_version == "1-included" and not interface.passive:
                send_scope = f"RIP network {interface.network} on {interface.interface}"
                if interface.vrf != "default":
                    send_scope += f" in VRF {interface.vrf}"
                self.add_issue(self._finding(
                    parser, "cisco.ios.routing.rip.version1_send",
                    "RIP interface sends unauthenticated version 1 updates",
                    f"{send_scope} explicitly sends RIP version 1 updates, which cannot be authenticated.",
                    "Routing information sent without authentication can be accepted or altered by an untrusted RIP neighbor.",
                    "Send only RIPv2 with an effective authenticated key chain, or disable RIP on this interface.",
                    Severity.MEDIUM,
                    tuple(item for item in interface.evidence),
                    (CISCO_IOS_RIP_GUIDE,),
                    FindingBasis.EXPLICIT_VALUE,
                ))
            if state == "configured-md5":
                report_unusable_key_lifetime(
                    f"RIPv2 on {interface.interface}", interface.key_reference,
                    tuple(item for item in interface.evidence),
                )
            if state in {"configured-md5", "unknown"}:
                continue
            scope = f"RIP network {interface.network} on {interface.interface}"
            if interface.vrf != "default":
                scope += f" in VRF {interface.vrf}"
            if interface.passive:
                scope += " (passive for outbound updates, still receiving)"
            if state == "version1-accepted":
                rule_id = "cisco.ios.routing.rip.version1_receive"
                title = "RIP interface accepts unauthenticated version 1 updates"
                observation = f"{scope} explicitly accepts RIP version 1 packets, which cannot use RIPv2 authentication."
                recommendation = "Accept only RIPv2 on this active interface and configure an effective authenticated key chain."
                severity = Severity.HIGH
            elif state == "unauthenticated":
                rule_id = "cisco.ios.routing.rip.authentication"
                title = "Active RIP interface lacks authentication"
                observation = f"{scope} has no effective RIP authentication key-chain binding."
                recommendation = "Bind a qualified key chain and use message-digest authentication on this interface."
                severity = Severity.HIGH
            elif state == "unresolved":
                rule_id = "cisco.ios.routing.rip.key_resolution"
                title = "RIP authentication key chain is unresolved"
                observation = f"{scope} references a key chain without an exported effective key value."
                recommendation = "Define the referenced key chain with protected key material and verify its intended lifetime."
                severity = Severity.MEDIUM
            else:
                rule_id = "cisco.ios.routing.rip.cleartext_authentication"
                title = "RIP interface uses cleartext authentication"
                observation = f"{scope} uses the RIPv2 text mode, which sends the authentication key in packets."
                recommendation = "Use an effective message-digest key-chain mode supported by this platform and its neighbors."
                severity = Severity.MEDIUM
            self.add_issue(self._finding(
                parser, rule_id, title, observation,
                "A reachable attacker may inject or tamper with routing updates, or learn a cleartext routing key.",
                recommendation, severity,
                tuple(item for item in interface.evidence),
                (CISCO_IOS_RIP_GUIDE,),
                basis=FindingBasis.EXPLICIT_VALUE if state == "version1-accepted" else None,
            ))

        for admission in ios.get_isis_authentication():
            if admission.state == "configured-md5":
                scope = (
                    f"IS-IS {admission.instance or 'default instance'} {admission.level} "
                    f"{admission.scope} authentication on {admission.interface}"
                )
                report_unusable_key_lifetime(
                    scope, admission.key_reference,
                    tuple(item for item in admission.evidence),
                )
            if admission.state not in {"send-only", "text-mode", "unresolved"}:
                continue
            scope = (
                f"IS-IS {admission.instance or 'default instance'} {admission.level} "
                f"{admission.scope} authentication on {admission.interface}"
            )
            if admission.state == "send-only":
                suffix = "send_only"
                title = "IS-IS authentication is send-only"
                observation = f"{scope} explicitly sends authentication but does not validate received packets."
                recommendation = "Disable send-only after configuring working authentication on all intended peers."
                severity = Severity.HIGH
                impact = "Incoming IS-IS packets are not checked against the configured authentication key."
            elif admission.state == "text-mode":
                suffix = "cleartext_authentication"
                title = "IS-IS selects cleartext authentication"
                observation = f"{scope} explicitly selects a cleartext authentication mode or legacy password."
                recommendation = "Use a supported authenticated key chain and message-digest mode for this scope."
                severity = Severity.MEDIUM
                impact = "A reachable observer may recover an authentication password from protocol traffic."
            else:
                suffix = "key_resolution"
                title = "IS-IS authentication key chain is unresolved"
                observation = f"{scope} selects MD5 but has no exported effective key in its bound key chain."
                recommendation = "Bind a populated key chain and verify both send and receive authentication."
                severity = Severity.MEDIUM
                impact = "The declared MD5 mode lacks the exported key material needed for effective authentication."
            self.add_issue(self._finding(
                parser, f"cisco.ios.routing.isis.{suffix}", title, observation,
                impact,
                recommendation, severity,
                tuple(item for item in admission.evidence),
                (CISCO_IOS_ISIS_AUTH_GUIDE,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))

        for interface in ios.get_eigrp_interfaces():
            if not interface.active or interface.passive:
                continue
            state = interface.authentication_state
            named = interface.named_instance
            scope = (
                f"EIGRP AS {interface.autonomous_system} (named instance {named}) on {interface.interface}"
                if named else f"EIGRP AS {interface.autonomous_system} on {interface.interface}"
            )
            if state == "configured-md5":
                report_unusable_key_lifetime(
                    scope, interface.key_reference, tuple(item for item in interface.evidence),
                )
            if state not in {"unauthenticated", "unresolved"}:
                continue
            if state == "unauthenticated":
                rule_id = "cisco.ios.routing.eigrp.authentication"
                title = "Active EIGRP interface lacks authentication"
                if named:
                    observation = f"{scope} has no effective EIGRP authentication mode for this interface or af-interface default."
                    recommendation = (
                        "Configure 'authentication mode hmac-sha-256' or 'authentication mode md5' with a "
                        "populated 'authentication key-chain' under the af-interface (or af-interface default)."
                    )
                else:
                    observation = f"{scope} has no effective EIGRP MD5 authentication mode."
                    recommendation = "Configure EIGRP authentication mode and a populated key chain for this AS on the interface."
                severity = Severity.HIGH
            else:
                rule_id = "cisco.ios.routing.eigrp.key_resolution"
                title = "EIGRP authentication key chain is unresolved"
                observation = f"{scope} enables MD5 but has no bound key chain with exported key material."
                recommendation = "Bind a populated key chain for this EIGRP AS and verify the intended key lifetime."
                severity = Severity.MEDIUM
            self.add_issue(self._finding(
                parser, rule_id, title, observation,
                "A reachable attacker may establish a routing adjacency or inject forged routing updates.",
                recommendation, severity,
                tuple(item for item in interface.evidence),
                (CISCO_IOS_EIGRP_GUIDE,),
            ))

    def check_discovery(self, parser: BaseDeviceParser) -> None:
        ios = self._ios(parser)
        if ios.get_version() == "?":
            return
        for interface in ios.get_discovery_interfaces():
            if not interface.active or interface.role != "external":
                continue
            directions = [
                direction for direction, enabled in (
                    ("transmit", interface.transmit), ("receive", interface.receive)
                ) if enabled
            ]
            if not directions:
                continue
            evidence = tuple(item for item in interface.evidence) + (
                f"assessment policy: {interface.interface} role external",
            )
            self.add_issue(self._finding(
                parser,
                f"cisco.ios.discovery.{interface.protocol}.external",
                f"{interface.protocol.upper()} is enabled on an external interface",
                f"Interface {interface.interface} is explicitly classified external and has {interface.protocol.upper()} {', '.join(directions)} enabled.",
                "Discovery advertisements or learned topology can expose device identity and network structure across an untrusted boundary.",
                f"Disable {interface.protocol.upper()} {', '.join(directions)} on this interface unless the assessment policy documents a required trusted use.",
                Severity.MEDIUM,
                evidence,
                (CISCO_IOS_DISCOVERY_GUIDE,),
            ))

    def check_switch_edge(self, parser: BaseDeviceParser) -> None:
        ios = self._ios(parser)
        if ios.get_version() == "?":
            return
        for interface in ios.get_switch_edge_interfaces():
            if not interface.active or interface.role != "access-edge" or interface.mode == "routed":
                continue
            evidence = tuple(item for item in interface.evidence) + (
                f"assessment policy: {interface.interface} role access-edge",
            )
            if interface.mode == "trunk":
                self.add_issue(self._finding(
                    parser, "cisco.ios.layer2.access_edge_trunk",
                    "Access-edge interface is configured as a trunk",
                    f"Interface {interface.interface} is explicitly classified access-edge but its effective switchport mode is trunk.",
                    "An unintended trunk can expose multiple VLANs to an endpoint and enable VLAN-hopping or segmentation bypass.",
                    "Configure a static access VLAN, or reclassify the interface as an approved uplink with documented trunk scope.",
                    Severity.HIGH, evidence, (CISCO_IOS_ROUTING_HARDENING_GUIDE,),
                ))
                continue
            if interface.mode not in {"access", "switchport"}:
                continue
            if interface.dhcp_trusted or interface.arp_trusted:
                trusted = ", ".join(
                    name for name, enabled in (
                        ("DHCP snooping", interface.dhcp_trusted),
                        ("ARP inspection", interface.arp_trusted),
                    ) if enabled
                )
                self.add_issue(self._finding(
                    parser, "cisco.ios.layer2.access_edge_trust",
                    "Access-edge interface is trusted by spoofing protections",
                    f"Interface {interface.interface} is explicitly classified access-edge but is trusted for {trusted}.",
                    "Trust bypasses validation intended to block rogue DHCP or forged ARP messages from endpoint-facing ports.",
                    "Remove trust from this access edge; reserve trust for explicitly classified DHCP-server or uplink ports.",
                    Severity.HIGH, evidence, (CISCO_IOS_ROUTING_HARDENING_GUIDE,),
                ))
            mechanisms = (
                ("dhcp_snooping", interface.dhcp_snooping, "DHCP snooping for its access VLAN", interface.access_vlan is not None),
                ("arp_inspection", interface.arp_inspection, "Dynamic ARP Inspection for its access VLAN", interface.access_vlan is not None),
                ("source_guard", interface.source_guard, "IP Source Guard", True),
                ("port_security", interface.port_security, "port security", True),
            )
            for suffix, present, label, applicable in mechanisms:
                if present or not applicable:
                    continue
                self.add_issue(self._finding(
                    parser, f"cisco.ios.layer2.access_edge.{suffix}",
                    f"Access-edge interface lacks {label}",
                    f"Interface {interface.interface} is explicitly classified access-edge but lacks {label}."
                    + (f" Its effective access VLAN is {interface.access_vlan}." if interface.access_vlan else " Its access VLAN is unresolved."),
                    "A connected endpoint may spoof addressing or identities, introduce a rogue service, or exceed the intended endpoint count.",
                    f"Enable and validate {label} for this access edge where supported by the exact switch model and attachment design.",
                    Severity.MEDIUM, evidence, (CISCO_IOS_ROUTING_HARDENING_GUIDE,),
                ))

    def check_ipv6_first_hop(self, parser: BaseDeviceParser) -> None:
        """SC-048: an assessed endpoint port explicitly trusted for IPv6 RAs or DHCPv6 server messages.

        Only explicit trust is graded (router/server device-role or trusted-port in an attached
        policy). A missing policy, switch/monitor roles, VLAN-qualified attachments and
        conflicting interface/VLAN attachments stay ungraded: absence of RA or DHCPv6 guard
        depends on whether IPv6 is in use, which the export does not establish.
        """
        ios = self._ios(parser)
        if ios.get_version() == "?":
            return
        checks = (
            ("ra_guard", "router", "cisco.ios.layer2.access_edge.ipv6_ra_trusted",
             "Access-edge port is trusted to send IPv6 router advertisements",
             "RA guard", "router advertisements and redirects",
             "A connected endpoint can announce itself as the IPv6 default router or change prefixes and DNS options, "
             "redirecting or intercepting traffic of other hosts on the VLAN, including on networks that treat IPv6 as unused.",
             "Attach an RA guard policy with device-role host (the default) to this endpoint port; reserve device-role "
             "router and trusted-port for ports classified as uplinks or router-facing."),
            ("dhcp_guard", "server", "cisco.ios.layer2.access_edge.ipv6_dhcp_server_trusted",
             "Access-edge port is trusted to send DHCPv6 server messages",
             "DHCPv6 guard", "DHCPv6 advertisements and replies",
             "A connected endpoint can act as a rogue DHCPv6 server and hand out attacker-controlled DNS servers or addresses.",
             "Attach a DHCPv6 guard policy with device-role client (the default) to this endpoint port; reserve "
             "device-role server and trusted-port for ports facing approved DHCPv6 servers or relays."),
        )
        for port in ios.get_ipv6_first_hop_ports():
            if not port.active or port.role != "access-edge" or port.mode not in {"access", "switchport"}:
                continue
            for attribute, role_state, rule, title, feature, messages, impact, recommendation in checks:
                attachment = getattr(port, attribute)
                if attachment.state not in {role_state, "trusted-port"}:
                    continue
                how = ("trusted-port, which disables policing" if attachment.state == "trusted-port"
                       else f"device-role {role_state}")
                where = "the interface" if attachment.source == "interface" else f"VLAN {port.access_vlan}"
                self.add_issue(self._finding(
                    parser, rule, title,
                    (f"Interface {port.interface} is explicitly classified access-edge, but the {feature} policy "
                     f"'{attachment.policy}' attached to {where} sets {how}, so {messages} from this port are accepted."),
                    impact, recommendation, Severity.HIGH,
                    tuple(port.evidence[:1]) + tuple(attachment.evidence)
                    + (f"assessment policy: {port.interface} role access-edge",),
                    (CISCO_IOS_IPV6_FHS_GUIDE, RFC_9099),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))

    def check_access_admission(self, parser: BaseDeviceParser) -> None:
        ios = self._ios(parser)
        for port in ios.get_access_admission_interfaces():
            if (not port.active or port.role != "access-edge"
                    or port.mode not in {"access", "switchport"}):
                continue
            evidence = tuple(item for item in port.evidence) + (
                f"assessment policy: {port.interface} role access-edge",
            )
            if port.port_control == "force-authorized":
                self.add_issue(self._finding(
                    parser, "cisco.ios.layer2.access_edge.dot1x_force_authorized",
                    "Access-edge port bypasses 802.1X authentication",
                    f"Interface {port.interface} is explicitly force-authorized, allowing port access without an 802.1X exchange.",
                    "An endpoint can obtain link access without the intended port-based authentication; other independent restrictions are not assessed by this finding.",
                    "Use an enforced port-control mode for this assessed access edge, or explicitly document and restrict an approved exception.",
                    Severity.HIGH, evidence, (CISCO_IOS_DOT1X_GUIDE,),
                ))
            elif port.port_control == "auto" and port.global_dot1x is False:
                self.add_issue(self._finding(
                    parser, "cisco.ios.layer2.access_edge.dot1x_global_disabled",
                    "Access-edge 802.1X is globally disabled",
                    f"Interface {port.interface} selects automatic port authentication, but the effective global command disables 802.1X.",
                    "The configured port authenticator cannot enforce the intended admission exchange while global system authentication is disabled.",
                    "Enable global 802.1X system authentication and verify the port's AAA binding before relying on admission control.",
                    Severity.HIGH, evidence, (CISCO_IOS_DOT1X_GUIDE,),
                ))
            elif (port.port_control == "auto" and port.global_dot1x is True
                    and port.open_access is True):
                self.add_issue(self._finding(
                    parser, "cisco.ios.layer2.access_edge.dot1x_open_access",
                    "Access-edge port permits pre-authentication access",
                    f"Interface {port.interface} has active open authentication, so traffic can pass before 802.1X succeeds.",
                    "Pre-authentication traffic is subject only to other independent port restrictions, which this static check does not establish.",
                    "Disable open authentication on this assessed access edge unless a documented pre-authentication exception has suitable independent restrictions.",
                    Severity.MEDIUM, evidence, (CISCO_IOS_OPEN_AUTH_GUIDE,),
                ))

    def check_bpdu_guard(self, parser: BaseDeviceParser) -> None:
        ios = self._ios(parser)
        for port in ios.get_bpdu_guard_policies():
            if (not port.active or port.role != "access-edge" or port.lag_member
                    or port.mode not in {"access", "switchport"}):
                continue
            evidence = tuple(item for item in port.evidence) + (
                f"assessment policy: {port.interface} role access-edge",
            )
            if port.guard_enabled is False:
                cause = {
                    "local-disabled": "an explicit per-port BPDU-guard disable overrides any global guard setting",
                    "global-disabled": "the global PortFast BPDU-guard setting is explicitly disabled",
                    "portfast-disabled": "PortFast is explicitly disabled, so the global PortFast-only guard does not apply",
                }.get(port.guard_state, "BPDU guard is explicitly ineffective")
                self.add_issue(self._finding(
                    parser, "cisco.ios.layer2.access_edge.bpdu_guard_ineffective",
                    "Access-edge port has ineffective BPDU guard",
                    f"Interface {port.interface} is an assessed access edge, but {cause}.",
                    "A connected device can send BPDUs without this edge protection shutting down the port, potentially affecting spanning-tree topology.",
                    "Enable effective BPDU guard on this access port; if relying on the global default, ensure the port is PortFast/edge-enabled and has no local guard disable.",
                    Severity.MEDIUM, evidence, (CISCO_IOS_BPDU_GUARD_GUIDE,),
                ))
            elif port.guard_enabled is True and port.filter_enabled is True:
                self.add_issue(self._finding(
                    parser, "cisco.ios.layer2.access_edge.bpdu_filter_bypass",
                    "Access-edge BPDU filtering can bypass guard",
                    f"Interface {port.interface} has BPDU guard configured but also explicitly filters received BPDUs.",
                    "A local BPDU filter can prevent the guard from seeing the very BPDU that should trigger edge-port shutdown.",
                    "Remove local BPDU filtering on the assessed access edge and retain effective BPDU guard.",
                    Severity.MEDIUM, evidence, (CISCO_IOS_BPDU_GUARD_GUIDE,),
                ))
    def analyze(self, parser: BaseDeviceParser) -> None:
        if not self._applicable(parser):
            return
        self.check_aaa(parser)
        self.check_management_lines(parser)
        self.check_ssh_policy(parser)
        self.check_https_public_certificate(parser)
        self.check_acl_effectiveness(parser)
        self.check_credentials(parser)
        self.check_snmp(parser)
        self.check_logging(parser)
        self.check_configuration_management(parser)
        self.check_ntp(parser)
        self.check_banner(parser)
        self.check_unnecessary_services(parser)
        self.check_programmability_api_acls(parser)
        self.check_smart_install(parser)
        self.check_pptp_dialin(parser)
        self.check_ppp_pap(parser)
        self.check_l2tp_dialin(parser)
        self.check_xe_security_warnings(parser)
        self.check_cis_follow_ups(parser)
        self.check_ike_aggressive_mode(parser)
        self.check_tacacs_keys(parser)
        self.check_ldap_transport(parser)
        self.check_http_tls(parser)
        self.check_fhrp_authentication(parser)
        self.check_ntp_access(parser)
        self.check_snmp_notifications(parser)
        self.check_embedded_credentials(parser)
        self.check_boot_config_retrieval(parser)
        self.check_interface_protections(parser)
        self.check_control_plane(parser)
        self.check_crypto(parser)
        self.check_release_defaults(parser)
        self.check_routing(parser)
        self.check_discovery(parser)
        self.check_switch_edge(parser)
        self.check_ipv6_first_hop(parser)
        self.check_access_admission(parser)
        self.check_bpdu_guard(parser)
