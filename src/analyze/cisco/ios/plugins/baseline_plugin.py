import re

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.credentials import credential_policy_from_context, evaluate_credential
from src.analyze.common.issue import Finding, Severity
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.common.policy_semantics import ProofState, network_covers, service_covers
from src.devices.cisco.ios import CiscoIOSParser
from src.devices.common.models import DefaultCredentialAssessment


CISCO_IOS_HARDENING_GUIDE = (
    "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
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
                        evidence or (line.line,),
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
            elif credential.context in {"radius_key", "line_password"}:
                self.add_issue(self._finding(
                    parser,
                    f"cisco.ios.credentials.{credential.context}_storage",
                    "Shared or line credential uses unsafe storage",
                    f"The {credential.context.replace('_', ' ')} at '{credential.account}' uses storage type '{credential.storage_type}', classified as '{result.storage_assessment.value}' under policy '{result.policy_version}'. The value is redacted.",
                    "Configuration disclosure can expose or permit recovery of the credential.",
                    "Use supported protected storage and rotate the exposed value.",
                    Severity.HIGH,
                    tuple(item for item in credential.evidence),
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
                )
            )
            return
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
                )
            )

    def check_unnecessary_services(self, parser: BaseDeviceParser) -> None:
        lines = self._global_lines(parser)
        unsafe = [
            line
            for line in lines
            if line in {
                "service finger",
                "service tcp-small-servers",
                "service udp-small-servers",
                "ip bootp server",
            }
        ]
        if unsafe:
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.services.unnecessary",
                    "Unnecessary legacy services are enabled",
                    f"Explicit legacy service commands are active: {', '.join(unsafe)}.",
                    "Unneeded listeners increase management-plane attack surface.",
                    "Disable every service that is not operationally required using its 'no' form.",
                    Severity.MEDIUM,
                    tuple(unsafe),
                )
            )

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
        if "no ip source-route" not in lines:
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.ip.source_route",
                    "IP source routing is not explicitly disabled",
                    "The configuration does not contain the IOS 'no ip source-route' hardening command.",
                    "Source-routed packets can bypass expected routing paths and trust boundaries on applicable releases.",
                    "Configure 'no ip source-route'.",
                    Severity.MEDIUM,
                    ("no ip source-route absent",),
                )
            )
        for interface in parser.get_native_config().find_objects(r"^interface\s+"):
            children = self._children(interface)
            if "shutdown" in children or not any(line.startswith("ip address ") for line in children):
                continue
            missing = []
            if "no ip redirects" not in children:
                missing.append("no ip redirects")
            if "no ip proxy-arp" not in children:
                missing.append("no ip proxy-arp")
            if missing:
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.interface.ip_hardening",
                        "Layer-3 interface hardening is incomplete",
                        f"{interface.text.strip()} lacks {', '.join(missing)}.",
                        "Redirects or proxy ARP can enable traffic redirection and weaken local network trust assumptions.",
                        "Disable redirects and proxy ARP on routed interfaces unless explicitly required.",
                        Severity.MEDIUM,
                        (interface.text.strip(), *missing),
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

    def check_crypto(self, parser: BaseDeviceParser) -> None:
        native = parser.get_native_config()
        for policy in native.find_objects(r"^crypto (?:isakmp|ikev1) policy\s+"):
            children = self._children(policy)
            weak = [
                line for line in children
                if re.fullmatch(r"encryption (?:des|3des)", line)
                or re.fullmatch(r"hash (?:md5|sha)", line)
                or re.fullmatch(r"group (?:1|2|5|14)", line)
            ]
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
            if state == "configured-md5":
                report_unusable_key_lifetime(
                    f"RIPv2 on {interface.interface}", interface.key_reference,
                    tuple(item for item in interface.evidence),
                )
            if state in {"configured-md5", "unknown"}:
                continue
            scope = f"RIPv2 network {interface.network} on {interface.interface}"
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
            ))

        for interface in ios.get_eigrp_interfaces():
            if not interface.active or interface.passive:
                continue
            state = interface.authentication_state
            if state == "configured-md5":
                report_unusable_key_lifetime(
                    f"EIGRP AS {interface.autonomous_system} on {interface.interface}",
                    interface.key_reference, tuple(item for item in interface.evidence),
                )
            if state not in {"unauthenticated", "unresolved"}:
                continue
            scope = f"EIGRP AS {interface.autonomous_system} on {interface.interface}"
            if state == "unauthenticated":
                rule_id = "cisco.ios.routing.eigrp.authentication"
                title = "Active EIGRP interface lacks authentication"
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
        self.check_boot_config_retrieval(parser)
        self.check_interface_protections(parser)
        self.check_control_plane(parser)
        self.check_crypto(parser)
        self.check_routing(parser)
        self.check_discovery(parser)
        self.check_switch_edge(parser)
        self.check_access_admission(parser)
        self.check_bpdu_guard(parser)
