from collections import defaultdict

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.controls import ControlOutcome, record_control
from src.analyze.common.issue import Finding, FindingBasis, Severity
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.common.policy_semantics import ProofState, network_covers, service_covers
from src.devices.juniper.junos import JunOSParser, JunosFirewallTerm


JUNIPER_REMOTE_ACCESS_GUIDE = (
    "https://www.juniper.net/documentation/us/en/software/junos/user-access/"
    "topics/topic-map/junos-software-remote-access-overview.html"
)
JUNIPER_FILTER_GUIDE = (
    "https://www.juniper.net/documentation/us/en/software/junos/user-access/"
    "topics/example/permitted-ip-configuring.html"
)
JUNIPER_REMOTE_ACCESS_OVERVIEW = (
    "https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/"
    "junos-software-remote-access-overview.html"
)
JUNIPER_SSH_REFERENCE = (
    "https://www.juniper.net/documentation/us/en/software/junos/cli-reference/"
    "topics/ref/statement/ssh-edit-system.html"
)
JUNIPER_SECURITY_POLICY_GUIDE = (
    "https://www.juniper.net/documentation/us/en/software/junos/"
    "security-policies/topics/topic-map/security-policy-configuration.html"
)
JUNIPER_POLICY_ORDER_GUIDE = (
    "https://www.juniper.net/documentation/us/en/software/junos/security-policies/"
    "topics/topic-map/security-reordering-policies.html"
)
JUNIPER_ADDRESS_BOOK_GUIDE = (
    "https://www.juniper.net/documentation/us/en/software/junos/security-policies/"
    "topics/topic-map/security-address-books-sets.html"
)
JUNIPER_APPLICATION_GUIDE = (
    "https://www.juniper.net/documentation/us/en/software/junos/security-policies/"
    "topics/topic-map/policy-application-sets-configuration.html"
)
JUNIPER_IPSEC_GUIDE = (
    "https://www.juniper.net/documentation/us/en/software/junos/vpn-ipsec/"
    "topics/topic-map/security-ipsec-vpn-configuration-overview.html"
)
IETF_IKEV2_ALGORITHM_GUIDANCE = "https://www.rfc-editor.org/rfc/rfc8247.html"


def _record_clean_or_absent(parser: JunOSParser, control: str, outcome: ControlOutcome, reason: str,
                            instance: str = "device") -> None:
    """SC-049: an absence-based outcome is unknown while apply-groups inheritance is not expanded."""
    if parser.has_unexpanded_inheritance():
        record_control(parser, control, ControlOutcome.UNKNOWN,
                       reason + " apply-groups inheritance is not expanded.", instance=instance)
    else:
        record_control(parser, control, outcome, reason, instance=instance)


class PluginJunOSChecks(BasePlugin):
    """Effective Junos services, attached firewall filters, and SSH root policy."""

    @staticmethod
    def _junos(parser: BaseDeviceParser) -> JunOSParser:
        if not isinstance(parser, JunOSParser):
            raise TypeError("PluginJunOSChecks requires a Junos parser")
        return parser

    def check_management(self, parser: BaseDeviceParser) -> None:
        services = self._junos(parser).get_services()
        insecure = [protocol for protocol in ("telnet", "http") if services[protocol]]
        for protocol in ("telnet", "http"):
            if services[protocol]:
                record_control(parser, "juniper.junos.cleartext-management", ControlOutcome.FINDING,
                               f"{protocol} management is enabled.", instance=protocol)
            else:
                _record_clean_or_absent(self._junos(parser), "juniper.junos.cleartext-management",
                                        ControlOutcome.NO_FINDING, f"{protocol} management is not configured.",
                                        instance=protocol)
        for protocol in insecure:
            self.add_issue(
                Finding(
                    rule_id="juniper.junos.management.insecure_protocol",
                    device=parser.device_type,
                    title="Insecure Management Service Enabled",
                    observation=f"The effective Junos configuration enables {protocol.upper()} management; HTTPS-only configuration does not trigger this rule.",
                    impact="The management protocol does not provide adequate transport confidentiality.",
                    severity=Severity.HIGH,
                    exploitability="An attacker on the management traffic path may intercept credentials or sessions.",
                    recommendation=f"Delete system services {protocol} and use SSH or HTTPS with source restrictions.",
                    evidence=tuple(
                        statement.evidence
                        for statement in self._junos(parser).statements
                        if statement.active and protocol in statement.path
                    ),
                    references=(JUNIPER_REMOTE_ACCESS_GUIDE,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                )
            )

    @staticmethod
    def _is_any(values: tuple[str, ...], family: str) -> bool:
        if not values:
            return True
        wildcards = {"0.0.0.0/0"} if family == "inet" else {"::/0", "0::/0"}
        return all(value.casefold() in wildcards for value in values)

    def _is_catch_all(self, term: JunosFirewallTerm) -> bool:
        return (
            self._is_any(term.sources, term.family)
            and self._is_any(term.destinations, term.family)
            and not term.protocols
        )

    def check_broad_filters(self, parser: BaseDeviceParser) -> None:
        terms_by_filter = defaultdict(list)
        for term in self._junos(parser).get_filter_terms():
            if term.active and term.attachments:
                terms_by_filter[(term.family, term.filter_name)].append(term)

        if not terms_by_filter:
            _record_clean_or_absent(self._junos(parser), "juniper.junos.filter-scope", ControlOutcome.NOT_APPLICABLE,
                                    "No attached firewall filter term is configured.")
        for (filter_family, filter_name), terms in terms_by_filter.items():
            filter_instance = f"{filter_family} filter {filter_name}"
            terminal_seen = False
            for term in sorted(terms, key=lambda item: item.position):
                if terminal_seen:
                    continue
                action = next(
                    (item for item in term.actions if item in {"accept", "discard", "reject"}),
                    "",
                )
                catch_all = self._is_catch_all(term)
                if action == "accept" and catch_all:
                    record_control(parser, "juniper.junos.filter-scope", ControlOutcome.FINDING,
                                   f"Term '{term.term_name}' accepts all traffic.", instance=filter_instance)
                    self.add_issue(
                        Finding(
                            rule_id="juniper.junos.filter.broad_accept",
                            device=parser.device_type,
                            title="Broad Firewall Filter",
                            observation=f"Attached {term.family} filter '{term.filter_name}' term '{term.term_name}' accepts all sources, destinations, and protocols at position {term.position}; attachments: {', '.join(term.attachments)}.",
                            impact="The term permits unrestricted traffic through every interface direction where the filter is attached.",
                            severity=Severity.CRITICAL,
                            exploitability="Any source can reach any destination and protocol within the attached filter scope.",
                            recommendation="Add explicit source, destination, and protocol matches before accepting traffic.",
                            evidence=tuple(item for item in term.evidence),
                            references=(JUNIPER_FILTER_GUIDE,),
                            basis=FindingBasis.EXPLICIT_VALUE,
                        )
                    )
                if catch_all and action in {"accept", "discard", "reject"}:
                    terminal_seen = True
            _record_clean_or_absent(self._junos(parser), "juniper.junos.filter-scope", ControlOutcome.NO_FINDING,
                                    "No reachable catch-all accept term.", instance=filter_instance)

    def check_ssh_root(self, parser: BaseDeviceParser) -> None:
        junos = self._junos(parser)
        value, evidence = junos.get_ssh_root_login()
        if not value:
            # SC-044 JUN-01: Junos remote access overview, 'The default is deny-password',
            # which still allows root logins with an SSH key. Only reported when the
            # service is on and root has a key configured.
            paths = junos._active_paths()
            keys = sorted({path[2] for path in paths
                           if path[:2] == ("system", "root-authentication") and len(path) > 2
                           and path[2].startswith("ssh-")})
            control = "juniper.junos.ssh-root-login"
            if junos.get_services().get("ssh") and keys:
                record_control(parser, control, ControlOutcome.FINDING,
                               "Default deny-password still admits root with its configured SSH key.")
            elif junos.has_unexpanded_inheritance():
                record_control(parser, control, ControlOutcome.UNKNOWN,
                               "root-login is absent and apply-groups inheritance is not expanded.")
            elif not junos.get_services().get("ssh"):
                record_control(parser, control, ControlOutcome.NOT_APPLICABLE, "SSH service is not configured.")
            else:
                record_control(parser, control, ControlOutcome.NO_FINDING,
                               "Default deny-password applies and root has no SSH key configured.")
            if junos.get_services().get("ssh") and keys:
                self.add_issue(Finding(
                    rule_id="juniper.junos.ssh.root_login",
                    device=parser.device_type,
                    title="SSH Root Login Permitted",
                    observation=("'root-login' is not configured, so the documented default 'deny-password' applies and "
                                 f"root can log in over SSH with its configured key ({', '.join(keys)})."),
                    impact="Direct use of the root identity reduces accountability and increases the impact of key compromise.",
                    severity=Severity.MEDIUM,
                    exploitability="An attacker who obtains the root private key gets immediate full privilege.",
                    recommendation="Configure 'set system services ssh root-login deny' and use named administrative accounts.",
                    evidence=("system services ssh root-login absent: default deny-password",
                              *(f"system root-authentication {key} <redacted>" for key in keys)),
                    references=(JUNIPER_SSH_REFERENCE, JUNIPER_REMOTE_ACCESS_OVERVIEW),
                    basis=FindingBasis.DOCUMENTED_DEFAULT,
                ))
            return
        if value == "deny":
            record_control(parser, "juniper.junos.ssh-root-login", ControlOutcome.NO_FINDING,
                           "root-login deny is configured.")
            return
        record_control(parser, "juniper.junos.ssh-root-login", ControlOutcome.FINDING,
                       f"root-login {value} permits direct root access." if value in {"allow", "deny-password"}
                       else "root-login uses an unrecognized value.")
        detail = (
            "permits root authentication by all configured SSH methods"
            if value == "allow"
            else "still permits direct root access using public-key authentication"
            if value == "deny-password"
            else f"uses unrecognized value '{value}'"
        )
        self.add_issue(
            Finding(
                rule_id="juniper.junos.ssh.root_login",
                device=parser.device_type,
                title="SSH Root Login Permitted",
                observation=f"Effective 'root-login {value}' {detail}.",
                impact="Direct use of the root identity reduces accountability and increases the impact of credential compromise.",
                severity=Severity.HIGH if value == "allow" else Severity.MEDIUM,
                exploitability="An attacker who compromises an allowed root credential obtains immediate full privilege.",
                recommendation="Configure 'set system services ssh root-login deny' and use named administrative accounts.",
                evidence=tuple(item for item in evidence) or (f"root-login {value}",),
                references=(JUNIPER_SSH_REFERENCE,),
                basis=FindingBasis.EXPLICIT_VALUE,
            )
        )

    def check_stateful_policies(self, parser: BaseDeviceParser) -> None:
        for policy in self._junos(parser).get_security_policies():
            if (
                policy.active
                and policy.action == "permit"
                and not policy.inheritance_unknown
                and policy.source_resolution == "wildcard"
                and policy.destination_resolution == "wildcard"
                and policy.application_resolution in {"wildcard", "default-any"}
            ):
                record_control(parser, "juniper.junos.policy-scope", ControlOutcome.FINDING,
                               "The policy permits wildcard sources, destinations and applications.",
                               instance=f"{policy.from_zone}->{policy.to_zone}:{policy.name}")
            if (
                not policy.active
                or policy.action != "permit"
                or policy.inheritance_unknown
                or policy.source_resolution != "wildcard"
                or policy.destination_resolution != "wildcard"
                or policy.application_resolution not in {"wildcard", "default-any"}
            ):
                continue
            application = (
                ", ".join(policy.applications)
                if policy.applications
                else "the omitted application default (any)"
            )
            tunnel = f" through IPsec VPN '{policy.tunnel}'" if policy.tunnel else ""
            self.add_issue(
                Finding(
                    rule_id="juniper.junos.policy.broad_permit",
                    device=parser.device_type,
                    title="Broad SRX security policy permits all traffic",
                    observation=f"Active policy '{policy.name}' at position {policy.position} from zone '{policy.from_zone}' to '{policy.to_zone}' permits wildcard sources, wildcard destinations, and {application}{tunnel}.",
                    impact="The stateful policy does not restrict hosts or applications within its zone-pair scope.",
                    severity=Severity.CRITICAL,
                    exploitability="Any source entering the source zone can attempt any application toward any destination in the destination zone allowed by routing and surrounding controls.",
                    recommendation="Replace wildcard address and application matches with explicitly required objects and applications, preserving an ordered terminal deny policy.",
                    evidence=tuple(item for item in policy.evidence),
                    references=(JUNIPER_SECURITY_POLICY_GUIDE,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                )
            )

    def check_stateful_policy_effectiveness(self, parser: BaseDeviceParser) -> None:
        """Prove SRX shadowing only inside one fully resolved zone pair."""

        prior_by_zone_pair = defaultdict(list)
        references = (
            JUNIPER_SECURITY_POLICY_GUIDE,
            JUNIPER_POLICY_ORDER_GUIDE,
            JUNIPER_ADDRESS_BOOK_GUIDE,
            JUNIPER_APPLICATION_GUIDE,
        )
        policies = self._junos(parser).get_security_policies()
        if not policies:
            for control in ("juniper.junos.policy-scope", "juniper.junos.policy-order"):
                _record_clean_or_absent(self._junos(parser), control, ControlOutcome.NOT_APPLICABLE,
                                        "No SRX security policy is configured.")
        unqualified_pairs: set[tuple[str, str]] = set()

        def qualified(item) -> bool:
            return (item.source_networks.complete and item.destination_networks.complete
                    and item.services.complete)

        for policy in policies:
            evidence = tuple(item for item in policy.evidence) or (
                f"security policy {policy.name}",
            )
            policy_instance = f"{policy.from_zone}->{policy.to_zone}:{policy.name}"
            if not policy.active or policy.action != "permit":
                record_control(parser, "juniper.junos.policy-scope", ControlOutcome.NOT_APPLICABLE,
                               "The policy is inactive or does not permit traffic.", instance=policy_instance)
            elif policy.inheritance_unknown or policy.services.any or not policy.services.complete:
                record_control(parser, "juniper.junos.policy-scope", ControlOutcome.UNKNOWN,
                               "apply-groups inheritance is not expanded or the application match is not fully resolved.",
                               instance=policy_instance)
            else:
                record_control(parser, "juniper.junos.policy-scope", ControlOutcome.NO_FINDING,
                               "The policy is restricted to resolved applications.", instance=policy_instance)
            if (
                policy.active
                and policy.action == "permit"
                and policy.services.any
                and not (
                    policy.source_resolution == "wildcard"
                    and policy.destination_resolution == "wildcard"
                )
            ):
                self.add_issue(Finding(
                    rule_id="juniper.junos.policy.broad_application",
                    device=parser.device_type,
                    title="SRX security policy is unrestricted by application",
                    observation=f"Active policy '{policy.name}' at position {policy.position} from zone '{policy.from_zone}' to '{policy.to_zone}' permits any application within its address scope.",
                    impact="Unnecessary protocols and destination ports can cross the zone boundary.",
                    severity=Severity.MEDIUM,
                    exploitability="A source matching the address scope can attempt any application reachable in the destination zone.",
                    recommendation="Replace application any with the smallest required custom or predefined applications.",
                    evidence=evidence,
                    references=references,
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
                record_control(parser, "juniper.junos.policy-scope", ControlOutcome.FINDING,
                               "The policy permits any application.", instance=policy_instance)

            if (
                not policy.active
                or policy.action not in {"permit", "deny", "reject"}
                or policy.inheritance_unknown
                or policy.unsupported_predicates
            ):
                if policy.active:
                    unqualified_pairs.add((policy.from_zone.casefold(), policy.to_zone.casefold()))
                record_control(parser, "juniper.junos.policy-order",
                               ControlOutcome.UNKNOWN if policy.active else ControlOutcome.NOT_APPLICABLE,
                               "The policy action, predicates or inheritance are not supported for order proof."
                               if policy.active else "The policy is inactive.", instance=policy_instance)
                continue
            key = (policy.from_zone.casefold(), policy.to_zone.casefold())
            for earlier in prior_by_zone_pair[key]:
                if not all(
                    result == ProofState.PROVEN
                    for result in (
                        network_covers(
                            earlier.source_networks, policy.source_networks
                        ),
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
                self.add_issue(Finding(
                    rule_id=(
                        "juniper.junos.policy.redundant_rule"
                        if same_action
                        else "juniper.junos.policy.shadowed_rule"
                    ),
                    device=parser.device_type,
                    title="SRX security policy is redundant" if same_action else "SRX security policy is shadowed",
                    observation=f"Policy '{policy.name}' at position {policy.position} in zone pair '{policy.from_zone}' to '{policy.to_zone}' is fully covered by earlier policy '{earlier.name}' at position {earlier.position} with {'equivalent behavior' if same_action else 'a different terminal action'}.",
                    impact="The later policy cannot alter first-match enforcement for the statically proven traffic scope and obscures policy intent.",
                    severity=Severity.LOW if same_action else Severity.HIGH,
                    exploitability="A conflicting shadowed policy can give reviewers a false impression of enforced zone access control.",
                    recommendation="Remove or reorder the policy after validating address-book, application, logging, tunnel and operational intent.",
                    evidence=evidence + tuple(item for item in earlier.evidence),
                    references=references,
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
                record_control(parser, "juniper.junos.policy-order", ControlOutcome.FINDING,
                               "Proven static shadow/redundancy; this does not prove observed nonuse.",
                               instance=policy_instance)
                break
            known = (key not in unqualified_pairs and qualified(policy)
                     and all(qualified(earlier) for earlier in prior_by_zone_pair[key]))
            record_control(parser, "juniper.junos.policy-order",
                           ControlOutcome.NO_FINDING if known else ControlOutcome.UNKNOWN,
                           "Bounded static comparison with earlier policies in the zone pair is qualified." if known
                           else "Address, application or earlier-policy semantics are not fully resolved.",
                           instance=policy_instance)
            prior_by_zone_pair[key].append(policy)

    def check_ipsec_vpns(self, parser: BaseDeviceParser) -> None:
        junos = self._junos(parser)
        inheritance_unknown = any("apply-groups" in item for item in junos.diagnostics)
        weak_encryption = {"des-cbc", "3des-cbc"}
        weak_authentication = {"md5", "sha1", "hmac-md5-96", "hmac-sha1-96"}
        weak_groups = {"group1", "group2", "group5", "group22", "group23", "group24"}
        vpns = junos.get_ipsec_vpns()
        if not vpns:
            _record_clean_or_absent(junos, "juniper.junos.vpn-crypto", ControlOutcome.NOT_APPLICABLE,
                                    "No attached or interface-bound IPsec VPN is configured.")
        for vpn in vpns:
            vpn_instance = f"vpn {vpn.name}"
            if not vpn.active:
                record_control(parser, "juniper.junos.vpn-crypto", ControlOutcome.NOT_APPLICABLE,
                               "The VPN is inactive or not attached.", instance=vpn_instance)
                continue
            evidence = tuple(item for item in vpn.evidence) or (
                f"security ipsec vpn {vpn.name}",
            )
            if vpn.resolution_state == "unresolved":
                record_control(parser, "juniper.junos.vpn-crypto",
                               ControlOutcome.UNKNOWN if inheritance_unknown else ControlOutcome.FINDING,
                               "The proposal chain does not resolve"
                               + ("; apply-groups inheritance is not expanded." if inheritance_unknown else "."),
                               instance=vpn_instance)
                if inheritance_unknown:
                    continue
                self.add_issue(
                    Finding(
                        rule_id="juniper.junos.vpn.unresolved",
                        device=parser.device_type,
                        title="Attached SRX IPsec VPN has an unresolved proposal chain",
                        observation=f"Active VPN '{vpn.name}' attached to {', '.join(vpn.attachments) or vpn.bind_interface or 'an active binding'} does not resolve through an enabled gateway, IKE policy/proposal, and IPsec policy/proposal chain.",
                        impact="The static configuration does not define a complete local negotiation policy for the intended protected path.",
                        severity=Severity.HIGH,
                        exploitability="A missing or inactive reference can prevent the protected tunnel from establishing and may cause traffic to follow an unintended alternative path.",
                        recommendation="Resolve every VPN, gateway, IKE policy/proposal and IPsec policy/proposal reference, then verify peer identity and selectors.",
                        evidence=evidence,
                        references=(JUNIPER_IPSEC_GUIDE,),
                        basis=FindingBasis.REQUIRED_SETTING_MISSING,
                    )
                )
                continue
            weak_ike_encryption = sorted(set(vpn.ike_encryption).intersection(weak_encryption))
            weak_ipsec_encryption = sorted(set(vpn.ipsec_encryption).intersection(weak_encryption))
            weak_auth = sorted(
                set(vpn.ike_authentication + vpn.ipsec_authentication).intersection(
                    weak_authentication
                )
            )
            weak_dh = sorted(
                set(vpn.ike_dh_groups + vpn.pfs_dh_groups).intersection(weak_groups)
            )
            weaknesses = []
            if weak_ike_encryption:
                weaknesses.append("IKE encryption " + ", ".join(weak_ike_encryption))
            if weak_ipsec_encryption:
                weaknesses.append("IPsec encryption " + ", ".join(weak_ipsec_encryption))
            if weak_auth:
                weaknesses.append("authentication " + ", ".join(weak_auth))
            if weak_dh:
                weaknesses.append("DH/PFS " + ", ".join(weak_dh))
            if weaknesses:
                record_control(parser, "juniper.junos.vpn-crypto", ControlOutcome.FINDING,
                               "Weak: " + "; ".join(weaknesses) + ".", instance=vpn_instance)
            elif vpn.resolution_state == "vendor-default":
                record_control(parser, "juniper.junos.vpn-crypto", ControlOutcome.UNKNOWN,
                               "A vendor proposal-set is used; its algorithms are not evaluated.", instance=vpn_instance)
            elif not (vpn.ike_encryption and vpn.ike_dh_groups and vpn.ipsec_encryption) or inheritance_unknown:
                record_control(parser, "juniper.junos.vpn-crypto", ControlOutcome.UNKNOWN,
                               "An algorithm is omitted (release default not verified) or apply-groups inheritance "
                               "is not expanded.", instance=vpn_instance)
            else:
                record_control(parser, "juniper.junos.vpn-crypto", ControlOutcome.NO_FINDING,
                               "Explicit IKE and IPsec algorithms contain no weak value.", instance=vpn_instance)
            if not weaknesses:
                continue
            self.add_issue(
                Finding(
                    rule_id="juniper.junos.vpn.weak_proposal",
                    device=parser.device_type,
                    title="Attached SRX IPsec VPN permits weak cryptography",
                    observation=f"Active VPN '{vpn.name}' resolves to {'; '.join(weaknesses)}.",
                    impact="Legacy encryption, integrity algorithms, or small Diffie-Hellman groups weaken the confidentiality and integrity of the VPN.",
                    severity=Severity.HIGH,
                    exploitability="An attacker capable of recording or interfering with tunnel negotiation or ciphertext may benefit from the explicitly permitted legacy transforms.",
                    recommendation="Use AES or an approved AEAD mode, SHA-256 or stronger integrity, and DH group 14 or an approved stronger group on both peers.",
                    evidence=evidence,
                    references=(JUNIPER_IPSEC_GUIDE, IETF_IKEV2_ALGORITHM_GUIDANCE),
                    basis=FindingBasis.EXPLICIT_VALUE,
                )
            )

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_management(parser)
        self.check_broad_filters(parser)
        self.check_ssh_root(parser)
        self.check_stateful_policies(parser)
        self.check_stateful_policy_effectiveness(parser)
        self.check_ipsec_vpns(parser)
