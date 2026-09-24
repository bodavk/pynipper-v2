from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.issue import Finding, Severity
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.common.policy_semantics import ProofState, network_covers, service_covers
from src.devices.juniper.screenos import JuniperScreenOSParser


JUNIPER_SCREENOS_DOCUMENTATION = (
    "https://www.juniper.net/documentation/product/us/en/screenos/6.3.0/"
)


class PluginScreenOSChecks(BasePlugin):
    """Evaluate effective ScreenOS interface management and ordered policies."""

    @staticmethod
    def _screenos(parser: BaseDeviceParser) -> JuniperScreenOSParser:
        if not isinstance(parser, JuniperScreenOSParser):
            raise TypeError("PluginScreenOSChecks requires a ScreenOS parser")
        return parser

    def _management_finding(
        self,
        parser: BaseDeviceParser,
        protocol: str,
        interface: str,
        zone: str,
        permitted_sources: tuple[str, ...],
        evidence: tuple[str, ...],
    ) -> Finding:
        rule_id = (
            "juniper.screenos.management.telnet"
            if protocol == "telnet"
            else "juniper.screenos.management.http"
        )
        title = "Telnet Service Enabled" if protocol == "telnet" else "Web Management (HTTP) Enabled"
        source_scope = ", ".join(permitted_sources) if permitted_sources else "unrestricted/unspecified manager sources"
        trust = "untrusted" if zone.casefold() in {"untrust", "dmz", "public"} else "trusted or unspecified"
        return Finding(
            rule_id=rule_id,
            device=parser.device_type,
            title=title,
            observation=f"Effective {protocol.upper()} management is enabled on {interface or 'global scope'} in zone '{zone or 'unspecified'}' ({trust}); permitted manager sources: {source_scope}.",
            impact="The clear-text management protocol can expose administrative credentials and sessions.",
            severity=Severity.HIGH,
            exploitability="An attacker with reachability through the stated interface/zone can intercept or attempt management access.",
            recommendation=f"Remove {protocol} management from the interface and use SSH or HTTPS with manager-IP restrictions.",
            evidence=evidence or (f"effective {protocol} management",),
            references=(JUNIPER_SCREENOS_DOCUMENTATION,),
        )

    def check_insecure_services(self, parser: BaseDeviceParser) -> None:
        screenos = self._screenos(parser)
        for protocol in sorted(screenos.global_management & {"telnet", "http"}):
            evidence = screenos.global_management_evidence.get(protocol)
            self.add_issue(
                self._management_finding(
                    parser,
                    protocol,
                    "",
                    "",
                    tuple(screenos.manager_ips),
                    (evidence,) if evidence else (),
                )
            )
        for interface in screenos.interfaces.values():
            if interface.disabled:
                continue
            for protocol in sorted(interface.management_methods & {"telnet", "http"}):
                self.add_issue(
                    self._management_finding(
                        parser,
                        protocol,
                        interface.name,
                        interface.zone,
                        tuple(interface.manager_ips or screenos.manager_ips),
                        tuple(item for item in interface.evidence),
                    )
                )

    @staticmethod
    def _all_any(values: list[str]) -> bool:
        return bool(values) and all(value.strip().casefold() == "any" for value in values)

    def check_broad_policy_rules(self, parser: BaseDeviceParser) -> None:
        for policy in self._screenos(parser).policies.values():
            if policy.disabled or policy.action.casefold() not in {"permit", "accept"}:
                continue
            if not (
                self._all_any(policy.sources)
                and self._all_any(policy.destinations)
                and self._all_any(policy.services)
            ):
                continue
            self.add_issue(
                Finding(
                    rule_id="juniper.screenos.policy.broad_permit",
                    device=parser.device_type,
                    title="Broad Policy Rule Detected",
                    observation=f"Enabled policy ID {policy.policy_id} at position {policy.position} permits Any source, Any destination, and Any service from zone '{policy.from_zone}' to '{policy.to_zone}'; tracking is '{policy.tracking or 'not configured'}'.",
                    impact="The policy allows unrestricted traffic between its source and destination zones.",
                    severity=Severity.CRITICAL,
                    exploitability="Any source in the source zone can target any destination and service in the destination zone.",
                    recommendation="Replace Any source, destination, and service values with explicit objects and enable session logging.",
                    evidence=tuple(item for item in policy.evidence),
                    references=(JUNIPER_SCREENOS_DOCUMENTATION,),
                )
            )

    def check_policy_effectiveness(self, parser: BaseDeviceParser) -> None:
        screenos = self._screenos(parser)
        prior_by_zone_pair = {}
        for policy in screenos.get_policy_semantics():
            evidence = tuple(item for item in policy.evidence) or (
                f"policy id {policy.policy_id}",
            )
            if not policy.enabled:
                if (
                    policy.action in {"permit", "accept"}
                    and policy.source_networks.any
                    and policy.destination_networks.any
                    and policy.services.any
                    and not policy.unsupported_predicates
                ):
                    self.add_issue(Finding(
                        rule_id="juniper.screenos.policy.disabled_permissive_rule",
                        device=parser.device_type,
                        title="Disabled permissive ScreenOS policy remains configured",
                        observation=f"Disabled policy ID {policy.policy_id} at position {policy.position} retains an Any-source, Any-destination, Any-service permit from zone '{policy.from_zone}' to '{policy.to_zone}'.",
                        impact="Stale permissive policy obscures intent and can create broad exposure if re-enabled.",
                        severity=Severity.LOW,
                        exploitability="The policy is disabled in the supplied configuration; exploitation requires reactivation.",
                        recommendation="Remove the obsolete policy or narrow and document it before reactivation.",
                        evidence=evidence,
                        references=(JUNIPER_SCREENOS_DOCUMENTATION,),
                    ))
                continue

            if (
                policy.action in {"permit", "accept"}
                and policy.services.any
                and not (policy.source_networks.any and policy.destination_networks.any)
            ):
                self.add_issue(Finding(
                    rule_id="juniper.screenos.policy.broad_service",
                    device=parser.device_type,
                    title="ScreenOS policy is unrestricted by service",
                    observation=f"Enabled policy ID {policy.policy_id} at position {policy.position} permits Any service within its address scope from zone '{policy.from_zone}' to '{policy.to_zone}'.",
                    impact="Unnecessary protocols and destination ports can cross the zone boundary.",
                    severity=Severity.MEDIUM,
                    exploitability="A matching source can attempt any service reachable in the destination zone.",
                    recommendation="Replace Any with the smallest required services or reviewed service group.",
                    evidence=evidence,
                    references=(JUNIPER_SCREENOS_DOCUMENTATION,),
                ))

            if (
                policy.action not in {"permit", "accept", "deny", "reject"}
                or policy.unsupported_predicates
            ):
                continue
            key = (policy.from_zone.casefold(), policy.to_zone.casefold())
            earlier_policies = prior_by_zone_pair.setdefault(key, [])
            for earlier in earlier_policies:
                if not all(
                    state == ProofState.PROVEN
                    for state in (
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
                        "juniper.screenos.policy.redundant_rule"
                        if same_action
                        else "juniper.screenos.policy.shadowed_rule"
                    ),
                    device=parser.device_type,
                    title="ScreenOS policy is redundant" if same_action else "ScreenOS policy is shadowed",
                    observation=f"Policy ID {policy.policy_id} at position {policy.position} in zone pair '{policy.from_zone}' to '{policy.to_zone}' is fully covered by earlier policy ID {earlier.policy_id} at position {earlier.position} with {'equivalent behavior' if same_action else 'a different terminal action'}.",
                    impact="The later policy cannot alter first-match enforcement for the statically proven traffic scope and obscures policy intent.",
                    severity=Severity.LOW if same_action else Severity.HIGH,
                    exploitability="A conflicting shadowed policy can give reviewers a false impression of enforced access control.",
                    recommendation="Remove or reorder the policy after validating address/service objects, logging and operational intent.",
                    evidence=evidence + tuple(item for item in earlier.evidence),
                    references=(JUNIPER_SCREENOS_DOCUMENTATION,),
                ))
                break
            earlier_policies.append(policy)

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_insecure_services(parser)
        self.check_broad_policy_rules(parser)
        self.check_policy_effectiveness(parser)
