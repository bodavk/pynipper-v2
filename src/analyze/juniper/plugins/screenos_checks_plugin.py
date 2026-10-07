from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.controls import ControlOutcome, record_control
from src.analyze.common.issue import Finding, FindingBasis, Severity
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.common.policy_semantics import ProofState, network_covers, service_covers
from src.devices.juniper.screenos import JuniperScreenOSParser


JUNIPER_SCREENOS_DOCUMENTATION = (
    "https://www.juniper.net/documentation/product/us/en/screenos/6.3.0/"
)
_MANAGEMENT_CONTROLS = {
    "telnet": "juniper.screenos.management-telnet",
    "http": "juniper.screenos.management-http",
}


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
            basis=FindingBasis.EXPLICIT_VALUE,
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
            record_control(parser, _MANAGEMENT_CONTROLS[protocol], ControlOutcome.FINDING,
                           f"{protocol.upper()} management is enabled globally.", instance="global")
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
                record_control(parser, _MANAGEMENT_CONTROLS[protocol], ControlOutcome.FINDING,
                               f"{protocol.upper()} management is enabled on the interface.",
                               instance=f"interface {interface.name}")
            for protocol in sorted({"telnet", "http"} - interface.management_methods):
                if interface.management_stated:
                    record_control(parser, _MANAGEMENT_CONTROLS[protocol], ControlOutcome.NO_FINDING,
                                   f"The interface's exported manage statements do not enable {protocol.upper()}.",
                                   instance=f"interface {interface.name}")
                else:
                    record_control(parser, _MANAGEMENT_CONTROLS[protocol], ControlOutcome.UNKNOWN,
                                   "The interface has no exported manage statement and the ScreenOS default "
                                   "management services are not verified for this release.",
                                   instance=f"interface {interface.name}")
        active_interfaces = [item for item in screenos.interfaces.values() if not item.disabled]
        for protocol, control_id in _MANAGEMENT_CONTROLS.items():
            if protocol in screenos.global_management or active_interfaces:
                continue
            if screenos.interfaces:
                record_control(parser, control_id, ControlOutcome.NOT_APPLICABLE,
                               "Every exported interface is disabled and no global management is enabled.")
            else:
                record_control(parser, control_id, ControlOutcome.UNKNOWN,
                               "No interface configuration is exported.")

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
            record_control(parser, "juniper.screenos.policy-scope", ControlOutcome.FINDING,
                           "The enabled permit policy uses literal Any source, destination and service.",
                           instance=f"policy {policy.policy_id}")
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
                    basis=FindingBasis.EXPLICIT_VALUE,
                )
            )

    def check_policy_effectiveness(self, parser: BaseDeviceParser) -> None:
        screenos = self._screenos(parser)
        prior_by_zone_pair = {}
        seen = {"scope": False, "order": False, "disabled": False}
        for policy in screenos.get_policy_semantics():
            instance = f"policy {policy.policy_id}"
            selectors = (policy.source_networks, policy.destination_networks, policy.services)
            evidence = tuple(item for item in policy.evidence) or (
                f"policy id {policy.policy_id}",
            )
            if not policy.enabled:
                seen["disabled"] = True
                broad_disabled = policy.action in {"permit", "accept"} and all(item.any for item in selectors)
                if broad_disabled and policy.unsupported_predicates:
                    record_control(parser, "juniper.screenos.disabled-permissive-policies", ControlOutcome.UNKNOWN,
                                   "The disabled Any/Any/Any permit carries unmodeled predicates: "
                                   + ", ".join(policy.unsupported_predicates) + ".", instance=instance)
                elif not broad_disabled:
                    if policy.action not in {"permit", "accept"}:
                        record_control(parser, "juniper.screenos.disabled-permissive-policies",
                                       ControlOutcome.NO_FINDING, "The disabled policy does not permit traffic.",
                                       instance=instance)
                    elif any(item.complete and not item.any for item in selectors):
                        record_control(parser, "juniper.screenos.disabled-permissive-policies",
                                       ControlOutcome.NO_FINDING,
                                       "The disabled permit policy is narrower than Any/Any/Any.", instance=instance)
                    else:
                        record_control(parser, "juniper.screenos.disabled-permissive-policies",
                                       ControlOutcome.UNKNOWN,
                                       "Unresolved objects prevent deciding whether the disabled permit is Any/Any/Any.",
                                       instance=instance)
                if (
                    policy.action in {"permit", "accept"}
                    and policy.source_networks.any
                    and policy.destination_networks.any
                    and policy.services.any
                    and not policy.unsupported_predicates
                ):
                    record_control(parser, "juniper.screenos.disabled-permissive-policies", ControlOutcome.FINDING,
                                   "A disabled Any/Any/Any permit policy is retained.", instance=instance)
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
                        basis=FindingBasis.EXPLICIT_VALUE,
                    ))
                continue

            if policy.action in {"permit", "accept"}:
                seen["scope"] = True
                if policy.services.any and policy.source_networks.any and policy.destination_networks.any:
                    raw = screenos.policies.get(policy.policy_id)
                    if raw is None or not (
                        self._all_any(raw.sources) and self._all_any(raw.destinations) and self._all_any(raw.services)
                    ):
                        record_control(parser, "juniper.screenos.policy-scope", ControlOutcome.UNKNOWN,
                                       "Source, destination and service resolve to Any through a group or alias, "
                                       "but the broad-permit check compares literal names only.", instance=instance)
                elif not policy.services.any:
                    if policy.services.complete:
                        record_control(parser, "juniper.screenos.policy-scope", ControlOutcome.NO_FINDING,
                                       "The permit policy is limited to resolved services.", instance=instance)
                    else:
                        record_control(parser, "juniper.screenos.policy-scope", ControlOutcome.UNKNOWN,
                                       "Service objects are unresolved: "
                                       + ", ".join(policy.services.unresolved[:5]) + ".", instance=instance)
            if (
                policy.action in {"permit", "accept"}
                and policy.services.any
                and not (policy.source_networks.any and policy.destination_networks.any)
            ):
                record_control(parser, "juniper.screenos.policy-scope", ControlOutcome.FINDING,
                               "The permit policy allows Any service within its address scope.", instance=instance)
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
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))

            seen["order"] = True
            if (
                policy.action not in {"permit", "accept", "deny", "reject"}
                or policy.unsupported_predicates
            ):
                record_control(parser, "juniper.screenos.policy-order", ControlOutcome.UNKNOWN,
                               f"Action '{policy.action or 'unset'}' or predicates "
                               f"{', '.join(policy.unsupported_predicates) or 'none'} are not modeled for order proof.",
                               instance=instance)
                continue
            key = (policy.from_zone.casefold(), policy.to_zone.casefold())
            earlier_policies = prior_by_zone_pair.setdefault(key, [])
            undecided = False
            fired = False
            for earlier in earlier_policies:
                states = (
                    network_covers(
                        earlier.source_networks, policy.source_networks
                    ),
                    network_covers(
                        earlier.destination_networks, policy.destination_networks
                    ),
                    service_covers(earlier.services, policy.services),
                )
                if not all(state == ProofState.PROVEN for state in states):
                    if ProofState.DISPROVEN not in states:
                        undecided = True
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
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
                record_control(parser, "juniper.screenos.policy-order", ControlOutcome.FINDING,
                               f"Fully covered by earlier policy ID {earlier.policy_id}.", instance=instance)
                fired = True
                break
            if not fired:
                record_control(
                    parser, "juniper.screenos.policy-order",
                    ControlOutcome.UNKNOWN if undecided else ControlOutcome.NO_FINDING,
                    "Coverage by an earlier policy in the zone pair could not be decided for unresolved objects."
                    if undecided else "No earlier policy in the zone pair fully covers this policy.",
                    instance=instance,
                )
            earlier_policies.append(policy)
        for name, control_id, reason in (
            ("scope", "juniper.screenos.policy-scope", "No enabled permit policy is configured."),
            ("order", "juniper.screenos.policy-order", "No enabled policy is configured."),
            ("disabled", "juniper.screenos.disabled-permissive-policies", "No disabled policy is configured."),
        ):
            if not seen[name]:
                record_control(parser, control_id, ControlOutcome.NOT_APPLICABLE, reason)

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_insecure_services(parser)
        self.check_broad_policy_rules(parser)
        self.check_policy_effectiveness(parser)
