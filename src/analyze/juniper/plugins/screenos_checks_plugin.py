from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.issue import Finding, Severity
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.juniper.screenos import JuniperScreenOSParser


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
                    (evidence.text,) if evidence else (),
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
                        tuple(item.text for item in interface.evidence),
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
                    evidence=tuple(item.text for item in policy.evidence),
                )
            )

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_insecure_services(parser)
        self.check_broad_policy_rules(parser)
