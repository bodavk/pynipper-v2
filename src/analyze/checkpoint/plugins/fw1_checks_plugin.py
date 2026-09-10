from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.issue import Finding, Severity
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.common.models import ConfigurationState, KnowledgeState


class PluginCheckPointChecks(BasePlugin):
    """Evaluate one normalized Check Point rule at a time."""

    _WILDCARDS = {"any"}

    @classmethod
    def _all_wildcard(cls, values: tuple[str, ...]) -> bool:
        return bool(values) and all(value.strip().casefold() in cls._WILDCARDS for value in values)

    def check_insecure_objects(self, parser: BaseDeviceParser) -> None:
        # Built-in wildcard objects are not defects by themselves. Their safety
        # can only be evaluated where an enabled policy actually references them.
        return None

    def check_broad_filter_rules(self, parser: BaseDeviceParser) -> None:
        policies = parser.get_normalized_config().policies
        if policies.state != KnowledgeState.KNOWN:
            return
        for policy in policies.items:
            if policy.state != ConfigurationState.ENABLED:
                continue
            if policy.action.casefold() not in {"accept", "allow"}:
                continue
            if not (
                self._all_wildcard(policy.sources)
                and self._all_wildcard(policy.destinations)
                and self._all_wildcard(policy.services)
            ):
                continue
            tracking = policy.tracking or "not configured"
            install_on = ", ".join(policy.install_on) or "unspecified targets"
            self.add_issue(
                Finding(
                    rule_id="checkpoint.fw1.policy.broad_accept",
                    device=parser.device_type,
                    title="Broad Filter Rule Detected",
                    observation=f"Enabled rule '{policy.name}' at position {policy.position} accepts Any source to Any destination for Any service; tracking is '{tracking}' and install-on is {install_on}.",
                    impact="The rule permits unrestricted traffic within every gateway and policy-layer scope where it is installed.",
                    severity=Severity.CRITICAL,
                    exploitability="Any reachable source can target any destination and service covered by the rule's install-on scope.",
                    recommendation="Replace wildcard source, destination, and service fields with explicit objects and enable appropriate tracking.",
                    evidence=tuple(item.text for item in policy.evidence) or (
                        f"Check Point rule {policy.name}",
                    ),
                )
            )

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_broad_filter_rules(parser)
