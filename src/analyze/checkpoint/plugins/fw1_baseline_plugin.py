"""Ordered Check Point FW1 policy, object, and service baseline checks."""

from datetime import date, datetime
import re

from src.analyze.common.risky_services import RISKY_SERVICE_NAMES, is_risky_port
from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.controls import ControlOutcome as CO, record_control
from src.analyze.checkpoint.plugins.fw1_checks_plugin import fw1_rule_instance
from src.analyze.common.issue import Finding, FindingBasis, Severity
from src.devices.common.policy_semantics import (
    ProofState,
    network_covers,
    service_covers,
)
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.checkpoint.fw1 import (
    CheckPointNetworkSemantics,
    CheckPointFW1Parser,
    CheckPointLayer,
    CheckPointObject,
    CheckPointRule,
    CheckPointService,
    CheckPointServiceSemantics,
)


CHECKPOINT_ACCESS_BEST_PRACTICES = (
    "https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/"
    "CP_R82_SecurityManagement_AdminGuide/Content/Topics-SECMG/"
    "Best-Practices-for-Access-Control-Rules.htm"
)
CHECKPOINT_BASIC_POLICY = (
    "https://sc1.checkpoint.com/documents/R82.10/WebAdminGuides/EN/"
    "CP_R82.10_SecurityManagement_AdminGuide/Content/Topics-SECMG/"
    "Creating-a-Basic-Access-Control-Policy.htm"
)
CHECKPOINT_LAYERS_GUIDE = (
    "https://sc1.checkpoint.com/documents/R82.10/WebAdminGuides/EN/"
    "CP_R82.10_SecurityManagement_AdminGuide/Content/Topics-SECMG/"
    "Ordered-Layers-and-Inline-Layers.htm"
)
CHECKPOINT_RULE_COLUMNS = (
    "https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/"
    "CP_R82_SecurityManagement_AdminGuide/Content/Topics-SECMG/"
    "The-Columns-of-the-Access-Control-Rule-Base.htm"
)
CHECKPOINT_TRACKING_GUIDE = (
    "https://sc1.checkpoint.com/documents/R82.10/WebAdminGuides/EN/"
    "CP_R82.10_LoggingAndMonitoring_AdminGuide/Content/Topics-LMG/"
    "Tracking-Options.htm"
)
CHECKPOINT_NEGATION_REFERENCE = (
    "https://sc1.checkpoint.com/documents/Appliances/Quantum_Spark_R82.00.X/"
    "CLI/EN/Content/Topics/set-access-rule-type-outgoing.htm"
)
CHECKPOINT_MANAGEMENT_GUIDE = (
    "https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/"
    "CP_R82_SecurityManagement_AdminGuide/CP_R82_SecurityManagement_AdminGuide.pdf"
)


# SC-049 controls recorded by this plugin (accept-scope is shared with PluginCheckPointChecks).
FW1_CONTROLS = (
    "checkpoint.fw1.layer-cleanup", "checkpoint.fw1.stealth-rule", "checkpoint.fw1.accept-scope",
    "checkpoint.fw1.risky-service-exposure", "checkpoint.fw1.accept-negation", "checkpoint.fw1.install-scope",
    "checkpoint.fw1.accept-tracking", "checkpoint.fw1.rule-expiry", "checkpoint.fw1.disabled-accept-rules",
    "checkpoint.fw1.policy-order", "checkpoint.fw1.object-references",
)
_TIME_FORMATS = ("%d-%b-%Y", "%d/%m/%Y", "%m/%d/%Y")


class PluginCheckPointBaseline(BasePlugin):
    """Evaluate only policy semantics provable from the supplied offline exports."""

    _ANY = {"any"}
    _ACCEPT = {"accept", "allow", "encrypt"}
    _DROP = {"drop", "reject"}
    _TRACKED = {"accounting", "alert", "log", "mail", "snmp"}
    _BUILT_INS = {
        "any",
        "all",
        "global",
        "internet",
        "original",
        "policy targets",
        "this gateway",
    }
    # NEEDS_HUMAN_REVIEW: this project risk catalogue is intentionally small;
    # replace/extend it with the organization's approved service-risk policy.
    # SC-043: shared catalogue in src/analyze/common/risky_services.py

    @staticmethod
    def _checkpoint(parser: BaseDeviceParser) -> CheckPointFW1Parser:
        if not isinstance(parser, CheckPointFW1Parser):
            raise TypeError("PluginCheckPointBaseline requires a Check Point FW1 parser")
        return parser

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
        basis=None,
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            device=parser.device_type,
            title=title,
            observation=observation,
            impact=impact,
            exploitability=(
                "A source within the effective rule and installation scope may exploit "
                "the policy weakness."
            ),
            recommendation=recommendation,
            severity=severity,
            evidence=evidence,
            references=references,
            basis=basis,
        )

    @staticmethod
    def _evidence(rule: CheckPointRule) -> tuple[str, ...]:
        return tuple(item for item in rule.evidence)

    @classmethod
    def _all_any(cls, values: tuple[str, ...]) -> bool:
        return bool(values) and all(value.strip().casefold() in cls._ANY for value in values)

    @classmethod
    def _tracked(cls, rule: CheckPointRule) -> bool:
        return bool(rule.tracking) and rule.tracking.casefold() in cls._TRACKED

    @staticmethod
    def _is_application_layer(layer: CheckPointLayer) -> bool:
        text = f"{layer.name} {layer.kind or ''}".casefold()
        return "application" in text or "url-filter" in text

    @staticmethod
    def _is_inline_layer(layer: CheckPointLayer) -> bool:
        return "inline" in f"{layer.name} {layer.kind or ''}".casefold()

    @staticmethod
    def _index(records) -> dict[str, object]:
        return {record.name.casefold(): record for record in records}

    def _expand(
        self,
        names: tuple[str, ...],
        index: dict[str, object],
        seen: frozenset[str] = frozenset(),
    ) -> frozenset[str]:
        expanded = set()
        for name in names:
            key = name.casefold()
            if key in seen:
                expanded.add(key)
                continue
            record = index.get(key)
            members = getattr(record, "members", ()) if record is not None else ()
            if members:
                expanded.update(self._expand(tuple(members), index, seen | {key}))
            else:
                expanded.add(key)
        return frozenset(expanded)

    @staticmethod
    def _port_numbers(value: str | None) -> set[int]:
        if not value:
            return set()
        numbers = {int(item) for item in re.findall(r"\d+", value)}
        range_match = re.fullmatch(r"\s*(\d+)\s*[-:]\s*(\d+)\s*", value)
        if range_match:
            start, end = (int(item) for item in range_match.groups())
            if start <= end and end - start <= 10000:
                numbers.update(range(start, end + 1))
        return numbers

    def _risky_services(
        self,
        rule: CheckPointRule,
        services: dict[str, CheckPointService],
    ) -> tuple[str, ...]:
        risky = set()
        for name in self._expand(rule.services, services):
            record = services.get(name)
            if name.casefold() in RISKY_SERVICE_NAMES:
                risky.add(name)
                continue
            if record is None:
                continue
            ports = self._port_numbers(record.port)
            if any(is_risky_port(port) for port in ports):
                risky.add(record.name)
        return tuple(sorted(risky, key=str.casefold))

    def _unresolved_services(
        self,
        rule: CheckPointRule,
        services: dict[str, CheckPointService],
    ) -> tuple[str, ...]:
        """Service names whose ports the risky-service check could not see (SC-049)."""
        return tuple(sorted(
            name for name in self._expand(rule.services, services)
            if name not in services and name not in RISKY_SERVICE_NAMES and name not in self._BUILT_INS
        ))

    def check_cleanup_rules(self, parser: BaseDeviceParser) -> None:
        checkpoint = self._checkpoint(parser)
        for layer in checkpoint.get_policy_layers():
            active = [rule for rule in layer.rules if rule.enabled]
            if not active:
                record_control(parser, "checkpoint.fw1.layer-cleanup", CO.NOT_APPLICABLE,
                               "The layer has no enabled rule.", instance=layer.name)
                continue
            last = active[-1]
            explicit_cleanup = (
                self._all_any(last.sources)
                and self._all_any(last.destinations)
                and self._all_any(last.services)
                and not (
                    last.source_negated
                    or last.destination_negated
                    or last.service_negated
                )
            )
            if layer.implicit_cleanup_action:
                expected = {layer.implicit_cleanup_action.casefold()}
                if "allow" in expected:
                    expected.add("accept")
                if "accept" in expected:
                    expected.add("allow")
            elif self._is_application_layer(layer):
                expected = self._ACCEPT
            else:
                expected = self._DROP
            if not explicit_cleanup or last.action not in expected:
                implicit = layer.implicit_cleanup_action or "not exported"
                self.add_issue(
                    self._finding(
                        parser,
                        "checkpoint.fw1.layer.explicit_cleanup_missing",
                        "Policy layer lacks a matching explicit cleanup rule",
                        f"Layer '{layer.name}' does not end with an enabled Any/Any/Any cleanup rule matching its implicit action ({implicit}).",
                        "Reviewers cannot verify the layer's default behavior from an explicit final rule, increasing policy-error risk.",
                        "Add an explicit final cleanup rule whose action matches the layer's intended implicit cleanup behavior.",
                        Severity.HIGH,
                        self._evidence(last),
                        (CHECKPOINT_ACCESS_BEST_PRACTICES, CHECKPOINT_LAYERS_GUIDE),
                        basis=(
                            FindingBasis.REQUIRED_SETTING_MISSING if not explicit_cleanup
                            else FindingBasis.EXPLICIT_VALUE
                        ),
                    )
                )
                record_control(parser, "checkpoint.fw1.layer-cleanup", CO.FINDING,
                               "The last enabled rule is not an Any/Any/Any cleanup matching the layer action.",
                               instance=layer.name)
                continue
            if not self._tracked(last):
                self.add_issue(
                    self._finding(
                        parser,
                        "checkpoint.fw1.layer.cleanup_untracked",
                        "Explicit cleanup rule is not tracked",
                        f"Layer '{layer.name}' ends with cleanup rule '{last.name}', but Track is '{last.tracking or 'not configured'}'.",
                        "Untracked denied traffic reduces visibility into unexpected policy misses and scanning.",
                        "Set the cleanup rule Track action to Log or an approved alerting option, balancing retention requirements.",
                        Severity.MEDIUM,
                        self._evidence(last),
                        (CHECKPOINT_BASIC_POLICY, CHECKPOINT_TRACKING_GUIDE),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )
                record_control(parser, "checkpoint.fw1.layer-cleanup", CO.FINDING,
                               "The explicit cleanup rule is not tracked.", instance=layer.name)
            else:
                record_control(parser, "checkpoint.fw1.layer-cleanup", CO.NO_FINDING,
                               f"The layer ends with tracked cleanup rule '{last.name}' ({last.action}).",
                               instance=layer.name)

    def check_stealth_rules(self, parser: BaseDeviceParser) -> None:
        checkpoint = self._checkpoint(parser)
        objects = checkpoint.get_policy_objects()
        object_index = self._index(objects)
        gateways = {
            item.name.casefold()
            for item in objects
            if item.firewall or item.kind in {"gateway", "gateway-cluster", "cluster-member"}
        }
        if not gateways:
            record_control(
                parser, "checkpoint.fw1.stealth-rule", CO.UNKNOWN,
                "No objects export was located, so the gateway objects are unknown."
                if not checkpoint.files.get("objects") else
                "The objects export lists no gateway object; a policy export does not establish the gateway inventory.",
                instance="policy",
            )
            return
        for layer in checkpoint.get_policy_layers():
            if self._is_application_layer(layer) or self._is_inline_layer(layer):
                record_control(parser, "checkpoint.fw1.stealth-rule", CO.NOT_APPLICABLE,
                               "Stealth rules belong in network layers; this is an application or inline layer.",
                               instance=layer.name)
                continue
            found = False
            stealth = None
            for rule in layer.rules:
                destinations = self._expand(rule.destinations, object_index)
                if (
                    rule.enabled
                    and rule.action in self._DROP
                    and self._all_any(rule.sources)
                    and self._all_any(rule.services)
                    and bool(destinations.intersection(gateways))
                    and not rule.destination_negated
                ):
                    found = True
                    stealth = rule
                    break
            if found:
                record_control(parser, "checkpoint.fw1.stealth-rule", CO.NO_FINDING,
                               f"Rule '{stealth.name}' drops Any traffic to gateway objects.", instance=layer.name)
            if not found and layer.rules:
                self.add_issue(
                    self._finding(
                        parser,
                        "checkpoint.fw1.layer.stealth_rule_missing",
                        "Network layer lacks a gateway stealth rule",
                        f"Layer '{layer.name}' contains no enabled Any-to-gateway drop rule for the exported gateway objects.",
                        "Traffic directed at Security Gateways may reach services not intended for general network access.",
                        "Add an early stealth rule that permits required administration first, then drops and tracks other traffic to gateway objects.",
                        Severity.HIGH,
                        self._evidence(layer.rules[0]),
                        (CHECKPOINT_ACCESS_BEST_PRACTICES, CHECKPOINT_BASIC_POLICY),
                        basis=FindingBasis.REQUIRED_SETTING_MISSING,
                    )
                )
                record_control(parser, "checkpoint.fw1.stealth-rule", CO.FINDING,
                               "No enabled Any-to-gateway drop rule in this network layer.", instance=layer.name)

    def check_rule_hygiene(self, parser: BaseDeviceParser) -> None:
        checkpoint = self._checkpoint(parser)
        disabled_accept = enabled_rule = False
        for rule in checkpoint.get_policy_rules():
            instance = fw1_rule_instance(rule)
            if not rule.enabled and rule.action in self._ACCEPT:
                disabled_accept = True
                record_control(parser, "checkpoint.fw1.disabled-accept-rules", CO.FINDING,
                               f"Disabled {rule.action} rule.", instance=instance)
                self.add_issue(
                    self._finding(
                        parser,
                        "checkpoint.fw1.policy.disabled_permissive_rule",
                        "Disabled permissive rule requires review",
                        f"Rule '{rule.name}' at position {rule.position} in layer '{rule.layer}' is a disabled {rule.action} rule.",
                        "A stale permissive rule can be re-enabled without undergoing current policy review.",
                        "Confirm the change workflow; remove obsolete rules or retain a documented owner and expiry condition.",
                        Severity.LOW,
                        self._evidence(rule),
                        (CHECKPOINT_ACCESS_BEST_PRACTICES,),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )
            if not rule.enabled:
                continue
            enabled_rule = True
            expired = self._expired_date(rule.time)
            if expired is None:
                values = [value for value in rule.time if value.strip().casefold() not in self._ANY]
                parsed = [value for value in values if self._parses_as_date(value)]
                if values and not parsed:
                    record_control(parser, "checkpoint.fw1.rule-expiry", CO.UNKNOWN,
                                   "The rule references a time object whose dates are not evaluated.",
                                   instance=instance)
                else:
                    record_control(parser, "checkpoint.fw1.rule-expiry", CO.NO_FINDING,
                                   "The rule's time constraint dates are not in the past." if parsed
                                   else "The rule has no time constraint.", instance=instance)
            if expired is not None:
                record_control(parser, "checkpoint.fw1.rule-expiry", CO.FINDING,
                               f"Expired date {expired.isoformat()}.", instance=instance)
                self.add_issue(
                    self._finding(
                        parser,
                        "checkpoint.fw1.policy.expired_rule",
                        "Enabled rule has an expired time constraint",
                        f"Rule '{rule.name}' in layer '{rule.layer}' contains the expired date {expired.isoformat()}.",
                        "An enabled rule whose intended validity period has ended creates policy drift or ambiguous enforcement intent.",
                        "Disable or remove the rule after confirming the exported time-object semantics and business owner.",
                        Severity.MEDIUM,
                        self._evidence(rule),
                        (CHECKPOINT_RULE_COLUMNS, CHECKPOINT_MANAGEMENT_GUIDE),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )
        if not disabled_accept:
            record_control(parser, "checkpoint.fw1.disabled-accept-rules", CO.NO_FINDING,
                           "No disabled accept rule is in the exported rulebase.", instance="policy")
        if not enabled_rule:
            record_control(parser, "checkpoint.fw1.rule-expiry", CO.NOT_APPLICABLE,
                           "The exported rulebase has no enabled rule.", instance="policy")

    @staticmethod
    def _parses_as_date(value: str) -> bool:
        candidate = value.strip().replace("Z", "+00:00")
        try:
            datetime.fromisoformat(candidate)
            return True
        except ValueError:
            pass
        for format_ in _TIME_FORMATS:
            try:
                datetime.strptime(candidate, format_)
                return True
            except ValueError:
                continue
        return False

    @staticmethod
    def _expired_date(values: tuple[str, ...]) -> date | None:
        parsed = []
        for value in values:
            candidate = value.strip().replace("Z", "+00:00")
            try:
                parsed.append(datetime.fromisoformat(candidate).date())
                continue
            except ValueError:
                pass
            for format_ in ("%d-%b-%Y", "%d/%m/%Y", "%m/%d/%Y"):
                try:
                    parsed.append(datetime.strptime(candidate, format_).date())
                    break
                except ValueError:
                    continue
        if parsed and max(parsed) < date.today():
            return max(parsed)
        return None

    def check_rule_scope_and_tracking(self, parser: BaseDeviceParser) -> None:
        checkpoint = self._checkpoint(parser)
        services = self._index(checkpoint.get_service_objects())
        any_accept = any_sensitive = False
        for rule in checkpoint.get_policy_rules():
            if not rule.enabled or rule.action not in self._ACCEPT:
                continue
            any_accept = True
            instance = fw1_rule_instance(rule)
            wildcard_count = sum(
                (
                    self._all_any(rule.sources),
                    self._all_any(rule.destinations),
                    self._all_any(rule.services),
                )
            )
            fully_broad = wildcard_count == 3
            partially_broad = wildcard_count >= 2 and not fully_broad
            risky = self._risky_services(rule, services)
            negated = []
            if rule.source_negated:
                negated.append("source")
            if rule.destination_negated:
                negated.append("destination")
            if rule.service_negated:
                negated.append("service")
            broad_source = self._all_any(rule.sources) or rule.source_negated
            unresolved = self._unresolved_services(rule, services) if broad_source and not risky else ()

            # SC-049: fully broad accept/allow rules are recorded by PluginCheckPointChecks.
            if partially_broad:
                record_control(parser, "checkpoint.fw1.accept-scope", CO.FINDING,
                               f"{wildcard_count} of source, destination and service are Any.", instance=instance)
            elif fully_broad and rule.action == "encrypt":
                record_control(parser, "checkpoint.fw1.accept-scope", CO.UNKNOWN,
                               "Any/Any/Any encrypt rule; its VPN community scope is not evaluated.", instance=instance)
            elif not fully_broad:
                record_control(parser, "checkpoint.fw1.accept-scope", CO.NO_FINDING,
                               "At most one of source, destination and service is Any.", instance=instance)
            if risky and broad_source:
                record_control(parser, "checkpoint.fw1.risky-service-exposure", CO.FINDING,
                               f"Broadly sourced risky service(s): {', '.join(risky)}.", instance=instance)
            elif not broad_source:
                record_control(parser, "checkpoint.fw1.risky-service-exposure", CO.NO_FINDING,
                               "The rule source is restricted.", instance=instance)
            elif unresolved:
                record_control(parser, "checkpoint.fw1.risky-service-exposure", CO.UNKNOWN,
                               f"Service(s) not in the exported service objects: {', '.join(unresolved)}.",
                               instance=instance)
            else:
                record_control(parser, "checkpoint.fw1.risky-service-exposure", CO.NO_FINDING,
                               "No service of this broadly sourced rule is in the risky-service catalogue"
                               + ("; its Any service is assessed by checkpoint.fw1.accept-scope." if self._all_any(rule.services) else "."),
                               instance=instance)
            record_control(parser, "checkpoint.fw1.accept-negation",
                           CO.FINDING if negated else CO.NO_FINDING,
                           f"Negated field(s): {', '.join(negated)}." if negated else "No match field is negated.",
                           instance=instance)
            install_any = any(value.casefold() == "any" for value in rule.install_on)
            record_control(parser, "checkpoint.fw1.install-scope",
                           CO.FINDING if install_any else CO.NO_FINDING,
                           "Install On contains Any." if install_any else
                           (f"Install On is {', '.join(rule.install_on)}." if rule.install_on
                            else "Install On is not set in the exported rule (not Any)."),
                           instance=instance)
            sensitive = bool(fully_broad or partially_broad or risky or negated)
            if sensitive:
                any_sensitive = True
                tracked = self._tracked(rule)
                record_control(parser, "checkpoint.fw1.accept-tracking",
                               CO.NO_FINDING if tracked else CO.FINDING,
                               f"Track is '{rule.tracking or 'not configured'}'.", instance=instance)
            elif unresolved and not self._tracked(rule):
                any_sensitive = True
                record_control(parser, "checkpoint.fw1.accept-tracking", CO.UNKNOWN,
                               "An untracked broadly sourced rule uses services that are not exported; "
                               "whether they are risky is unknown.", instance=instance)

            if partially_broad:
                self.add_issue(
                    self._finding(
                        parser,
                        "checkpoint.fw1.policy.overly_broad_accept",
                        "Accept rule has multiple unrestricted dimensions",
                        f"Rule '{rule.name}' in layer '{rule.layer}' accepts traffic with {wildcard_count} of source, destination, and service set entirely to Any.",
                        "The rule grants a wide traffic population access and is difficult to justify or monitor precisely.",
                        "Replace Any values with the smallest required network, service, VPN, and installation objects.",
                        Severity.HIGH,
                        self._evidence(rule),
                        (CHECKPOINT_ACCESS_BEST_PRACTICES, CHECKPOINT_RULE_COLUMNS),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )
            if risky and (self._all_any(rule.sources) or rule.source_negated):
                self.add_issue(
                    self._finding(
                        parser,
                        "checkpoint.fw1.policy.risky_service_exposure",
                        "Risky service is accepted from a broad source scope",
                        f"Rule '{rule.name}' in layer '{rule.layer}' accepts broadly sourced service(s): {', '.join(risky)}.",
                        "Clear-text, file-sharing, or remote-administration services can expose credentials or high-impact control paths.",
                        "Restrict sources and destinations, replace clear-text protocols, and require protected administrative paths.",
                        Severity.HIGH,
                        self._evidence(rule),
                        (CHECKPOINT_ACCESS_BEST_PRACTICES, CHECKPOINT_RULE_COLUMNS),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )
            if negated:
                self.add_issue(
                    self._finding(
                        parser,
                        "checkpoint.fw1.policy.negated_accept",
                        "Accept rule uses a negated match dimension",
                        f"Rule '{rule.name}' in layer '{rule.layer}' negates its {', '.join(negated)} field(s), matching everything except the listed objects.",
                        "Negation can make an allow rule substantially broader and harder to review than its object list suggests.",
                        "Prefer explicit positive allow lists, or document and test why negation is necessary.",
                        Severity.HIGH,
                        self._evidence(rule),
                        (CHECKPOINT_NEGATION_REFERENCE, CHECKPOINT_RULE_COLUMNS),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )
            if any(value.casefold() == "any" for value in rule.install_on):
                self.add_issue(
                    self._finding(
                        parser,
                        "checkpoint.fw1.policy.install_scope_any",
                        "Accept rule is installed on Any target",
                        f"Rule '{rule.name}' in layer '{rule.layer}' explicitly uses Any in Install On.",
                        "A permissive rule may be distributed to gateways outside its intended enforcement scope.",
                        "Replace Any with the required Policy Targets or explicit gateway/cluster objects.",
                        Severity.MEDIUM,
                        self._evidence(rule),
                        (CHECKPOINT_RULE_COLUMNS, CHECKPOINT_MANAGEMENT_GUIDE),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )
            if (fully_broad or partially_broad or risky or negated) and not self._tracked(rule):
                self.add_issue(
                    self._finding(
                        parser,
                        "checkpoint.fw1.policy.sensitive_accept_untracked",
                        "Broad or risky accept rule is not tracked",
                        f"Rule '{rule.name}' in layer '{rule.layer}' has Track '{rule.tracking or 'not configured'}'.",
                        "Traffic allowed by a high-exposure rule may not produce evidence for detection or investigation.",
                        "Set Track to Log, Accounting, Alert, or another approved recorded option.",
                        Severity.MEDIUM,
                        self._evidence(rule),
                        (CHECKPOINT_TRACKING_GUIDE, CHECKPOINT_RULE_COLUMNS),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )
        if not any_accept:
            for control in ("checkpoint.fw1.accept-scope", "checkpoint.fw1.risky-service-exposure",
                            "checkpoint.fw1.accept-negation", "checkpoint.fw1.install-scope"):
                record_control(parser, control, CO.NOT_APPLICABLE,
                               "The exported rulebase has no enabled accept rule.", instance="policy")
        if not any_sensitive:
            record_control(parser, "checkpoint.fw1.accept-tracking", CO.NOT_APPLICABLE,
                           "No enabled accept rule is broad, risky or negated.", instance="policy")

    @classmethod
    def _install_covers(cls, prior: tuple[str, ...], current: tuple[str, ...]) -> bool:
        prior_set = {value.casefold() for value in prior}
        current_set = {value.casefold() for value in current}
        if prior_set == current_set:
            return True
        return "any" in prior_set

    @classmethod
    def _network_semantics_cover(
        cls, prior: CheckPointNetworkSemantics, current: CheckPointNetworkSemantics
    ) -> bool:
        return network_covers(prior, current) == ProofState.PROVEN

    @classmethod
    def _service_semantics_cover(
        cls, prior: CheckPointServiceSemantics, current: CheckPointServiceSemantics
    ) -> bool:
        return service_covers(prior, current) == ProofState.PROVEN

    def check_shadowing(self, parser: BaseDeviceParser) -> None:
        checkpoint = self._checkpoint(parser)
        enabled_rule = False
        for layer in checkpoint.get_policy_layers():
            previous: list[CheckPointRule] = []
            for rule in layer.rules:
                if not rule.enabled:
                    continue
                enabled_rule = True
                instance = fw1_rule_instance(rule)
                if rule.action not in self._ACCEPT | self._DROP:
                    record_control(parser, "checkpoint.fw1.policy-order", CO.UNKNOWN,
                                   f"Rule action '{rule.action}' is not compared.", instance=instance)
                    previous.append(rule)
                    continue
                if rule.source_negated or rule.destination_negated or rule.service_negated:
                    record_control(parser, "checkpoint.fw1.policy-order", CO.UNKNOWN,
                                   "Rules with negated fields are not compared.", instance=instance)
                    previous.append(rule)
                    continue
                covered = False
                current_dimensions = (
                    checkpoint.resolve_network_semantics(rule.sources),
                    checkpoint.resolve_network_semantics(rule.destinations),
                    checkpoint.resolve_service_semantics(rule.services),
                )
                for earlier in previous:
                    if (
                        earlier.source_negated
                        or earlier.destination_negated
                        or earlier.service_negated
                        or earlier.action not in self._ACCEPT | self._DROP
                        or earlier.time != rule.time
                        or earlier.vpn != rule.vpn
                        or earlier.through != rule.through
                        or not self._install_covers(earlier.install_on, rule.install_on)
                    ):
                        continue
                    earlier_dimensions = (
                        checkpoint.resolve_network_semantics(earlier.sources),
                        checkpoint.resolve_network_semantics(earlier.destinations),
                        checkpoint.resolve_service_semantics(earlier.services),
                    )
                    if not (
                        self._network_semantics_cover(
                            earlier_dimensions[0], current_dimensions[0]
                        )
                        and self._network_semantics_cover(
                            earlier_dimensions[1], current_dimensions[1]
                        )
                        and self._service_semantics_cover(
                            earlier_dimensions[2], current_dimensions[2]
                        )
                    ):
                        continue
                    same_action = earlier.action == rule.action
                    self.add_issue(
                        self._finding(
                            parser,
                            (
                                "checkpoint.fw1.policy.redundant_rule"
                                if same_action
                                else "checkpoint.fw1.policy.shadowed_rule"
                            ),
                            "Rule is redundant" if same_action else "Rule is shadowed",
                            f"Rule '{rule.name}' at position {rule.position} in layer '{layer.name}' is fully covered by earlier rule '{earlier.name}' at position {earlier.position} with {'the same' if same_action else 'a different'} action.",
                            "The later rule cannot alter enforcement for the statically comparable traffic scope and obscures policy intent.",
                            "Remove or reorder the rule after validating dynamic objects, implied rules, and compiled policy behavior on the management server.",
                            Severity.LOW if same_action else Severity.HIGH,
                            self._evidence(rule) + self._evidence(earlier),
                            (CHECKPOINT_LAYERS_GUIDE, CHECKPOINT_MANAGEMENT_GUIDE),
                            basis=FindingBasis.EXPLICIT_VALUE,
                        )
                    )
                    covered = True
                    record_control(parser, "checkpoint.fw1.policy-order", CO.FINDING,
                                   f"Fully covered by earlier rule '{earlier.name}'.", instance=instance)
                    break
                if not covered:
                    # SC-017: implied rules and Global Properties are not in the export.
                    record_control(parser, "checkpoint.fw1.policy-order", CO.UNKNOWN,
                                   "No earlier exported rule covers this rule; implied rules from Global "
                                   "Properties are not in the export.", instance=instance)
                previous.append(rule)
        if not enabled_rule:
            record_control(parser, "checkpoint.fw1.policy-order", CO.NOT_APPLICABLE,
                           "The exported rulebase has no enabled rule.", instance="policy")

    def check_references(self, parser: BaseDeviceParser) -> None:
        checkpoint = self._checkpoint(parser)
        control = "checkpoint.fw1.object-references"
        if not checkpoint.files.get("objects"):
            record_control(parser, control, CO.UNKNOWN,
                           "No objects export was located; references cannot be resolved.", instance="policy")
            return
        objects = checkpoint.get_policy_objects()
        services = checkpoint.get_service_objects()
        object_index = self._index(objects)
        service_index = self._index(services)
        if not object_index and not service_index:
            record_control(parser, control, CO.UNKNOWN,
                           "No network or service object could be parsed from the objects export.", instance="policy")
            return

        for rule in checkpoint.get_policy_rules():
            unresolved = []
            if object_index:
                for field, values in (
                    ("source", rule.sources),
                    ("destination", rule.destinations),
                    ("install-on", rule.install_on),
                    ("through", rule.through),
                    ("VPN", rule.vpn),
                ):
                    unresolved.extend(
                        f"{field}:{value}"
                        for value in values
                        if value.casefold() not in object_index
                        and value.casefold() not in self._BUILT_INS
                    )
            if service_index:
                unresolved.extend(
                    f"service:{value}"
                    for value in rule.services
                    if value.casefold() not in service_index
                    and value.casefold() not in self._BUILT_INS
                )
            if unresolved:
                self.add_issue(
                    self._finding(
                        parser,
                        "checkpoint.fw1.policy.unresolved_reference",
                        "Policy rule contains unresolved object references",
                        f"Rule '{rule.name}' in layer '{rule.layer}' references objects absent from the parsed object export: {', '.join(unresolved)}.",
                        "Incomplete references prevent reliable review and may indicate an incomplete or inconsistent export set.",
                        "Regenerate a matching complete object/rule export and resolve or remove stale references.",
                        Severity.MEDIUM,
                        self._evidence(rule),
                        (CHECKPOINT_RULE_COLUMNS, CHECKPOINT_MANAGEMENT_GUIDE),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )
                record_control(parser, control, CO.FINDING, f"Unresolved: {', '.join(unresolved)}.",
                               instance=fw1_rule_instance(rule))
            elif object_index and service_index:
                record_control(parser, control, CO.NO_FINDING,
                               "Every rule reference resolves to an exported or built-in object.",
                               instance=fw1_rule_instance(rule))
            else:
                record_control(parser, control, CO.UNKNOWN,
                               "The objects export has no parsed "
                               + ("network" if not object_index else "service")
                               + " objects, so those references were not checked.",
                               instance=fw1_rule_instance(rule))

        for kind, records, index in (
            ("network", objects, object_index),
            ("service", services, service_index),
        ):
            for record in records:
                missing = [
                    member
                    for member in record.members
                    if member.casefold() not in index
                    and member.casefold() not in self._BUILT_INS
                ]
                if not missing:
                    if record.members:
                        record_control(parser, control, CO.NO_FINDING, "Every group member resolves.",
                                       instance=f"{kind} group {record.name}")
                    continue
                self.add_issue(
                    self._finding(
                        parser,
                        "checkpoint.fw1.object.unresolved_group_member",
                        "Object group contains unresolved members",
                        f"{kind.title()} group '{record.name}' references missing member(s): {', '.join(missing)}.",
                        "An incomplete group hierarchy prevents accurate policy expansion and review.",
                        "Regenerate a complete object export and repair stale group membership.",
                        Severity.MEDIUM,
                        tuple(item for item in record.evidence),
                        (CHECKPOINT_RULE_COLUMNS, CHECKPOINT_MANAGEMENT_GUIDE),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )
                record_control(parser, control, CO.FINDING, f"Missing member(s): {', '.join(missing)}.",
                               instance=f"{kind} group {record.name}")

    def analyze(self, parser: BaseDeviceParser) -> None:
        checkpoint = self._checkpoint(parser)
        if not checkpoint.get_policy_rules():
            reason = (
                "No rules.C or rulebases export was located."
                if "rules" not in checkpoint.parsed_data and "rulebases" not in checkpoint.parsed_data
                else "No rule could be parsed from the rule export."
            )
            for control in FW1_CONTROLS:
                record_control(parser, control, CO.UNKNOWN, reason, instance="policy")
            return
        self.check_cleanup_rules(parser)
        self.check_stealth_rules(parser)
        self.check_rule_hygiene(parser)
        self.check_rule_scope_and_tracking(parser)
        self.check_shadowing(parser)
        self.check_references(parser)


__all__ = ["PluginCheckPointBaseline"]
