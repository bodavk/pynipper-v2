"""Ordered Check Point FW1 policy, object, and service baseline checks."""

from datetime import date, datetime
import re

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.issue import Finding, Severity
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.checkpoint.fw1 import (
    CheckPointFW1Parser,
    CheckPointLayer,
    CheckPointObject,
    CheckPointRule,
    CheckPointService,
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
    _RISKY_SERVICE_NAMES = {
        "ftp",
        "microsoft-ds",
        "ms-wbt-server",
        "netbios-dgm",
        "netbios-ns",
        "netbios-ssn",
        "rdp",
        "rlogin",
        "rsh",
        "telnet",
        "tftp",
        "vnc",
    }
    _RISKY_PORTS = {21, 23, 69, 135, 137, 138, 139, 445, 513, 514, 3389}

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
        )

    @staticmethod
    def _evidence(rule: CheckPointRule) -> tuple[str, ...]:
        return tuple(item.text for item in rule.evidence)

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
            if name in self._RISKY_SERVICE_NAMES:
                risky.add(name)
                continue
            if record is None:
                continue
            ports = self._port_numbers(record.port)
            if ports.intersection(self._RISKY_PORTS) or any(5900 <= port <= 5999 for port in ports):
                risky.add(record.name)
        return tuple(sorted(risky, key=str.casefold))

    def check_cleanup_rules(self, parser: BaseDeviceParser) -> None:
        checkpoint = self._checkpoint(parser)
        for layer in checkpoint.get_policy_layers():
            active = [rule for rule in layer.rules if rule.enabled]
            if not active:
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
                    )
                )
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
                    )
                )

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
            return
        for layer in checkpoint.get_policy_layers():
            if self._is_application_layer(layer) or self._is_inline_layer(layer):
                continue
            found = False
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
                    break
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
                    )
                )

    def check_rule_hygiene(self, parser: BaseDeviceParser) -> None:
        checkpoint = self._checkpoint(parser)
        for rule in checkpoint.get_policy_rules():
            if not rule.enabled and rule.action in self._ACCEPT:
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
                    )
                )
            if not rule.enabled:
                continue
            expired = self._expired_date(rule.time)
            if expired is not None:
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
                    )
                )

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
        for rule in checkpoint.get_policy_rules():
            if not rule.enabled or rule.action not in self._ACCEPT:
                continue
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
                    )
                )

    @classmethod
    def _dimension_covers(cls, prior: frozenset[str], current: frozenset[str]) -> bool:
        if not prior or not current:
            return False
        if prior == cls._ANY:
            return True
        if current == cls._ANY:
            return prior == cls._ANY
        return bool(prior) and bool(current) and current.issubset(prior)

    @classmethod
    def _install_covers(cls, prior: tuple[str, ...], current: tuple[str, ...]) -> bool:
        prior_set = {value.casefold() for value in prior}
        current_set = {value.casefold() for value in current}
        if prior_set == current_set:
            return True
        return "any" in prior_set

    def check_shadowing(self, parser: BaseDeviceParser) -> None:
        checkpoint = self._checkpoint(parser)
        object_index = self._index(checkpoint.get_policy_objects())
        service_index = self._index(checkpoint.get_service_objects())
        for layer in checkpoint.get_policy_layers():
            previous: list[CheckPointRule] = []
            for rule in layer.rules:
                if not rule.enabled:
                    continue
                if rule.action not in self._ACCEPT | self._DROP:
                    previous.append(rule)
                    continue
                if rule.source_negated or rule.destination_negated or rule.service_negated:
                    previous.append(rule)
                    continue
                current_dimensions = (
                    self._expand(rule.sources, object_index),
                    self._expand(rule.destinations, object_index),
                    self._expand(rule.services, service_index),
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
                        self._expand(earlier.sources, object_index),
                        self._expand(earlier.destinations, object_index),
                        self._expand(earlier.services, service_index),
                    )
                    if not all(
                        self._dimension_covers(prior, current)
                        for prior, current in zip(earlier_dimensions, current_dimensions)
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
                        )
                    )
                    break
                previous.append(rule)

    def check_references(self, parser: BaseDeviceParser) -> None:
        checkpoint = self._checkpoint(parser)
        if not checkpoint.files.get("objects"):
            return
        objects = checkpoint.get_policy_objects()
        services = checkpoint.get_service_objects()
        object_index = self._index(objects)
        service_index = self._index(services)
        if not object_index and not service_index:
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
                    )
                )

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
                        tuple(item.text for item in record.evidence),
                        (CHECKPOINT_RULE_COLUMNS, CHECKPOINT_MANAGEMENT_GUIDE),
                    )
                )

    def analyze(self, parser: BaseDeviceParser) -> None:
        checkpoint = self._checkpoint(parser)
        if not checkpoint.get_policy_rules():
            return
        self.check_cleanup_rules(parser)
        self.check_stealth_rules(parser)
        self.check_rule_hygiene(parser)
        self.check_rule_scope_and_tracking(parser)
        self.check_shadowing(parser)
        self.check_references(parser)


__all__ = ["PluginCheckPointBaseline"]
