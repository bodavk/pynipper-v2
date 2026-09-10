from collections import defaultdict

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.issue import Finding, Severity
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.juniper.junos import JunOSParser, JunosFirewallTerm


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
                        statement.evidence.text
                        for statement in self._junos(parser).statements
                        if statement.active and protocol in statement.path
                    ),
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

        for terms in terms_by_filter.values():
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
                            evidence=tuple(item.text for item in term.evidence),
                        )
                    )
                if catch_all and action in {"accept", "discard", "reject"}:
                    terminal_seen = True

    def check_ssh_root(self, parser: BaseDeviceParser) -> None:
        value, evidence = self._junos(parser).get_ssh_root_login()
        if not value or value == "deny":
            return
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
                evidence=tuple(item.text for item in evidence) or (f"root-login {value}",),
            )
        )

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_management(parser)
        self.check_broad_filters(parser)
        self.check_ssh_root(parser)
