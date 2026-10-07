from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.controls import ControlOutcome, record_control
from src.analyze.common.issue import Finding, FindingBasis, Severity
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.common.models import ConfigurationState
from src.devices.fortinet.fortios import FortiOSParser


FORTINET_MANAGEMENT_GUIDE = (
    "https://docs.fortinet.com/document/fortigate/7.6.5/administration-guide/"
    "616955/configuring-ports"
)
FORTINET_POLICY_GUIDE = (
    "https://docs.fortinet.com/document/fortigate/7.6.5/administration-guide/"
    "826586/configuring-a-firewall-policy"
)
FORTINET_TLS_REFERENCE = (
    "https://docs.fortinet.com/document/fortigate/7.6.5/cli-reference/339914554"
)
FORTINET_LOGGING_GUIDE = (
    "https://docs.fortinet.com/document/fortigate/7.6.5/administration-guide/"
    "250999/log-settings-and-targets"
)


class PluginFortiOSChecks(BasePlugin):
    """Effective-state FortiOS management, policy, TLS, and logging checks."""

    @staticmethod
    def _fortios(parser: BaseDeviceParser) -> FortiOSParser:
        if not isinstance(parser, FortiOSParser):
            raise TypeError("PluginFortiOSChecks requires a FortiOS parser")
        return parser

    @staticmethod
    def _is_unrestricted_trust(value: str) -> bool:
        normalized = value.strip().lower()
        return normalized in {
            "0.0.0.0 0.0.0.0",
            "0.0.0.0/0",
            "::/0",
            "0:0:0:0:0:0:0:0/0",
        }

    def check_admin_access(self, parser: BaseDeviceParser) -> None:
        fortios = self._fortios(parser)
        normalized = fortios.get_normalized_config()
        administrators = [admin for admin in fortios.get_administrator_trust() if admin["enabled"]]

        cleartext = False
        for service in normalized.management_services.items:
            protocol = service.protocol.lower()
            if protocol not in {"http", "telnet"}:
                continue
            cleartext = True
            record_control(parser, "fortinet.fortios.management-cleartext", ControlOutcome.FINDING,
                           f"{protocol.upper()} administration is allowed on the interface.",
                           instance=f"{service.scope}/{service.interface}/{protocol}")
            relevant_admins = [
                admin
                for admin in administrators
                if admin["scope"] in {service.scope, "root", "global"}
            ]
            unrestricted_admins = [
                admin
                for admin in relevant_admins
                if not admin["trusted_hosts"]
                or any(self._is_unrestricted_trust(value) for value in admin["trusted_hosts"])
            ]
            role = (service.zone or "unspecified").lower()
            exposure = "WAN-facing" if role == "wan" or (service.interface or "").lower().startswith("wan") else role
            trust_summary = (
                "at least one enabled administrator has no effective trusted-host restriction"
                if unrestricted_admins or not relevant_admins
                else "all parsed enabled administrators have trusted-host restrictions"
            )
            self.add_issue(
                Finding(
                    rule_id="fortinet.fortios.management.insecure_protocol",
                    device=parser.device_type,
                    title="Weak Administrative Access",
                    observation=f"{protocol.upper()} management is enabled on interface '{service.interface}' in VDOM/scope '{service.scope}' ({exposure}); {trust_summary}.",
                    impact="Clear-text administrative traffic can expose credentials and device-management activity.",
                    severity=Severity.HIGH,
                    exploitability="An attacker with reachability to the named interface can intercept or attempt access to the insecure service.",
                    recommendation=f"Remove {protocol} from this interface's allowaccess list and use HTTPS or SSH with restricted administrator trusted hosts.",
                    evidence=tuple(item for item in service.evidence) or (
                        f"{service.scope}:{service.interface}:allowaccess {protocol}",
                    ),
                    references=(FORTINET_MANAGEMENT_GUIDE,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                )
            )
        if not cleartext:
            exported = any(True for _ in fortios.iter_interfaces())
            record_control(parser, "fortinet.fortios.management-cleartext",
                           ControlOutcome.NO_FINDING if exported else ControlOutcome.UNKNOWN,
                           "No exported interface allows HTTP or Telnet administration." if exported
                           else "No system interface section is exported.")

    @staticmethod
    def _values(settings: dict, key: str) -> list[str]:
        value = settings.get(key)
        if value is None:
            return []
        return [str(item) for item in value] if isinstance(value, list) else [str(value)]

    def check_broad_policies(self, parser: BaseDeviceParser) -> None:
        fortios = self._fortios(parser)
        prior_by_scope = {}
        for policy in fortios.get_firewall_policy_semantics():
            key = (policy.scope.casefold(), policy.family)
            earlier = tuple(prior_by_scope.get(key, ()))
            prior_by_scope.setdefault(key, []).append(policy)
            if not (policy.proof_eligible and policy.schedule_explicit and policy.action == "accept"
                    and policy.source_unrestricted and policy.destination_unrestricted
                    and policy.services.any
                    and policy.source_interfaces and policy.destination_interfaces):
                continue
            instance = f"{policy.scope}/{policy.family}/policy:{policy.name}"
            if fortios.get_covering_prior_policy_union(policy, earlier, "deny"):
                record_control(parser, "fortinet.fortios.policy-broad-permission", ControlOutcome.NO_FINDING,
                               "The all-address, all-service permission is fully covered by earlier deny policies.",
                               instance=instance)
                continue
            record_control(parser, "fortinet.fortios.policy-broad-permission", ControlOutcome.FINDING,
                           "Accept policy covers every source and destination address with service ALL.",
                           instance=instance)
            interface_scope = (
                "all interfaces"
                if {value.casefold() for value in policy.source_interfaces + policy.destination_interfaces} == {"any"}
                else f"{list(policy.source_interfaces)} to {list(policy.destination_interfaces)}"
            )
            behavior = dict(policy.behavior_signature)
            self.add_issue(
                Finding(
                    rule_id="fortinet.fortios.policy.broad_accept",
                    device=parser.device_type,
                    title="Broad Firewall Policy",
                    observation=(f"Enabled {policy.family} accept policy '{policy.name}' at position "
                                 f"{policy.position} in '{policy.scope}' has resolved source and destination "
                                 f"objects covering every address, service ALL, and schedule always across "
                                 f"{interface_scope}; logtraffic is {behavior.get('logtraffic', 'disable')} "
                                 f"and NAT is {behavior.get('nat', 'disable')}. "
                                 "This is a configured broad permission, not proof of "
                                 "end-to-end reachability."),
                    impact="The policy permits unrestricted service access between its configured interface scopes.",
                    severity=Severity.CRITICAL,
                    exploitability="Any source matching the interface scope can target any reachable destination and service.",
                    recommendation="Constrain source and destination addresses, services, schedule, and interfaces; enable appropriate policy logging.",
                    evidence=policy.evidence or (f"firewall {policy.family} policy {policy.name}",),
                    references=(FORTINET_POLICY_GUIDE,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                )
            )

    def check_tls_settings(self, parser: BaseDeviceParser) -> None:
        fortios = self._fortios(parser)
        for scope, section, path in fortios._scoped_sections("system global"):
            weak_values = []
            minimum = str(section.get("ssl-min-proto-version", "")).lower()
            if minimum in {"tlsv1", "tlsv1-1"}:
                weak_values.append(f"ssl-min-proto-version {minimum}")
            admin_versions = {
                value.lower()
                for value in fortios._as_list(section.get("admin-https-ssl-versions"))
            }
            weak_admin = admin_versions & {"tlsv1", "tlsv1-1", "sslv3"}
            if weak_admin:
                weak_values.append(
                    "admin-https-ssl-versions " + " ".join(sorted(weak_admin))
                )
            if not weak_values:
                continue
            record_control(parser, "fortinet.fortios.management-tls", ControlOutcome.FINDING,
                           "Legacy TLS versions are explicitly permitted: " + ", ".join(weak_values) + ".",
                           instance=scope)
            evidence = []
            for key in ("ssl-min-proto-version", "admin-https-ssl-versions"):
                evidence.extend(item for item in fortios._field_evidence(path + (key,)))
            self.add_issue(
                Finding(
                    rule_id="fortinet.fortios.tls.minimum_version",
                    device=parser.device_type,
                    title="Insecure TLS Version",
                    observation=f"Scope '{scope}' permits legacy TLS values: {', '.join(weak_values)}.",
                    impact="Legacy TLS protocols have known weaknesses and do not meet modern management-plane requirements.",
                    severity=Severity.HIGH,
                    exploitability="An on-path attacker may target protocol downgrade or legacy cryptographic weaknesses.",
                    recommendation="Permit only tlsv1-2 and tlsv1-3 for administrative HTTPS and related TLS services.",
                    evidence=tuple(evidence) or tuple(weak_values),
                    references=(FORTINET_TLS_REFERENCE,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                )
            )

    def check_syslog(self, parser: BaseDeviceParser) -> None:
        destinations = self._fortios(parser).get_normalized_config().logging_destinations.items
        usable = [
            destination
            for destination in destinations
            if destination.state == ConfigurationState.ENABLED
            and (destination.address or destination.destination_type == "forticloud")
        ]
        if usable:
            record_control(parser, "fortinet.fortios.remote-logging", ControlOutcome.NO_FINDING,
                           "An enabled remote log destination is configured.")
            return
        record_control(parser, "fortinet.fortios.remote-logging", ControlOutcome.FINDING,
                       "No enabled and usable remote log destination was found.")
        configured = [
            f"{destination.scope}:{destination.destination_type}:{destination.state.value}"
            for destination in destinations
        ]
        local = [
            destination.destination_type
            for destination in destinations
            if destination.destination_type in {"local-disk", "local-memory"}
            and destination.state == ConfigurationState.ENABLED
        ]
        self.add_issue(
            Finding(
                rule_id="fortinet.fortios.logging.missing",
                device=parser.device_type,
                title="Remote security logging is not configured",
                observation=(
                    "No enabled and usable syslog, FortiAnalyzer, FortiManager, or FortiCloud destination was found. "
                    + ("Local logging is explicitly enabled: " + ", ".join(sorted(set(local))) + "." if local
                       else "This finding assesses remote forwarding, not the availability of local logs.")
                ),
                impact="Security events may not reach a centralized audit and monitoring system.",
                severity=Severity.MEDIUM,
                exploitability="Reduced centralized visibility makes malicious activity harder to detect and investigate.",
                recommendation="Enable at least one supported centralized logging target and configure its destination and filters.",
                evidence=tuple(configured) or ("No supported logging target configured",),
                references=(FORTINET_LOGGING_GUIDE,),
                basis=FindingBasis.REQUIRED_SETTING_MISSING,
            )
        )

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_admin_access(parser)
        self.check_broad_policies(parser)
        self.check_tls_settings(parser)
        self.check_syslog(parser)
