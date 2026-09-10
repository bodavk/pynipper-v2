from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.issue import Finding, Severity
from src.devices.common.base_parser import BaseDeviceParser


class PluginPANOSChecks(BasePlugin):

    def __init__(self):
        super().__init__()

    # PAN-01: Insecure Management Interfaces
    def check_insecure_management(self, parser: BaseDeviceParser) -> None:
        root = parser.get_raw_config()
        profiles = root.findall(".//mgt-config/profiles/entry")
        for profile in profiles:
            http = profile.find("./http")
            if http is not None and http.text == "yes":
                issue = Finding(
                    rule_id="paloalto.panos.management.http",
                    device="PAN_OS",
                    title="Insecure Management Interface",
                    observation=f"Profile '{profile.get('name')}' allows HTTP management.",
                    impact="HTTP is cleartext.",
                    severity=Severity.HIGH,
                    recommendation="Disable HTTP in management profile.",
                )
                self.add_issue(issue)

    # PAN-02: Broad Security Rules
    def check_broad_rules(self, parser: BaseDeviceParser) -> None:
        root = parser.get_raw_config()
        rules = root.findall(".//security/rules/entry")
        for rule in rules:
            source = rule.find("./source/member")
            destination = rule.find("./destination/member")
            service = rule.find("./service/member")
            action = rule.find("./action")
            
            if source is not None and source.text == "any" and \
               destination is not None and destination.text == "any" and \
               service is not None and service.text == "any" and \
               action is not None and action.text == "allow":
                issue = Finding(
                    rule_id="paloalto.panos.policy.broad_allow",
                    device="PAN_OS",
                    title="Broad Security Rule",
                    observation=f"Rule '{rule.get('name')}' is overly permissive (any-any-any allow).",
                    impact="Security bypass.",
                    severity=Severity.CRITICAL,
                    recommendation="Restrict the rule.",
                )
                self.add_issue(issue)

    # PAN-03: Missing Syslog Forwarding
    def check_syslog(self, parser: BaseDeviceParser) -> None:
        root = parser.get_raw_config()
        syslog = root.find(".//log-settings/syslog")
        if syslog is None:
            issue = Finding(
                rule_id="paloalto.panos.logging.missing_syslog",
                device="PAN_OS",
                title="Missing Syslog Forwarding",
                observation="Syslog forwarding is not configured.",
                impact="Security events cannot be audited centrally.",
                severity=Severity.MEDIUM,
                recommendation="Configure syslog server in 'log-settings/syslog'.",
            )
            self.add_issue(issue)

    # PAN-04: Weak Password Parameters
    def check_weak_password(self, parser: BaseDeviceParser) -> None:
        root = parser.get_raw_config()
        # Look for password-complexity settings
        complexity = root.find(".//mgt-config/password-complexity")
        if complexity is None:
            issue = Finding(
                rule_id="paloalto.panos.credentials.password_complexity",
                device="PAN_OS",
                title="Weak Password Policy",
                observation="Password complexity is not configured.",
                impact="Passwords may be easily guessed.",
                severity=Severity.HIGH,
                recommendation="Configure password complexity settings.",
            )
            self.add_issue(issue)

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_insecure_management(parser)
        self.check_broad_rules(parser)
        self.check_syslog(parser)
        self.check_weak_password(parser)
