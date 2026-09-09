from src.analyze.common.base_plugin import BasePlugin
from src.analyze.cisco.ios.issue.cisco_ios_issue import CiscoIOSIssue
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
                issue = CiscoIOSIssue(
                    "Insecure Management Interface",
                    f"Profile '{profile.get('name')}' allows HTTP management.",
                    "HTTP is cleartext.",
                    "High",
                    "Disable HTTP in management profile."
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
                issue = CiscoIOSIssue(
                    "Broad Security Rule",
                    f"Rule '{rule.get('name')}' is overly permissive (any-any-any allow).",
                    "Security bypass.",
                    "Critical",
                    "Restrict the rule."
                )
                self.add_issue(issue)

    # PAN-03: Missing Syslog Forwarding
    def check_syslog(self, parser: BaseDeviceParser) -> None:
        root = parser.get_raw_config()
        syslog = root.find(".//log-settings/syslog")
        if syslog is None:
            issue = CiscoIOSIssue(
                "Missing Syslog Forwarding",
                "Syslog forwarding is not configured.",
                "Security events cannot be audited centrally.",
                "Medium",
                "Configure syslog server in 'log-settings/syslog'."
            )
            self.add_issue(issue)

    # PAN-04: Weak Password Parameters
    def check_weak_password(self, parser: BaseDeviceParser) -> None:
        root = parser.get_raw_config()
        # Look for password-complexity settings
        complexity = root.find(".//mgt-config/password-complexity")
        if complexity is None:
            issue = CiscoIOSIssue(
                "Weak Password Policy",
                "Password complexity is not configured.",
                "Passwords may be easily guessed.",
                "High",
                "Configure password complexity settings."
            )
            self.add_issue(issue)

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_insecure_management(parser)
        self.check_broad_rules(parser)
        self.check_syslog(parser)
        self.check_weak_password(parser)
