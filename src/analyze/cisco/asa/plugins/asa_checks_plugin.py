import re
from src.analyze.common.base_plugin import BasePlugin
from src.analyze.cisco.ios.issue.cisco_ios_issue import CiscoIOSIssue
from src.devices.common.base_parser import BaseDeviceParser


class PluginASAChecks(BasePlugin):

    def __init__(self):
        super().__init__()

    # ASA-01: Telnet Enabled
    def check_telnet(self, parser: BaseDeviceParser) -> None:
        services = parser.get_services()
        if services.get("telnet", False):
            issue = CiscoIOSIssue(
                "Telnet Service Enabled",
                "The Telnet service is currently enabled on the device. Telnet is an insecure, clear-text protocol and does not encrypt management traffic.",
                "An attacker who is able to sniff network traffic can easily capture administrative credentials in transit.",
                "High — Sniffing tools are widely available and extremely easy to use.",
                "It is strongly recommended to disable Telnet access using 'no telnet ...' and use SSH for encrypted remote management."
            )
            self.add_issue(issue)

    # ASA-02: Weak Enable Password
    def check_weak_enable_password(self, parser: BaseDeviceParser) -> None:
        # In ASA we use get_enable_password()
        # Since it's a mock/subclass, we can check if it returns a known weak password
        enable_pw = parser.get_enable_password()
        weak_passwords = ["cisco", "cisco123", "admin", "password"]
        if enable_pw in weak_passwords:
            issue = CiscoIOSIssue(
                "Weak Enable Password Configured",
                f"The enable password '{enable_pw}' is weak, common, or easily guessable.",
                "An attacker who gets user-level access can guess the enable password and obtain full administrative control over the firewall.",
                "High — Weak passwords are highly susceptible to dictionary and automated brute-force attacks.",
                "Change the enable password to a complex value using the command: enable password <complex_password>"
            )
            self.add_issue(issue)

    # ASA-03: Insecure SNMP Communities
    def check_snmp_communities(self, parser: BaseDeviceParser) -> None:
        communities = parser.get_snmp_communities()
        for comm in communities:
            if comm.lower() in ["public", "private"]:
                issue = CiscoIOSIssue(
                    "Insecure SNMP Community String",
                    f"The device has an insecure SNMP community string '{comm}' configured.",
                    "An attacker can read (public) or modify (private) system configuration and status via SNMP, exposing sensitive info.",
                    "High — SNMP brute force scanners will automatically test default community strings.",
                    "Change community strings to a private complex value: snmp-server community <complex_string>"
                )
                self.add_issue(issue)
                break  # avoid duplicate alerts

    # ASA-04: Unrestricted SSH Access
    def check_unrestricted_ssh(self, parser: BaseDeviceParser) -> None:
        hosts = parser.get_ssh_hosts()
        for host in hosts:
            if host["ip"] == "0.0.0.0" and host["mask"] == "0.0.0.0":
                issue = CiscoIOSIssue(
                    "Unrestricted SSH Access Enabled",
                    "SSH access is configured with 0.0.0.0/0, allowing access from any IP address on the network/internet.",
                    "Exposes the SSH management interface to password guessing and potential zero-day exploit attempts from unauthorized hosts.",
                    "Medium — Requires credentials to exploit, but massively increases exposure.",
                    "Restrict SSH access to trusted administration subnets using 'ssh <ip> <mask> <interface>'."
                )
                self.add_issue(issue)
                break

    # ASA-05: Missing Logging Configuration
    def check_logging(self, parser: BaseDeviceParser) -> None:
        if not parser.get_logging_enabled():
            issue = CiscoIOSIssue(
                "Logging Disabled or Missing Configuration",
                "System logging is not enabled on this firewall ('no logging enable' is active).",
                "Without logs, it is impossible to detect security incidents, perform audit trails, or conduct forensic analysis after a breach.",
                "Low — Does not directly allow penetration, but severely cripples security operations and compliance.",
                "Enable logging and configure a secure external syslog host: logging enable; logging host <interface> <ip>"
            )
            self.add_issue(issue)

    # ASA-06: Insecure SSL/TLS Versions
    def check_ssl_version(self, parser: BaseDeviceParser) -> None:
        min_ver = parser.get_ssl_min_version()
        if min_ver.lower() in ["tlsv1", "tlsv1.1", "sslv3"]:
            issue = CiscoIOSIssue(
                "Insecure SSL/TLS Version Configured",
                f"The firewall's minimum SSL/TLS version is configured as '{min_ver}'.",
                "TLS 1.0, 1.1, and SSLv3 have known cryptographic vulnerabilities (e.g. POODLE, BEAST) that can lead to session decryption.",
                "Medium — Interception of admin management sessions can reveal login credentials.",
                "Configure TLS 1.2 as the minimum version: ssl minimum-version tlsv1.2"
            )
            self.add_issue(issue)

    # ASA-07: Wide Open ACLs
    def check_wide_open_acls(self, parser: BaseDeviceParser) -> None:
        interfaces = parser.get_interfaces()
        bindings = parser.get_acl_bindings()
        
        # Identify interface security levels
        low_sec_interfaces = [i["nameif"] for i in interfaces if i["security_level"] <= 10]
        
        for binding in bindings:
            # Check if ACL is on a low security level interface (e.g. outside)
            if binding["interface"] in low_sec_interfaces and binding["direction"] == "in":
                acl_name = binding["acl_name"]
                rules = parser.get_acl_rules(acl_name)
                for rule in rules:
                    # Look for "permit ip any any" or similar wide open rules
                    if re.search(r'permit\s+ip\s+any\s+any', rule) or re.search(r'permit\s+tcp\s+any\s+any', rule):
                        issue = CiscoIOSIssue(
                            "Wide Open ACL Rule on Outside Interface",
                            f"ACL '{acl_name}' on low-security interface '{binding['interface']}' contains a wide-open rule: '{rule}'",
                            "Allows unrestricted inbound network traffic from any source to any destination, defeating the primary firewall security boundary.",
                            "Critical — Allows immediate access/attack vector to all internal resources.",
                            "Restrict the ACL to only permit traffic to authorized hosts/ports: permit tcp any host <ip> eq <port>"
                        )
                        self.add_issue(issue)
                        break

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_telnet(parser)
        self.check_weak_enable_password(parser)
        self.check_snmp_communities(parser)
        self.check_unrestricted_ssh(parser)
        self.check_logging(parser)
        self.check_ssl_version(parser)
        self.check_wide_open_acls(parser)
