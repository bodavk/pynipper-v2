# flake8: noqa

from ..core.base_plugin import GenericPlugin
from ..issue.cisco_ios_issue import CiscoIOSIssue
from src.devices.common.base_parser import BaseDeviceParser


class PluginSSH(GenericPlugin):

    def __init__(self):
        super().__init__()

    # If the device has ssh configured -> true

    def _has_cisco_ios_ssh(self, parser: BaseDeviceParser) -> bool:
        cisco_parser = parser.get_raw_config()
        transport_disable = cisco_parser.find_objects("transport input none")
        ssh_disable = cisco_parser.find_objects("no transport input ssh")
        ssh_ip_disable = cisco_parser.find_objects("no ip ssh")
        if (len(transport_disable) > 0 or len(ssh_disable) > 0 or len(ssh_ip_disable) > 0):
            return False
        else:
            return True

    # Number of ssh version

    def _get_cisco_ios_ssh_version(self, parser: BaseDeviceParser) -> str:
        cisco_parser = parser.get_raw_config()
        ssh_version = cisco_parser.find_objects("ip ssh version")
        if (len(ssh_version) > 0):
            version = ssh_version[0].re_match_typed(
                r'^ip ssh version\s+(\S+)', default='')
            return version
        else:
            return ""

    def get_cisco_ios_ssh(self, parser: BaseDeviceParser):
        if (not self._has_cisco_ios_ssh(parser) or self._get_cisco_ios_ssh_version(parser) == "" or self._get_cisco_ios_ssh_version(parser) != "2"):
            return CiscoIOSIssue(
                "SSH Protocol Version",
                "The SSH service is commonly used for encrypted command-based remote device management. There are multiple SSH protocol versions and SSH servers will often support multiple versions to maintain backwards compatibility. Although flaws have been identified in implementations of version 2 of the SSH protocol, fundamental flaws exist in SSH protocol version 1.",  # noqa: E501
                "An attacker who was able to intercept SSH protocol version 1 traffic would be able to perform a man-in-the-middle style attack. The attacker could then capture network traffic and possibly authentication credentials.",  # noqa: E501
                "Although vulnerabilities are widely known, exploiting the vulnerabilities in the SSH protocol can be difficult.",
                "When SSH protocol version 2 support is configured on Cisco IOS devices, support for version 1 will be disabled. This can be configured with the following command: ip ssh version 2"  # noqa: E501
            )
        return None

    # Number of max. retries configured to login with ssh

    def _get_cisco_ios_ssh_retries(self, parser: BaseDeviceParser) -> str:
        cisco_parser = parser.get_raw_config()
        retries = cisco_parser.find_objects("ip ssh authentication-retries")
        if (len(retries) > 0):
            max_retries = retries[0].re_match_typed(
                r'^ip ssh authentication-retries\s+(\S+)', default='')
            return max_retries
        else:
            return ""

    def get_cisco_ios_ssh_reties(self, parser: BaseDeviceParser):
        retries = self._get_cisco_ios_ssh_retries(parser)
        if (retries == "" or int(retries) > 5):
            return CiscoIOSIssue(
                "SSH retries misconfiguration",
                "The SSH service must have a defined number of retries, the recommended is between 0 and 5.",
                "Set a retries number allows to reduce the bruteforce and dictionary attacks. If a retry number is defined, the attacker can not test with an user multiple passwords.",  # noqa: E501
                "This issue improve the hardening of passwords in the network device.",
                "This can be configured with the following command: ip ssh authentication-retries <retry-number>."
            )
        return None

    # Number of seconds of ssh timeout

    def _get_cisco_ios_ssh_timeout(self, parser: BaseDeviceParser) -> int:
        cisco_parser = parser.get_raw_config()
        timeout = cisco_parser.find_objects("ip ssh time-out")
        if (len(timeout) > 0):
            seconds = timeout[0].re_match_typed(
                r'^ip ssh time-out\s+(\S+)', default='')
            return int(seconds)
        else:
            return 0

    def get_cisco_ios_ssh_timeout(self, parser: BaseDeviceParser):
        timeout = self._get_cisco_ios_ssh_timeout(parser)
        if (timeout == 0 or timeout > 120):
            return CiscoIOSIssue(
                "SSH timeout misconfiguration",
                "The SSH service must have a defined timeout between 0 and 60 seconds.",
                "Set a timeout allows disable not used or malicious sessions in background.",
                "This issue only increase the device management security, it is not exploitable.",
                "This can be configured with the following command: ip ssh time-out <timeout-in-seconds>."
            )
        return None

    # Get the source interface

    def _get_cisco_ios_ssh_interface(self, parser: BaseDeviceParser) -> str:
        cisco_parser = parser.get_raw_config()
        src_interface = cisco_parser.find_objects("ip ssh source-interface")
        if (len(src_interface) > 0):
            interface = src_interface[0].re_match_typed(
                r'^ip ssh source-interface\s+(\S+)', default='')
            return interface
        else:
            return ""

    def get_cisco_ios_ssh_interface(self, parser: BaseDeviceParser):
        if (self._get_cisco_ios_ssh_interface(parser) == ""):
            return CiscoIOSIssue(
                "SSH source-interface enabled",
                "The SSH service must have a controlated set of source interfaces to manage the device",
                "To reduce bruteforce attacks is usefull have a set of source interfaces, logged and filtered, to access to SSH device management.",
                "This issue only increase the device management security, it is not exploitable, but it reduce bruteforce attacks.",
                "This can be configured with the following command: ip ssh source-interface <interface> "
            )
        return None

    def analyze(self, parser: BaseDeviceParser) -> None:
        issues = []

        issues.append(self.get_cisco_ios_ssh(parser))
        issues.append(self.get_cisco_ios_ssh_reties(parser))
        issues.append(self.get_cisco_ios_ssh_timeout(parser))
        issues.append(self.get_cisco_ios_ssh_interface(parser))

        for issue in issues:
            if issue is not None:
                self.add_issue(issue)
