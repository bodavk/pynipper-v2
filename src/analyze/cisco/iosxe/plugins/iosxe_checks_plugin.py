from src.analyze.common.base_plugin import BasePlugin
from src.analyze.cisco.ios.issue.cisco_ios_issue import CiscoIOSIssue
from src.devices.common.base_parser import BaseDeviceParser


class PluginIOSXEChecks(BasePlugin):

    def __init__(self):
        super().__init__()

    # XE-01: Lack of MACsec
    def check_macsec(self, parser: BaseDeviceParser) -> None:
        # parser.get_raw_config() returns a CiscoConfParse object
        conf_parse = parser.get_raw_config()
        interfaces = conf_parse.find_objects(r"^interface\s+")
        for intf in interfaces:
            # Check for MKA policy
            if not intf.has_child_with("mka policy"):
                issue = CiscoIOSIssue(
                    "Lack of MACsec",
                    f"MACsec not configured on interface {intf.text}.",
                    "Layer 2 traffic not encrypted.",
                    "Medium",
                    "Configure MKA policy."
                )
                self.add_issue(issue)
                break

    # XE-02: Legacy Crypto Ciphers
    def check_legacy_crypto(self, parser: BaseDeviceParser) -> None:
        conf_parse = parser.get_raw_config()
        proposals = conf_parse.find_objects(r"^crypto ikev2 proposal\s+")
        for prop in proposals:
            if prop.has_child_with("encryption 3des") or prop.has_child_with("integrity md5"):
                issue = CiscoIOSIssue(
                    "Legacy Crypto Ciphers",
                    f"Weak cipher in IKEv2 proposal: {prop.text}",
                    "Vulnerable to decryption.",
                    "High",
                    "Use AES-256 and SHA-256."
                )
                self.add_issue(issue)
                break

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_macsec(parser)
        self.check_legacy_crypto(parser)
