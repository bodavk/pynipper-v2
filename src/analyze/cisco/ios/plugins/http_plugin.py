from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.issue import Finding, Severity
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.cisco.ios import CiscoIOSParser, ConfigurationState


CISCO_IOS_HTTP_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/https/configuration/"
    "xe-17/https-xe-17-book/HTTP_1-1_Web_Server_and_Client.html"
)


class PluginHTTP(BasePlugin):
    """Evaluate the effective IOS embedded HTTP server configuration."""

    _SUPPORTED_AUTHENTICATION = {"aaa", "enable", "local", "tacacs"}

    @staticmethod
    def _ios_parser(parser: BaseDeviceParser) -> CiscoIOSParser:
        if not isinstance(parser, CiscoIOSParser):
            raise TypeError("PluginHTTP requires a Cisco IOS-family parser")
        return parser

    def get_cisco_ios_http(self, parser: BaseDeviceParser):
        ios = self._ios_parser(parser)
        if ios.get_http_server_state() != ConfigurationState.ENABLED:
            return None
        return Finding(
            rule_id="cisco.ios.http.cleartext_service",
            device=parser.device_type,
            title="Clear-text HTTP management service enabled",
            observation="The IOS HTTP management server is explicitly enabled.",
            impact="Administrative credentials and sessions can be exposed to interception or modification.",
            exploitability="An attacker with access to the management traffic path can observe or alter clear-text HTTP traffic.",
            recommendation="Disable it with 'no ip http server' and use HTTPS or SSH for remote administration.",
            severity=Severity.HIGH,
            evidence=("ip http server",),
            references=(CISCO_IOS_HTTP_GUIDE,),
        )

    def get_cisco_ios_http_access_list(self, parser: BaseDeviceParser):
        ios = self._ios_parser(parser)
        if ios.get_http_server_state() != ConfigurationState.ENABLED:
            return None
        access_class = ios.get_http_access_class()
        if access_class:
            return None
        return Finding(
            rule_id="cisco.ios.http.access_restriction",
            device=parser.device_type,
            title="HTTP management access is unrestricted",
            observation="The enabled HTTP server has no effective 'ip http access-class' restriction.",
            impact="Untrusted networks may be able to reach the device management service.",
            exploitability="An attacker only needs network reachability to attempt authentication or exploit the HTTP service.",
            recommendation="Restrict management sources with 'ip http access-class <ACL>' or disable HTTP.",
            severity=Severity.HIGH,
            evidence=("ip http server",),
            references=(CISCO_IOS_HTTP_GUIDE,),
        )

    def get_cisco_ios_http_auth(self, parser: BaseDeviceParser):
        ios = self._ios_parser(parser)
        if ios.get_http_server_state() != ConfigurationState.ENABLED:
            return None
        authentication = ios.get_http_authentication()
        method = authentication.split()[0].lower() if authentication else ""
        if method in self._SUPPORTED_AUTHENTICATION:
            return None

        detail = (
            f"unsupported authentication value {authentication!r}"
            if authentication
            else "no authentication method"
        )
        evidence = (
            (f"ip http authentication {authentication}",)
            if authentication
            else ("ip http server",)
        )
        return Finding(
            rule_id="cisco.ios.http.authentication",
            device=parser.device_type,
            title="HTTP management authentication is not safely defined",
            observation=f"The enabled HTTP server has {detail}.",
            impact="The management service may use an unintended or weak authentication path.",
            exploitability="A reachable management service can be probed for weak or missing authentication.",
            recommendation="Configure a supported authentication method with 'ip http authentication local', 'aaa', 'tacacs', or 'enable', or disable HTTP.",
            severity=Severity.HIGH,
            evidence=evidence,
            references=(CISCO_IOS_HTTP_GUIDE,),
        )

    def analyze(self, parser: BaseDeviceParser) -> None:
        for issue in (
            self.get_cisco_ios_http(parser),
            self.get_cisco_ios_http_access_list(parser),
            self.get_cisco_ios_http_auth(parser),
        ):
            if issue is not None:
                self.add_issue(issue)
