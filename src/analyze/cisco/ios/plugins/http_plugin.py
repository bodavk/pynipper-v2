from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.issue import Finding, FindingBasis, Severity
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.cisco.ios import CiscoIOSParser, ConfigurationState


CISCO_IOS_HTTP_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/https/configuration/"
    "xe-17/https-xe-17-book/HTTP_1-1_Web_Server_and_Client.html"
)


CISCO_IOS_HTTP_SERVICES_CR = (
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/https/command/nm-https-cr-book/m_nm-https-cr-cl-sh.html"
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
        platform = ios.get_http_platform_default()
        if ios.get_http_server_state() == ConfigurationState.ABSENT and platform is not None:
            return Finding(
                rule_id="cisco.ios.http.cleartext_service",
                device=parser.device_type,
                title="Clear-text HTTP management service enabled",
                observation="'ip http server' is not configured, and on this Catalyst platform the HTTP server is enabled by default for clustering.",
                impact="Administrative credentials and sessions can be exposed to interception or modification.",
                exploitability="An attacker with access to the management traffic path can observe or alter clear-text HTTP traffic.",
                recommendation="Configure 'no ip http server' (and 'no ip http secure-server' if unused) and manage the switch over SSH.",
                severity=Severity.HIGH,
                evidence=(platform, "ip http server absent: platform default enabled"),
                references=(CISCO_IOS_HTTP_SERVICES_CR, CISCO_IOS_HTTP_GUIDE),
                basis=FindingBasis.DOCUMENTED_DEFAULT,
            )
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

        # SC-044 IOS-16: HTTP guide, 'enable' is the default method when no
        # 'ip http authentication' is configured.
        detail = (
            f"unsupported authentication value {authentication!r}"
            if authentication
            else "no 'ip http authentication' method, so the documented default applies: the shared enable password"
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
            recommendation="Configure per-user authentication with 'ip http authentication aaa' or 'local', or disable HTTP.",
            severity=Severity.HIGH,
            evidence=evidence,
            references=(CISCO_IOS_HTTP_GUIDE,),
            basis=FindingBasis.EXPLICIT_VALUE if authentication else FindingBasis.DOCUMENTED_DEFAULT,
        )

    def analyze(self, parser: BaseDeviceParser) -> None:
        ios = self._ios_parser(parser)
        enabled = [name for name, state in (
            ("HTTP", ios.get_http_server_state()),
            ("HTTPS", ios.get_https_server_state()),
        ) if state == ConfigurationState.ENABLED]
        name = ios.get_http_access_class()
        if enabled and name:
            acl = ios.get_management_ipv4_acl(name)
            if acl.state == "permit-all":
                self.add_issue(Finding(
                    rule_id="cisco.ios.http.unrestricted_sources",
                    device=parser.device_type,
                    title="Web management ACL permits every IPv4 source",
                    observation=f"Enabled {' and '.join(enabled)} management uses standard IPv4 ACL {name}, which permits every source.",
                    impact="The attached ACL provides no IPv4 source restriction for web administration.",
                    exploitability="A source with network reachability can attempt web administration; upstream controls are not assessed.",
                    recommendation="Restrict the attached ACL to approved management sources.",
                    severity=Severity.HIGH,
                    evidence=(f"ip http access-class {name}",) + acl.evidence,
                    references=(CISCO_IOS_HTTP_GUIDE,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
        if enabled and ios.device_type == "IOS_XE":
            name6 = ios.get_http_ipv6_access_class()
            if name6:
                acl6 = ios.get_management_ipv6_acl(name6)
                if acl6.state == "permit-all":
                    self.add_issue(Finding(
                        rule_id="cisco.ios.http.ipv6_unrestricted_sources",
                        device=parser.device_type,
                        title="Web management ACL permits every IPv6 source",
                        observation=f"Enabled {' and '.join(enabled)} management uses IPv6 ACL {name6}, which permits every source.",
                        impact="The attached ACL provides no IPv6 source restriction for web administration.",
                        exploitability="A source with network reachability can attempt web administration; upstream controls are not assessed.",
                        recommendation="Restrict the IPv6 ACL to approved management sources.",
                        severity=Severity.HIGH,
                        evidence=(f"ip http access-class ipv6 {name6}",) + acl6.evidence,
                        references=(CISCO_IOS_HTTP_GUIDE,
                                    "https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/ios-xe-17/221107-filter-traffic-destined-to-cisco-ios-xe.html"),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    ))
        for issue in (
            self.get_cisco_ios_http(parser),
            self.get_cisco_ios_http_access_list(parser),
            self.get_cisco_ios_http_auth(parser),
        ):
            if issue is not None:
                self.add_issue(issue)
