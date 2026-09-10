from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.issue import Finding, Severity
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.cisco.ios import CiscoIOSParser, ConfigurationState, NumericSetting


class PluginSSH(BasePlugin):
    """Evaluate IOS SSH protocol, limits, and inbound VTY restrictions."""

    MAX_AUTHENTICATION_RETRIES = 5
    MAX_NEGOTIATION_TIMEOUT_SECONDS = 60

    @staticmethod
    def _ios_parser(parser: BaseDeviceParser) -> CiscoIOSParser:
        if not isinstance(parser, CiscoIOSParser):
            raise TypeError("PluginSSH requires a Cisco IOS-family parser")
        return parser

    def get_cisco_ios_ssh(self, parser: BaseDeviceParser):
        ios = self._ios_parser(parser)
        if ios.get_ssh_state() != ConfigurationState.ENABLED:
            return None

        version = ios.get_ssh_version()
        if version == "2":
            return None
        mode = "compatibility mode (SSHv1 and SSHv2)" if version is None else f"version {version!r}"
        evidence = (f"ip ssh version {version}",) if version else tuple(
            profile.line for profile in ios.get_vty_profiles() if profile.permits_ssh
        )
        return Finding(
            rule_id="cisco.ios.ssh.protocol_version",
            device=parser.device_type,
            title="SSH protocol version 2 is not enforced",
            observation=f"The reachable SSH service uses {mode}.",
            impact="SSHv1 has fundamental protocol weaknesses and permits downgrade exposure where compatibility mode is allowed.",
            exploitability="An on-path attacker may be able to exploit SSHv1 weaknesses or force use of the legacy protocol.",
            recommendation="Enforce SSHv2 with 'ip ssh version 2'.",
            severity=Severity.HIGH,
            evidence=evidence or ("SSH configuration present",),
        )

    @staticmethod
    def _numeric_evidence(setting: NumericSetting, default: int) -> tuple[str, ...]:
        if setting.raw_line:
            return (setting.raw_line,)
        return (f"effective documented default: {default}",)

    def get_cisco_ios_ssh_retries(self, parser: BaseDeviceParser):
        ios = self._ios_parser(parser)
        if ios.get_ssh_state() != ConfigurationState.ENABLED:
            return None
        retries = ios.get_ssh_authentication_retries()
        if retries.value is not None and 0 < retries.value <= self.MAX_AUTHENTICATION_RETRIES:
            return None

        observation = (
            f"The SSH authentication-retries value could not be parsed: {retries.parse_error}."
            if retries.parse_error
            else f"The effective SSH authentication retry limit is {retries.value}; it must be between 1 and {self.MAX_AUTHENTICATION_RETRIES}."
        )
        return Finding(
            rule_id="cisco.ios.ssh.authentication_retries",
            device=parser.device_type,
            title="SSH authentication retry limit is unsafe",
            observation=observation,
            impact="A high or invalid retry limit increases the opportunity for password guessing attacks.",
            exploitability="An attacker with SSH reachability can repeatedly attempt authentication.",
            recommendation=f"Configure 'ip ssh authentication-retries <1-{self.MAX_AUTHENTICATION_RETRIES}>'.",
            severity=Severity.MEDIUM,
            evidence=self._numeric_evidence(retries, 3),
        )

    def get_cisco_ios_ssh_timeout(self, parser: BaseDeviceParser):
        ios = self._ios_parser(parser)
        if ios.get_ssh_state() != ConfigurationState.ENABLED:
            return None
        timeout = ios.get_ssh_timeout()
        if timeout.value is not None and 0 < timeout.value <= self.MAX_NEGOTIATION_TIMEOUT_SECONDS:
            return None

        observation = (
            f"The SSH time-out value could not be parsed: {timeout.parse_error}."
            if timeout.parse_error
            else f"The effective SSH negotiation timeout is {timeout.value} seconds; the policy maximum is {self.MAX_NEGOTIATION_TIMEOUT_SECONDS} seconds."
        )
        return Finding(
            rule_id="cisco.ios.ssh.negotiation_timeout",
            device=parser.device_type,
            title="SSH negotiation timeout is unsafe",
            observation=observation,
            impact="Long unauthenticated negotiations consume management-plane resources and leave sessions open unnecessarily.",
            exploitability="A reachable attacker can hold multiple unauthenticated SSH negotiations open.",
            recommendation=f"Configure 'ip ssh time-out <1-{self.MAX_NEGOTIATION_TIMEOUT_SECONDS}>'.",
            severity=Severity.LOW,
            evidence=self._numeric_evidence(timeout, 120),
        )

    def get_cisco_ios_vty_access_restriction(self, parser: BaseDeviceParser):
        ios = self._ios_parser(parser)
        if ios.get_ssh_state() != ConfigurationState.ENABLED:
            return None
        ssh_profiles = [profile for profile in ios.get_vty_profiles() if profile.permits_ssh]
        unrestricted = [profile for profile in ssh_profiles if not profile.has_inbound_access_class]
        if ssh_profiles and not unrestricted:
            return None

        evidence = tuple(profile.line for profile in unrestricted) or ("No SSH-enabled VTY access-class found",)
        return Finding(
            rule_id="cisco.ios.ssh.vty_access_restriction",
            device=parser.device_type,
            title="SSH VTY access is not source-restricted",
            observation="At least one SSH-enabled VTY range lacks an inbound IPv4 or IPv6 access-class.",
            impact="Any source with network reachability can attempt to access the SSH management service.",
            exploitability="An attacker can probe and brute-force SSH from any network permitted by upstream controls.",
            recommendation="Apply 'access-class <ACL> in' or 'ipv6 access-class <ACL> in' to every SSH-enabled VTY range.",
            severity=Severity.MEDIUM,
            evidence=evidence,
        )

    def analyze(self, parser: BaseDeviceParser) -> None:
        for issue in (
            self.get_cisco_ios_ssh(parser),
            self.get_cisco_ios_ssh_retries(parser),
            self.get_cisco_ios_ssh_timeout(parser),
            self.get_cisco_ios_vty_access_restriction(parser),
        ):
            if issue is not None:
                self.add_issue(issue)
