import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional
from ciscoconfparse import CiscoConfParse
from src.devices.common.base_parser import BaseDeviceParser


class ConfigurationState(str, Enum):
    """State of an IOS feature visible in the supplied configuration."""

    ENABLED = "enabled"
    DISABLED = "disabled"
    ABSENT = "absent"


@dataclass(frozen=True)
class NumericSetting:
    value: Optional[int]
    configured: bool
    raw_line: str = ""
    parse_error: str = ""


@dataclass(frozen=True)
class VTYProfile:
    line: str
    transports: tuple[str, ...]
    ipv4_access_class: str = ""
    ipv6_access_class: str = ""

    @property
    def permits_ssh(self) -> bool:
        return "ssh" in self.transports or "all" in self.transports

    @property
    def permits_telnet(self) -> bool:
        return "telnet" in self.transports or "all" in self.transports

    @property
    def has_inbound_access_class(self) -> bool:
        return bool(self.ipv4_access_class or self.ipv6_access_class)


class CiscoIOSParser(BaseDeviceParser):

    device_type = "IOS_ROUTER"

    def __init__(self, config_filepath: str):
        super().__init__(config_filepath)
        self.parser = CiscoConfParse(config_filepath, syntax='ios')

    def get_hostname(self) -> str:
        host = self.parser.find_objects("^hostname")
        if len(host) > 0:
            return host[0].re_match_typed(r'^hostname\s+(\S+)', default='')
        return "?"

    def get_version(self) -> str:
        version = self.parser.find_objects(r"^version(?:\s|$)")
        if version:
            # Preserve the supplied release token exactly. Advisory matching may
            # normalize it later, but the parser must never invent a build.
            return version[0].re_match_typed(r"^version\s+(\S+)", default="") or "?"
        return "?"

    def _global_lines(self) -> list[str]:
        """Return top-level commands in source order with whitespace removed."""

        return [
            line.strip()
            for line in self.parser.ioscfg
            if line.strip() and not line[:1].isspace()
        ]

    def _last_global_match(self, pattern: str) -> Optional[re.Match]:
        expression = re.compile(pattern)
        match = None
        for line in self._global_lines():
            candidate = expression.fullmatch(line)
            if candidate:
                match = candidate
        return match

    def get_http_server_state(self) -> ConfigurationState:
        match = self._last_global_match(r"(?P<disabled>no )?ip http server")
        if match is None:
            # Defaults vary across old IOS trains. Absence is deliberately kept
            # distinct instead of being converted into an enabled assertion.
            return ConfigurationState.ABSENT
        return (
            ConfigurationState.DISABLED
            if match.group("disabled")
            else ConfigurationState.ENABLED
        )

    def get_https_server_state(self) -> ConfigurationState:
        match = self._last_global_match(r"(?P<disabled>no )?ip http secure-server")
        if match is None:
            return ConfigurationState.ABSENT
        return (
            ConfigurationState.DISABLED
            if match.group("disabled")
            else ConfigurationState.ENABLED
        )

    def get_http_access_class(self) -> Optional[str]:
        value: Optional[str] = None
        expression = re.compile(r"(?:(?P<disabled>no)\s+)?ip http access-class(?:\s+(?P<value>\S+))?")
        for line in self._global_lines():
            match = expression.fullmatch(line)
            if match:
                value = None if match.group("disabled") else match.group("value")
        return value

    def get_http_authentication(self) -> Optional[str]:
        value: Optional[str] = None
        expression = re.compile(
            r"(?:(?P<disabled>no)\s+)?ip http auth(?:entication)?(?:\s+(?P<value>.+))?"
        )
        for line in self._global_lines():
            match = expression.fullmatch(line)
            if match:
                value = None if match.group("disabled") else match.group("value")
        return value

    def get_ssh_state(self) -> ConfigurationState:
        ssh_commands = [
            line
            for line in self._global_lines()
            if re.fullmatch(r"(?:no )?ip ssh(?:\s+.*)?", line)
        ]
        if ssh_commands and ssh_commands[-1] == "no ip ssh":
            return ConfigurationState.DISABLED

        profiles = self.get_vty_profiles()
        if any(profile.permits_ssh for profile in profiles):
            return ConfigurationState.ENABLED

        # An SSH-specific global command shows configuration intent, but a VTY
        # which explicitly excludes SSH makes the service unreachable.
        has_ssh_configuration = bool(ssh_commands and not ssh_commands[-1].startswith("no "))
        if has_ssh_configuration and not profiles:
            return ConfigurationState.ENABLED
        return ConfigurationState.ABSENT

    def get_ssh_version(self) -> Optional[str]:
        value: Optional[str] = None
        expression = re.compile(r"(?:(?P<disabled>no)\s+)?ip ssh version(?:\s+(?P<value>\S+))?")
        for line in self._global_lines():
            match = expression.fullmatch(line)
            if match:
                value = None if match.group("disabled") else match.group("value")
        return value

    def _get_numeric_ssh_setting(
        self,
        command: str,
        default: int,
    ) -> NumericSetting:
        selected_line = ""
        selected_value: Optional[str] = None
        configured = False
        command_pattern = (
            r"ip\ ssh\ time-?out"
            if command == "ip ssh time-out"
            else re.escape(command)
        )
        expression = re.compile(
            rf"(?:(?P<disabled>no)\s+)?{command_pattern}(?:\s+(?P<value>\S+))?"
        )
        for line in self._global_lines():
            match = expression.fullmatch(line)
            if not match:
                continue
            selected_line = line
            if match.group("disabled"):
                configured = False
                selected_value = None
            else:
                configured = True
                selected_value = match.group("value")

        if not configured:
            return NumericSetting(default, False, selected_line)
        if selected_value is None:
            return NumericSetting(
                None,
                True,
                selected_line,
                f"{command} is missing its numeric value",
            )
        try:
            return NumericSetting(int(selected_value), True, selected_line)
        except ValueError:
            return NumericSetting(
                None,
                True,
                selected_line,
                f"invalid numeric value {selected_value!r}",
            )

    def get_ssh_authentication_retries(self) -> NumericSetting:
        return self._get_numeric_ssh_setting("ip ssh authentication-retries", 3)

    def get_ssh_timeout(self) -> NumericSetting:
        return self._get_numeric_ssh_setting("ip ssh time-out", 120)

    def get_vty_profiles(self) -> list[VTYProfile]:
        profiles = []
        for parent in self.parser.find_objects(r"^line vty(?:\s|$)"):
            transports: tuple[str, ...] = ()
            ipv4_access_class = ""
            ipv6_access_class = ""
            for child in parent.children:
                line = child.text.strip()
                transport = re.fullmatch(r"transport input(?:\s+(.+))?", line)
                if transport:
                    transports = tuple((transport.group(1) or "").lower().split())
                    continue
                access_class = re.fullmatch(r"access-class\s+(\S+)\s+in(?:\s+vrf-also)?", line)
                if access_class:
                    ipv4_access_class = access_class.group(1)
                    continue
                ipv6_access = re.fullmatch(r"ipv6 access-class\s+(\S+)\s+in", line)
                if ipv6_access:
                    ipv6_access_class = ipv6_access.group(1)
            profiles.append(
                VTYProfile(
                    line=parent.text.strip(),
                    transports=transports,
                    ipv4_access_class=ipv4_access_class,
                    ipv6_access_class=ipv6_access_class,
                )
            )
        return profiles

    def get_users(self) -> list[dict]:
        users = []
        user_lines = self.parser.find_objects("^username")
        for line in user_lines:
            text = line.text
            # Simple match for username and optional privilege/password
            match_name = re.search(r'^username\s+(\S+)', text)
            if match_name:
                name = match_name.group(1)
                priv_match = re.search(r'privilege\s+(\d+)', text)
                priv = int(priv_match.group(1)) if priv_match else 1
                users.append({
                    "username": name,
                    "privilege": priv,
                    "raw_line": text
                })
        return users

    def get_services(self) -> dict:
        profiles = self.get_vty_profiles()
        return {
            "telnet": any(profile.permits_telnet for profile in profiles),
            "ssh": self.get_ssh_state() == ConfigurationState.ENABLED,
            "http": self.get_http_server_state() == ConfigurationState.ENABLED,
            "https": self.get_https_server_state() == ConfigurationState.ENABLED,
        }

    def get_native_config(self) -> CiscoConfParse:
        return self.parser

    # Keep classic helper functions as methods of the parser to facilitate transition
    def get_passwd_enc(self) -> bool:
        passwd_enc = self.parser.find_objects("no service password-encryption")
        return len(passwd_enc) > 0

    def get_passwd_length(self) -> str:
        passwd_length = self.parser.find_objects("security passwords min-length")
        if len(passwd_length) > 0:
            return passwd_length[0].re_match_typed(r'^security passwords min-length\s+(\S+)', default='')
        return "No specified"

    def get_ip_source_routing(self) -> bool:
        ip_src_routing = self.parser.find_objects("no ip source routing")
        return len(ip_src_routing) == 0

    def get_bootp(self) -> bool:
        bootp_server = self.parser.find_objects("no ip bootp server")
        return len(bootp_server) == 0

    def get_tcp_keep_alives_in(self) -> bool:
        keep_alives_in = self.parser.find_objects("service tcp-keepalives-in")
        return len(keep_alives_in) > 0

    def get_tcp_keep_alives_out(self) -> bool:
        keep_alives_out = self.parser.find_objects("service tcp-keepalives-out")
        return len(keep_alives_out) > 0
