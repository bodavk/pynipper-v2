"""Typed Arista EOS parser with scope-aware eAPI reconstruction."""

from __future__ import annotations

from dataclasses import dataclass
import re
import shlex
from typing import Any

from src.devices.cisco.ios import CiscoIOSParser
from src.devices.common.models import (
    ConfigEvidence,
    ConfigurationState,
    CryptoSetting,
    LocalUser,
    LoggingDestination,
    ManagementService,
    NormalizedCollection,
    NormalizedConfig,
    NormalizedValue,
)


@dataclass(frozen=True)
class AristaCommand:
    text: str
    line_number: int
    indent: int


@dataclass(frozen=True)
class AristaEAPIEndpoint:
    scope: str
    active: bool
    http: bool
    https: bool
    ipv4_acl: str
    ipv6_acl: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class AristaSSHSettings:
    configured: bool
    empty_passwords: str
    ipv4_acls: tuple[str, ...]
    ipv6_acls: tuple[str, ...]
    ciphers: tuple[str, ...]
    key_exchanges: tuple[str, ...]
    macs: tuple[str, ...]
    evidence: tuple[ConfigEvidence, ...]


class AristaEOSParser(CiscoIOSParser):
    device_type = "ARISTA_EOS"

    def __init__(self, config_filepath: str):
        super().__init__(config_filepath)
        with open(config_filepath, encoding="utf-8-sig") as config_file:
            self.commands = tuple(
                AristaCommand(
                    text=line.strip(),
                    line_number=number,
                    indent=len(line) - len(line.lstrip()),
                )
                for number, line in enumerate(config_file, start=1)
                if line.strip() and line.strip() != "!"
            )

    def _evidence(self, command: AristaCommand) -> ConfigEvidence:
        return ConfigEvidence(command.text, self.config_filepath, command.line_number)

    @staticmethod
    def _tokens(line: str) -> list[str]:
        try:
            return shlex.split(line)
        except ValueError:
            return line.split()

    def get_version(self) -> str:
        for command in self.commands:
            match = re.search(r"EOS[- ](?:version\s+)?([0-9][^\s,)]+)", command.text, re.IGNORECASE)
            if match:
                return match.group(1)
        return super().get_version()

    def get_model(self) -> str:
        for command in self.commands:
            match = re.fullmatch(r"!?#?\s*device:\s*.+?\(([^,()]+),\s*EOS[^)]*\)", command.text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return "?"

    def _blocks(self, parent_text: str) -> list[tuple[AristaCommand, list[AristaCommand]]]:
        blocks = []
        for index, command in enumerate(self.commands):
            if command.indent != 0 or command.text.casefold() != parent_text.casefold():
                continue
            children = []
            for child in self.commands[index + 1 :]:
                if child.indent <= command.indent:
                    break
                children.append(child)
            blocks.append((command, children))
        return blocks

    @staticmethod
    def _last_toggle(commands: list[AristaCommand], positive: str, *, default: bool) -> bool:
        state = default
        expression = re.compile(rf"(?P<no>no\s+|default\s+)?{positive}", re.IGNORECASE)
        for command in commands:
            match = expression.fullmatch(command.text)
            if match:
                state = not bool(match.group("no"))
        return state

    def get_eapi_endpoints(self) -> list[AristaEAPIEndpoint]:
        endpoints = []
        for parent, children in self._blocks("management api http-commands"):
            direct_indent = min((item.indent for item in children), default=parent.indent + 1)
            root_commands = [item for item in children if item.indent == direct_indent]
            # EOS defaults API shutdown, HTTPS available, and HTTP disabled.
            root_active = self._last_toggle(root_commands, r"shutdown", default=False)
            # For shutdown semantics the positive form disables and 'no' enables.
            for command in root_commands:
                if re.fullmatch(r"shutdown", command.text, re.IGNORECASE):
                    root_active = False
                elif re.fullmatch(r"no\s+shutdown", command.text, re.IGNORECASE):
                    root_active = True
            http = False
            https = True
            ipv4_acl = ""
            ipv6_acl = ""
            for command in root_commands:
                if re.fullmatch(r"protocol\s+http(?:\s+(?:port\s+)?\d+)?", command.text, re.IGNORECASE):
                    http = True
                elif re.fullmatch(r"(?:no|default)\s+protocol\s+http", command.text, re.IGNORECASE):
                    http = False
                elif re.fullmatch(r"protocol\s+https(?:\s+(?:port\s+)?\d+)?", command.text, re.IGNORECASE):
                    https = True
                elif re.fullmatch(r"no\s+protocol\s+https", command.text, re.IGNORECASE):
                    https = False
                elif match := re.fullmatch(r"ip\s+access-group\s+(\S+)(?:\s+in)?", command.text, re.IGNORECASE):
                    ipv4_acl = match.group(1)
                elif match := re.fullmatch(r"ipv6\s+access-group\s+(\S+)(?:\s+in)?", command.text, re.IGNORECASE):
                    ipv6_acl = match.group(1)

            vrf_indexes = [index for index, item in enumerate(children) if item.text.lower().startswith("vrf ")]
            if not vrf_indexes:
                endpoints.append(
                    AristaEAPIEndpoint(
                        scope="default",
                        active=root_active,
                        http=http,
                        https=https,
                        ipv4_acl=ipv4_acl,
                        ipv6_acl=ipv6_acl,
                        evidence=(self._evidence(parent),) + tuple(self._evidence(item) for item in children),
                    )
                )
                continue
            for position, index in enumerate(vrf_indexes):
                vrf_command = children[index]
                boundary = vrf_indexes[position + 1] if position + 1 < len(vrf_indexes) else len(children)
                scoped = children[index + 1 : boundary]
                active = root_active
                scope_ipv4 = ipv4_acl
                scope_ipv6 = ipv6_acl
                for command in scoped:
                    if re.fullmatch(r"shutdown", command.text, re.IGNORECASE):
                        active = False
                    elif re.fullmatch(r"no\s+shutdown", command.text, re.IGNORECASE):
                        active = True
                    elif match := re.fullmatch(r"ip\s+access-group\s+(\S+)(?:\s+in)?", command.text, re.IGNORECASE):
                        scope_ipv4 = match.group(1)
                    elif match := re.fullmatch(r"ipv6\s+access-group\s+(\S+)(?:\s+in)?", command.text, re.IGNORECASE):
                        scope_ipv6 = match.group(1)
                endpoints.append(
                    AristaEAPIEndpoint(
                        scope=vrf_command.text.split(maxsplit=1)[1],
                        active=active,
                        http=http,
                        https=https,
                        ipv4_acl=scope_ipv4,
                        ipv6_acl=scope_ipv6,
                        evidence=(self._evidence(parent), self._evidence(vrf_command))
                        + tuple(self._evidence(item) for item in scoped),
                    )
                )
        return endpoints

    def get_remote_authentication(self) -> tuple[str, ...]:
        methods = set()
        for command in self.commands:
            match = re.fullmatch(r"aaa\s+authentication\s+login\s+\S+\s+(.+)", command.text, re.IGNORECASE)
            if match:
                tokens = {token.casefold() for token in self._tokens(match.group(1))}
                methods.update(token for token in ("radius", "tacacs+") if token in tokens)
        return tuple(sorted(methods))

    def has_exec_authorization(self) -> bool:
        active = False
        expression = re.compile(
            r"(?P<no>no\s+)?aaa\s+authorization\s+exec\s+\S+\s+(.+)",
            re.IGNORECASE,
        )
        for command in self.commands:
            match = expression.fullmatch(command.text)
            if not match:
                continue
            methods = {token.casefold() for token in self._tokens(match.group(2))}
            active = not bool(match.group("no")) and bool(methods & {"tacacs+", "radius"})
        return active

    def get_ssh_settings(self) -> AristaSSHSettings:
        blocks = self._blocks("management ssh")
        if not blocks:
            return AristaSSHSettings(False, "unknown", (), (), (), (), (), ())

        evidence: list[ConfigEvidence] = []
        empty_passwords = "auto"
        ipv4_acls: dict[tuple[str, str], str] = {}
        ipv6_acls: dict[tuple[str, str], str] = {}
        algorithms: dict[str, set[str]] = {
            "cipher": set(),
            "key-exchange": set(),
            "mac": set(),
        }
        for parent, children in blocks:
            evidence.extend([self._evidence(parent), *(self._evidence(item) for item in children)])
            for command in children:
                text = command.text
                if match := re.fullmatch(r"authentication\s+empty-passwords\s+(auto|deny|permit)", text, re.IGNORECASE):
                    empty_passwords = match.group(1).casefold()
                elif re.fullmatch(r"(?:no|default)\s+authentication(?:\s+empty-passwords)?", text, re.IGNORECASE):
                    empty_passwords = "auto"
                elif match := re.fullmatch(r"ip\s+access-group\s+(\S+)\s+in(?:\s+vrf\s+(\S+))?", text, re.IGNORECASE):
                    ipv4_acls[(match.group(2) or "default", match.group(1))] = match.group(1)
                elif match := re.fullmatch(r"ipv6\s+access-group\s+(\S+)\s+in(?:\s+vrf\s+(\S+))?", text, re.IGNORECASE):
                    ipv6_acls[(match.group(2) or "default", match.group(1))] = match.group(1)
                elif match := re.fullmatch(r"(?P<no>no\s+)?(?P<kind>cipher|key-exchange|mac)\s+(?P<value>\S+)", text, re.IGNORECASE):
                    kind = match.group("kind").casefold()
                    value = match.group("value").casefold()
                    if match.group("no"):
                        algorithms[kind].discard(value)
                    else:
                        algorithms[kind].add(value)
                elif match := re.fullmatch(r"(?:no|default)\s+(cipher|key-exchange|mac)", text, re.IGNORECASE):
                    algorithms[match.group(1).casefold()].clear()
        return AristaSSHSettings(
            configured=True,
            empty_passwords=empty_passwords,
            ipv4_acls=tuple(ipv4_acls.values()),
            ipv6_acls=tuple(ipv6_acls.values()),
            ciphers=tuple(sorted(algorithms["cipher"])),
            key_exchanges=tuple(sorted(algorithms["key-exchange"])),
            macs=tuple(sorted(algorithms["mac"])),
            evidence=tuple(evidence),
        )

    def _local_users(self) -> list[LocalUser]:
        users = []
        for command in self.commands:
            match = re.fullmatch(r"username\s+(\S+)(?:\s+privilege\s+(\d+))?(?:\s+role\s+(\S+))?.*", command.text, re.IGNORECASE)
            if not match:
                continue
            users.append(
                LocalUser(
                    username=match.group(1),
                    state=ConfigurationState.ENABLED,
                    role=match.group(3),
                    privilege=int(match.group(2)) if match.group(2) else None,
                    authentication="local",
                    scope="switch",
                    evidence=(ConfigEvidence(f"username {match.group(1)} <credential redacted>", self.config_filepath, command.line_number),),
                )
            )
        return users

    def get_users(self) -> list[dict]:
        return [
            {"username": user.username, "privilege": user.privilege, "role": user.role}
            for user in self._local_users()
        ]

    def get_snmp_communities(self) -> list[tuple[str, ConfigEvidence]]:
        communities: dict[str, ConfigEvidence] = {}
        for command in self.commands:
            match = re.fullmatch(r"(?P<no>no\s+)?snmp-server\s+community\s+(?P<name>\S+)(?:\s+.*)?", command.text, re.IGNORECASE)
            if not match:
                continue
            key = match.group("name").casefold()
            if match.group("no"):
                communities.pop(key, None)
            else:
                communities[key] = ConfigEvidence("snmp-server community <redacted>", self.config_filepath, command.line_number)
        return [(name, evidence) for name, evidence in communities.items()]

    def has_secure_snmpv3_user(self) -> bool:
        for command in self.commands:
            if re.fullmatch(r"snmp-server\s+user\s+\S+\s+\S+\s+v3\s+auth\s+(?:sha|sha224|sha256|sha384|sha512)\s+\S+\s+priv\s+(?:aes|aes192|aes256)\s+\S+.*", command.text, re.IGNORECASE):
                return True
        return False

    def get_logging_destinations(self) -> list[LoggingDestination]:
        destinations = {}
        for command in self.commands:
            match = re.fullmatch(r"(?P<no>no\s+)?logging\s+host\s+(?P<address>\S+)(?:\s+.*)?", command.text, re.IGNORECASE)
            if not match:
                continue
            address = match.group("address")
            if match.group("no"):
                destinations.pop(address, None)
            else:
                destinations[address] = LoggingDestination(
                    destination_type="syslog",
                    state=ConfigurationState.ENABLED,
                    address=address,
                    scope="switch",
                    evidence=(self._evidence(command),),
                )
        return list(destinations.values())

    def get_ntp_servers(self) -> tuple[str, ...]:
        servers = {}
        for command in self.commands:
            match = re.fullmatch(r"(?P<no>no\s+)?ntp\s+server\s+(?P<address>\S+)(?:\s+.*)?", command.text, re.IGNORECASE)
            if match:
                servers[match.group("address")] = not bool(match.group("no"))
        return tuple(address for address, enabled in servers.items() if enabled)

    def get_services(self) -> dict[str, bool]:
        endpoints = self.get_eapi_endpoints()
        inherited = super().get_services()
        return {
            **inherited,
            "eapi_http": any(item.active and item.http for item in endpoints),
            "eapi_https": any(item.active and item.https for item in endpoints),
        }

    def get_native_config(self) -> Any:
        return self.parser

    def get_normalized_config(self) -> NormalizedConfig:
        hostname = self.get_hostname()
        version = self.get_version()
        model = self.get_model()
        endpoints = self.get_eapi_endpoints()
        services = [
            ManagementService(
                protocol=protocol,
                state=ConfigurationState.ENABLED,
                scope=endpoint.scope,
                permitted_sources=tuple(filter(None, (endpoint.ipv4_acl, endpoint.ipv6_acl))),
                evidence=endpoint.evidence,
            )
            for endpoint in endpoints
            if endpoint.active
            for protocol, active in (("http", endpoint.http), ("https", endpoint.https))
            if active
        ]
        return NormalizedConfig(
            device_type=self.device_type,
            hostname=NormalizedValue.known(hostname) if hostname != "?" else NormalizedValue.unknown("Hostname absent"),
            device_model=NormalizedValue.known(model) if model != "?" else NormalizedValue.unknown("Model metadata absent"),
            software_version=NormalizedValue.known(version) if version != "?" else NormalizedValue.unknown("EOS version absent"),
            management_services=NormalizedCollection.known(*services),
            users=NormalizedCollection.known(*self._local_users()),
            interfaces=NormalizedCollection.unknown("EOS interface roles are not normalized in this revision"),
            policies=NormalizedCollection.unsupported("EOS is not parsed as a firewall policy platform"),
            logging_destinations=NormalizedCollection.known(*self.get_logging_destinations()),
            crypto_settings=(
                NormalizedCollection.known(
                    *(
                        CryptoSetting(
                            name=f"ssh-{kind}",
                            value=value,
                            state=ConfigurationState.CONFIGURED,
                            scope="management-ssh",
                            evidence=ssh.evidence,
                        )
                        for kind, values in (
                            ("cipher", ssh.ciphers),
                            ("key-exchange", ssh.key_exchanges),
                            ("mac", ssh.macs),
                        )
                        for value in values
                    )
                )
                if (ssh := self.get_ssh_settings()).configured
                else NormalizedCollection.unknown("No explicit management SSH policy block")
            ),
        )


__all__ = ["AristaCommand", "AristaEAPIEndpoint", "AristaEOSParser", "AristaSSHSettings"]
