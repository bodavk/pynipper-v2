"""Parser for SonicOS 7 E-CLI show-current-config text exports."""

from __future__ import annotations

from dataclasses import dataclass
import re
import shlex
from typing import Any

from src.devices.common.base_parser import BaseDeviceParser
from src.devices.common.models import (
    ConfigEvidence,
    ConfigurationState,
    LoggingDestination,
    ManagementService,
    NetworkInterface,
    NormalizedCollection,
    NormalizedConfig,
    NormalizedValue,
    SecurityPolicy,
)


class UnsupportedSonicOSFormat(ValueError):
    """Raised when input is not the supported SonicOS 7 E-CLI text dialect."""


@dataclass(frozen=True)
class SonicCommand:
    text: str
    line_number: int
    indent: int


@dataclass(frozen=True)
class SonicInterface:
    name: str
    zone: str
    management: tuple[str, ...]
    user_login: tuple[str, ...]
    enabled: bool
    address: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class SonicAccessRule:
    name: str
    position: int
    enabled: bool
    action: str
    from_zone: str
    to_zone: str
    source: str
    destination: str
    service: str
    schedule: str
    logging: bool
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class SonicVPNPolicy:
    name: str
    enabled: bool
    ike_encryption: str
    ike_authentication: str
    dh_group: str
    ipsec_encryption: str
    ipsec_authentication: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class SonicNTPServer:
    address: str
    authenticated: bool
    evidence: tuple[ConfigEvidence, ...]


class SonicOSParser(BaseDeviceParser):
    """Parse only SonicOS 7 plain-text E-CLI current-configuration output."""

    device_type = "SONICOS"
    format_name = "sonicos7-ecli-current-config"

    def __init__(self, config_filepath: str):
        super().__init__(config_filepath)
        with open(config_filepath, encoding="utf-8-sig") as config_file:
            self.commands = tuple(
                SonicCommand(
                    text=line.strip(),
                    line_number=number,
                    indent=len(line) - len(line.lstrip()),
                )
                for number, line in enumerate(config_file, start=1)
                if line.strip()
                and not line.strip().startswith(("#", "//"))
                and line.strip() not in {"configure", "commit", "exit"}
            )
        self.config = [command.text for command in self.commands]
        version = self._version_from_commands()
        if not re.search(r"\bSonicOS(?:X)?\b.*\b7(?:\.|\b)", version, re.IGNORECASE):
            if any(re.match(r"set\s+(?:service|admin|vpn)\b", command.text, re.IGNORECASE) for command in self.commands):
                detail = "legacy test-only 'set service/admin/vpn' syntax"
            elif any(command.text.casefold().startswith(("prefs", "preferences")) for command in self.commands):
                detail = "binary/legacy SonicOS preferences export"
            else:
                detail = "unidentified configuration dialect or missing SonicOS 7 firmware-version marker"
            raise UnsupportedSonicOSFormat(
                f"Unsupported SonicOS input: {detail}. Supply plain-text output from 'show current-config custom'."
            )

    def _evidence(self, command: SonicCommand) -> ConfigEvidence:
        text = command.text
        if any(secret in text.casefold() for secret in ("password ", "shared-secret ", "community ")):
            words = self._tokens(text)
            text = " ".join(words[:2] + ["<redacted>"])
        return ConfigEvidence(text, self.config_filepath, command.line_number)

    @staticmethod
    def _tokens(text: str) -> list[str]:
        try:
            return shlex.split(text)
        except ValueError:
            return text.split()

    @staticmethod
    def _after(tokens: list[str], *path: str) -> str:
        lowered = [token.casefold() for token in tokens]
        expected = [token.casefold() for token in path]
        for index in range(len(tokens) - len(expected)):
            if lowered[index : index + len(expected)] == expected:
                return tokens[index + len(expected)]
        return ""

    def _version_from_commands(self) -> str:
        for command in self.commands:
            match = re.fullmatch(r'firmware-version\s+(?:"([^"]+)"|(.+))', command.text, re.IGNORECASE)
            if match:
                return (match.group(1) or match.group(2)).strip()
        return ""

    def _record_commands(self, index: int) -> tuple[SonicCommand, ...]:
        parent = self.commands[index]
        children = [parent]
        for command in self.commands[index + 1 :]:
            if command.indent <= parent.indent:
                break
            children.append(command)
        return tuple(children)

    def get_hostname(self) -> str:
        for command in self.commands:
            match = re.fullmatch(r'(?:firewall-name|host-name|hostname)\s+(?:"([^"]+)"|(\S+))', command.text, re.IGNORECASE)
            if match:
                return match.group(1) or match.group(2)
        return "?"

    def get_version(self) -> str:
        version = self._version_from_commands()
        match = re.search(r"\b(7\.\S+)", version)
        return match.group(1).rstrip('"') if match else version

    def get_model(self) -> str:
        for command in self.commands:
            match = re.fullmatch(r"(?:product-name|appliance-name)\s+(.+)", command.text, re.IGNORECASE)
            if match:
                return match.group(1).strip('"')
        return "?"

    def get_interfaces(self) -> list[SonicInterface]:
        interfaces = []
        for index, command in enumerate(self.commands):
            match = re.match(r"interface\s+(X\d+(?::V\d+)?)\b", command.text, re.IGNORECASE)
            if not match:
                continue
            records = self._record_commands(index)
            tokens = self._tokens(" ".join(item.text for item in records))
            management = []
            user_login = []
            lowered = [token.casefold() for token in tokens]
            if "management" in lowered:
                start = lowered.index("management") + 1
                for token in lowered[start:]:
                    if token in {"http", "https", "ssh", "snmp", "ping"}:
                        management.append(token)
                    else:
                        break
            if "user-login" in lowered:
                start = lowered.index("user-login") + 1
                for token in lowered[start:]:
                    if token in {"http", "https"}:
                        user_login.append(token)
                    else:
                        break
            interfaces.append(
                SonicInterface(
                    name=match.group(1).upper(),
                    zone=self._after(tokens, "zone"),
                    management=tuple(dict.fromkeys(management)),
                    user_login=tuple(dict.fromkeys(user_login)),
                    enabled="shutdown" not in lowered or "no shutdown" in " ".join(lowered),
                    address=self._after(tokens, "ip-address") or self._after(tokens, "ip"),
                    evidence=tuple(self._evidence(item) for item in records),
                )
            )
        return interfaces

    def get_access_rules(self) -> list[SonicAccessRule]:
        rules = []
        for index, command in enumerate(self.commands):
            if not re.match(r"access-rule\s+(?:ipv[46]\s+)?(?:from|uuid)\b", command.text, re.IGNORECASE):
                continue
            records = self._record_commands(index)
            tokens = self._tokens(" ".join(item.text for item in records))
            lowered = [token.casefold() for token in tokens]
            enabled = "no enable" not in " ".join(lowered)
            name = self._after(tokens, "name") or self._after(tokens, "uuid") or f"rule-{len(rules) + 1}"
            rules.append(
                SonicAccessRule(
                    name=name,
                    position=len(rules) + 1,
                    enabled=enabled,
                    action=self._after(tokens, "action").casefold(),
                    from_zone=self._after(tokens, "from"),
                    to_zone=self._after(tokens, "to"),
                    source=self._after(tokens, "source", "address"),
                    destination=self._after(tokens, "destination", "address"),
                    service=self._after(tokens, "service"),
                    schedule=self._after(tokens, "schedule"),
                    logging="logging" in lowered and "no logging" not in " ".join(lowered),
                    evidence=tuple(self._evidence(item) for item in records),
                )
            )
        return rules

    def get_vpn_policies(self) -> list[SonicVPNPolicy]:
        policies = []
        for index, command in enumerate(self.commands):
            match = re.match(r'vpn\s+policy\s+(?:site-to-site\s+)?(?:"([^"]+)"|(\S+))', command.text, re.IGNORECASE)
            if not match:
                continue
            records = self._record_commands(index)
            text = " ".join(item.text for item in records)
            tokens = self._tokens(text)
            lowered = text.casefold()
            policies.append(
                SonicVPNPolicy(
                    name=match.group(1) or match.group(2),
                    enabled="enable" in [token.casefold() for token in tokens] and "no enable" not in lowered,
                    ike_encryption=self._after(tokens, "proposal", "ike", "encryption").casefold(),
                    ike_authentication=self._after(tokens, "proposal", "ike", "authentication").casefold(),
                    dh_group=self._after(tokens, "proposal", "ike", "dh-group").casefold(),
                    ipsec_encryption=self._after(tokens, "proposal", "ipsec", "encryption").casefold(),
                    ipsec_authentication=self._after(tokens, "proposal", "ipsec", "authentication").casefold(),
                    evidence=tuple(self._evidence(item) for item in records),
                )
            )
        return policies

    def get_syslog_destinations(self) -> list[LoggingDestination]:
        destinations = []
        for command in self.commands:
            match = re.search(r"(?:syslog-server|server)\s+(?:name\s+)?(?:\"([^\"]+)\"|(\S+))", command.text, re.IGNORECASE)
            if match and "syslog" in command.text.casefold() and "no enable" not in command.text.casefold():
                address = match.group(1) or match.group(2)
                destinations.append(
                    LoggingDestination(
                        destination_type="syslog",
                        state=ConfigurationState.ENABLED,
                        address=address,
                        scope="firewall",
                        evidence=(self._evidence(command),),
                    )
                )
        return destinations

    def get_ntp_server_records(self) -> list[SonicNTPServer]:
        servers: dict[str, SonicNTPServer] = {}
        for command in self.commands:
            match = re.fullmatch(r"(?P<no>no\s+)?ntp-server\s+(?P<address>\S+)(?:\s+.*)?", command.text, re.IGNORECASE)
            if match:
                address = match.group("address")
                if match.group("no"):
                    servers.pop(address.casefold(), None)
                    continue
                tokens = {token.casefold() for token in self._tokens(command.text)}
                authenticated = bool(tokens & {"md5", "sha", "sha1", "sha256"}) and bool(
                    tokens & {"key-number", "trust-key-no", "authentication"}
                )
                servers[address.casefold()] = SonicNTPServer(
                    address=address,
                    authenticated=authenticated,
                    evidence=(self._evidence(command),),
                )
        return list(servers.values())

    def get_ntp_servers(self) -> tuple[str, ...]:
        return tuple(server.address for server in self.get_ntp_server_records())

    def get_security_services(self) -> dict[str, bool | None]:
        states: dict[str, bool | None] = {
            "gateway-anti-virus": None,
            "cloud-gateway-anti-virus": None,
            "intrusion-prevention": None,
            "anti-spyware": None,
            "capture-atp": None,
        }
        for command in self.commands:
            match = re.fullmatch(r"(?P<no>no\s+)?(?P<name>gateway-anti-virus|cloud-gateway-anti-virus|intrusion-prevention|anti-spyware|capture-atp)\s+enable", command.text, re.IGNORECASE)
            if match:
                states[match.group("name").casefold()] = not bool(match.group("no"))
        return states

    def has_secure_snmpv3_user(self) -> bool:
        for command in self.commands:
            if re.fullmatch(
                r"snmp(?:-server)?\s+user\s+\S+.*\bauth\s+(?:sha|sha256|sha384|sha512)\b.*\bpriv\s+(?:aes|aes128|aes192|aes256)\b.*",
                command.text,
                re.IGNORECASE,
            ):
                return True
        return False

    def get_users(self) -> list[dict]:
        # The E-CLI custom export does not prove whether the built-in password
        # remains at its factory value, and secret material must not be exposed.
        return []

    def get_services(self) -> dict[str, bool]:
        interfaces = self.get_interfaces()
        return {
            protocol: any(protocol in interface.management for interface in interfaces if interface.enabled)
            for protocol in ("http", "https", "ssh", "snmp")
        }

    def get_native_config(self) -> Any:
        return self.commands

    def get_normalized_config(self) -> NormalizedConfig:
        hostname = self.get_hostname()
        version = self.get_version()
        model = self.get_model()
        interfaces = self.get_interfaces()
        return NormalizedConfig(
            device_type=self.device_type,
            hostname=NormalizedValue.known(hostname) if hostname != "?" else NormalizedValue.unknown("Hostname absent"),
            device_model=NormalizedValue.known(model) if model != "?" else NormalizedValue.unknown("Product metadata absent"),
            software_version=NormalizedValue.known(version, ConfigEvidence(self._version_from_commands(), self.config_filepath)),
            management_services=NormalizedCollection.known(*(
                ManagementService(
                    protocol=protocol,
                    state=ConfigurationState.ENABLED,
                    interface=interface.name,
                    zone=interface.zone or None,
                    scope="interface",
                    evidence=interface.evidence,
                )
                for interface in interfaces
                if interface.enabled
                for protocol in interface.management
            )),
            users=NormalizedCollection.unknown("E-CLI export cannot prove whether built-in administrator credentials are unchanged"),
            interfaces=NormalizedCollection.known(*(
                NetworkInterface(
                    name=interface.name,
                    state=ConfigurationState.ENABLED if interface.enabled else ConfigurationState.DISABLED,
                    zone=interface.zone or None,
                    scope="firewall",
                    addresses=(interface.address,) if interface.address else (),
                    evidence=interface.evidence,
                )
                for interface in interfaces
            )),
            policies=NormalizedCollection.known(*(
                SecurityPolicy(
                    name=rule.name,
                    state=ConfigurationState.ENABLED if rule.enabled else ConfigurationState.DISABLED,
                    action=rule.action,
                    position=rule.position,
                    scope="firewall",
                    source_interfaces=(rule.from_zone,),
                    destination_interfaces=(rule.to_zone,),
                    sources=(rule.source,),
                    destinations=(rule.destination,),
                    services=(rule.service,),
                    tracking="logging" if rule.logging else None,
                    evidence=rule.evidence,
                )
                for rule in self.get_access_rules()
            )),
            logging_destinations=NormalizedCollection.known(*self.get_syslog_destinations()),
            crypto_settings=NormalizedCollection.unknown("VPN proposals remain available through vendor-specific typed records"),
        )


__all__ = [
    "SonicAccessRule",
    "SonicCommand",
    "SonicInterface",
    "SonicNTPServer",
    "SonicOSParser",
    "SonicVPNPolicy",
    "UnsupportedSonicOSFormat",
]
