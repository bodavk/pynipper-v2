import re
import shlex
from dataclasses import dataclass, field
from typing import Optional

from src.devices.common.base_parser import BaseDeviceParser
from src.devices.common.models import (
    ConfigEvidence,
    ConfigurationState,
    CryptoSetting,
    LocalUser,
    LoggingDestination,
    ManagementService,
    NetworkInterface,
    NormalizedCollection,
    NormalizedConfig,
    NormalizedValue,
    SecurityPolicy,
)


@dataclass
class ScreenOSInterface:
    name: str
    zone: str = ""
    addresses: list[str] = field(default_factory=list)
    management_methods: set[str] = field(default_factory=set)
    manager_ips: list[str] = field(default_factory=list)
    disabled: bool = False
    evidence: list[ConfigEvidence] = field(default_factory=list)


@dataclass
class ScreenOSPolicy:
    policy_id: str
    position: int
    from_zone: str = ""
    to_zone: str = ""
    sources: list[str] = field(default_factory=list)
    destinations: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    action: str = ""
    disabled: bool = False
    tracking: str = ""
    evidence: list[ConfigEvidence] = field(default_factory=list)


@dataclass(frozen=True)
class ScreenOSObject:
    name: str
    scope: str
    value: str
    evidence: ConfigEvidence


@dataclass(frozen=True)
class ScreenOSCommand:
    tokens: tuple[str, ...]
    evidence: ConfigEvidence


class JuniperScreenOSParser(BaseDeviceParser):

    device_type = "SCREENOS"

    _MANAGEMENT_ALIASES = {
        "web": "http",
        "http": "http",
        "ssl": "https",
        "https": "https",
        "telnet": "telnet",
        "ssh": "ssh",
        "snmp": "snmp",
        "ping": "ping",
    }

    def __init__(self, config_filepath: str):
        super().__init__(config_filepath)
        with open(config_filepath, "r", encoding="utf-8") as config_file:
            self.raw_lines = config_file.read().splitlines()
        self.diagnostics: list[str] = []
        self.hostname = ""
        self.version = ""
        self.model = ""
        self.interfaces: dict[str, ScreenOSInterface] = {}
        self.policies: dict[str, ScreenOSPolicy] = {}
        self.address_objects: dict[tuple[str, str], ScreenOSObject] = {}
        self.service_objects: dict[str, ScreenOSObject] = {}
        self.users: dict[str, dict] = {}
        self.global_management: set[str] = set()
        self.global_management_evidence: dict[str, ConfigEvidence] = {}
        self.manager_ips: list[str] = []
        self.effective_commands: list[ScreenOSCommand] = []
        self._parse()
        self.config = self._effective_native_lines()

    def _evidence(self, text: str, line_number: int, redact: bool = False) -> ConfigEvidence:
        evidence_text = text
        if redact:
            evidence_text = re.sub(
                r"(?i)(password|secret|key|community)\s+\S+",
                r"\1 <redacted>",
                evidence_text,
            )
        return ConfigEvidence(evidence_text, self.config_filepath, line_number)

    @staticmethod
    def _append_unique(values: list[str], value: str) -> None:
        if value and value not in values:
            values.append(value)

    def _interface(self, name: str) -> ScreenOSInterface:
        return self.interfaces.setdefault(name, ScreenOSInterface(name))

    def _policy(self, policy_id: str) -> ScreenOSPolicy:
        return self.policies.setdefault(
            policy_id,
            ScreenOSPolicy(policy_id=policy_id, position=len(self.policies)),
        )

    @staticmethod
    def _is_token_prefix(prefix: tuple[str, ...], value: tuple[str, ...]) -> bool:
        return len(value) >= len(prefix) and value[: len(prefix)] == prefix

    def _record_effective_command(
        self, tokens: list[str], raw_line: str, line_number: int
    ) -> None:
        operation = tokens[0].casefold()
        command = tuple(token.casefold() for token in tokens[1:])
        if operation == "unset":
            self.effective_commands = [
                item
                for item in self.effective_commands
                if not self._is_token_prefix(command, item.tokens)
            ]
            return
        self.effective_commands.append(
            ScreenOSCommand(command, self._evidence(raw_line, line_number, redact=True))
        )

    def get_effective_commands(
        self, prefix: tuple[str, ...] = ()
    ) -> list[ScreenOSCommand]:
        normalized = tuple(token.casefold() for token in prefix)
        return [
            command
            for command in self.effective_commands
            if self._is_token_prefix(normalized, command.tokens)
        ]

    def _parse(self) -> None:
        policy_context: Optional[str] = None
        for line_number, raw_line in enumerate(self.raw_lines, 1):
            stripped = raw_line.strip()
            if not stripped:
                continue
            self._parse_metadata_line(stripped)
            if stripped.startswith("#"):
                continue
            if stripped.casefold() == "exit":
                policy_context = None
                continue
            try:
                tokens = shlex.split(stripped, comments=True, posix=True)
            except ValueError as error:
                self.diagnostics.append(f"line {line_number}: {error}")
                continue
            if not tokens:
                continue
            lowered = [token.casefold() for token in tokens]
            operation = lowered[0]
            if operation not in {"set", "unset"}:
                self._parse_metadata_line(stripped)
                continue
            self._record_effective_command(tokens, stripped, line_number)

            if lowered[:2] == ["set", "hostname"] and len(tokens) >= 3:
                self.hostname = tokens[2]
                continue
            if lowered[:2] == ["unset", "hostname"]:
                self.hostname = ""
                continue
            if lowered[:2] == ["set", "version"] and len(tokens) >= 3:
                self.version = tokens[2]
                continue
            if lowered[:2] == ["set", "chassis"] and len(tokens) >= 3:
                self.model = tokens[2]
                continue

            if len(tokens) >= 3 and lowered[1] == "interface":
                self._parse_interface(tokens, lowered, stripped, line_number)
                continue
            if lowered[:3] in (["set", "admin", "manager-ip"], ["unset", "admin", "manager-ip"]):
                self._parse_manager_ip(tokens, operation)
                continue
            if len(tokens) >= 3 and lowered[1] == "admin" and lowered[2] in self._MANAGEMENT_ALIASES:
                method = self._MANAGEMENT_ALIASES[lowered[2]]
                if operation == "set" and (len(tokens) == 3 or "enable" in lowered[3:]):
                    self.global_management.add(method)
                    self.global_management_evidence[method] = self._evidence(
                        stripped, line_number
                    )
                elif operation == "unset" or "disable" in lowered[3:]:
                    self.global_management.discard(method)
                    self.global_management_evidence.pop(method, None)
                continue
            if lowered[:3] == ["set", "admin", "name"] and len(tokens) >= 4:
                self.users["admin"] = {
                    "username": tokens[3],
                    "role": "root",
                    "authentication": "configured",
                    "evidence": [self._evidence(stripped, line_number)],
                }
                continue
            if len(tokens) >= 4 and lowered[:3] == ["set", "admin", "user"]:
                self._parse_user(tokens, lowered, stripped, line_number)
                continue

            if len(tokens) >= 5 and lowered[:2] == ["set", "address"]:
                zone, name = tokens[2], tokens[3]
                self.address_objects[(zone, name)] = ScreenOSObject(
                    name, zone, " ".join(tokens[4:]), self._evidence(stripped, line_number)
                )
                continue
            if len(tokens) >= 4 and lowered[:2] == ["unset", "address"]:
                self.address_objects.pop((tokens[2], tokens[3]), None)
                continue
            if len(tokens) >= 4 and lowered[:2] == ["set", "service"]:
                self.service_objects[tokens[2]] = ScreenOSObject(
                    tokens[2], "global", " ".join(tokens[3:]), self._evidence(stripped, line_number)
                )
                continue
            if len(tokens) >= 3 and lowered[:2] == ["unset", "service"]:
                self.service_objects.pop(tokens[2], None)
                continue

            if len(tokens) >= 4 and lowered[1:3] == ["policy", "id"]:
                policy_context = self._parse_policy_command(
                    tokens, lowered, stripped, line_number
                )
                continue
            if policy_context:
                self._parse_policy_continuation(
                    self._policy(policy_context), tokens, lowered, stripped, line_number
                )

    def _parse_metadata_line(self, line: str) -> None:
        version = re.search(r"(?:ScreenOS|software)\s+(?:version\s+)?([\w.()-]+)", line, re.IGNORECASE)
        if version and not self.version:
            self.version = version.group(1)
        model = re.search(r"(?:model|device)\s*[:=]\s*(\S+)", line, re.IGNORECASE)
        if model and not self.model:
            self.model = model.group(1)

    def _parse_interface(
        self,
        tokens: list[str],
        lowered: list[str],
        raw_line: str,
        line_number: int,
    ) -> None:
        operation, name = lowered[0], tokens[2]
        interface = self._interface(name)
        interface.evidence.append(self._evidence(raw_line, line_number))
        if len(tokens) == 3 and operation == "unset":
            self.interfaces.pop(name, None)
            return
        if len(tokens) < 4:
            return
        command = lowered[3]
        if command == "zone" and len(tokens) >= 5:
            interface.zone = tokens[4] if operation == "set" else ""
        elif command == "ip" and len(tokens) >= 5:
            if operation == "set":
                self._append_unique(interface.addresses, " ".join(tokens[4:]))
            else:
                interface.addresses = [value for value in interface.addresses if value != " ".join(tokens[4:])]
        elif command == "manage":
            methods = [self._MANAGEMENT_ALIASES[item] for item in lowered[4:] if item in self._MANAGEMENT_ALIASES]
            if operation == "set":
                interface.management_methods.update(methods)
            elif methods:
                interface.management_methods.difference_update(methods)
            else:
                interface.management_methods.clear()
        elif command == "manage-ip" and len(tokens) >= 5:
            if operation == "set":
                self._append_unique(interface.manager_ips, " ".join(tokens[4:]))
            else:
                interface.manager_ips = [item for item in interface.manager_ips if item != " ".join(tokens[4:])]
        elif command == "disable":
            interface.disabled = operation == "set"

    def _parse_manager_ip(self, tokens: list[str], operation: str) -> None:
        if len(tokens) < 4:
            if operation == "unset":
                self.manager_ips.clear()
            return
        value = " ".join(tokens[3:])
        if operation == "set":
            self._append_unique(self.manager_ips, value)
        else:
            self.manager_ips = [item for item in self.manager_ips if item != value]

    def _parse_user(
        self,
        tokens: list[str],
        lowered: list[str],
        raw_line: str,
        line_number: int,
    ) -> None:
        username = tokens[3]
        role = ""
        authentication = "unknown"
        if "privilege" in lowered and lowered.index("privilege") + 1 < len(tokens):
            role = tokens[lowered.index("privilege") + 1]
        if "password" in lowered:
            authentication = "password"
        self.users[username] = {
            "username": username,
            "role": role,
            "authentication": authentication,
            "evidence": [self._evidence(raw_line, line_number, redact=True)],
        }

    def _parse_policy_command(
        self,
        tokens: list[str],
        lowered: list[str],
        raw_line: str,
        line_number: int,
    ) -> Optional[str]:
        operation, policy_id = lowered[0], tokens[3]
        if operation == "unset" and len(tokens) == 4:
            self.policies.pop(policy_id, None)
            return None
        policy = self._policy(policy_id)
        policy.evidence.append(self._evidence(raw_line, line_number))
        remainder = lowered[4:]
        if operation == "unset" and remainder == ["disable"]:
            policy.disabled = False
            return policy_id
        if operation == "set" and remainder == ["disable"]:
            policy.disabled = True
            return policy_id
        if operation == "set" and "from" in remainder and "to" in remainder:
            from_index = lowered.index("from")
            to_index = lowered.index("to", from_index + 1)
            if to_index + 4 >= len(tokens):
                self.diagnostics.append(f"line {line_number}: incomplete policy declaration")
                return policy_id
            policy.from_zone = tokens[from_index + 1]
            policy.to_zone = tokens[to_index + 1]
            policy.sources = [tokens[to_index + 2]]
            policy.destinations = [tokens[to_index + 3]]
            policy.services = [tokens[to_index + 4]]
            if to_index + 5 < len(tokens):
                policy.action = lowered[to_index + 5]
            if "log" in lowered[to_index + 6:]:
                policy.tracking = "log"
        return policy_id

    def _parse_policy_continuation(
        self,
        policy: ScreenOSPolicy,
        tokens: list[str],
        lowered: list[str],
        raw_line: str,
        line_number: int,
    ) -> None:
        if len(tokens) < 2:
            return
        operation, command = lowered[0], lowered[1]
        policy.evidence.append(self._evidence(raw_line, line_number))
        target = {
            "src-address": policy.sources,
            "dst-address": policy.destinations,
            "service": policy.services,
        }.get(command)
        if target is not None and len(tokens) >= 3:
            value = tokens[2]
            if operation == "set":
                self._append_unique(target, value)
            else:
                target[:] = [item for item in target if item != value]
        elif command == "action" and len(tokens) >= 3:
            policy.action = lowered[2] if operation == "set" else ""
        elif command == "disable":
            policy.disabled = operation == "set"
        elif command == "log":
            policy.tracking = " ".join(tokens[1:]) if operation == "set" else ""

    def _effective_native_lines(self) -> list[str]:
        lines = []
        for method in sorted(self.global_management):
            original = "web" if method == "http" else method
            lines.append(f"set admin {original} enable")
        for interface in self.interfaces.values():
            for method in sorted(interface.management_methods):
                original = "web" if method == "http" else method
                lines.append(f'set interface "{interface.name}" manage {original}')
        for policy in self.policies.values():
            if policy.disabled:
                continue
            source = policy.sources[0] if policy.sources else ""
            destination = policy.destinations[0] if policy.destinations else ""
            service = policy.services[0] if policy.services else ""
            lines.append(
                (
                    f'set policy id {policy.policy_id} from "{policy.from_zone}" '
                    f'to "{policy.to_zone}" "{source}" "{destination}" '
                    f'"{service}" {policy.action}'
                ).strip()
            )
        return lines

    def get_hostname(self) -> str:
        return self.hostname or "juniper-device"

    def get_version(self) -> str:
        return self.version or "?"

    def get_users(self) -> list[dict]:
        return list(self.users.values())

    def get_services(self) -> dict:
        enabled = set(self.global_management)
        for interface in self.interfaces.values():
            if not interface.disabled:
                enabled.update(interface.management_methods)
        ssl_enabled = bool(self.get_effective_commands(("ssl", "enable")))
        return {
            "telnet": "telnet" in enabled,
            "ssh": "ssh" in enabled,
            "http": "http" in enabled,
            "https": "https" in enabled and ssl_enabled,
        }

    def get_native_config(self) -> list[str]:
        return self.config

    def get_logging_destinations(self) -> list[LoggingDestination]:
        enabled = bool(self.get_effective_commands(("syslog", "enable")))
        destinations = []
        for command in self.get_effective_commands(("syslog", "config")):
            if len(command.tokens) < 3:
                continue
            destinations.append(
                LoggingDestination(
                    destination_type="syslog",
                    state=(
                        ConfigurationState.ENABLED
                        if enabled
                        else ConfigurationState.DISABLED
                    ),
                    address=command.tokens[2],
                    evidence=(command.evidence,),
                )
            )
        return destinations

    def get_crypto_settings(self) -> list[CryptoSetting]:
        settings = []
        for command in self.effective_commands:
            tokens = command.tokens
            if tokens[:2] == ("ssl", "encrypt") and len(tokens) > 2:
                name, values = "ssl/encrypt", tokens[2:]
            elif tokens[:2] == ("ike", "p1-proposal") and len(tokens) > 3:
                name, values = f"ike/p1-proposal/{tokens[2]}", tokens[3:]
            elif tokens[:2] == ("ike", "p2-proposal") and len(tokens) > 3:
                name, values = f"ike/p2-proposal/{tokens[2]}", tokens[3:]
            else:
                continue
            settings.append(
                CryptoSetting(
                    name=name,
                    value=" ".join(values),
                    state=ConfigurationState.CONFIGURED,
                    evidence=(command.evidence,),
                )
            )
        return settings

    def get_normalized_config(self) -> NormalizedConfig:
        management = []
        for method in sorted(self.global_management):
            management.append(
                ManagementService(
                    method,
                    ConfigurationState.ENABLED,
                    scope="global",
                    permitted_sources=tuple(self.manager_ips),
                    evidence=(self.global_management_evidence[method],),
                )
            )
        for interface in self.interfaces.values():
            if interface.disabled:
                continue
            for method in sorted(interface.management_methods):
                if method == "https" and not self.get_effective_commands(
                    ("ssl", "enable")
                ):
                    continue
                management.append(
                    ManagementService(
                        method,
                        ConfigurationState.ENABLED,
                        interface=interface.name,
                        zone=interface.zone or None,
                        permitted_sources=tuple(interface.manager_ips or self.manager_ips),
                        evidence=tuple(interface.evidence),
                    )
                )
        normalized_users = [
            LocalUser(
                username=user["username"],
                state=ConfigurationState.CONFIGURED,
                role=user["role"] or None,
                authentication=user["authentication"],
                evidence=tuple(user["evidence"]),
            )
            for user in self.users.values()
        ]
        normalized_interfaces = [
            NetworkInterface(
                name=interface.name,
                state=ConfigurationState.DISABLED if interface.disabled else ConfigurationState.ENABLED,
                zone=interface.zone or None,
                addresses=tuple(interface.addresses),
                evidence=tuple(interface.evidence),
            )
            for interface in self.interfaces.values()
        ]
        normalized_policies = [
            SecurityPolicy(
                name=policy.policy_id,
                state=ConfigurationState.DISABLED if policy.disabled else ConfigurationState.ENABLED,
                action=policy.action or "unknown",
                position=policy.position,
                scope=f"{policy.from_zone}->{policy.to_zone}",
                source_interfaces=(policy.from_zone,) if policy.from_zone else (),
                destination_interfaces=(policy.to_zone,) if policy.to_zone else (),
                sources=tuple(policy.sources),
                destinations=tuple(policy.destinations),
                services=tuple(policy.services),
                tracking=policy.tracking or None,
                evidence=tuple(policy.evidence),
            )
            for policy in self.policies.values()
        ]
        return NormalizedConfig(
            device_type=self.device_type,
            hostname=(
                NormalizedValue.known(self.hostname)
                if self.hostname
                else NormalizedValue.unknown("ScreenOS hostname is not present")
            ),
            device_model=(
                NormalizedValue.known(self.model)
                if self.model
                else NormalizedValue.unknown("ScreenOS model metadata is not present")
            ),
            software_version=(
                NormalizedValue.known(self.version)
                if self.version
                else NormalizedValue.unknown("ScreenOS version metadata is not present")
            ),
            management_services=NormalizedCollection.known(*management),
            users=NormalizedCollection.known(*normalized_users),
            interfaces=NormalizedCollection.known(*normalized_interfaces),
            policies=NormalizedCollection.known(*normalized_policies),
            logging_destinations=NormalizedCollection.known(
                *self.get_logging_destinations()
            ),
            crypto_settings=NormalizedCollection.known(*self.get_crypto_settings()),
        )
