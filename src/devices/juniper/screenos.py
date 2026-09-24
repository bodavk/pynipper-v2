import ipaddress
import re
import shlex
from dataclasses import dataclass, field
from typing import Optional

from src.devices.common.base_parser import BaseDeviceParser
from src.devices.common.source_lines import group_double_quoted_lines, single_line_evidence
from src.devices.common.models import (
    BlocklistCredentialAssessment,
    ConfigEvidence,
    ConfigurationState,
    CredentialMetadata,
    CredentialStorageAssessment,
    CryptoSetting,
    DefaultCredentialAssessment,
    LocalUser,
    LoggingDestination,
    ManagementService,
    NetworkInterface,
    NormalizedCollection,
    NormalizedConfig,
    NormalizedValue,
    SecurityPolicy,
)
from src.devices.common.policy_semantics import (
    AddressInterval,
    NetworkSemantics,
    ServiceInterval,
    ServiceSemantics,
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
    auth_server: str = ""
    auth_server_evidence: Optional[ConfigEvidence] = None
    unsupported_predicates: list[str] = field(default_factory=list)
    evidence: list[ConfigEvidence] = field(default_factory=list)


@dataclass(frozen=True)
class ScreenOSObject:
    name: str
    scope: str
    value: str
    evidence: ConfigEvidence


@dataclass(frozen=True)
class ScreenOSPolicySemantics:
    policy_id: str
    position: int
    from_zone: str
    to_zone: str
    enabled: bool
    action: str
    source_networks: NetworkSemantics
    destination_networks: NetworkSemantics
    services: ServiceSemantics
    unsupported_predicates: tuple[str, ...]
    behavior_signature: tuple[str, ...]
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class ScreenOSCommand:
    tokens: tuple[str, ...]
    evidence: ConfigEvidence


@dataclass(frozen=True)
class ScreenOSFirewallPolicyState:
    """ScreenOS 6.3 unmatched interzone-policy behavior."""

    default_action: str
    configured_policy_count: int
    resolution_state: str
    evidence: tuple[ConfigEvidence, ...] = ()


@dataclass(frozen=True)
class ScreenOSSessionControl:
    """One effective administrative or authentication-user timeout."""

    scope: str
    name: str
    uses: tuple[str, ...]
    timeout_minutes: Optional[int]
    value_source: str
    resolution_state: str
    active: bool
    evidence: tuple[ConfigEvidence, ...] = ()


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
    _KNOWN_DEFAULT_PASSWORD_HASHES = {
        value.casefold()
        for value in {
            "nBh1JgrWI8BMcxVE1sfD3ZHtPvNqOn",
            "nIEXLGrQKPGFclpK2srC+GItLBIaYn",
            "nEgTC0rULyNDcfOHZsFDJSAtfiPqWn",
            "nJBnMRrmG7cFc3ALdsWMLIKtWHC4ln",
            "nL1kB1ryFpdIcuHBksgKNQLttDFjCn",
            "nA0XKervNIgBctzLBsjNKyEtOcM5an",
            "nFR1M7r3PBEHcA0FWs1JJ8LtBTOHIn",
            "nDQFBzrfECTDcLFD7sRA2kMtP4FNwn",
            "nH/vDirbE5GBcjdGoslAEBBtHFA6En",
            "nMjFM0rdC9iOc+xIFsGEm3LtAeGZhn",
            "nO8gOKrtJ/YMclhNlsoJCrCtllAL7n",
            "nDC0GjreNnlGcIPHTsGOUAFt6BJZdn",
            "nKv3LvrdAVtOcE5EcsGIpYBtniNbUn",
            "nKVUM2rwMUzPcrkG5sWIHdCtqkAibn",
        }
    }
    _KNOWN_DEFAULT_PASSWORDS = {"password", "netscreen", "admin", "administrator"}

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
        self.address_groups: dict[tuple[str, str], list[str]] = {}
        self.service_objects: dict[str, ScreenOSObject] = {}
        self.service_groups: dict[str, list[str]] = {}
        self.users: dict[str, dict] = {}
        self.global_management: set[str] = set()
        self.global_management_evidence: dict[str, ConfigEvidence] = {}
        self.manager_ips: list[str] = []
        self.effective_commands: list[ScreenOSCommand] = []
        self._statement_end_lines: dict[int, int] = {}
        self._parse()
        self.config = self._effective_native_lines()

    def _evidence(self, text: str, line_number: int, redact: bool = False) -> ConfigEvidence:
        evidence_text = text
        if redact:
            evidence_text = re.sub(
                r'''(?i)(password|secret|key|community)\s+(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\S+)''',
                r"\1 <redacted>",
                evidence_text,
            )
        evidence_text = single_line_evidence(
            evidence_text, self._statement_end_lines.get(line_number)
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

    def is_screenos_63(self) -> bool:
        """Return true only for the release family qualified by recovered manuals."""

        return bool(re.search(r"(?:^|\D)6\.3(?:\.0)?(?:r\d+)?(?:\D|$)", self.version, re.I))

    @staticmethod
    def _timeout_value(command: Optional[ScreenOSCommand]) -> Optional[int]:
        if command is None or not command.tokens:
            return None
        value = command.tokens[-1]
        return int(value) if value.isdigit() else None

    def get_firewall_policy_state(self) -> ScreenOSFirewallPolicyState:
        """Resolve only the documented ScreenOS 6.3 unmatched-policy default."""

        if not self.is_screenos_63():
            return ScreenOSFirewallPolicyState(
                default_action="unknown",
                configured_policy_count=len(self.policies),
                resolution_state="unsupported-release",
            )
        commands = self.get_effective_commands(("policy", "default-permit-all"))
        if commands:
            return ScreenOSFirewallPolicyState(
                default_action="permit-all",
                configured_policy_count=len(
                    [policy for policy in self.policies.values() if not policy.disabled]
                ),
                resolution_state="explicit",
                evidence=(commands[-1].evidence,),
            )
        return ScreenOSFirewallPolicyState(
            default_action="deny-all",
            configured_policy_count=len(
                [policy for policy in self.policies.values() if not policy.disabled]
            ),
            resolution_state="documented-default",
        )

    def get_session_controls(self) -> tuple[ScreenOSSessionControl, ...]:
        """Resolve ScreenOS 6.3 timeout domains and active AAA bindings."""

        if not self.is_screenos_63():
            return ()

        controls: list[ScreenOSSessionControl] = []
        console_commands = self.get_effective_commands(("console", "timeout"))
        console_command = console_commands[-1] if console_commands else None
        console_disabled = bool(self.get_effective_commands(("console", "disable")))
        controls.append(
            ScreenOSSessionControl(
                scope="console-telnet",
                name="console/Telnet",
                uses=("console", "telnet"),
                timeout_minutes=(
                    self._timeout_value(console_command)
                    if console_command is not None
                    else 10
                ),
                value_source="explicit" if console_command else "documented-default",
                resolution_state=(
                    "known"
                    if console_command is None or self._timeout_value(console_command) is not None
                    else "invalid"
                ),
                active=not console_disabled or self.get_services()["telnet"],
                evidence=(console_command.evidence,) if console_command else (),
            )
        )

        web_commands = self.get_effective_commands(("admin", "auth", "web", "timeout"))
        value_source = "explicit"
        if not web_commands:
            # Older exported configurations use the spelling corrected by the 6.3
            # release-note erratum. Preserve it as an explicit legacy alias.
            web_commands = self.get_effective_commands(("admin", "auth", "timeout"))
            value_source = "explicit-legacy-alias" if web_commands else "documented-default"
        web_command = web_commands[-1] if web_commands else None
        controls.append(
            ScreenOSSessionControl(
                scope="web-management",
                name="Web administration",
                uses=("http", "https"),
                timeout_minutes=(
                    self._timeout_value(web_command) if web_command is not None else 10
                ),
                value_source=value_source,
                resolution_state=(
                    "known"
                    if web_command is None or self._timeout_value(web_command) is not None
                    else "invalid"
                ),
                active=self.get_services()["http"] or self.get_services()["https"],
                evidence=(web_command.evidence,) if web_command else (),
            )
        )

        bindings: dict[str, set[str]] = {}
        binding_evidence: dict[str, list[ConfigEvidence]] = {}

        def bind(name: str, use: str, evidence: ConfigEvidence) -> None:
            normalized = name.casefold()
            bindings.setdefault(normalized, set()).add(use)
            binding_evidence.setdefault(normalized, []).append(evidence)

        admin_bindings = self.get_effective_commands(("admin", "auth", "server"))
        if admin_bindings and len(admin_bindings[-1].tokens) > 3:
            bind(
                admin_bindings[-1].tokens[3],
                "administrator",
                admin_bindings[-1].evidence,
            )
        user_bindings = self.get_effective_commands(("auth", "default", "auth", "server"))
        if user_bindings and len(user_bindings[-1].tokens) > 4:
            bind(
                user_bindings[-1].tokens[4],
                "authentication-user",
                user_bindings[-1].evidence,
            )

        for policy in self.policies.values():
            if (
                policy.auth_server
                and policy.auth_server_evidence is not None
                and not policy.disabled
            ):
                bind(
                    policy.auth_server,
                    f"policy:{policy.policy_id}",
                    policy.auth_server_evidence,
                )

        for command in self.effective_commands:
            tokens = command.tokens
            if tokens[:1] == ("interface",) and "dot1x" in tokens and "auth-server" in tokens:
                server_index = tokens.index("auth-server")
                if server_index + 1 < len(tokens):
                    bind(
                        tokens[server_index + 1],
                        f"dot1x:{tokens[1]}",
                        command.evidence,
                    )

        server_names = {
            command.tokens[1]
            for command in self.effective_commands
            if command.tokens[:1] == ("auth-server",)
            and len(command.tokens) > 2
            and command.tokens[1] != "forced-timeout"
        }
        server_names.update(bindings)
        for server_name in sorted(server_names):
            commands = [
                command
                for command in self.effective_commands
                if command.tokens[:2] == ("auth-server", server_name)
            ]
            timeout_commands = [
                command
                for command in commands
                if len(command.tokens) > 3 and command.tokens[2] == "timeout"
            ]
            timeout_command = timeout_commands[-1] if timeout_commands else None
            known_definition = bool(commands) or server_name == "local"
            timeout = (
                self._timeout_value(timeout_command)
                if timeout_command is not None
                else (10 if known_definition else None)
            )
            evidence = list(binding_evidence.get(server_name, ()))
            if timeout_command:
                evidence.append(timeout_command.evidence)
            controls.append(
                ScreenOSSessionControl(
                    scope="authentication-server",
                    name=server_name,
                    uses=tuple(sorted(bindings.get(server_name, ()))),
                    timeout_minutes=timeout,
                    value_source="explicit" if timeout_command else "documented-default",
                    resolution_state=(
                        "unresolved"
                        if not known_definition
                        else (
                            "known"
                            if timeout_command is None
                            or self._timeout_value(timeout_command) is not None
                            else "invalid"
                        )
                    ),
                    active=server_name in bindings,
                    evidence=tuple(evidence),
                )
            )
        return tuple(controls)

    def _parse(self) -> None:
        policy_context: Optional[str] = None
        # A quoted value (for example banner text) may span several physical
        # lines; its body must not be read as separate set/unset commands.
        grouping = group_double_quoted_lines(self.raw_lines, comment_prefixes=("#",))
        if grouping.unterminated_line is not None:
            self.diagnostics.append(
                f"line {grouping.unterminated_line}: quoted value is not closed before end of file"
            )
        for statement in grouping.lines:
            line_number = statement.start_line
            if statement.is_multiline:
                self._statement_end_lines[line_number] = statement.end_line
            stripped = statement.text.strip()
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
            if len(tokens) >= 4 and lowered[1:3] == ["admin", "user"]:
                if operation == "unset" and len(tokens) == 4:
                    self.users.pop(tokens[3], None)
                elif operation == "set":
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

            if len(tokens) >= 5 and lowered[1:3] == ["group", "address"]:
                key = (tokens[3], tokens[4])
                if operation == "unset" and len(tokens) == 5:
                    self.address_groups.pop(key, None)
                elif len(tokens) >= 7 and lowered[5] in {"add", "remove"}:
                    members = self.address_groups.setdefault(key, [])
                    if operation == "set" and lowered[5] == "add":
                        self._append_unique(members, tokens[6])
                    else:
                        members[:] = [item for item in members if item != tokens[6]]
                continue
            if len(tokens) >= 4 and lowered[1:3] == ["group", "service"]:
                name = tokens[3]
                if operation == "unset" and len(tokens) == 4:
                    self.service_groups.pop(name, None)
                elif len(tokens) >= 6 and lowered[4] in {"add", "remove"}:
                    members = self.service_groups.setdefault(name, [])
                    if operation == "set" and lowered[4] == "add":
                        self._append_unique(members, tokens[5])
                    else:
                        members[:] = [item for item in members if item != tokens[5]]
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
        if remainder[:2] == ["auth", "server"]:
            if operation == "set" and len(tokens) >= 7:
                policy.auth_server = tokens[6]
                self._append_unique(policy.unsupported_predicates, "authentication")
                policy.auth_server_evidence = self._evidence(
                    raw_line, line_number, redact=True
                )
            elif operation == "unset":
                policy.auth_server = ""
                policy.unsupported_predicates = [
                    item for item in policy.unsupported_predicates
                    if item != "authentication"
                ]
                policy.auth_server_evidence = None
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
            tail = lowered[to_index + 6:]
            consumed: set[int] = set()
            for index in range(to_index + 6, len(lowered) - 2):
                if lowered[index : index + 2] == ["auth", "server"]:
                    policy.auth_server = tokens[index + 2]
                    self._append_unique(policy.unsupported_predicates, "authentication")
                    consumed.update({index - (to_index + 6), index + 1 - (to_index + 6), index + 2 - (to_index + 6)})
                    policy.auth_server_evidence = self._evidence(
                        raw_line, line_number, redact=True
                    )
                    break
            for index, token in enumerate(tail):
                if index not in consumed and token != "log":
                    self._append_unique(policy.unsupported_predicates, token)
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
        elif command == "auth" and len(tokens) >= 4 and lowered[2] == "server":
            policy.auth_server = tokens[3] if operation == "set" else ""
            if operation == "set":
                self._append_unique(policy.unsupported_predicates, "authentication")
            else:
                policy.unsupported_predicates = [
                    item for item in policy.unsupported_predicates
                    if item != "authentication"
                ]
            policy.auth_server_evidence = (
                self._evidence(raw_line, line_number, redact=True)
                if operation == "set"
                else None
            )
        else:
            if operation == "set":
                self._append_unique(policy.unsupported_predicates, command)
            else:
                policy.unsupported_predicates = [
                    item for item in policy.unsupported_predicates if item != command
                ]

    @staticmethod
    def _screenos_network_interval(value: str) -> AddressInterval | None:
        parts = value.split()
        try:
            if len(parts) == 1:
                network = ipaddress.ip_network(parts[0], strict=False)
            elif len(parts) == 2:
                network = ipaddress.ip_network(f"{parts[0]}/{parts[1]}", strict=False)
            else:
                return None
        except ValueError:
            return None
        return AddressInterval(
            network.version,
            int(network.network_address),
            int(network.broadcast_address),
        )

    @staticmethod
    def _screenos_port_range(value: str) -> tuple[int, int] | None:
        parts = value.split("-", 1)
        if not all(item.isdigit() for item in parts):
            return None
        first, last = int(parts[0]), int(parts[-1])
        if not 0 <= first <= last <= 65535:
            return None
        return first, last

    def get_policy_semantics(self) -> tuple[ScreenOSPolicySemantics, ...]:
        """Adapt ordered ScreenOS policies without inferring unresolved objects."""

        policy_order_unknown = any(
            command.tokens[:2] in {("policy", "global"), ("policy", "move")}
            for command in self.effective_commands
        )

        def matching_key(mapping: dict, requested: tuple[str, str]):
            if requested in mapping:
                return requested
            folded = tuple(item.casefold() for item in requested)
            return next(
                (
                    key for key in mapping
                    if tuple(str(item).casefold() for item in key) == folded
                ),
                None,
            )

        def address_member(
            name: str,
            zone: str,
            definition_zone: str | None,
            seen: frozenset[tuple[str, str]],
            budget: list[int],
        ) -> NetworkSemantics:
            if name.casefold() == "any":
                return NetworkSemantics(any=True)
            literal = self._screenos_network_interval(name)
            if literal is not None:
                return NetworkSemantics(intervals=(literal,))
            candidates = (
                (definition_zone, "Global")
                if definition_zone and definition_zone.casefold() != "global"
                else (definition_zone,)
                if definition_zone
                else (zone, "Global")
            )
            for candidate in dict.fromkeys(candidates):
                if candidate is None:
                    continue
                requested = (candidate, name)
                object_key = matching_key(self.address_objects, requested)
                group_key = matching_key(self.address_groups, requested)
                key = object_key or group_key or requested
                if key in seen or budget[0] <= 0:
                    return NetworkSemantics(complete=False, unresolved=(name,))
                if object_key is not None:
                    interval = self._screenos_network_interval(
                        self.address_objects[object_key].value
                    )
                    if interval is None:
                        return NetworkSemantics(complete=False, unresolved=(name,))
                    budget[0] -= 1
                    return NetworkSemantics(intervals=(interval,))
                if group_key is not None:
                    members = self.address_groups[group_key]
                    if not members:
                        return NetworkSemantics(complete=False, unresolved=(name,))
                    budget[0] -= 1
                    intervals: list[AddressInterval] = []
                    unresolved: list[str] = []
                    for member_name in members:
                        member = address_member(
                            member_name,
                            zone,
                            group_key[0],
                            seen | {key},
                            budget,
                        )
                        if member.any:
                            return NetworkSemantics(any=True)
                        intervals.extend(member.intervals)
                        unresolved.extend(member.unresolved)
                    if unresolved or not intervals:
                        return NetworkSemantics(
                            intervals=tuple(sorted(set(intervals))),
                            complete=False,
                            unresolved=tuple(dict.fromkeys(unresolved or members)),
                        )
                    return NetworkSemantics(intervals=tuple(sorted(set(intervals))))
            return NetworkSemantics(complete=False, unresolved=(name,))

        def networks(values: list[str], zone: str) -> NetworkSemantics:
            if not values:
                return NetworkSemantics(complete=False, unresolved=("missing",))
            intervals: list[AddressInterval] = []
            unresolved: list[str] = []
            budget = [4096]
            for value in values:
                member = address_member(value, zone, None, frozenset(), budget)
                if member.any:
                    return NetworkSemantics(any=True)
                intervals.extend(member.intervals)
                unresolved.extend(member.unresolved)
            if unresolved or not intervals:
                return NetworkSemantics(
                    intervals=tuple(sorted(set(intervals))),
                    complete=False,
                    unresolved=tuple(dict.fromkeys(unresolved or values)),
                )
            return NetworkSemantics(intervals=tuple(sorted(set(intervals))))

        builtins = {
            "dns": (("tcp", 53, 53), ("udp", 53, 53)),
            "ftp": (("tcp", 21, 21),),
            "http": (("tcp", 80, 80),),
            "https": (("tcp", 443, 443),),
            "icmp-any": (("icmp", 0, 65535),),
            "ping": (("icmp", 0, 65535),),
            "ssh": (("tcp", 22, 22),),
            "telnet": (("tcp", 23, 23),),
        }

        def service_member(
            name: str,
            seen: frozenset[str],
            budget: list[int],
        ) -> ServiceSemantics:
            lowered = name.casefold()
            if lowered in {"any", "all"}:
                return ServiceSemantics(any=True)
            if lowered in builtins:
                return ServiceSemantics(intervals=tuple(
                    ServiceInterval(*item) for item in builtins[lowered]
                ))
            if lowered in seen or budget[0] <= 0:
                return ServiceSemantics(complete=False, unresolved=(name,))
            object_name = next(
                (value for value in self.service_objects if value.casefold() == lowered),
                None,
            )
            group_name = next(
                (value for value in self.service_groups if value.casefold() == lowered),
                None,
            )
            budget[0] -= 1
            if object_name is not None:
                try:
                    tokens = shlex.split(
                        self.service_objects[object_name].value,
                        comments=False,
                        posix=True,
                    )
                except ValueError:
                    return ServiceSemantics(complete=False, unresolved=(name,))
                lowered_tokens = [value.casefold() for value in tokens]
                if "protocol" not in lowered_tokens:
                    return ServiceSemantics(complete=False, unresolved=(name,))
                protocol_index = lowered_tokens.index("protocol")
                if protocol_index + 1 >= len(tokens):
                    return ServiceSemantics(complete=False, unresolved=(name,))
                protocol = lowered_tokens[protocol_index + 1]
                protocol = {"6": "tcp", "17": "udp", "1": "icmp"}.get(
                    protocol, protocol
                )
                allowed_indexes = {protocol_index, protocol_index + 1}
                source_range = None
                destination_range = None
                for field in ("src-port", "dst-port"):
                    if field not in lowered_tokens:
                        continue
                    index = lowered_tokens.index(field)
                    if index + 1 >= len(tokens):
                        return ServiceSemantics(complete=False, unresolved=(name,))
                    parsed = self._screenos_port_range(tokens[index + 1])
                    if parsed is None:
                        return ServiceSemantics(complete=False, unresolved=(name,))
                    allowed_indexes.update({index, index + 1})
                    if field == "src-port":
                        source_range = parsed
                    else:
                        destination_range = parsed
                if len(allowed_indexes) != len(tokens):
                    return ServiceSemantics(complete=False, unresolved=(name,))
                if source_range not in {None, (0, 65535), (1, 65535)}:
                    return ServiceSemantics(complete=False, unresolved=(name,))
                if protocol in {"tcp", "udp"}:
                    if destination_range is None:
                        return ServiceSemantics(complete=False, unresolved=(name,))
                    return ServiceSemantics(intervals=(ServiceInterval(
                        protocol, destination_range[0], destination_range[1]
                    ),))
                if destination_range is not None:
                    return ServiceSemantics(complete=False, unresolved=(name,))
                return ServiceSemantics(
                    intervals=(ServiceInterval(protocol, 0, 65535),)
                )
            if group_name is not None:
                members = self.service_groups[group_name]
                if not members:
                    return ServiceSemantics(complete=False, unresolved=(name,))
                intervals: list[ServiceInterval] = []
                unresolved: list[str] = []
                for member_name in members:
                    member = service_member(member_name, seen | {lowered}, budget)
                    if member.any:
                        return ServiceSemantics(any=True)
                    intervals.extend(member.intervals)
                    unresolved.extend(member.unresolved)
                if unresolved or not intervals:
                    return ServiceSemantics(
                        intervals=tuple(sorted(set(intervals))),
                        complete=False,
                        unresolved=tuple(dict.fromkeys(unresolved or members)),
                    )
                return ServiceSemantics(intervals=tuple(sorted(set(intervals))))
            return ServiceSemantics(complete=False, unresolved=(name,))

        def services(values: list[str]) -> ServiceSemantics:
            if not values:
                return ServiceSemantics(complete=False, unresolved=("missing",))
            intervals: list[ServiceInterval] = []
            unresolved: list[str] = []
            budget = [4096]
            for value in values:
                member = service_member(value, frozenset(), budget)
                if member.any:
                    return ServiceSemantics(any=True)
                intervals.extend(member.intervals)
                unresolved.extend(member.unresolved)
            if unresolved or not intervals:
                return ServiceSemantics(
                    intervals=tuple(sorted(set(intervals))),
                    complete=False,
                    unresolved=tuple(dict.fromkeys(unresolved or values)),
                )
            return ServiceSemantics(intervals=tuple(sorted(set(intervals))))

        records = []
        for policy in self.policies.values():
            action = policy.action.casefold()
            if action == "accept":
                action = "permit"
            unsupported = list(policy.unsupported_predicates)
            if policy_order_unknown:
                self._append_unique(unsupported, "unmodeled-policy-order")
            records.append(ScreenOSPolicySemantics(
                policy_id=policy.policy_id,
                position=policy.position,
                from_zone=policy.from_zone,
                to_zone=policy.to_zone,
                enabled=not policy.disabled,
                action=action,
                source_networks=networks(policy.sources, policy.from_zone),
                destination_networks=networks(policy.destinations, policy.to_zone),
                services=services(policy.services),
                unsupported_predicates=tuple(unsupported),
                behavior_signature=(
                    action,
                    policy.tracking.casefold(),
                    policy.auth_server.casefold(),
                ),
                evidence=tuple(policy.evidence),
            ))
        return tuple(records)

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

    def get_credential_metadata(self) -> list[CredentialMetadata]:
        """Classify only ScreenOS properties proven by the legacy export."""

        primary_name = "primary admin"
        for command in self.get_effective_commands(("admin", "name")):
            if len(command.tokens) > 2:
                primary_name = command.tokens[2]

        credentials: dict[str, CredentialMetadata] = {}
        for command in self.effective_commands:
            tokens = command.tokens
            if tokens[:2] == ("admin", "password"):
                account = primary_name
                value = tokens[2] if len(tokens) > 2 else ""
            elif tokens[:2] == ("admin", "user") and "password" in tokens:
                account = tokens[2] if len(tokens) > 2 else "unknown"
                index = tokens.index("password")
                value = tokens[index + 1] if index + 1 < len(tokens) else ""
            else:
                continue

            if not value:
                storage = CredentialStorageAssessment.EMPTY
                default = DefaultCredentialAssessment.MATCH
                storage_type = "empty"
            elif value in self._KNOWN_DEFAULT_PASSWORDS:
                storage = CredentialStorageAssessment.PLAINTEXT
                default = DefaultCredentialAssessment.MATCH
                storage_type = "plaintext-known-default"
            else:
                storage = CredentialStorageAssessment.UNKNOWN
                default = (
                    DefaultCredentialAssessment.MATCH
                    if value in self._KNOWN_DEFAULT_PASSWORD_HASHES
                    else DefaultCredentialAssessment.NO_MATCH
                )
                storage_type = "screenos-opaque"
            credentials[account.casefold()] = CredentialMetadata(
                account=account,
                context="local_user" if tokens[:2] == ("admin", "user") else "primary_admin",
                method="password",
                storage_type=storage_type,
                storage_assessment=storage,
                default_assessment=default,
                plaintext_length=(
                    len(value)
                    if storage == CredentialStorageAssessment.PLAINTEXT
                    else None
                ),
                blocklist_assessment=BlocklistCredentialAssessment.from_optional_match(
                    self.assessment_context.plaintext_credential_blocklisted(value)
                    if storage == CredentialStorageAssessment.PLAINTEXT
                    else None
                ),
                evidence=(command.evidence,),
            )
        return list(credentials.values())

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
