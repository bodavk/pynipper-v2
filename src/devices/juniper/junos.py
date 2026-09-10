import re
import shlex
from dataclasses import dataclass
from typing import Optional

from src.devices.common.base_parser import BaseDeviceParser
from src.devices.common.models import (
    ConfigEvidence,
    ConfigurationState,
    LocalUser,
    ManagementService,
    NetworkInterface,
    NormalizedCollection,
    NormalizedConfig,
    NormalizedValue,
    SecurityPolicy,
)


@dataclass(frozen=True)
class JunosStatement:
    path: tuple[str, ...]
    active: bool
    evidence: ConfigEvidence

    @property
    def set_line(self) -> str:
        return "set " + " ".join(self.path)


@dataclass(frozen=True)
class JunosFirewallTerm:
    family: str
    filter_name: str
    term_name: str
    position: int
    active: bool
    sources: tuple[str, ...]
    destinations: tuple[str, ...]
    protocols: tuple[str, ...]
    actions: tuple[str, ...]
    attachments: tuple[str, ...]
    evidence: tuple[ConfigEvidence, ...]


class JunosParseError(ValueError):
    pass


class JunOSParser(BaseDeviceParser):

    device_type = "JUNOS"

    def __init__(self, config_filepath: str):
        super().__init__(config_filepath)
        with open(config_filepath, "r", encoding="utf-8") as config_file:
            self.raw_text = config_file.read()
        self.raw_lines = self.raw_text.splitlines()
        self.diagnostics: list[str] = []
        self.parse_error = ""
        self.format = self._detect_format()
        try:
            if self.format == "set":
                self.statements = self._parse_set_configuration()
            else:
                self.statements = self._parse_hierarchical_configuration()
        except JunosParseError as error:
            self.parse_error = str(error)
            self.diagnostics.append(self.parse_error)
            self.statements = []
        if any("apply-groups" in statement.path for statement in self.statements):
            self.diagnostics.append(
                "apply-groups is preserved but group inheritance is not expanded"
            )
        self.config = [statement.set_line for statement in self.statements if statement.active]

    def _detect_format(self) -> str:
        meaningful = [
            line.strip()
            for line in self.raw_lines
            if line.strip() and not line.lstrip().startswith(('#', '/*', '*'))
        ]
        if meaningful and all(
            line.split(maxsplit=1)[0] in {"set", "delete", "activate", "deactivate"}
            for line in meaningful
        ):
            return "set"
        return "hierarchical"

    def _evidence(self, text: str, line_number: int) -> ConfigEvidence:
        return ConfigEvidence(text=text, source=self.config_filepath, line_number=line_number)

    @staticmethod
    def _is_prefix(prefix: tuple[str, ...], path: tuple[str, ...]) -> bool:
        return len(path) >= len(prefix) and path[:len(prefix)] == prefix

    def _parse_set_configuration(self) -> list[JunosStatement]:
        statements: list[JunosStatement] = []
        deactivated: list[tuple[str, ...]] = []
        for line_number, raw_line in enumerate(self.raw_lines, 1):
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                tokens = shlex.split(stripped, comments=True, posix=True)
            except ValueError as error:
                raise JunosParseError(f"line {line_number}: {error}") from error
            if not tokens:
                continue
            operation, path = tokens[0], tuple(tokens[1:])
            if operation not in {"set", "delete", "activate", "deactivate"} or not path:
                raise JunosParseError(
                    f"line {line_number}: unsupported display-set operation"
                )
            if operation == "delete":
                statements = [
                    item for item in statements if not self._is_prefix(path, item.path)
                ]
                deactivated = [
                    prefix
                    for prefix in deactivated
                    if not self._is_prefix(path, prefix)
                ]
            elif operation == "deactivate":
                if path not in deactivated:
                    deactivated.append(path)
            elif operation == "activate":
                deactivated = [
                    prefix for prefix in deactivated if not self._is_prefix(path, prefix)
                ]
            else:
                statements = [item for item in statements if item.path != path]
                statements.append(
                    JunosStatement(path, True, self._evidence(stripped, line_number))
                )

        return [
            JunosStatement(
                item.path,
                not any(self._is_prefix(prefix, item.path) for prefix in deactivated),
                item.evidence,
            )
            for item in statements
        ]

    def _lex_hierarchy(self) -> list[tuple[str, int]]:
        tokens: list[tuple[str, int]] = []
        word = ""
        word_line = 1
        line = 1
        quote: Optional[str] = None
        escaped = False
        line_comment = False
        block_comment = False
        index = 0
        while index < len(self.raw_text):
            char = self.raw_text[index]
            following = self.raw_text[index + 1] if index + 1 < len(self.raw_text) else ""
            if line_comment:
                if char == "\n":
                    line_comment = False
                    line += 1
                index += 1
                continue
            if block_comment:
                if char == "*" and following == "/":
                    block_comment = False
                    index += 2
                    continue
                if char == "\n":
                    line += 1
                index += 1
                continue
            if quote:
                if escaped:
                    word += char
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                else:
                    word += char
                if char == "\n":
                    line += 1
                index += 1
                continue
            if char == "#":
                if word:
                    tokens.append((word, word_line))
                    word = ""
                line_comment = True
            elif char == "/" and following == "*":
                if word:
                    tokens.append((word, word_line))
                    word = ""
                block_comment = True
                index += 1
            elif char in {'"', "'"}:
                if not word:
                    word_line = line
                quote = char
            elif char in "{};[]":
                if word:
                    tokens.append((word, word_line))
                    word = ""
                tokens.append((char, line))
            elif char.isspace():
                if word:
                    tokens.append((word, word_line))
                    word = ""
                if char == "\n":
                    line += 1
            else:
                if not word:
                    word_line = line
                word += char
            index += 1
        if quote:
            raise JunosParseError(f"line {line}: unterminated quoted string")
        if block_comment:
            raise JunosParseError("unterminated block comment")
        if word:
            tokens.append((word, word_line))
        return tokens

    @staticmethod
    def _clean_segment(tokens: list[str]) -> tuple[tuple[str, ...], bool]:
        inactive = "inactive:" in tokens
        modifiers = {"inactive:", "replace:", "protect:"}
        return tuple(token for token in tokens if token not in modifiers), inactive

    def _parse_hierarchical_configuration(self) -> list[JunosStatement]:
        statements: list[JunosStatement] = []
        path: tuple[str, ...] = ()
        inherited_inactive = False
        stack: list[tuple[tuple[str, ...], bool]] = []
        pending: list[str] = []
        pending_line = 1
        bracket_depth = 0

        for token, line_number in self._lex_hierarchy():
            if not pending:
                pending_line = line_number
            if token == "[":
                bracket_depth += 1
                continue
            if token == "]":
                bracket_depth -= 1
                if bracket_depth < 0:
                    raise JunosParseError(f"line {line_number}: unmatched closing bracket")
                continue
            if bracket_depth and token not in {";", "{", "}"}:
                pending.append(token)
                continue
            if token == "{":
                segment, inactive = self._clean_segment(pending)
                if not segment:
                    raise JunosParseError(f"line {line_number}: block has no name")
                stack.append((path, inherited_inactive))
                path = path + segment
                inherited_inactive = inherited_inactive or inactive
                pending = []
            elif token == ";":
                segment, inactive = self._clean_segment(pending)
                if segment:
                    statement_path = path + segment
                    statements.append(
                        JunosStatement(
                            statement_path,
                            not (inherited_inactive or inactive),
                            self._evidence("set " + " ".join(statement_path), pending_line),
                        )
                    )
                pending = []
            elif token == "}":
                if pending:
                    raise JunosParseError(
                        f"line {line_number}: missing semicolon before closing brace"
                    )
                if not stack:
                    raise JunosParseError(f"line {line_number}: unmatched closing brace")
                path, inherited_inactive = stack.pop()
            else:
                pending.append(token)

        if stack:
            raise JunosParseError("unclosed hierarchical configuration block")
        if bracket_depth:
            raise JunosParseError("unclosed bracket list")
        if pending:
            raise JunosParseError("configuration statement is missing a semicolon")
        return statements

    def _active_paths(self) -> list[tuple[str, ...]]:
        return [statement.path for statement in self.statements if statement.active]

    def _first_value(self, prefix: tuple[str, ...]) -> Optional[JunosStatement]:
        for statement in reversed(self.statements):
            if statement.active and self._is_prefix(prefix, statement.path):
                return statement
        return None

    def get_hostname(self) -> str:
        statement = self._first_value(("system", "host-name"))
        if statement and len(statement.path) > 2:
            return statement.path[2]
        return "junos-device"

    def get_version(self) -> str:
        statement = self._first_value(("version",))
        if statement and len(statement.path) > 1:
            return statement.path[1]
        for raw_line in self.raw_lines:
            match = re.match(r"\s*##\s+JUNOS\s+(.+?)\s*$", raw_line, re.IGNORECASE)
            if match:
                return match.group(1)
        return "?"

    def get_model(self) -> str:
        for raw_line in self.raw_lines:
            match = re.match(r"\s*##\s+Model:\s*(.+?)\s*$", raw_line, re.IGNORECASE)
            if match:
                return match.group(1)
        return "?"

    def get_users(self) -> list[dict]:
        users: dict[str, dict] = {}
        for statement in self.statements:
            path = statement.path
            if not statement.active or path[:3] != ("system", "login", "user") or len(path) < 4:
                continue
            username = path[3]
            user = users.setdefault(
                username,
                {"username": username, "class": "", "authentication": "", "evidence": []},
            )
            user["evidence"].append(statement.evidence)
            if len(path) > 5 and path[4] == "class":
                user["class"] = path[5]
            if "authentication" in path:
                auth_index = path.index("authentication")
                if auth_index + 1 < len(path):
                    user["authentication"] = path[auth_index + 1]
        return list(users.values())

    def get_services(self) -> dict:
        paths = self._active_paths()
        return {
            "telnet": any(self._is_prefix(("system", "services", "telnet"), path) for path in paths),
            "ssh": any(self._is_prefix(("system", "services", "ssh"), path) for path in paths),
            "http": any(self._is_prefix(("system", "services", "web-management", "http"), path) for path in paths),
            "https": any(self._is_prefix(("system", "services", "web-management", "https"), path) for path in paths),
        }

    def get_ssh_root_login(self) -> tuple[str, tuple[ConfigEvidence, ...]]:
        selected: Optional[JunosStatement] = None
        prefix = ("system", "services", "ssh", "root-login")
        for statement in self.statements:
            if statement.active and self._is_prefix(prefix, statement.path) and len(statement.path) > 4:
                selected = statement
        if selected is None:
            return "", ()
        return selected.path[4], (selected.evidence,)

    def get_filter_terms(self) -> list[JunosFirewallTerm]:
        term_data: dict[tuple[str, str, str], dict] = {}
        filter_attachments: dict[str, list[str]] = {}
        for statement in self.statements:
            path = statement.path
            if statement.active and "filter" in path and path[:1] == ("interfaces",):
                filter_index = path.index("filter")
                if filter_index + 2 < len(path) and path[filter_index + 1] in {"input", "output"}:
                    filter_attachments.setdefault(path[filter_index + 2], []).append(
                        f"{path[1]}:{path[filter_index + 1]}"
                    )
            if not path or path[0] != "firewall" or "filter" not in path or "term" not in path:
                continue
            filter_index = path.index("filter")
            term_index = path.index("term", filter_index)
            if filter_index + 1 >= len(path) or term_index + 1 >= len(path):
                continue
            family = path[path.index("family") + 1] if "family" in path and path.index("family") < filter_index else "inet"
            key = (family, path[filter_index + 1], path[term_index + 1])
            data = term_data.setdefault(
                key,
                {
                    "position": len(term_data),
                    "active": False,
                    "sources": [],
                    "destinations": [],
                    "protocols": [],
                    "actions": [],
                    "evidence": [],
                },
            )
            data["active"] = data["active"] or statement.active
            data["evidence"].append(statement.evidence)
            suffix = path[term_index + 2:]
            for field, target in (
                ("source-address", "sources"),
                ("destination-address", "destinations"),
                ("protocol", "protocols"),
            ):
                if field in suffix and suffix.index(field) + 1 < len(suffix):
                    value = suffix[suffix.index(field) + 1]
                    if value not in data[target]:
                        data[target].append(value)
            if "then" in suffix:
                then_values = suffix[suffix.index("then") + 1:]
                for action in ("accept", "discard", "reject", "log", "syslog"):
                    if action in then_values and action not in data["actions"]:
                        data["actions"].append(action)

        return [
            JunosFirewallTerm(
                family=family,
                filter_name=filter_name,
                term_name=term_name,
                position=data["position"],
                active=data["active"],
                sources=tuple(data["sources"]),
                destinations=tuple(data["destinations"]),
                protocols=tuple(data["protocols"]),
                actions=tuple(data["actions"]),
                attachments=tuple(filter_attachments.get(filter_name, [])),
                evidence=tuple(data["evidence"]),
            )
            for (family, filter_name, term_name), data in term_data.items()
        ]

    def get_native_config(self) -> list[str]:
        return self.config

    def get_normalized_config(self) -> NormalizedConfig:
        if self.parse_error:
            return NormalizedConfig(
                device_type=self.device_type,
                hostname=NormalizedValue.parse_error(self.parse_error),
                device_model=NormalizedValue.parse_error(self.parse_error),
                software_version=NormalizedValue.parse_error(self.parse_error),
                management_services=NormalizedCollection.parse_error(self.parse_error),
                users=NormalizedCollection.parse_error(self.parse_error),
                interfaces=NormalizedCollection.parse_error(self.parse_error),
                policies=NormalizedCollection.parse_error(self.parse_error),
                logging_destinations=NormalizedCollection.parse_error(self.parse_error),
                crypto_settings=NormalizedCollection.parse_error(self.parse_error),
            )
        hostname_statement = self._first_value(("system", "host-name"))
        hostname = (
            NormalizedValue.known(self.get_hostname(), hostname_statement.evidence)
            if hostname_statement
            else NormalizedValue.unknown("No active system host-name statement")
        )
        version = self.get_version()
        model = self.get_model()
        services = []
        service_map = self.get_services()
        for protocol, enabled in service_map.items():
            evidence = tuple(
                statement.evidence
                for statement in self.statements
                if statement.active
                and self._is_prefix(
                    ("system", "services", "web-management", protocol)
                    if protocol in {"http", "https"}
                    else ("system", "services", protocol),
                    statement.path,
                )
            )
            if enabled:
                services.append(
                    ManagementService(protocol, ConfigurationState.ENABLED, evidence=evidence)
                )

        normalized_users = []
        for user in self.get_users():
            normalized_users.append(
                LocalUser(
                    username=user["username"],
                    state=ConfigurationState.CONFIGURED,
                    role=user["class"] or None,
                    authentication=user["authentication"] or None,
                    evidence=tuple(user["evidence"]),
                )
            )

        interfaces: dict[str, dict] = {}
        zone_map = {}
        for statement in self.statements:
            path = statement.path
            if statement.active and path[:3] == ("security", "zones", "security-zone") and "interfaces" in path:
                zone_map[path[path.index("interfaces") + 1]] = path[3]
            if len(path) > 1 and path[0] == "interfaces" and path[1] != "interface-range":
                data = interfaces.setdefault(path[1], {"active": False, "disabled": False, "addresses": [], "evidence": []})
                data["evidence"].append(statement.evidence)
                data["active"] = data["active"] or statement.active
                if statement.active and "disable" in path[2:]:
                    data["disabled"] = True
                if statement.active and "address" in path[2:] and path.index("address") + 1 < len(path):
                    data["addresses"].append(path[path.index("address") + 1])
        normalized_interfaces = [
            NetworkInterface(
                name=name,
                state=ConfigurationState.DISABLED if data["disabled"] or not data["active"] else ConfigurationState.ENABLED,
                zone=zone_map.get(name) or next(
                    (
                        zone
                        for logical_name, zone in zone_map.items()
                        if logical_name.startswith(name + ".")
                    ),
                    None,
                ),
                addresses=tuple(data["addresses"]),
                evidence=tuple(data["evidence"]),
            )
            for name, data in interfaces.items()
        ]

        policies = []
        for term in self.get_filter_terms():
            action = next((item for item in term.actions if item in {"accept", "discard", "reject"}), "unknown")
            policies.append(
                SecurityPolicy(
                    name=f"{term.filter_name}/{term.term_name}",
                    state=ConfigurationState.ENABLED if term.active else ConfigurationState.DISABLED,
                    action=action,
                    position=term.position,
                    scope=term.family,
                    source_interfaces=term.attachments,
                    sources=term.sources,
                    destinations=term.destinations,
                    services=term.protocols,
                    tracking="log" if any(item in term.actions for item in {"log", "syslog"}) else None,
                    evidence=term.evidence,
                )
            )

        return NormalizedConfig(
            device_type=self.device_type,
            hostname=hostname,
            device_model=(
                NormalizedValue.known(model)
                if model != "?"
                else NormalizedValue.unknown("Model metadata is not present")
            ),
            software_version=(
                NormalizedValue.known(version)
                if version != "?"
                else NormalizedValue.unknown("Version metadata is not present")
            ),
            management_services=NormalizedCollection.known(*services),
            users=NormalizedCollection.known(*normalized_users),
            interfaces=NormalizedCollection.known(*normalized_interfaces),
            policies=NormalizedCollection.known(*policies),
            logging_destinations=NormalizedCollection.unknown(
                "Junos logging normalization is deferred to the baseline task"
            ),
            crypto_settings=NormalizedCollection.unknown(
                "Junos cryptographic normalization is deferred to the baseline task"
            ),
        )
