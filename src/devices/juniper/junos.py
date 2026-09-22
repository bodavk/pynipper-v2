import ipaddress
import re
import shlex
from dataclasses import dataclass
from typing import Optional

from src.devices.common.base_parser import BaseDeviceParser
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


@dataclass(frozen=True)
class JunosStatement:
    path: tuple[str, ...]
    active: bool
    evidence: ConfigEvidence

    @property
    def set_line(self) -> str:
        return "set " + " ".join(self.path)


@dataclass(frozen=True)
class JunosDefaultSecurityPolicy:
    action: str | None
    resolution_state: str
    evidence: tuple[ConfigEvidence, ...]


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


@dataclass(frozen=True)
class JunosPolicer:
    name: str
    family: str
    bandwidth_limit: str
    burst_size_limit: str
    discard: bool
    resolution_state: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class JunosRoutingEngineTerm:
    name: str
    position: int
    match_conditions: tuple[str, ...]
    actions: tuple[str, ...]
    policer: str
    policer_resolution: str
    enforcement_state: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class JunosRoutingEngineProtection:
    interface: str
    unit: str
    family: str
    filter_name: str
    filter_resolved: bool
    protection_state: str
    inheritance_unknown: bool
    terms: tuple[JunosRoutingEngineTerm, ...]
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class JunosSyslogSelector:
    facility: str
    severity: str | None
    evidence: ConfigEvidence


@dataclass(frozen=True)
class JunosSyslogDestination:
    address: str
    selectors: tuple[JunosSyslogSelector, ...]
    transport: str | None
    port: str | None
    source_address: str | None
    routing_instance: str | None
    has_unknown_selector: bool
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class JunosNTPAssociation:
    role: str
    address: str
    key_id: str
    authentication_state: str
    algorithm: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class JunosAAATransportProfile:
    """Secret-free administrative RADIUS transport evidence."""

    address: str
    roles: tuple[str, ...]
    transport: str
    port: str | None
    trusted_ca_group: str | None
    mutual_authentication: bool
    client_certificate_id: str | None
    message_authenticator: str
    protected_path: bool
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class JunosBGPNeighbor:
    """Effective Junos BGP neighbor state in a routing-instance/family."""

    address: str
    group: str
    peer_role: str
    routing_instance: str
    address_family: str
    active: bool
    authentication_state: str
    authentication_method: str
    inbound_policy: bool
    outbound_policy: bool
    prefix_limit: bool
    inheritance_unknown: bool
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class JunosOSPFInterface:
    process: str
    interface: str
    area: str
    routing_instance: str
    passive: bool
    active: bool
    authentication_state: str
    authentication_method: str
    key_reference: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class JunosDiscoveryInterface:
    interface: str
    protocol: str
    transmit: bool
    receive: bool
    active: bool
    role: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class JunosSecurityPolicy:
    from_zone: str
    to_zone: str
    name: str
    position: int
    active: bool
    sources: tuple[str, ...]
    destinations: tuple[str, ...]
    applications: tuple[str, ...]
    action: str
    tunnel: str
    log_events: tuple[str, ...]
    source_resolution: str
    destination_resolution: str
    application_resolution: str
    inheritance_unknown: bool
    source_networks: NetworkSemantics
    destination_networks: NetworkSemantics
    services: ServiceSemantics
    unsupported_predicates: tuple[str, ...]
    behavior_signature: tuple[str, ...]
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class JunosIPSecVPN:
    name: str
    active: bool
    attachments: tuple[str, ...]
    bind_interface: str
    resolution_state: str
    ike_proposals: tuple[str, ...]
    ike_encryption: tuple[str, ...]
    ike_authentication: tuple[str, ...]
    ike_dh_groups: tuple[str, ...]
    ipsec_proposals: tuple[str, ...]
    ipsec_encryption: tuple[str, ...]
    ipsec_authentication: tuple[str, ...]
    pfs_dh_groups: tuple[str, ...]
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class JunosLoginClassPolicy:
    name: str
    predefined: bool
    defined: bool
    permissions: tuple[str, ...]
    users: tuple[str, ...]
    idle_timeout_minutes: Optional[int]
    timeout_source: str
    resolution_state: str
    inheritance_unknown: bool
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class JunosAccountingPolicy:
    events: tuple[str, ...]
    destination_methods: tuple[str, ...]
    resolved_methods: tuple[str, ...]
    inheritance_unknown: bool
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class JunosWebManagementPolicy:
    enabled: bool
    protocols: tuple[str, ...]
    idle_timeout_minutes: Optional[int]
    idle_timeout_source: str
    idle_timeout_resolution: str
    session_limit: Optional[int]
    session_limit_source: str
    session_limit_resolution: str
    inheritance_unknown: bool
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class JunosLoginNoticePolicy:
    message_configured: bool
    announcement_configured: bool
    inheritance_unknown: bool
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class JunosArchiveSite:
    destination: str
    protocol: str
    transport_security: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class JunosConfigurationManagement:
    sites: tuple[JunosArchiveSite, ...]
    transfer_on_commit: bool
    transfer_interval_minutes: int | None
    schedule_state: str
    routing_instance: str
    change_audit_state: str
    change_audit_destinations: tuple[str, ...]
    inheritance_unknown: bool
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
        redacted = re.sub(
            r'''(?i)((?:encrypted-password|plain-text-password|authentication-password|privacy-password|secret)\s+)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\S+)''',
            r"\1<redacted>",
            text,
        )
        redacted = re.sub(
            r'''(?i)((?:authentication-key|pre-shared-key)\b.*?\b(?:value|ascii-text)\s+)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\S+)''',
            r"\1<redacted>",
            redacted,
        )
        redacted = re.sub(
            r'''(?i)((?:authentication-key|simple-password|\bkey)\s+)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\S+)''',
            r"\1<redacted>",
            redacted,
        )
        redacted = re.sub(
            r"(?i)([a-z][a-z0-9+.-]*://)[^/@\s]+@",
            r"\1<credentials>@",
            redacted,
        )
        return ConfigEvidence(
            text=redacted,
            source=self.config_filepath,
            line_number=line_number,
        )

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
            operation = tokens[0]
            # Display-set output may retain brackets around multi-value lists.
            # The hierarchical lexer treats those as structure rather than
            # semantic values, so normalize them away in both representations.
            path = tuple(token for token in tokens[1:] if token not in {"[", "]"})
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

    def get_active_statements(
        self, prefix: tuple[str, ...] = ()
    ) -> list[JunosStatement]:
        """Return effective statements under an exact token-path prefix."""

        return [
            statement
            for statement in self.statements
            if statement.active and self._is_prefix(prefix, statement.path)
        ]

    def get_default_security_policy(self) -> JunosDefaultSecurityPolicy:
        """Resolve the fallback for traffic unmatched by SRX security policies."""
        if self.parse_error:
            return JunosDefaultSecurityPolicy(None, "parse-error", ())
        prefix = ("security", "policies", "default-policy")
        direct = [item for item in self.statements if item.path[:3] == prefix]
        active_direct = [item for item in direct if item.active]
        if active_direct:
            last = active_direct[-1]
            action = last.path[3] if len(last.path) == 4 else None
            if action in {"permit-all", "deny-all"}:
                return JunosDefaultSecurityPolicy(action, "explicit", (last.evidence,))
            return JunosDefaultSecurityPolicy(None, "unknown", (last.evidence,))
        if direct:
            return JunosDefaultSecurityPolicy(None, "unknown", tuple(item.evidence for item in direct))

        applications = [
            item for item in self.statements
            if item.active and len(item.path) >= 2 and item.path[:-1] in {
                ("apply-groups",),
                ("security", "apply-groups"),
                ("security", "policies", "apply-groups"),
            }
        ]
        if applications:
            candidates: list[JunosStatement] = []
            for application in applications:
                group = application.path[-1]
                inherited = [
                    item for item in self.statements
                    if item.active and item.path[:4] == ("groups", group, "security", "policies")
                    and len(item.path) >= 5 and item.path[4] == "default-policy"
                ]
                if not inherited:
                    return JunosDefaultSecurityPolicy(None, "unknown", (application.evidence,))
                candidates.extend(inherited)
            actions = {
                item.path[5] for item in candidates
                if len(item.path) == 6 and item.path[5] in {"permit-all", "deny-all"}
            }
            if len(actions) == 1 and all(
                len(item.path) == 6 and item.path[5] in actions for item in candidates
            ):
                return JunosDefaultSecurityPolicy(
                    next(iter(actions)), "inherited",
                    tuple(item.evidence for item in applications + candidates),
                )
            return JunosDefaultSecurityPolicy(
                None, "unknown", tuple(item.evidence for item in applications + candidates),
            )
        return JunosDefaultSecurityPolicy(None, "not-configured", ())

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

    def has_unexpanded_inheritance(self) -> bool:
        return any(
            statement.active and "apply-groups" in statement.path
            for statement in self.statements
        )

    @staticmethod
    def _bounded_integer(value: str, minimum: int, maximum: int) -> Optional[int]:
        if not value.isdigit():
            return None
        parsed = int(value)
        return parsed if minimum <= parsed <= maximum else None

    def get_login_class_policies(self) -> tuple[JunosLoginClassPolicy, ...]:
        """Resolve effective named-user class and CLI idle-timeout relationships."""

        predefined = {"operator", "read-only", "super-user", "superuser", "unauthorized"}
        inheritance_unknown = self.has_unexpanded_inheritance()
        class_data: dict[str, dict] = {}
        for statement in self.get_active_statements(("system", "login", "class")):
            if len(statement.path) < 4:
                continue
            name = statement.path[3]
            data = class_data.setdefault(
                name.casefold(),
                {
                    "name": name,
                    "permissions": [],
                    "timeout": None,
                    "evidence": [],
                },
            )
            data["evidence"].append(statement.evidence)
            suffix = statement.path[4:]
            if suffix[:1] == ("permissions",):
                for permission in suffix[1:]:
                    if permission not in data["permissions"]:
                        data["permissions"].append(permission)
            elif suffix[:1] == ("idle-timeout",) and len(suffix) > 1:
                data["timeout"] = statement

        users_by_class: dict[str, list[str]] = {}
        user_evidence: dict[str, list[ConfigEvidence]] = {}
        for user in self.get_users():
            class_name = user["class"]
            if not class_name:
                continue
            key = class_name.casefold()
            users_by_class.setdefault(key, []).append(user["username"])
            user_evidence.setdefault(key, []).extend(user["evidence"])
            class_data.setdefault(
                key,
                {
                    "name": class_name,
                    "permissions": [],
                    "timeout": None,
                    "evidence": [],
                },
            )

        global_timeouts = [
            statement
            for statement in self.get_active_statements(("system", "login", "idle-timeout"))
            if len(statement.path) == 4
        ]
        global_timeout = global_timeouts[-1] if global_timeouts else None
        policies = []
        for key in sorted(class_data):
            data = class_data[key]
            class_timeout = data["timeout"]
            effective_timeout = class_timeout or global_timeout
            timeout_minutes: Optional[int] = None
            if effective_timeout is None:
                timeout_source = "unconfigured"
                resolution_state = (
                    "inheritance-unknown" if inheritance_unknown else "known"
                )
            else:
                timeout_source = (
                    "class-explicit" if class_timeout is not None else "global-explicit"
                )
                maximum = 4294967295 if class_timeout is not None else 60
                timeout_minutes = self._bounded_integer(
                    effective_timeout.path[-1], 0 if class_timeout is not None else 1, maximum
                )
                resolution_state = "known" if timeout_minutes is not None else "invalid"
            evidence = list(data["evidence"])
            evidence.extend(user_evidence.get(key, ()))
            if class_timeout is None and global_timeout is not None:
                evidence.append(global_timeout.evidence)
            policies.append(
                JunosLoginClassPolicy(
                    name=data["name"],
                    predefined=key in predefined,
                    defined=key in predefined or bool(data["evidence"]),
                    permissions=tuple(data["permissions"]),
                    users=tuple(users_by_class.get(key, ())),
                    idle_timeout_minutes=timeout_minutes,
                    timeout_source=timeout_source,
                    resolution_state=resolution_state,
                    inheritance_unknown=inheritance_unknown,
                    evidence=tuple(evidence),
                )
            )
        return tuple(policies)

    def get_login_notice_policy(self) -> JunosLoginNoticePolicy:
        statements = self.get_active_statements(("system", "login"))
        messages = [item for item in statements if item.path[2:3] == ("message",)]
        announcements = [
            item for item in statements if item.path[2:3] == ("announcement",)
        ]
        return JunosLoginNoticePolicy(
            message_configured=any(len(item.path) > 3 for item in messages),
            announcement_configured=any(len(item.path) > 3 for item in announcements),
            inheritance_unknown=self.has_unexpanded_inheritance(),
            evidence=tuple(item.evidence for item in messages + announcements),
        )

    def get_accounting_policy(self) -> JunosAccountingPolicy:
        statements = self.get_active_statements(("system", "accounting"))
        events: list[str] = []
        methods: list[str] = []
        resolved: list[str] = []
        for statement in statements:
            path = statement.path
            if path[2:3] == ("events",):
                for event in path[3:]:
                    if event not in events:
                        events.append(event)
            if path[2:3] == ("destination",) and len(path) > 3:
                method = path[3].casefold()
                if method not in methods:
                    methods.append(method)

        active_paths = self._active_paths()
        for method in methods:
            explicit_server = any(
                path[:4] == ("system", "accounting", "destination", method)
                and "server" in path[4:]
                for path in active_paths
            )
            fallback_prefix = (
                ("system", "tacplus-server")
                if method == "tacplus"
                else ("system", "radius-server")
            )
            fallback_server = method in {"tacplus", "radius"} and any(
                self._is_prefix(fallback_prefix, path) for path in active_paths
            )
            if explicit_server or fallback_server:
                resolved.append(method)
        evidence = [item.evidence for item in statements]
        for statement in self.get_active_statements(("system",)):
            if statement.path[:2] in {
                ("system", "tacplus-server"),
                ("system", "radius-server"),
            }:
                evidence.append(statement.evidence)
        return JunosAccountingPolicy(
            events=tuple(events),
            destination_methods=tuple(methods),
            resolved_methods=tuple(resolved),
            inheritance_unknown=self.has_unexpanded_inheritance(),
            evidence=tuple(evidence),
        )

    def get_aaa_transport_profiles(self) -> tuple[JunosAAATransportProfile, ...]:
        """Resolve RADIUS transport used for system login and accounting.

        Plain RADIUS is not automatically graded as unsafe because its routed
        path is not established by a configuration export.  Explicit RadSec
        certificate bindings and explicit Message-Authenticator disablement
        remain locally provable.
        """

        active = self._active_paths()
        order = self.get_active_statements(("system", "authentication-order"))
        radius_authentication = any("radius" in item.path[2:] for item in order)
        accounting_paths = [
            path for path in active
            if self._is_prefix(("system", "accounting", "destination", "radius"), path)
        ]
        radius_accounting = bool(accounting_paths)
        explicit_accounting = any(
            len(path) > 5 and path[4] == "server" for path in accounting_paths
        )

        definitions: list[tuple[str, str, list[tuple[str, ...]], tuple[str, ...]]] = []
        system_addresses = sorted({
            path[2]
            for path in active
            if len(path) >= 3 and path[:2] == ("system", "radius-server")
        })
        for address in system_addresses:
            roles = []
            if radius_authentication:
                roles.append("authentication")
            if radius_accounting and not explicit_accounting:
                roles.append("accounting")
            if roles:
                definitions.append((
                    address,
                    "system",
                    [
                        path[3:] for path in active
                        if len(path) >= 3
                        and path[:3] == ("system", "radius-server", address)
                    ],
                    tuple(roles),
                ))

        accounting_addresses = sorted({
            path[5]
            for path in accounting_paths
            if len(path) >= 6 and path[4] == "server"
        })
        for address in accounting_addresses:
            definitions.append((
                address,
                "accounting",
                [path[6:] for path in accounting_paths if path[:6] == (
                    "system", "accounting", "destination", "radius", "server", address
                )],
                ("accounting",),
            ))

        profiles = []
        for address, source, tails, roles in definitions:
            tls = any(tail[:1] == ("tls",) for tail in tails)
            port_field = "accounting-port" if source == "accounting" else "port"
            port = next(
                (tail[1] for tail in reversed(tails) if tail[:1] == (port_field,) and len(tail) > 1),
                None,
            )
            trusted_ca = next(
                (tail[2] for tail in reversed(tails)
                 if tail[:2] == ("tls", "trusted-ca-group") and len(tail) > 2),
                None,
            )
            mutual = any(tail[:2] == ("tls", "mutual-authentication") for tail in tails)
            certificate_id = next(
                (tail[3] for tail in reversed(tails)
                 if tail[:3] == ("tls", "mutual-authentication", "certificate-id")
                 and len(tail) > 3),
                None,
            )
            if tls:
                message_authenticator = "not-applicable"
            elif any(tail[:1] == ("no-message-authenticator",) for tail in tails):
                message_authenticator = "disabled"
            elif any(tail[:1] == ("message-authenticator",) for tail in tails):
                message_authenticator = "enabled"
            else:
                message_authenticator = "unknown"

            prefix = (
                ("system", "radius-server", address)
                if source == "system"
                else ("system", "accounting", "destination", "radius", "server", address)
            )
            evidence = tuple(
                statement.evidence
                for statement in self.get_active_statements(prefix)
                if "secret" not in statement.path
            )
            profiles.append(JunosAAATransportProfile(
                address=address,
                roles=roles,
                transport="tls" if tls else "udp",
                port=port,
                trusted_ca_group=trusted_ca,
                mutual_authentication=mutual,
                client_certificate_id=certificate_id,
                message_authenticator=message_authenticator,
                protected_path=self.assessment_context.aaa_profile_has_protected_path(
                    "system", address
                ),
                evidence=evidence,
            ))
        return tuple(profiles)

    @staticmethod
    def _archive_site_details(destination: str) -> tuple[str, str, str]:
        sanitized = re.sub(
            r"(?i)([a-z][a-z0-9+.-]*://)[^/@\s]+@",
            r"\1<credentials>@",
            destination,
        )
        if "://" in destination:
            protocol = destination.split(":", 1)[0].casefold()
        elif re.match(r"^[^/@:]+@[^:]+:", destination):
            protocol = "scp"
        else:
            protocol = "file"
        security = (
            "secure" if protocol in {"scp", "sftp", "https"}
            else "insecure" if protocol in {"ftp", "pasvftp", "http"}
            else "local" if protocol == "file"
            else "unknown"
        )
        return sanitized, protocol, security

    def get_configuration_management(self) -> JunosConfigurationManagement:
        """Resolve automatic configuration archival and static change-audit selectors."""

        archival = self.get_active_statements(("system", "archival", "configuration"))
        sites: dict[str, JunosArchiveSite] = {}
        transfer_on_commit = False
        interval: int | None = None
        invalid_interval = False
        routing_instance = ""
        for statement in archival:
            path = statement.path
            tail = path[3:]
            if tail[:1] == ("archive-sites",) and len(tail) > 1:
                raw_destination = tail[1]
                sanitized, protocol, security = self._archive_site_details(raw_destination)
                sites[sanitized.casefold()] = JunosArchiveSite(
                    destination=sanitized,
                    protocol=protocol,
                    transport_security=security,
                    evidence=(statement.evidence,),
                )
            elif tail == ("transfer-on-commit",):
                transfer_on_commit = True
            elif tail[:1] in (("transfer-interval",), ("transfer",)):
                value = tail[1] if tail[:1] == ("transfer-interval",) and len(tail) > 1 else (
                    tail[2] if tail[:2] == ("transfer", "interval") and len(tail) > 2 else ""
                )
                invalid_interval = not value.isdigit() or not 15 <= int(value) <= 2880
                interval = int(value) if not invalid_interval else None
            elif tail[:1] == ("routing-instance",) and len(tail) > 1:
                routing_instance = tail[1]

        if transfer_on_commit and interval is not None:
            schedule_state = "conflict"
        elif transfer_on_commit or interval is not None:
            schedule_state = "effective"
        elif invalid_interval:
            schedule_state = "invalid"
        else:
            schedule_state = "missing"

        accounting = self.get_accounting_policy()
        accounting_audit = (
            "change-log" in accounting.events
            and bool(set(accounting.destination_methods) & set(accounting.resolved_methods))
        )
        audit_destinations: list[str] = []
        audit_evidence: list[ConfigEvidence] = []
        for statement in self.get_active_statements(("system", "syslog")):
            path = statement.path
            if len(path) < 6 or path[2] not in {"host", "file"}:
                continue
            facility, severity = path[4].casefold(), path[5].casefold()
            if facility != "change-log" or severity == "none":
                continue
            destination = f"{path[2]}:{path[3]}"
            if destination not in audit_destinations:
                audit_destinations.append(destination)
            audit_evidence.append(statement.evidence)
        if accounting_audit:
            audit_destinations.extend(
                f"accounting:{method}" for method in accounting.resolved_methods
                if f"accounting:{method}" not in audit_destinations
            )
            audit_evidence.extend(accounting.evidence)
        change_audit_state = (
            "effective" if audit_destinations
            else "unknown-inheritance" if self.has_unexpanded_inheritance()
            else "missing"
        )
        return JunosConfigurationManagement(
            sites=tuple(sites.values()),
            transfer_on_commit=transfer_on_commit,
            transfer_interval_minutes=interval,
            schedule_state=schedule_state,
            routing_instance=routing_instance,
            change_audit_state=change_audit_state,
            change_audit_destinations=tuple(audit_destinations),
            inheritance_unknown=self.has_unexpanded_inheritance(),
            evidence=tuple(item.evidence for item in archival) + tuple(audit_evidence),
        )

    def get_web_management_policy(self) -> JunosWebManagementPolicy:
        statements = self.get_active_statements(
            ("system", "services", "web-management")
        )
        protocols = tuple(
            protocol for protocol in ("http", "https") if self.get_services()[protocol]
        )
        timeout_statements = [
            item
            for item in statements
            if "idle-timeout" in item.path[3:]
            and item.path.index("idle-timeout", 3) + 1 < len(item.path)
        ]
        limit_statements = [
            item
            for item in statements
            if "session-limit" in item.path[3:]
            and item.path.index("session-limit", 3) + 1 < len(item.path)
        ]
        timeout = timeout_statements[-1] if timeout_statements else None
        limit = limit_statements[-1] if limit_statements else None
        inheritance_unknown = self.has_unexpanded_inheritance()
        timeout_value = (
            self._bounded_integer(timeout.path[-1], 1, 1440) if timeout else None
        )
        limit_value = self._bounded_integer(limit.path[-1], 1, 1024) if limit else None
        return JunosWebManagementPolicy(
            enabled=bool(protocols),
            protocols=protocols,
            idle_timeout_minutes=timeout_value,
            idle_timeout_source="explicit" if timeout else "unresolved-default",
            idle_timeout_resolution=(
                "known"
                if timeout and timeout_value is not None
                else "invalid"
                if timeout
                else "inheritance-unknown"
                if inheritance_unknown
                else "unknown"
            ),
            session_limit=limit_value,
            session_limit_source="explicit" if limit else "documented-default-unlimited",
            session_limit_resolution=(
                "known"
                if limit and limit_value is not None
                else "invalid"
                if limit
                else "inheritance-unknown"
                if inheritance_unknown
                else "known"
            ),
            inheritance_unknown=inheritance_unknown,
            evidence=tuple(item.evidence for item in statements),
        )

    @staticmethod
    def _credential_storage(method: str, value: str) -> CredentialStorageAssessment:
        if method == "plain-text-password":
            return (
                CredentialStorageAssessment.PLAINTEXT
                if value
                else CredentialStorageAssessment.UNKNOWN
            )
        if method != "encrypted-password":
            return CredentialStorageAssessment.UNKNOWN
        if not value:
            return CredentialStorageAssessment.MALFORMED
        lowered = value.casefold()
        if lowered.startswith(("$1$", "$md5$")):
            return (
                CredentialStorageAssessment.WEAK_HASH
                if len(value.split("$")) >= 4
                else CredentialStorageAssessment.MALFORMED
            )
        if lowered.startswith("$9$"):
            return (
                CredentialStorageAssessment.WEAK_REVERSIBLE
                if len(value) > 3
                else CredentialStorageAssessment.MALFORMED
            )
        if lowered.startswith(("$5$", "$6$")):
            return (
                CredentialStorageAssessment.APPROVED_HASH
                if len(value.split("$")) >= 4
                else CredentialStorageAssessment.MALFORMED
            )
        if lowered.startswith("$8$"):
            return (
                CredentialStorageAssessment.APPROVED_REVERSIBLE
                if len(value.split("$")) >= 9
                else CredentialStorageAssessment.MALFORMED
            )
        return (
            CredentialStorageAssessment.UNKNOWN
            if value.startswith("$")
            else CredentialStorageAssessment.MALFORMED
        )

    @staticmethod
    def _credential_default(
        storage: CredentialStorageAssessment, value: str
    ) -> DefaultCredentialAssessment:
        if value.casefold() in {"admin", "juniper", "password", "root"}:
            return DefaultCredentialAssessment.MATCH
        if storage in {
            CredentialStorageAssessment.PLAINTEXT,
            CredentialStorageAssessment.MALFORMED,
            CredentialStorageAssessment.UNKNOWN,
        }:
            return DefaultCredentialAssessment.NO_MATCH
        return DefaultCredentialAssessment.NOT_EVALUATED

    def get_credential_metadata(self) -> list[CredentialMetadata]:
        """Expose secret-free properties for effective local and root credentials."""

        credentials: dict[tuple[str, str], CredentialMetadata] = {}
        for statement in self.statements:
            if not statement.active:
                continue
            path = statement.path
            context = ""
            account = ""
            auth_index = -1
            if path[:3] == ("system", "login", "user") and len(path) > 5:
                account = path[3]
                context = "local_user"
                if path[4] != "authentication":
                    continue
                auth_index = 4
            elif path[:2] == ("system", "root-authentication") and len(path) > 2:
                account = "root"
                context = "root"
                auth_index = 1
            else:
                continue
            method = path[auth_index + 1]
            if method not in {"plain-text-password", "encrypted-password"}:
                continue
            value = path[auth_index + 2] if len(path) > auth_index + 2 else ""
            storage = self._credential_storage(method, value)
            credentials[(context, account)] = CredentialMetadata(
                account=account,
                context=context,
                method=method,
                storage_type=(
                    value.split("$", 2)[1]
                    if value.startswith("$") and "$" in value[1:]
                    else method
                ),
                storage_assessment=storage,
                default_assessment=self._credential_default(storage, value),
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
                evidence=(statement.evidence,),
            )
        return list(credentials.values())

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

    def get_routing_engine_protections(self) -> list[JunosRoutingEngineProtection]:
        """Resolve effective lo0 input filters, terms, and policer references."""

        policer_data: dict[tuple[str, str], dict] = {}
        for statement in self.statements:
            if not statement.active:
                continue
            path = statement.path
            if not path or path[0] != "firewall" or "policer" not in path:
                continue
            policer_index = path.index("policer")
            if "filter" in path[:policer_index] or policer_index + 1 >= len(path):
                continue
            family = (
                path[path.index("family") + 1]
                if "family" in path[:policer_index]
                and path.index("family") + 1 < policer_index
                else ""
            )
            name = path[policer_index + 1]
            data = policer_data.setdefault(
                (family, name),
                {
                    "bandwidth": "",
                    "burst": "",
                    "discard": False,
                    "evidence": [],
                },
            )
            data["evidence"].append(statement.evidence)
            suffix = path[policer_index + 2 :]
            for field in ("bandwidth-limit", "bandwidth-percent"):
                if field in suffix and suffix.index(field) + 1 < len(suffix):
                    data["bandwidth"] = suffix[suffix.index(field) + 1]
            if "burst-size-limit" in suffix and suffix.index("burst-size-limit") + 1 < len(suffix):
                data["burst"] = suffix[suffix.index("burst-size-limit") + 1]
            if "then" in suffix and "discard" in suffix[suffix.index("then") + 1 :]:
                data["discard"] = True

        policers = {
            key: JunosPolicer(
                name=key[1],
                family=key[0],
                bandwidth_limit=data["bandwidth"],
                burst_size_limit=data["burst"],
                discard=data["discard"],
                resolution_state=(
                    "complete"
                    if data["bandwidth"] and data["burst"] and data["discard"]
                    else "incomplete"
                ),
                evidence=tuple(data["evidence"]),
            )
            for key, data in policer_data.items()
        }

        filter_data: dict[tuple[str, str], dict] = {}
        for statement in self.statements:
            if not statement.active:
                continue
            path = statement.path
            if not path or path[0] != "firewall" or "filter" not in path:
                continue
            filter_index = path.index("filter")
            if filter_index + 1 >= len(path):
                continue
            family = (
                path[path.index("family") + 1]
                if "family" in path[:filter_index]
                and path.index("family") + 1 < filter_index
                else "inet"
            )
            filter_name = path[filter_index + 1]
            data = filter_data.setdefault(
                (family, filter_name),
                {"present": True, "terms": {}, "evidence": []},
            )
            data["evidence"].append(statement.evidence)
            if "term" not in path[filter_index + 2 :]:
                continue
            term_index = path.index("term", filter_index + 2)
            if term_index + 1 >= len(path):
                continue
            term_name = path[term_index + 1]
            term = data["terms"].setdefault(
                term_name,
                {
                    "position": len(data["terms"]),
                    "matches": [],
                    "actions": [],
                    "policer": "",
                    "evidence": [],
                },
            )
            term["evidence"].append(statement.evidence)
            suffix = path[term_index + 2 :]
            if "from" in suffix:
                condition = " ".join(suffix[suffix.index("from") + 1 :])
                if condition and condition not in term["matches"]:
                    term["matches"].append(condition)
            if "then" in suffix:
                action_values = suffix[suffix.index("then") + 1 :]
                action = " ".join(action_values)
                if action and action not in term["actions"]:
                    term["actions"].append(action)
                if action_values[:1] == ("policer",) and len(action_values) > 1:
                    term["policer"] = action_values[1]

        attachments: list[tuple[str, str, str, str, ConfigEvidence]] = []
        for statement in self.statements:
            if not statement.active:
                continue
            path = statement.path
            if len(path) < 8 or path[:2] != ("interfaces", "lo0"):
                continue
            if "unit" not in path or "family" not in path or "filter" not in path:
                continue
            unit_index = path.index("unit")
            family_index = path.index("family")
            filter_index = path.index("filter")
            if (
                unit_index + 1 >= len(path)
                or family_index + 1 >= len(path)
                or filter_index + 2 >= len(path)
            ):
                continue
            direction = path[filter_index + 1]
            if direction not in {"input", "input-list"}:
                continue
            for filter_name in path[filter_index + 2 :]:
                attachments.append((
                    "lo0",
                    path[unit_index + 1],
                    path[family_index + 1],
                    filter_name,
                    statement.evidence,
                ))

        inheritance_unknown = any(
            statement.active
            and "apply-groups" in statement.path
            and statement.path[:1] in {("interfaces",), ("firewall",)}
            for statement in self.statements
        )
        records = []
        for interface, unit, family, filter_name, attachment_evidence in attachments:
            definition = filter_data.get((family, filter_name))
            if definition is None:
                records.append(JunosRoutingEngineProtection(
                    interface, unit, family, filter_name, False,
                    "unknown-inheritance" if inheritance_unknown else "undefined-filter",
                    inheritance_unknown, (), (attachment_evidence,),
                ))
                continue

            terms = []
            for name, data in definition["terms"].items():
                policer_name = data["policer"]
                policer = (
                    policers.get((family, policer_name))
                    or policers.get(("", policer_name))
                    if policer_name
                    else None
                )
                if not policer_name:
                    policer_resolution = "not-referenced"
                elif policer is None:
                    policer_resolution = "undefined"
                else:
                    policer_resolution = policer.resolution_state
                actions = tuple(data["actions"])
                explicit_discard = any(
                    action.split()[:1] in (["discard"], ["reject"])
                    for action in actions
                )
                enforcement_state = (
                    "discard"
                    if explicit_discard
                    else "policed-discard"
                    if policer and policer.resolution_state == "complete"
                    else "unresolved-policer"
                    if policer_name and policer_resolution != "complete"
                    else "conditional-permit"
                    if data["matches"]
                    else "unconditional-permit"
                )
                term_evidence = tuple(data["evidence"]) + (
                    policer.evidence if policer else ()
                )
                terms.append(JunosRoutingEngineTerm(
                    name=name,
                    position=data["position"],
                    match_conditions=tuple(data["matches"]),
                    actions=actions,
                    policer=policer_name,
                    policer_resolution=policer_resolution,
                    enforcement_state=enforcement_state,
                    evidence=term_evidence,
                ))

            ordered_terms = tuple(sorted(terms, key=lambda item: item.position))
            has_enforcement = any(
                term.enforcement_state in {"discard", "policed-discard"}
                for term in ordered_terms
            )
            has_unconditional_permit = any(
                term.enforcement_state == "unconditional-permit"
                for term in ordered_terms
            )
            has_conditional_permit = any(
                term.enforcement_state == "conditional-permit"
                for term in ordered_terms
            )
            if not ordered_terms:
                protection_state = "empty-filter"
            elif has_enforcement or (has_conditional_permit and not has_unconditional_permit):
                protection_state = "effective"
            elif any(term.enforcement_state == "unresolved-policer" for term in ordered_terms):
                protection_state = "unresolved-policer"
            else:
                protection_state = "no-enforcement"
            records.append(JunosRoutingEngineProtection(
                interface=interface,
                unit=unit,
                family=family,
                filter_name=filter_name,
                filter_resolved=True,
                protection_state=protection_state,
                inheritance_unknown=inheritance_unknown,
                terms=ordered_terms,
                evidence=(attachment_evidence,)
                + tuple(definition["evidence"])
                + tuple(item for term in ordered_terms for item in term.evidence),
            ))
        return records

    @staticmethod
    def _unique(values: list[str]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(values))

    def _address_resolution(
        self,
        references: tuple[str, ...],
        zone: str,
        address_objects: dict[tuple[str, str], tuple[str, ...]],
        address_sets: dict[tuple[str, str], tuple[str, ...]],
        zone_books: dict[str, str],
    ) -> str:
        if not references:
            return "unresolved"
        wildcards = {"any", "any-ipv4", "any-ipv6", "0.0.0.0/0", "::/0", "0::/0"}
        if all(reference.casefold() in wildcards for reference in references):
            return "wildcard"
        book = zone_books.get(zone, zone)

        def resolve(
            name: str,
            seen: set[tuple[str, str]],
            definition_book: str | None = None,
        ) -> tuple[str, ...] | None:
            if name.casefold() in wildcards:
                return (name,)
            candidate_books = (
                (definition_book, "global")
                if definition_book and definition_book != "global"
                else (definition_book,)
                if definition_book
                else (book, "global")
            )
            for candidate_book in dict.fromkeys(candidate_books):
                key = (candidate_book, name)
                if key in seen:
                    return None
                if key in address_objects:
                    return address_objects[key]
                if key in address_sets:
                    resolved: list[str] = []
                    for member in address_sets[key]:
                        child = resolve(member, seen | {key}, candidate_book)
                        if child is None:
                            return None
                        resolved.extend(child)
                    return tuple(resolved)
            return None

        expanded: list[str] = []
        for reference in references:
            values = resolve(reference, set())
            if values is None:
                return "unresolved"
            expanded.extend(values)
        return (
            "wildcard"
            if expanded and all(value.casefold() in wildcards for value in expanded)
            else "resolved"
        )

    def get_security_policies(self) -> list[JunosSecurityPolicy]:
        """Return zone-pair SRX policies separately from stateless filters."""

        address_objects: dict[tuple[str, str], list[str]] = {}
        address_sets: dict[tuple[str, str], list[str]] = {}
        address_definitions: dict[tuple[str, str], list[tuple[str, ...]]] = {}
        address_set_members: dict[tuple[str, str], list[str]] = {}
        zone_books: dict[str, str] = {}
        applications: set[str] = set()
        application_sets: dict[str, list[str]] = {}
        application_definitions: dict[str, list[tuple[str, ...]]] = {}
        for statement in self.statements:
            if not statement.active:
                continue
            path = statement.path
            if path[:2] == ("security", "address-book") and len(path) >= 5:
                book = path[2]
                if path[3] == "attach" and len(path) > 5 and path[4] == "zone":
                    zone_books[path[5]] = book
                elif path[3] == "address":
                    address_objects.setdefault((book, path[4]), []).extend(path[5:6])
                    address_definitions.setdefault((book, path[4]), []).append(path[5:])
                elif (
                    path[3] == "address-set"
                    and len(path) > 6
                    and path[5] in {"address", "address-set"}
                ):
                    address_sets.setdefault((book, path[4]), []).extend(path[6:])
                    address_set_members.setdefault((book, path[4]), []).extend(path[6:])
            elif (
                path[:3] == ("security", "zones", "security-zone")
                and len(path) >= 7
                and path[4] == "address-book"
            ):
                zone = path[3]
                if path[5] == "address":
                    address_objects.setdefault((zone, path[6]), []).extend(path[7:8])
                    address_definitions.setdefault((zone, path[6]), []).append(path[7:])
                elif (
                    path[5] == "address-set"
                    and len(path) > 8
                    and path[7] in {"address", "address-set"}
                ):
                    address_sets.setdefault((zone, path[6]), []).extend(path[8:])
                    address_set_members.setdefault((zone, path[6]), []).extend(path[8:])
            elif path[:2] == ("applications", "application") and len(path) > 2:
                applications.add(path[2])
                application_definitions.setdefault(path[2], []).append(path[3:])
            elif (
                path[:2] == ("applications", "application-set")
                and len(path) > 4
                and path[3] in {"application", "application-set"}
            ):
                application_sets.setdefault(path[2], []).extend(path[4:])

        policies: dict[tuple[str, str, str], dict] = {}
        positions: dict[tuple[str, str], int] = {}
        policy_prefix = ("security", "policies", "from-zone")
        inheritance_unknown = any(
            statement.active
            and (
                "apply-groups" in statement.path
                or statement.path[:3] == ("security", "policies", "global")
            )
            for statement in self.statements
        )
        for statement in self.statements:
            path = statement.path
            if path[:3] != policy_prefix or len(path) < 8 or path[4] != "to-zone":
                continue
            from_zone, to_zone = path[3], path[5]
            if path[6] != "policy":
                continue
            name = path[7]
            key = (from_zone, to_zone, name)
            if key not in policies:
                pair = (from_zone, to_zone)
                positions[pair] = positions.get(pair, 0) + 1
                policies[key] = {
                    "position": positions[pair],
                    "active": False,
                    "sources": [],
                    "destinations": [],
                    "applications": [],
                    "action": "",
                    "tunnel": "",
                    "logs": [],
                    "unsupported": [],
                    "behavior": [],
                    "evidence": [],
                }
            data = policies[key]
            data["evidence"].append(statement.evidence)
            if not statement.active:
                continue
            data["active"] = True
            suffix = path[8:]
            if len(suffix) >= 3 and suffix[:2] == ("match", "source-address"):
                data["sources"].extend(suffix[2:])
            elif len(suffix) >= 3 and suffix[:2] == ("match", "destination-address"):
                data["destinations"].extend(suffix[2:])
            elif len(suffix) >= 3 and suffix[:2] == ("match", "application"):
                data["applications"].extend(suffix[2:])
            elif suffix[:1] == ("match",):
                data["unsupported"].append(" ".join(suffix[1:]))
            elif len(suffix) >= 2 and suffix[0] == "then":
                data["behavior"].append(" ".join(suffix))
                if suffix[1] in {"permit", "deny", "reject"}:
                    data["action"] = suffix[1]
                if "ipsec-vpn" in suffix:
                    index = suffix.index("ipsec-vpn")
                    if index + 1 < len(suffix):
                        data["tunnel"] = suffix[index + 1]
                if "log" in suffix:
                    index = suffix.index("log")
                    if index + 1 < len(suffix):
                        data["logs"].append(suffix[index + 1])
            elif suffix and suffix[0] != "description":
                data["unsupported"].append(" ".join(suffix))

        address_object_values = {
            key: tuple(values) for key, values in address_objects.items()
        }
        address_set_values = {key: tuple(values) for key, values in address_sets.items()}

        def application_resolution(values: tuple[str, ...]) -> str:
            if not values or all(value.casefold() == "any" for value in values):
                return "default-any" if not values else "wildcard"

            def resolved(name: str, seen: set[str]) -> bool:
                if name.casefold().startswith("junos-") or name in applications:
                    return True
                if name in seen or name not in application_sets:
                    return False
                return all(
                    resolved(member, seen | {name})
                    for member in application_sets[name]
                )

            return "resolved" if all(resolved(value, set()) for value in values) else "unresolved"

        def address_member(
            name: str,
            zone: str,
            definition_book: str | None,
            seen: frozenset[tuple[str, str]],
            budget: list[int],
        ) -> NetworkSemantics:
            lowered = name.casefold()
            if lowered == "any":
                return NetworkSemantics(any=True)
            if lowered in {"any-ipv4", "0.0.0.0/0"}:
                return NetworkSemantics(
                    intervals=(AddressInterval(4, 0, (1 << 32) - 1),)
                )
            if lowered in {"any-ipv6", "::/0", "0::/0"}:
                return NetworkSemantics(
                    intervals=(AddressInterval(6, 0, (1 << 128) - 1),)
                )
            try:
                literal = ipaddress.ip_network(name, strict=False)
            except ValueError:
                literal = None
            if literal is not None:
                return NetworkSemantics(intervals=(AddressInterval(
                    literal.version,
                    int(literal.network_address),
                    int(literal.broadcast_address),
                ),))

            book = zone_books.get(zone, zone)
            candidate_books = (
                (definition_book, "global")
                if definition_book and definition_book != "global"
                else (definition_book,)
                if definition_book
                else (book, "global")
            )
            for candidate in dict.fromkeys(candidate_books):
                if candidate is None:
                    continue
                key = (candidate, name)
                if key in seen or budget[0] <= 0:
                    return NetworkSemantics(complete=False, unresolved=(name,))
                definitions = [
                    value
                    for value in address_definitions.get(key, [])
                    if value and value[0] != "description"
                ]
                if definitions:
                    if len(definitions) != 1:
                        return NetworkSemantics(complete=False, unresolved=(name,))
                    definition = definitions[0]
                    interval = None
                    if len(definition) == 1:
                        try:
                            network = ipaddress.ip_network(definition[0], strict=False)
                        except ValueError:
                            network = None
                        if network is not None:
                            interval = AddressInterval(
                                network.version,
                                int(network.network_address),
                                int(network.broadcast_address),
                            )
                    elif (
                        len(definition) == 4
                        and definition[0] == "range-address"
                        and definition[2] == "to"
                    ):
                        try:
                            first = ipaddress.ip_address(definition[1])
                            last = ipaddress.ip_address(definition[3])
                        except ValueError:
                            first = last = None
                        if (
                            first is not None
                            and last is not None
                            and first.version == last.version
                            and int(first) <= int(last)
                        ):
                            interval = AddressInterval(
                                first.version, int(first), int(last)
                            )
                    if interval is None:
                        return NetworkSemantics(complete=False, unresolved=(name,))
                    budget[0] -= 1
                    return NetworkSemantics(intervals=(interval,))
                members = address_set_members.get(key)
                if members is not None:
                    if not members:
                        return NetworkSemantics(complete=False, unresolved=(name,))
                    budget[0] -= 1
                    intervals: list[AddressInterval] = []
                    unresolved: list[str] = []
                    for member in members:
                        child = address_member(
                            member,
                            zone,
                            candidate,
                            seen | {key},
                            budget,
                        )
                        if child.any:
                            return NetworkSemantics(any=True)
                        intervals.extend(child.intervals)
                        unresolved.extend(child.unresolved)
                    if unresolved or not intervals:
                        return NetworkSemantics(
                            intervals=tuple(sorted(set(intervals))),
                            complete=False,
                            unresolved=tuple(dict.fromkeys(unresolved or members)),
                        )
                    return NetworkSemantics(intervals=tuple(sorted(set(intervals))))
            return NetworkSemantics(complete=False, unresolved=(name,))

        def network_semantics(values: tuple[str, ...], zone: str) -> NetworkSemantics:
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

        def application_member(
            name: str,
            seen: frozenset[str],
            budget: list[int],
        ) -> ServiceSemantics:
            lowered = name.casefold()
            if lowered == "any":
                return ServiceSemantics(any=True)
            if lowered in {"junos-tcp-any", "junos-udp-any"}:
                return ServiceSemantics(intervals=(ServiceInterval(
                    "tcp" if lowered == "junos-tcp-any" else "udp", 0, 65535
                ),))
            if name in seen or budget[0] <= 0:
                return ServiceSemantics(complete=False, unresolved=(name,))
            budget[0] -= 1
            next_seen = seen | {name}
            definitions = application_definitions.get(name)
            if definitions is not None:
                semantic = [value for value in definitions if value and value[0] != "description"]
                if any(
                    value[0] not in {"protocol", "destination-port"}
                    for value in semantic
                ):
                    return ServiceSemantics(complete=False, unresolved=(name,))
                protocols = tuple(
                    value[1].casefold()
                    for value in semantic
                    if value[0] == "protocol" and len(value) == 2
                )
                if len(protocols) != 1:
                    return ServiceSemantics(complete=False, unresolved=(name,))
                protocol = protocols[0]
                ports: list[tuple[int, int]] = []
                for value in semantic:
                    if value[0] != "destination-port":
                        continue
                    if len(value) < 2:
                        return ServiceSemantics(complete=False, unresolved=(name,))
                    for token in value[1:]:
                        parts = token.split("-", 1)
                        if not all(part.isdigit() for part in parts):
                            return ServiceSemantics(complete=False, unresolved=(name,))
                        first, last = int(parts[0]), int(parts[-1])
                        if not 1 <= first <= last <= 65535:
                            return ServiceSemantics(complete=False, unresolved=(name,))
                        ports.append((first, last))
                if protocol in {"tcp", "udp", "sctp"} and not ports:
                    return ServiceSemantics(complete=False, unresolved=(name,))
                if ports and protocol not in {"tcp", "udp", "sctp"}:
                    return ServiceSemantics(complete=False, unresolved=(name,))
                if not ports:
                    ports.append((0, 65535))
                return ServiceSemantics(intervals=tuple(
                    ServiceInterval(protocol, first, last)
                    for first, last in ports
                ))
            members = application_sets.get(name)
            if members is not None:
                if not members:
                    return ServiceSemantics(complete=False, unresolved=(name,))
                intervals: list[ServiceInterval] = []
                unresolved: list[str] = []
                for member_name in members:
                    member = application_member(member_name, next_seen, budget)
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

        def application_semantics(values: tuple[str, ...]) -> ServiceSemantics:
            if not values:
                return ServiceSemantics(any=True)
            intervals: list[ServiceInterval] = []
            unresolved: list[str] = []
            budget = [4096]
            for value in values:
                member = application_member(value, frozenset(), budget)
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

        return [
            JunosSecurityPolicy(
                from_zone=from_zone,
                to_zone=to_zone,
                name=name,
                position=data["position"],
                active=data["active"],
                sources=self._unique(data["sources"]),
                destinations=self._unique(data["destinations"]),
                applications=self._unique(data["applications"]),
                action=data["action"],
                tunnel=data["tunnel"],
                log_events=self._unique(data["logs"]),
                source_resolution=self._address_resolution(
                    self._unique(data["sources"]),
                    from_zone,
                    address_object_values,
                    address_set_values,
                    zone_books,
                ),
                destination_resolution=self._address_resolution(
                    self._unique(data["destinations"]),
                    to_zone,
                    address_object_values,
                    address_set_values,
                    zone_books,
                ),
                application_resolution=application_resolution(
                    self._unique(data["applications"])
                ),
                inheritance_unknown=inheritance_unknown,
                source_networks=network_semantics(
                    self._unique(data["sources"]), from_zone
                ),
                destination_networks=network_semantics(
                    self._unique(data["destinations"]), to_zone
                ),
                services=application_semantics(
                    self._unique(data["applications"])
                ),
                unsupported_predicates=self._unique(data["unsupported"]),
                behavior_signature=tuple(sorted(set(data["behavior"]))),
                evidence=tuple(data["evidence"]),
            )
            for (from_zone, to_zone, name), data in policies.items()
        ]

    def get_ipsec_vpns(self) -> list[JunosIPSecVPN]:
        """Resolve attached or interface-bound SRX VPN proposal chains."""

        policies = self.get_security_policies()
        policy_attachments: dict[str, list[str]] = {}
        for policy in policies:
            if policy.active and policy.action == "permit" and policy.tunnel:
                policy_attachments.setdefault(policy.tunnel, []).append(
                    f"{policy.from_zone}->{policy.to_zone}:{policy.name}"
                )

        def objects(prefix: tuple[str, ...]) -> dict[str, dict]:
            result: dict[str, dict] = {}
            for statement in self.statements:
                path = statement.path
                if not self._is_prefix(prefix, path) or len(path) <= len(prefix):
                    continue
                name = path[len(prefix)]
                item = result.setdefault(
                    name,
                    {"present": False, "active": False, "paths": [], "evidence": []},
                )
                item["present"] = True
                item["evidence"].append(statement.evidence)
                if statement.active:
                    item["active"] = True
                    item["paths"].append(path[len(prefix) + 1 :])
            return result

        ike_proposals = objects(("security", "ike", "proposal"))
        ike_policies = objects(("security", "ike", "policy"))
        ike_gateways = objects(("security", "ike", "gateway"))
        ipsec_proposals = objects(("security", "ipsec", "proposal"))
        ipsec_policies = objects(("security", "ipsec", "policy"))
        vpns = objects(("security", "ipsec", "vpn"))

        def values(item: dict | None, field: tuple[str, ...]) -> tuple[str, ...]:
            if not item:
                return ()
            output = []
            for path in item["paths"]:
                for index in range(len(path) - len(field)):
                    if path[index : index + len(field)] == field:
                        value_index = index + len(field)
                        if value_index < len(path):
                            output.append(path[value_index])
            return self._unique(output)

        candidate_names = set(policy_attachments)
        candidate_names.update(
            name
            for name, item in vpns.items()
            if values(item, ("bind-interface",))
        )
        records = []
        for name in sorted(candidate_names):
            vpn = vpns.get(name)
            attachments = tuple(policy_attachments.get(name, ()))
            if vpn is not None and not vpn["active"]:
                active = False
            else:
                active = bool(attachments or values(vpn, ("bind-interface",)))
            bind_interface = next(iter(values(vpn, ("bind-interface",))), "")
            gateway_name = next(iter(values(vpn, ("ike", "gateway"))), "")
            ipsec_policy_name = next(
                iter(values(vpn, ("ike", "ipsec-policy"))), ""
            )
            gateway = ike_gateways.get(gateway_name)
            ike_policy_name = next(iter(values(gateway, ("ike-policy",))), "")
            ike_policy = ike_policies.get(ike_policy_name)
            selected_ike_proposals = values(ike_policy, ("proposals",))
            selected_ike_sets = values(ike_policy, ("proposal-set",))
            selected_ipsec_policy = ipsec_policies.get(ipsec_policy_name)
            selected_ipsec_proposals = values(
                selected_ipsec_policy, ("proposals",)
            )
            selected_ipsec_sets = values(selected_ipsec_policy, ("proposal-set",))
            chain_objects = (vpn, gateway, ike_policy, selected_ipsec_policy)
            resolution_state = (
                "resolved"
                if all(item is not None and item["active"] for item in chain_objects)
                and bool(selected_ike_proposals or selected_ike_sets)
                and bool(selected_ipsec_proposals or selected_ipsec_sets)
                else "unresolved"
            )
            ike_definitions = [ike_proposals.get(item) for item in selected_ike_proposals]
            ipsec_definitions = [
                ipsec_proposals.get(item) for item in selected_ipsec_proposals
            ]
            if any(item is None or not item["active"] for item in ike_definitions + ipsec_definitions):
                resolution_state = "unresolved"
            elif resolution_state == "resolved" and (
                selected_ike_sets or selected_ipsec_sets
            ):
                resolution_state = "vendor-default"
            evidence: list[ConfigEvidence] = []
            for item in chain_objects + tuple(ike_definitions) + tuple(ipsec_definitions):
                if item:
                    evidence.extend(item["evidence"])
            records.append(
                JunosIPSecVPN(
                    name=name,
                    active=active,
                    attachments=attachments,
                    bind_interface=bind_interface,
                    resolution_state=resolution_state,
                    ike_proposals=selected_ike_proposals,
                    ike_encryption=self._unique(
                        [value for item in ike_definitions for value in values(item, ("encryption-algorithm",))]
                    ),
                    ike_authentication=self._unique(
                        [value for item in ike_definitions for value in values(item, ("authentication-algorithm",))]
                    ),
                    ike_dh_groups=self._unique(
                        [value for item in ike_definitions for value in values(item, ("dh-group",))]
                    ),
                    ipsec_proposals=selected_ipsec_proposals,
                    ipsec_encryption=self._unique(
                        [value for item in ipsec_definitions for value in values(item, ("encryption-algorithm",))]
                    ),
                    ipsec_authentication=self._unique(
                        [value for item in ipsec_definitions for value in values(item, ("authentication-algorithm",))]
                    ),
                    pfs_dh_groups=values(
                        selected_ipsec_policy,
                        ("perfect-forward-secrecy", "keys"),
                    ),
                    evidence=tuple(dict.fromkeys(evidence)),
                )
            )
        return records

    def get_native_config(self) -> list[str]:
        return self.config

    def get_ntp_associations(self) -> list[JunosNTPAssociation]:
        trusted = {
            item.path[3]
            for item in self.get_active_statements(("system", "ntp", "trusted-key"))
            if len(item.path) > 3
        }
        keys: dict[str, tuple[str, bool, tuple[ConfigEvidence, ...]]] = {}
        for item in self.get_active_statements(("system", "ntp", "authentication-key")):
            if len(item.path) <= 3:
                continue
            key_id = item.path[3]
            suffix = item.path[4:]
            algorithm = ""
            material_present = False
            if "type" in suffix and suffix.index("type") + 1 < len(suffix):
                algorithm = suffix[suffix.index("type") + 1].casefold()
            if "value" in suffix and suffix.index("value") + 1 < len(suffix):
                material_present = True
            prior = keys.get(key_id)
            evidence = (prior[2] if prior else ()) + (item.evidence,)
            keys[key_id] = (
                algorithm or (prior[0] if prior else ""),
                material_present or (prior[1] if prior else False),
                evidence,
            )
        configured_associations: dict[
            tuple[str, str], tuple[str, tuple[ConfigEvidence, ...]]
        ] = {}
        for role in ("server", "peer"):
            for item in self.get_active_statements(("system", "ntp", role)):
                if len(item.path) <= 3:
                    continue
                address = item.path[3]
                suffix = item.path[4:]
                previous = configured_associations.get((role, address), ("", ()))
                key_id = previous[0]
                if "key" in suffix and suffix.index("key") + 1 < len(suffix):
                    key_id = suffix[suffix.index("key") + 1]
                configured_associations[(role, address)] = (
                    key_id,
                    previous[1] + (item.evidence,),
                )
        associations = []
        for (role, address), (key_id, association_evidence) in configured_associations.items():
            key = keys.get(key_id)
            if not key_id:
                state = "unauthenticated"
            elif key is None or key_id not in trusted or not key[0] or not key[1]:
                state = "unresolved"
            else:
                state = "authenticated"
            associations.append(JunosNTPAssociation(
                role=role,
                address=address,
                key_id=key_id,
                authentication_state=state,
                algorithm=key[0] if key else "",
                evidence=association_evidence + (key[2] if key else ()),
            ))
        return associations

    @staticmethod
    def _routing_scope(path: tuple[str, ...], protocol: str) -> tuple[str, int] | None:
        marker = ("protocols", protocol)
        for index in range(len(path) - 1):
            if path[index:index + 2] == marker:
                if index >= 2 and path[index - 2] == "routing-instances":
                    return path[index - 1], index
                return "default", index
        return None

    def _routing_keychains(self) -> dict[str, tuple[int, set[str], tuple[ConfigEvidence, ...]]]:
        chains: dict[str, dict] = {}
        prefix = ("security", "authentication-key-chains", "key-chain")
        for statement in self.get_active_statements(prefix):
            path = statement.path
            if len(path) < 4:
                continue
            name = path[3]
            data = chains.setdefault(name, {"keys": set(), "algorithms": set(), "evidence": []})
            data["evidence"].append(statement.evidence)
            if "key" in path[4:]:
                key_index = path.index("key", 4)
                if key_index + 1 < len(path):
                    data["keys"].add(path[key_index + 1])
            for keyword in ("authentication-algorithm", "algorithm"):
                if keyword in path[4:]:
                    index = path.index(keyword, 4)
                    if index + 1 < len(path):
                        data["algorithms"].add(path[index + 1].casefold())
        return {
            name: (len(data["keys"]), data["algorithms"], tuple(data["evidence"]))
            for name, data in chains.items()
        }

    def get_bgp_neighbors(self) -> list[JunosBGPNeighbor]:
        """Resolve Junos group inheritance without expanding apply-groups."""

        groups: dict[tuple[str, str], dict] = {}
        neighbors: dict[tuple[str, str, str], dict] = {}
        keychains = self._routing_keychains()
        global_unknown = any(
            statement.active and "apply-groups" in statement.path
            for statement in self.statements
        )
        for statement in self.statements:
            if not statement.active:
                continue
            scoped = self._routing_scope(statement.path, "bgp")
            if scoped is None:
                continue
            routing_instance, index = scoped
            tail = statement.path[index + 2:]
            if len(tail) < 2 or tail[0] != "group":
                continue
            group = tail[1]
            group_data = groups.setdefault((routing_instance, group), {"props": {}, "family_props": {}, "families": set(), "evidence": []})
            group_data["evidence"].append(statement.evidence)
            if "neighbor" in tail[2:]:
                neighbor_index = tail.index("neighbor", 2)
                if neighbor_index + 1 >= len(tail):
                    continue
                address = tail[neighbor_index + 1]
                data = neighbors.setdefault((routing_instance, group, address), {"props": {}, "family_props": {}, "families": set(), "evidence": []})
                data["evidence"].append(statement.evidence)
                prop_tail = tail[neighbor_index + 2:]
            else:
                data = group_data
                prop_tail = tail[2:]
            family = ""
            if "family" in prop_tail:
                family_index = prop_tail.index("family")
                family = " ".join(prop_tail[family_index + 1:family_index + 3])
                if family:
                    data["families"].add(family)
            selected_props = data["family_props"].setdefault(family, {}) if family else data["props"]
            for field in ("type", "peer-as", "authentication-key", "authentication-key-chain", "authentication-algorithm", "import", "export"):
                if field in prop_tail:
                    field_index = prop_tail.index(field)
                    value = prop_tail[field_index + 1] if field_index + 1 < len(prop_tail) else ""
                    selected_props[field] = value
            if "shutdown" in prop_tail:
                selected_props["shutdown"] = True
            if "prefix-limit" in prop_tail or "accepted-prefix-limit" in prop_tail:
                selected_props["prefix-limit"] = True

        records: list[JunosBGPNeighbor] = []
        for (routing_instance, group, address), neighbor in sorted(neighbors.items()):
            parent = groups[(routing_instance, group)]

            def prop(name: str, family: str = ""):
                for source in (
                    neighbor["family_props"].get(family, {}),
                    parent["family_props"].get(family, {}),
                    neighbor["props"],
                    parent["props"],
                ):
                    if name in source:
                        return source[name]
                return ""

            families = neighbor["families"] or parent["families"] or {"inet unicast"}
            peer_type = prop("type")
            peer_role = peer_type if peer_type in {"external", "internal"} else "unknown"
            static_key = bool(prop("authentication-key"))
            chain_name = prop("authentication-key-chain")
            algorithm = str(prop("authentication-algorithm")).casefold()
            chain = keychains.get(chain_name) if chain_name else None
            if static_key:
                auth_state, auth_method = "authenticated", "md5"
            elif chain_name:
                if chain is None or chain[0] == 0 or not algorithm:
                    auth_state = "unresolved"
                elif algorithm not in {"ao", "md5"}:
                    auth_state = "unknown"
                else:
                    auth_state = "authenticated"
                auth_method = algorithm
            else:
                auth_state, auth_method = "unauthenticated", ""
            evidence = tuple(dict.fromkeys(parent["evidence"] + neighbor["evidence"] + (list(chain[2]) if chain else [])))
            for family in sorted(families):
                records.append(JunosBGPNeighbor(
                    address=address,
                    group=group,
                    peer_role=peer_role,
                    routing_instance=routing_instance,
                    address_family=family,
                    active=not bool(prop("shutdown")),
                    authentication_state=auth_state,
                    authentication_method=auth_method,
                    inbound_policy=bool(prop("import", family)),
                    outbound_policy=bool(prop("export", family)),
                    prefix_limit=bool(prop("prefix-limit", family)),
                    inheritance_unknown=global_unknown,
                    evidence=evidence,
                ))
        return records

    def get_ospf_interfaces(self) -> list[JunosOSPFInterface]:
        """Return explicit OSPFv2 interface state; OSPFv3/IPsec is separate."""

        keychains = self._routing_keychains()
        records: dict[tuple[str, str, str], dict] = {}
        unknown_inheritance = any(
            statement.active and "apply-groups" in statement.path
            for statement in self.statements
        )
        for statement in self.statements:
            if not statement.active:
                continue
            scoped = self._routing_scope(statement.path, "ospf")
            if scoped is None:
                continue
            routing_instance, index = scoped
            tail = statement.path[index + 2:]
            if len(tail) < 4 or tail[0] != "area" or "interface" not in tail:
                continue
            area = tail[1]
            interface_index = tail.index("interface")
            if interface_index + 1 >= len(tail) or tail[interface_index + 1] == "all":
                continue
            interface = tail[interface_index + 1]
            data = records.setdefault((routing_instance, area, interface), {"passive": False, "disable": False, "mode": "", "chain": "", "key": False, "unknown": unknown_inheritance, "evidence": []})
            data["evidence"].append(statement.evidence)
            remainder = tail[interface_index + 2:]
            if "passive" in remainder:
                data["passive"] = True
            if "disable" in remainder:
                data["disable"] = True
            if "authentication" in remainder:
                auth_index = remainder.index("authentication")
                auth_tail = remainder[auth_index + 1:]
                if auth_tail:
                    data["mode"] = auth_tail[0].casefold()
                    if data["mode"] == "key-chain" and len(auth_tail) > 1:
                        data["chain"] = auth_tail[1]
                    if "key" in auth_tail or data["mode"] == "simple-password":
                        data["key"] = len(auth_tail) > 1

        output = []
        for (routing_instance, area, interface), data in sorted(records.items()):
            mode = data["mode"]
            chain = keychains.get(data["chain"]) if data["chain"] else None
            if data["unknown"] and not mode:
                state = "unknown"
            elif not mode:
                state = "unauthenticated"
            elif mode == "simple-password":
                state = "weak" if data["key"] else "unresolved"
            elif mode == "md5":
                state = "authenticated" if data["key"] else "unresolved"
            elif mode == "key-chain":
                if not chain or chain[0] == 0:
                    state = "unresolved"
                elif chain[1] and not chain[1].issubset({"hmac-sha-1", "hmac-sha-256", "hmac-sha-384", "hmac-sha-512", "md5"}):
                    state = "unknown"
                else:
                    state = "authenticated"
            else:
                state = "unknown"
            evidence = list(data["evidence"])
            if chain:
                evidence.extend(chain[2])
            output.append(JunosOSPFInterface(
                process="ospf",
                interface=interface,
                area=area,
                routing_instance=routing_instance,
                passive=bool(data["passive"]),
                active=not bool(data["disable"]),
                authentication_state=state,
                authentication_method=mode,
                key_reference=str(data["chain"]),
                evidence=tuple(dict.fromkeys(evidence)),
            ))
        return output

    def get_discovery_interfaces(self) -> list[JunosDiscoveryInterface]:
        """Resolve Junos LLDP all-interface inheritance and local overrides."""

        lldp = self.get_active_statements(("protocols", "lldp"))
        globally_disabled = any(statement.path == ("protocols", "lldp", "disable") for statement in lldp)
        all_statements = [
            statement for statement in lldp
            if statement.path[:4] == ("protocols", "lldp", "interface", "all")
        ]
        all_enabled = bool(all_statements) and not any(
            "disable" in statement.path[4:] for statement in all_statements
        )
        specific: dict[str, list[JunosStatement]] = {}
        for statement in lldp:
            path = statement.path
            if len(path) >= 4 and path[:3] == ("protocols", "lldp", "interface") and path[3] != "all":
                specific.setdefault(path[3], []).append(statement)

        configured_interfaces = {
            statement.path[1]
            for statement in self.get_active_statements(("interfaces",))
            if len(statement.path) > 1 and statement.path[1] != "interface-range"
        }
        configured_interfaces.update(name for name, _ in self.assessment_context.interface_roles)
        records = []
        for interface in sorted(configured_interfaces):
            statements = specific.get(interface, [])
            enabled = all_enabled
            if statements:
                enabled = not any("disable" in statement.path[4:] for statement in statements)
            if globally_disabled:
                enabled = False
            interface_statements = self.get_active_statements(("interfaces", interface))
            active = not any("disable" in statement.path[2:] for statement in interface_statements)
            evidence = tuple(
                dict.fromkeys(all_statements + statements)
            )
            records.append(JunosDiscoveryInterface(
                interface=interface,
                protocol="lldp",
                transmit=enabled,
                receive=enabled,
                active=active,
                role=self.assessment_context.role_for_interface(interface),
                evidence=tuple(statement.evidence for statement in evidence) + tuple(
                    statement.evidence for statement in interface_statements
                    if "disable" in statement.path[2:]
                ),
            ))
        return records

    def get_syslog_destinations(self) -> list[JunosSyslogDestination]:
        """Return effective per-host selectors without inferring transport defaults."""

        hosts: dict[str, dict] = {}
        prefix = ("system", "syslog", "host")
        severities = {
            "any", "emergency", "alert", "critical", "error", "warning",
            "notice", "info", "informational", "none",
        }
        properties = {
            "allow-duplicates", "exclude", "explicit-priority", "facility-override",
            "log-prefix", "match", "port", "routing-instance", "source-address",
            "structured-data", "transport",
        }
        for statement in self.get_active_statements(prefix):
            if len(statement.path) < 4:
                continue
            address = statement.path[3]
            data = hosts.setdefault(
                address,
                {
                    "selectors": [],
                    "transport": None,
                    "port": None,
                    "source_address": None,
                    "routing_instance": None,
                    "unknown_selector": False,
                    "evidence": [],
                },
            )
            data["evidence"].append(statement.evidence)
            if len(statement.path) < 5:
                continue
            field = statement.path[4].casefold()
            value = statement.path[5] if len(statement.path) > 5 else None
            if field == "transport":
                data["transport"] = value
            elif field == "port":
                data["port"] = value
            elif field == "source-address":
                data["source_address"] = value
            elif field == "routing-instance":
                data["routing_instance"] = value
            elif len(statement.path) > 5 and statement.path[5].casefold() in severities:
                selector = JunosSyslogSelector(
                    facility=statement.path[4].casefold(),
                    severity=statement.path[5].casefold(),
                    evidence=statement.evidence,
                )
                if selector not in data["selectors"]:
                    data["selectors"].append(selector)
            elif field not in properties and len(statement.path) > 5:
                # The syntax resembles a facility selector, but its severity is
                # outside the verified Junos vocabulary. Preserve uncertainty.
                data["unknown_selector"] = True
        return [
            JunosSyslogDestination(
                address=address,
                selectors=tuple(data["selectors"]),
                transport=data["transport"],
                port=data["port"],
                source_address=data["source_address"],
                routing_instance=data["routing_instance"],
                has_unknown_selector=data["unknown_selector"],
                evidence=tuple(data["evidence"]),
            )
            for address, data in hosts.items()
        ]

    def get_logging_destinations(self) -> list[LoggingDestination]:
        return [
            LoggingDestination(
                destination_type="syslog",
                state=ConfigurationState.ENABLED,
                address=destination.address,
                severity=",".join(
                    selector.severity
                    for selector in destination.selectors
                    if selector.severity is not None
                ) or None,
                scope=destination.routing_instance or "default",
                evidence=destination.evidence,
            )
            for destination in self.get_syslog_destinations()
        ]

    def get_crypto_settings(self) -> list[CryptoSetting]:
        settings = []
        fields = {
            "ciphers",
            "macs",
            "key-exchange",
            "hostkey-algorithm",
            "authentication-algorithm",
            "encryption-algorithm",
            "dh-group",
            "perfect-forward-secrecy",
        }
        for statement in self.get_active_statements():
            path = statement.path
            field_index = next(
                (index for index, token in enumerate(path) if token in fields),
                None,
            )
            if field_index is None or field_index + 1 >= len(path):
                continue
            settings.append(
                CryptoSetting(
                    name="/".join(path[: field_index + 1]),
                    value=" ".join(path[field_index + 1 :]),
                    state=ConfigurationState.CONFIGURED,
                    evidence=(statement.evidence,),
                )
            )
        return settings

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
        for policy in self.get_security_policies():
            policies.append(
                SecurityPolicy(
                    name=f"{policy.from_zone}->{policy.to_zone}/{policy.name}",
                    state=(
                        ConfigurationState.ENABLED
                        if policy.active
                        else ConfigurationState.DISABLED
                    ),
                    action=policy.action or "unknown",
                    position=policy.position,
                    scope=f"security:{policy.from_zone}->{policy.to_zone}",
                    source_interfaces=(policy.from_zone,),
                    destination_interfaces=(policy.to_zone,),
                    sources=policy.sources,
                    destinations=policy.destinations,
                    services=policy.applications,
                    tracking=",".join(policy.log_events) or None,
                    evidence=policy.evidence,
                )
            )

        default_policy = self.get_default_security_policy()
        if default_policy.resolution_state in {"explicit", "inherited"}:
            policies.append(SecurityPolicy(
                name="security/default-policy",
                state=ConfigurationState.ENABLED,
                action=default_policy.action or "unknown",
                position=len(policies) + 1,
                scope="security:unmatched-transit",
                evidence=default_policy.evidence,
            ))

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
            policies=(
                NormalizedCollection.unknown("Security default-policy depends on unresolved group or malformed state")
                if default_policy.resolution_state == "unknown"
                else NormalizedCollection.known(*policies)
            ),
            logging_destinations=NormalizedCollection.known(
                *self.get_logging_destinations()
            ),
            crypto_settings=NormalizedCollection.known(*self.get_crypto_settings()),
        )
