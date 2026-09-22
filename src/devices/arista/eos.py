"""Typed Arista EOS parser with scope-aware eAPI reconstruction."""

from __future__ import annotations

from dataclasses import dataclass
import re
import shlex
from typing import Any

from src.devices.cisco.ios import CiscoIOSParser
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
    ssl_profile: str
    client_certificate: bool
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


@dataclass(frozen=True)
class AristaAdministrator:
    name: str
    role: str
    privilege: int | None
    role_class: str
    role_resolved: bool
    credential_state: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class AristaAAAPolicy:
    policy_type: str
    service: str
    connection: str
    methods: tuple[str, ...] | None
    centralized: bool | None
    local_fallback: bool | None
    unauthenticated: bool | None
    resolution_state: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class AristaAccountingPolicy:
    service: str
    connection: str
    mode: str
    destinations: tuple[str, ...]
    resolution_state: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class AristaManagementSession:
    channel: str
    applicable: bool | None
    idle_timeout_minutes: int | None
    absolute_timeout_minutes: int | None
    resolution_state: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class AristaBannerPolicy:
    login_enabled: bool | None
    motd_enabled: bool | None
    resolution_state: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class AristaLockoutPolicy:
    enabled: bool | None
    failure_count: int | None
    duration_seconds: int | None
    window_seconds: int | None
    resolution_state: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class AristaSSLProfile:
    name: str
    certificate: str
    tls_versions: tuple[str, ...] | None
    resolution_state: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class AristaNTPKey:
    key_id: str
    algorithm: str
    trusted: bool
    material_present: bool
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class AristaNTPAssociation:
    address: str
    vrf: str
    key_id: str
    nts_profile: str
    authentication_state: str
    algorithm: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class AristaSNMPView:
    name: str
    included_subtrees: tuple[str, ...]
    excluded_subtrees: tuple[str, ...]
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class AristaSNMPGroup:
    name: str
    security_level: str
    read_view: str
    write_view: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class AristaSNMPUser:
    name: str
    group: str
    authentication: str
    privacy: str
    authentication_key_state: str
    privacy_key_state: str
    group_security_level: str
    group_resolved: bool
    read_view: str
    read_view_resolved: bool
    source_restricted: bool
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class AristaControlPlaneACL:
    family: str
    name: str
    resolution_state: str
    protection_state: str
    entries: tuple[str, ...]
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class AristaCoPPClass:
    name: str
    selector_reference: str
    selector_state: str
    actions: tuple[str, ...]
    enforcement_state: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class AristaCoPPPolicy:
    name: str
    resolution_state: str
    classes: tuple[AristaCoPPClass, ...]
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

    def _release_tuple(self) -> tuple[int, int, int] | None:
        match = re.match(r"(\d+)\.(\d+)\.(\d+)", self.get_version())
        return tuple(map(int, match.groups())) if match else None

    def supports_nts(self) -> bool | None:
        release = self._release_tuple()
        return None if release is None else release >= (4, 35, 0)

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

    @staticmethod
    def _active_acl_entries(
        children: list[AristaCommand], previous: tuple[str, ...] = ()
    ) -> tuple[str, ...]:
        """Apply common EOS ACL entry and sequence removals in source order."""

        entries = list(previous)
        for child in children:
            text = child.text.strip()
            if re.match(r"^(?:\d+\s+)?(?:permit|deny)\b", text, re.IGNORECASE):
                sequence = re.match(r"^(\d+)\s+", text)
                if sequence:
                    entries = [
                        item for item in entries
                        if not re.match(rf"^{re.escape(sequence.group(1))}\s+", item)
                    ]
                if text not in entries:
                    entries.append(text)
                continue
            removed = re.fullmatch(r"(?:no|default)\s+(.*)", text, re.IGNORECASE)
            if not removed:
                continue
            target = removed.group(1)
            if target.isdigit():
                entries = [item for item in entries if not re.match(rf"^{target}\s+", item)]
            elif re.match(r"^(?:permit|deny)\b", target, re.IGNORECASE):
                entries = [
                    item for item in entries
                    if re.sub(r"^\d+\s+", "", item, flags=re.IGNORECASE).casefold()
                    != target.casefold()
                ]
        return tuple(entries)

    @staticmethod
    def _is_unconditional_acl_permit(tokens: list[str]) -> bool:
        if tokens and tokens[0].isdigit():
            tokens = tokens[1:]
        if not tokens or tokens[0] != "permit":
            return False
        body = tokens[1:]
        while body and body[-1] in {"log", "tracked"}:
            body = body[:-1]
        return body in (["any"], ["ip", "any", "any"], ["ipv6", "any", "any"])

    def get_control_plane_acls(self) -> tuple[AristaControlPlaneACL, ...]:
        """Resolve only ACLs that are actively attached to the EOS control plane."""

        definitions: dict[tuple[str, str], tuple[str, tuple[str, ...], tuple[ConfigEvidence, ...]]] = {}
        for index, command in enumerate(self.commands):
            removed = re.fullmatch(
                r"(?:no|default)\s+(ip|ipv6)\s+access-list\s+(?:standard\s+|extended\s+)?(\S+)",
                command.text,
                re.IGNORECASE,
            )
            if command.indent == 0 and removed:
                definitions.pop((removed.group(1).casefold(), removed.group(2).casefold()), None)
                continue
            match = re.fullmatch(
                r"(ip|ipv6)\s+access-list\s+(?:standard\s+|extended\s+)?(\S+)",
                command.text,
                re.IGNORECASE,
            )
            if command.indent != 0 or not match:
                continue
            children = []
            for child in self.commands[index + 1 :]:
                if child.indent <= command.indent:
                    break
                children.append(child)
            previous = definitions.get((match.group(1).casefold(), match.group(2).casefold()))
            entries = self._active_acl_entries(children, previous[1] if previous else ())
            definitions[(match.group(1).casefold(), match.group(2).casefold())] = (
                match.group(2),
                entries,
                (self._evidence(command),) + tuple(self._evidence(item) for item in children),
            )

        attachments: dict[str, tuple[str, ConfigEvidence]] = {}
        for parent, children in self._blocks("system control-plane"):
            for command in children:
                match = re.fullmatch(r"(ip|ipv6)\s+access-group\s+(\S+)(?:\s+in)?", command.text, re.IGNORECASE)
                if match:
                    attachments[match.group(1).casefold()] = (match.group(2), self._evidence(command))
                    continue
                removed = re.fullmatch(
                    r"(?:no|default)\s+(ip|ipv6)\s+access-group(?:\s+\S+)?(?:\s+in)?",
                    command.text,
                    re.IGNORECASE,
                )
                if removed:
                    attachments.pop(removed.group(1).casefold(), None)

        resolved = []
        for family, (name, attachment_evidence) in attachments.items():
            definition = definitions.get((family, name.casefold()))
            if definition is None:
                resolved.append(AristaControlPlaneACL(
                    family=family,
                    name=name,
                    resolution_state="undefined",
                    protection_state="unknown",
                    entries=(),
                    evidence=(attachment_evidence,),
                ))
                continue
            original_name, entries, definition_evidence = definition
            if not entries:
                protection_state = "empty"
            else:
                restrictive = False
                unconditional_permit = False
                for entry in entries:
                    tokens = [token.casefold() for token in self._tokens(entry)]
                    if tokens and tokens[0].isdigit():
                        tokens = tokens[1:]
                    if not tokens:
                        continue
                    action = tokens[0]
                    unconditional = self._is_unconditional_acl_permit(tokens)
                    if action == "deny":
                        restrictive = True
                    if unconditional:
                        unconditional_permit = True
                        break
                # A non-empty list with no reachable catch-all permit ends in implicit deny.
                if not restrictive:
                    restrictive = not unconditional_permit
                protection_state = "effective" if restrictive else "no-enforcement"
            resolved.append(AristaControlPlaneACL(
                family=family,
                name=original_name,
                resolution_state="resolved",
                protection_state=protection_state,
                entries=entries,
                evidence=(attachment_evidence,) + definition_evidence,
            ))
        return tuple(resolved)

    def get_copp_policy(self) -> AristaCoPPPolicy:
        """Resolve exported EOS CoPP overrides while preserving omitted defaults as managed state."""

        acl_entries: dict[tuple[str, str], tuple[str, ...]] = {}
        for index, command in enumerate(self.commands):
            removed = re.fullmatch(
                r"(?:no|default)\s+(ip|ipv6)\s+access-list\s+(?:standard\s+|extended\s+)?(\S+)",
                command.text,
                re.IGNORECASE,
            )
            if command.indent == 0 and removed:
                acl_entries.pop((removed.group(1).casefold(), removed.group(2).casefold()), None)
                continue
            match = re.fullmatch(
                r"(ip|ipv6)\s+access-list\s+(?:standard\s+|extended\s+)?(\S+)",
                command.text,
                re.IGNORECASE,
            )
            if command.indent != 0 or not match:
                continue
            children = []
            for child in self.commands[index + 1 :]:
                if child.indent <= command.indent:
                    break
                children.append(child)
            key = (match.group(1).casefold(), match.group(2).casefold())
            acl_entries[key] = self._active_acl_entries(children, acl_entries.get(key, ()))

        acl_states = {}
        for key, entries in acl_entries.items():
            permitted = False
            for entry in entries:
                tokens = [token.casefold() for token in self._tokens(entry)]
                if tokens and tokens[0].isdigit():
                    tokens = tokens[1:]
                if tokens and tokens[0] == "permit":
                    permitted = True
                    break
            acl_states[key] = "resolved" if permitted else "empty-selector"

        class_maps: dict[str, tuple[str, str, str, tuple[ConfigEvidence, ...]]] = {}
        for index, command in enumerate(self.commands):
            removed = re.fullmatch(
                r"(?:no|default)\s+class-map\s+type\s+(?:control-plane|copp)\s+(?:match-(?:any|all)\s+)?(\S+)",
                command.text,
                re.IGNORECASE,
            )
            if command.indent == 0 and removed:
                class_maps.pop(removed.group(1).casefold(), None)
                continue
            match = re.fullmatch(
                r"class-map\s+type\s+(?:control-plane|copp)\s+(?:match-(?:any|all)\s+)?(\S+)",
                command.text,
                re.IGNORECASE,
            )
            if command.indent != 0 or not match:
                continue
            children = []
            for child in self.commands[index + 1 :]:
                if child.indent <= command.indent:
                    break
                children.append(child)
            selector = ""
            selector_family = ""
            for child in children:
                selector_match = re.fullmatch(
                    r"match\s+(ip|ipv6)\s+access-group(?:\s+name)?\s+(\S+)",
                    child.text,
                    re.IGNORECASE,
                )
                if selector_match:
                    selector_family = selector_match.group(1).casefold()
                    selector = selector_match.group(2)
                elif re.fullmatch(r"(?:no|default)\s+match(?:\s+.*)?", child.text, re.IGNORECASE):
                    selector = ""
                    selector_family = ""
            class_maps[match.group(1).casefold()] = (
                match.group(1),
                selector,
                selector_family,
                (self._evidence(command),) + tuple(self._evidence(item) for item in children),
            )

        blocks = self._blocks("policy-map type copp copp-system-policy")
        if not blocks:
            return AristaCoPPPolicy("copp-system-policy", "platform-managed", (), ())

        parent, children = blocks[-1]
        direct_indent = min((item.indent for item in children), default=parent.indent + 1)
        class_indexes = [
            index for index, item in enumerate(children)
            if item.indent == direct_indent and re.fullmatch(r"class\s+\S+", item.text, re.IGNORECASE)
        ]
        classes = []
        for position, index in enumerate(class_indexes):
            class_command = children[index]
            name = class_command.text.split(maxsplit=1)[1]
            boundary = class_indexes[position + 1] if position + 1 < len(class_indexes) else len(children)
            scoped = children[index + 1 : boundary]
            active_actions: dict[str, str] = {}
            for item in scoped:
                action = re.match(r"^(shape|bandwidth)\b", item.text, re.IGNORECASE)
                if action:
                    active_actions[action.group(1).casefold()] = item.text
                    continue
                removed_action = re.match(
                    r"^(?:no|default)\s+(shape|bandwidth)(?:\s+.*)?$",
                    item.text,
                    re.IGNORECASE,
                )
                if removed_action:
                    active_actions.pop(removed_action.group(1).casefold(), None)
            actions = tuple(active_actions.values())
            valid_action = any(
                any(token.isdigit() and int(token) > 0 for token in self._tokens(action))
                for action in actions
            )
            mapped = class_maps.get(name.casefold())
            if mapped:
                selector_reference = mapped[1]
                selector_state = (
                    acl_states.get((mapped[2], selector_reference.casefold()), "undefined-selector")
                    if selector_reference
                    else "empty-class"
                )
                class_evidence = mapped[3]
                enforcement = "effective" if selector_state == "resolved" and valid_action else "no-enforcement"
            elif name.casefold() == "class-default" or name.casefold().startswith("copp-system-"):
                selector_reference = ""
                selector_state = "platform-managed"
                class_evidence = ()
                enforcement = "effective" if valid_action else "platform-managed"
            else:
                selector_reference = ""
                selector_state = "undefined-class"
                class_evidence = ()
                enforcement = "unknown"
            classes.append(AristaCoPPClass(
                name=name,
                selector_reference=selector_reference,
                selector_state=selector_state,
                actions=actions,
                enforcement_state=enforcement,
                evidence=(self._evidence(class_command),)
                + tuple(self._evidence(item) for item in scoped)
                + class_evidence,
            ))
        return AristaCoPPPolicy(
            name="copp-system-policy",
            resolution_state="explicit" if classes else "platform-managed",
            classes=tuple(classes),
            evidence=(self._evidence(parent),) + tuple(self._evidence(item) for item in children),
        )

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
            ssl_profile = ""
            client_certificate = False
            for command in root_commands:
                if re.fullmatch(r"protocol\s+http(?:\s+(?:port\s+)?\d+)?", command.text, re.IGNORECASE):
                    http = True
                elif re.fullmatch(r"(?:no|default)\s+protocol\s+http", command.text, re.IGNORECASE):
                    http = False
                elif re.fullmatch(r"protocol\s+https(?:\s+(?:port\s+)?\d+)?", command.text, re.IGNORECASE):
                    https = True
                    ssl_profile = ""
                elif re.fullmatch(r"no\s+protocol\s+https", command.text, re.IGNORECASE):
                    https = False
                    ssl_profile = ""
                elif re.fullmatch(r"default\s+protocol\s+https", command.text, re.IGNORECASE):
                    https = True
                    ssl_profile = ""
                elif match := re.fullmatch(
                    r"protocol\s+https(?:\s+port\s+\d+)?\s+ssl\s+profile\s+(\S+)",
                    command.text,
                    re.IGNORECASE,
                ):
                    https = True
                    ssl_profile = match.group(1)
                elif re.fullmatch(
                    r"(?:no|default)\s+protocol\s+https\s+ssl\s+profile(?:\s+\S+)?",
                    command.text,
                    re.IGNORECASE,
                ):
                    ssl_profile = ""
                elif re.fullmatch(r"protocol\s+https\s+certificate", command.text, re.IGNORECASE):
                    client_certificate = True
                elif re.fullmatch(r"(?:no|default)\s+protocol\s+https\s+certificate", command.text, re.IGNORECASE):
                    client_certificate = False
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
                        ssl_profile=ssl_profile,
                        client_certificate=client_certificate,
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
                        ssl_profile=ssl_profile,
                        client_certificate=client_certificate,
                        evidence=(self._evidence(parent), self._evidence(vrf_command))
                        + tuple(self._evidence(item) for item in scoped),
                    )
                )
        return endpoints

    def get_remote_authentication(self) -> tuple[str, ...]:
        methods = {
            method.removeprefix("group:")
            for policy in self.get_aaa_policies()
            if policy.policy_type == "authentication"
            and policy.service == "login"
            and policy.connection == "default"
            and policy.methods is not None
            for method in policy.methods
            if method.startswith("group:")
        }
        return tuple(sorted(methods))

    def has_exec_authorization(self) -> bool:
        return any(
            policy.policy_type == "authorization"
            and policy.service == "exec"
            and policy.connection == "default"
            and policy.methods is not None
            and any(method.startswith("group:") for method in policy.methods)
            and not policy.unauthenticated
            for policy in self.get_aaa_policies()
        )

    @staticmethod
    def _method_list(tokens: list[str]) -> tuple[str, ...]:
        methods: list[str] = []
        index = 0
        while index < len(tokens):
            token = tokens[index].casefold()
            if token == "group" and index + 1 < len(tokens):
                methods.append(f"group:{tokens[index + 1].casefold()}")
                index += 2
            else:
                methods.append(token)
                index += 1
        return tuple(methods)

    def get_aaa_policies(self) -> list[AristaAAAPolicy]:
        policies: dict[tuple[str, str], AristaAAAPolicy] = {}
        expression = re.compile(
            r"(?P<reset>(?:no|default)\s+)?aaa\s+"
            r"(?P<kind>authentication|authorization)\s+"
            r"(?P<service>login|enable|exec|commands(?:\s+all)?)\s+"
            r"(?P<connection>default|console)(?:\s+(?P<methods>.+))?",
            re.IGNORECASE,
        )
        for command in self.commands:
            match = expression.fullmatch(command.text)
            if not match:
                continue
            service = match.group("service").casefold().replace(" ", "-")
            policy_type = match.group("kind").casefold()
            connection = match.group("connection").casefold()
            key = (f"{policy_type}:{service}", connection)
            if match.group("reset"):
                # EOS removes authentication lists back to local. Explicitly
                # resetting an authorization list instead installs the
                # documented `none` behavior, which permits the action.
                methods = ("local",) if policy_type == "authentication" else ("none",)
                policies[key] = AristaAAAPolicy(
                    policy_type, service, connection, methods, False,
                    "local" in methods, "none" in methods,
                    "explicit-reset", (self._evidence(command),),
                )
                continue
            methods = self._method_list(self._tokens(match.group("methods") or ""))
            centralized = any(item.startswith("group:") for item in methods)
            policies[key] = AristaAAAPolicy(
                policy_type=policy_type,
                service=service,
                connection=connection,
                methods=methods,
                centralized=centralized,
                local_fallback="local" in methods,
                unauthenticated="none" in methods,
                resolution_state="explicit",
                evidence=(self._evidence(command),),
            )
        return list(policies.values())

    def get_accounting_policies(self) -> list[AristaAccountingPolicy]:
        policies: dict[tuple[str, str], AristaAccountingPolicy] = {}
        expression = re.compile(
            r"(?P<reset>(?:no|default)\s+)?aaa\s+accounting\s+"
            r"(?P<service>exec|commands\s+all)\s+"
            r"(?P<connection>default|console)(?:\s+(?P<mode>start-stop|stop-only|stop|none))?"
            r"(?:\s+(?P<methods>.+))?",
            re.IGNORECASE,
        )
        for command in self.commands:
            match = expression.fullmatch(command.text)
            if not match:
                continue
            service = match.group("service").casefold().replace(" ", "-")
            connection = match.group("connection").casefold()
            key = (service, connection)
            if match.group("reset"):
                policies.pop(key, None)
                continue
            methods = self._method_list(self._tokens(match.group("methods") or ""))
            policies[key] = AristaAccountingPolicy(
                service=service,
                connection=connection,
                mode=(match.group("mode") or "").casefold(),
                destinations=methods,
                resolution_state="explicit",
                evidence=(self._evidence(command),),
            )
        return list(policies.values())

    def get_administrators(self) -> list[AristaAdministrator]:
        defined_roles = {"network-admin", "network-operator"}
        for command in self.commands:
            match = re.fullmatch(r"role\s+(\S+)", command.text, re.IGNORECASE)
            if match:
                defined_roles.add(match.group(1).casefold())
            elif match := re.fullmatch(r"(?:no|default)\s+role\s+(\S+)", command.text, re.IGNORECASE):
                defined_roles.discard(match.group(1).casefold())

        default_role = "network-operator"
        for command in self.commands:
            match = re.fullmatch(
                r"aaa\s+authorization\s+policy\s+local\s+default-role\s+(\S+)",
                command.text,
                re.IGNORECASE,
            )
            if match:
                default_role = match.group(1)
            elif re.fullmatch(
                r"(?:no|default)\s+aaa\s+authorization\s+policy\s+local\s+default-role(?:\s+\S+)?",
                command.text,
                re.IGNORECASE,
            ):
                default_role = "network-operator"

        credentials = {item.account.casefold(): item for item in self.get_credential_metadata()}
        administrators = []
        for user in self._local_users():
            role = user.role or default_role
            folded_role = role.casefold()
            credential = credentials.get(user.username.casefold())
            administrators.append(AristaAdministrator(
                name=user.username,
                role=role,
                privilege=user.privilege,
                role_class=(
                    "full-admin" if folded_role == "network-admin"
                    else "operator" if folded_role == "network-operator"
                    else "custom"
                ),
                role_resolved=folded_role in defined_roles,
                credential_state=(
                    credential.storage_assessment.value if credential else "not-exported"
                ),
                evidence=user.evidence + (credential.evidence if credential else ()),
            ))
        return administrators

    def get_management_sessions(self) -> list[AristaManagementSession]:
        sessions = []
        release = self._release_tuple()
        for channel in ("console", "ssh", "telnet"):
            blocks = self._blocks(f"management {channel}")
            reset_commands = [
                command for command in self.commands
                if command.indent == 0 and re.fullmatch(
                    rf"(?:no|default)\s+management\s+{channel}",
                    command.text,
                    re.IGNORECASE,
                )
            ]
            if not blocks and not reset_commands:
                continue
            applicable: bool | None = True if channel in {"console", "ssh"} else False
            idle: int | None = 0 if release is not None else None
            absolute: int | None = 0 if release is not None and release >= (4, 36, 0) else None
            resolution = "documented-default" if release is not None else "unknown-release"
            evidence: list[ConfigEvidence] = []
            events = [
                (parent.line_number, "block", parent, children)
                for parent, children in blocks
            ] + [
                (command.line_number, "reset", command, [])
                for command in reset_commands
            ]
            for _, event_type, parent, children in sorted(events):
                evidence.append(self._evidence(parent))
                if event_type == "reset":
                    applicable = True if channel in {"console", "ssh"} else False
                    idle = 0 if release is not None else None
                    absolute = 0 if release is not None and release >= (4, 36, 0) else None
                    resolution = "explicit-reset" if release is not None else "unknown-release"
                    continue
                for command in children:
                    tokens = self._tokens(command.text)
                    folded = [token.casefold() for token in tokens]
                    if folded == ["shutdown"]:
                        applicable = False
                    elif folded == ["no", "shutdown"]:
                        applicable = True
                    elif folded and folded[0] == "idle-timeout":
                        try:
                            idle = int(tokens[1])
                        except (IndexError, ValueError):
                            idle = None
                            resolution = "invalid"
                        else:
                            resolution = "explicit"
                    elif folded and folded[0] == "timeout":
                        if release is not None and release < (4, 36, 0):
                            absolute = None
                            resolution = "unsupported-release"
                        else:
                            try:
                                absolute = int(tokens[1])
                            except (IndexError, ValueError):
                                absolute = None
                                resolution = "invalid"
                            else:
                                resolution = "explicit"
                    elif folded[:2] in (["no", "idle-timeout"], ["default", "idle-timeout"]):
                        idle = 0 if release is not None else None
                    elif folded[:2] in (["no", "timeout"], ["default", "timeout"]):
                        absolute = 0 if release is not None and release >= (4, 36, 0) else None
                    else:
                        continue
                    evidence.append(self._evidence(command))
            sessions.append(AristaManagementSession(
                channel, applicable, idle, absolute, resolution, tuple(evidence)
            ))
        return sessions

    def get_banner_policy(self) -> AristaBannerPolicy:
        login: bool | None = False if self._release_tuple() is not None else None
        motd: bool | None = False if self._release_tuple() is not None else None
        resolution = "documented-default" if self._release_tuple() is not None else "unknown-release"
        evidence: list[ConfigEvidence] = []
        for command in self.commands:
            if re.fullmatch(r"banner\s+login(?:\s+.*)?", command.text, re.IGNORECASE):
                login = True
            elif re.fullmatch(r"(?:no|default)\s+banner\s+login", command.text, re.IGNORECASE):
                login = False
            elif re.fullmatch(r"banner\s+motd(?:\s+.*)?", command.text, re.IGNORECASE):
                motd = True
            elif re.fullmatch(r"(?:no|default)\s+banner\s+motd", command.text, re.IGNORECASE):
                motd = False
            else:
                continue
            resolution = "explicit"
            evidence.append(self._evidence(command))
        return AristaBannerPolicy(login, motd, resolution, tuple(evidence))

    def get_lockout_policy(self) -> AristaLockoutPolicy:
        enabled: bool | None = False if self._release_tuple() is not None else None
        failures: int | None = None
        duration: int | None = None
        window: int | None = None
        resolution = "documented-default" if self._release_tuple() is not None else "unknown-release"
        evidence: tuple[ConfigEvidence, ...] = ()
        for command in self.commands:
            tokens = self._tokens(command.text)
            folded = [token.casefold() for token in tokens]
            if folded[:5] == ["aaa", "authentication", "policy", "lockout", "failure"]:
                enabled = True
                try:
                    failures = int(tokens[5])
                    duration = int(tokens[folded.index("duration") + 1])
                    window = int(tokens[folded.index("window") + 1]) if "window" in folded else 86400
                except (IndexError, ValueError):
                    failures = duration = window = None
                    resolution = "invalid"
                else:
                    resolution = "explicit"
                evidence = (self._evidence(command),)
            elif folded[:6] in (
                ["no", "aaa", "authentication", "policy", "lockout", "failure"],
                ["default", "aaa", "authentication", "policy", "lockout", "failure"],
            ):
                enabled = False if self._release_tuple() is not None else None
                failures = duration = window = None
                resolution = "explicit-reset" if enabled is False else "unknown-release"
                evidence = (self._evidence(command),)
        return AristaLockoutPolicy(enabled, failures, duration, window, resolution, evidence)

    def get_ssl_profiles(self) -> dict[str, AristaSSLProfile]:
        profiles: dict[str, AristaSSLProfile] = {}
        for index, command in enumerate(self.commands):
            removed = re.fullmatch(
                r"(?:no|default)\s+ssl\s+profile\s+(\S+)",
                command.text,
                re.IGNORECASE,
            )
            if removed:
                profiles.pop(removed.group(1).casefold(), None)
                continue
            match = re.fullmatch(r"ssl\s+profile\s+(\S+)", command.text, re.IGNORECASE)
            if not match:
                continue
            previous = profiles.get(match.group(1).casefold())
            children = []
            for child in self.commands[index + 1:]:
                if child.indent <= command.indent:
                    break
                children.append(child)
            certificate = previous.certificate if previous else ""
            versions: set[str] | None = (
                set(previous.tls_versions)
                if previous and previous.tls_versions is not None
                else None
            )
            resolution = previous.resolution_state if previous else "explicit-empty"
            for child in children:
                tokens = self._tokens(child.text)
                folded = [token.casefold() for token in tokens]
                if folded and folded[0] == "certificate" and len(tokens) > 1:
                    certificate = tokens[1]
                    resolution = "explicit"
                elif folded[:2] == ["no", "certificate"]:
                    certificate = ""
                elif folded[:2] == ["tls", "versions"]:
                    numeric = {value for value in folded[2:] if value in {"1.0", "1.1", "1.2", "1.3"}}
                    if "remove" in folded:
                        versions = versions - numeric if versions is not None else None
                        resolution = "partial-removal" if versions is None else "explicit"
                    elif "add" in folded:
                        versions = (versions or set()) | numeric
                        resolution = "partial-addition" if len(versions) == len(numeric) else "explicit"
                    else:
                        versions = numeric
                        resolution = "explicit"
                elif folded[:3] in (["no", "tls", "versions"], ["default", "tls", "versions"]):
                    versions = None
                    resolution = "explicit-reset"
            profiles[match.group(1).casefold()] = AristaSSLProfile(
                name=match.group(1),
                certificate=certificate,
                tls_versions=tuple(sorted(versions)) if versions is not None else None,
                resolution_state=resolution,
                evidence=(previous.evidence if previous else ())
                + (self._evidence(command),)
                + tuple(self._evidence(item) for item in children),
            )
        return profiles

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
        users: dict[str, LocalUser] = {}
        for command in self.commands:
            tokens = self._tokens(command.text)
            lowered = [token.casefold() for token in tokens]
            if len(tokens) >= 3 and lowered[0] in {"no", "default"} and lowered[1] == "username":
                if len(tokens) == 3:
                    users.pop(tokens[2].casefold(), None)
                continue
            if len(tokens) < 2 or lowered[0] != "username":
                continue
            account = tokens[1]
            previous = users.get(account.casefold())
            privilege = previous.privilege if previous else None
            role = previous.role if previous else None
            if "privilege" in lowered:
                index = lowered.index("privilege")
                if index + 1 < len(tokens) and tokens[index + 1].isdigit():
                    privilege = int(tokens[index + 1])
            if "role" in lowered:
                index = lowered.index("role")
                if index + 1 < len(tokens):
                    role = tokens[index + 1]
            users[account.casefold()] = LocalUser(
                username=account,
                state=ConfigurationState.ENABLED,
                role=role,
                privilege=privilege,
                authentication="local",
                scope="switch",
                evidence=(ConfigEvidence(
                    f"username {account} <credential redacted>",
                    self.config_filepath,
                    command.line_number,
                ),),
            )
        return list(users.values())

    @staticmethod
    def _eos_storage(storage_type: str, value: str) -> CredentialStorageAssessment:
        if storage_type == "none" or not value:
            return CredentialStorageAssessment.EMPTY
        if storage_type == "0":
            return CredentialStorageAssessment.PLAINTEXT
        if storage_type == "5":
            return (
                CredentialStorageAssessment.WEAK_HASH
                if value.startswith("$1$") and len(value) > 3
                else CredentialStorageAssessment.MALFORMED
            )
        if storage_type == "sha512":
            return (
                CredentialStorageAssessment.APPROVED_HASH
                if value.startswith("$6$") and len(value) > 3
                else CredentialStorageAssessment.MALFORMED
            )
        return CredentialStorageAssessment.UNKNOWN

    @staticmethod
    def _eos_default(
        storage: CredentialStorageAssessment, value: str
    ) -> DefaultCredentialAssessment:
        if storage == CredentialStorageAssessment.EMPTY:
            return DefaultCredentialAssessment.MATCH
        if storage != CredentialStorageAssessment.PLAINTEXT:
            return DefaultCredentialAssessment.NOT_EVALUATED
        return (
            DefaultCredentialAssessment.MATCH
            if value.casefold() in {"admin", "arista", "password"}
            else DefaultCredentialAssessment.NO_MATCH
        )

    def get_credential_metadata(self) -> list[CredentialMetadata]:
        credentials: dict[str, CredentialMetadata] = {}
        for command in self.commands:
            tokens = self._tokens(command.text)
            lowered = [token.casefold() for token in tokens]
            if len(tokens) >= 3 and lowered[0] in {"no", "default"} and lowered[1] == "username":
                if len(tokens) != 3:
                    continue
                account = tokens[2]
                credentials.pop(account.casefold(), None)
                if lowered[0] == "default" and account.casefold() == "admin":
                    credentials["admin"] = CredentialMetadata(
                        account="admin",
                        context="local_user",
                        method="nopassword",
                        storage_type="none",
                        storage_assessment=CredentialStorageAssessment.EMPTY,
                        default_assessment=DefaultCredentialAssessment.MATCH,
                        evidence=(self._evidence(command),),
                    )
                continue
            if len(tokens) < 3 or lowered[0] != "username":
                continue
            account = tokens[1]
            method = ""
            storage_type = ""
            value = ""
            if "nopassword" in lowered[2:]:
                method = "nopassword"
                storage_type = "none"
            elif "secret" in lowered[2:]:
                method = "secret"
                index = lowered.index("secret") + 1
                if index < len(tokens) and lowered[index] in {"0", "5", "sha5", "sha512"}:
                    marker = lowered[index]
                    storage_type = "sha512" if marker in {"sha5", "sha512"} else marker
                    index += 1
                else:
                    storage_type = "0"
                value = tokens[index] if index < len(tokens) else ""
            else:
                # A role/privilege-only update retains the existing credential.
                continue
            storage = self._eos_storage(storage_type, value)
            credentials[account.casefold()] = CredentialMetadata(
                account=account,
                context="local_user",
                method=method,
                storage_type=storage_type,
                storage_assessment=storage,
                default_assessment=self._eos_default(storage, value),
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
                evidence=(ConfigEvidence(
                    f"username {account} {method} {storage_type} <credential redacted>",
                    self.config_filepath,
                    command.line_number,
                ),),
            )
        return list(credentials.values())

    def get_additional_credential_metadata(self) -> list[CredentialMetadata]:
        """Classify configured RADIUS keys and literal TerminAttr ingestion auth."""

        credentials: dict[str, CredentialMetadata] = {}

        def record(account: str, context: str, marker: str, value: str,
                   command: AristaCommand) -> None:
            if not value or value.casefold() in {"<redacted>", "redacted", "<hidden>", "***"}:
                storage = CredentialStorageAssessment.UNKNOWN
            elif marker == "7":
                storage = (CredentialStorageAssessment.WEAK_REVERSIBLE
                           if re.fullmatch(r"(?:0[0-9]|1[0-5])[0-9A-Fa-f]+", value)
                           else CredentialStorageAssessment.MALFORMED)
            elif marker == "0":
                storage = CredentialStorageAssessment.PLAINTEXT
            else:
                storage = CredentialStorageAssessment.UNKNOWN
            credentials[account.casefold()] = CredentialMetadata(
                account=account,
                context=context,
                method="ingestauth" if context == "terminattr_ingestauth" else "key",
                storage_type=marker,
                storage_assessment=storage,
                default_assessment=DefaultCredentialAssessment.NOT_EVALUATED,
                plaintext_length=len(value) if storage == CredentialStorageAssessment.PLAINTEXT else None,
                evidence=(ConfigEvidence(
                    f"{account} {'-ingestauth=key' if context == 'terminattr_ingestauth' else 'key'} {marker} <credential redacted>",
                    self.config_filepath, command.line_number,
                ),),
            )

        daemon = False
        daemon_active = True
        daemon_exec: AristaCommand | None = None
        for command in self.commands:
            tokens = self._tokens(command.text)
            lowered = [token.casefold() for token in tokens]
            if command.indent == 0:
                daemon = lowered[:2] == ["daemon", "terminattr"]
                if daemon:
                    daemon_active = True
                    daemon_exec = None
                elif lowered[:3] == ["no", "daemon", "terminattr"]:
                    credentials.pop("daemon terminattr", None)
                if lowered[:2] == ["radius-server", "key"]:
                    marker = tokens[2] if len(tokens) > 2 and tokens[2].isdigit() else "0"
                    index = 3 if len(tokens) > 2 and tokens[2].isdigit() else 2
                    record("radius-server", "radius_key", marker, tokens[index] if len(tokens) > index else "", command)
                elif lowered[:3] in (["no", "radius-server", "key"], ["default", "radius-server", "key"]):
                    credentials.pop("radius-server", None)
                elif lowered[:2] == ["radius-server", "host"] and len(tokens) > 3:
                    account = f"radius-server host {tokens[2]}"
                    if "key" in lowered[3:]:
                        index = lowered.index("key", 3) + 1
                        marker = tokens[index] if index < len(tokens) and tokens[index].isdigit() else "0"
                        if index < len(tokens) and tokens[index].isdigit():
                            index += 1
                        record(account, "radius_key", marker, tokens[index] if index < len(tokens) else "", command)
                elif lowered[:3] in (["no", "radius-server", "host"], ["default", "radius-server", "host"]) and len(tokens) > 3:
                    credentials.pop(f"radius-server host {tokens[3].casefold()}", None)
                continue
            if daemon:
                if lowered[:1] == ["exec"]:
                    daemon_exec = command
                    credentials.pop("daemon terminattr", None)
                elif lowered[:2] == ["no", "shutdown"]:
                    daemon_active = True
                elif lowered[:1] == ["shutdown"]:
                    daemon_active = False
                if daemon_exec and daemon_active:
                    match = re.search(r"(?:^|\s)-ingestauth=key,([^\s]+)", daemon_exec.text)
                    if match:
                        record("daemon TerminAttr", "terminattr_ingestauth", "0", match.group(1), daemon_exec)
                if not daemon_active:
                    credentials.pop("daemon terminattr", None)
        return list(credentials.values())

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

    def get_snmp_default_vrf_enabled(self) -> bool:
        state = True
        for command in self.commands:
            if re.fullmatch(r"no\s+snmp-server\s+vrf\s+default", command.text, re.IGNORECASE):
                state = False
            elif re.fullmatch(
                r"(?:snmp-server|default\s+snmp-server)\s+vrf\s+default",
                command.text,
                re.IGNORECASE,
            ):
                state = True
        return state

    def has_secure_snmpv3_user(self) -> bool:
        return any(
            user.group_resolved
            and user.group_security_level == "priv"
            and user.authentication.startswith("sha")
            and user.privacy.startswith("aes")
            for user in self.get_snmpv3_relationships()[2]
        )

    def get_snmpv3_relationships(
        self,
    ) -> tuple[list[AristaSNMPView], list[AristaSNMPGroup], list[AristaSNMPUser]]:
        view_entries: dict[tuple[str, str], tuple[str, ConfigEvidence]] = {}
        groups: dict[str, AristaSNMPGroup] = {}
        raw_users: dict[
            str, tuple[str, str, str, str, str, str, ConfigEvidence]
        ] = {}
        source_acls: dict[str, ConfigEvidence] = {}

        for command in self.commands:
            tokens = self._tokens(command.text)
            folded = [token.casefold() for token in tokens]
            if not folded:
                continue

            offset = 1 if folded[0] in {"no", "default"} else 0
            removed = bool(offset)
            if folded[offset : offset + 2] == ["snmp-server", "view"] and len(tokens) >= offset + 4:
                name, subtree = tokens[offset + 2], tokens[offset + 3]
                key = (name.casefold(), subtree.casefold())
                if removed:
                    view_entries.pop(key, None)
                elif len(tokens) > offset + 4 and folded[offset + 4] in {"include", "included", "exclude", "excluded"}:
                    inclusion = "included" if folded[offset + 4].startswith("include") else "excluded"
                    view_entries[key] = (
                        inclusion,
                        ConfigEvidence(
                            f"snmp-server view {name} {subtree} {inclusion}",
                            self.config_filepath,
                            command.line_number,
                        ),
                    )
                continue

            if folded[offset : offset + 2] == ["snmp-server", "group"] and len(tokens) >= offset + 4:
                name = tokens[offset + 2]
                if removed:
                    groups.pop(name.casefold(), None)
                    continue
                tail = folded[offset + 3 :]
                if "v3" not in tail:
                    continue
                index = tail.index("v3") + 1
                level = tail[index] if index < len(tail) and tail[index] in {"noauth", "auth", "priv"} else "noauth"

                def option(keyword: str) -> str:
                    return tail[tail.index(keyword) + 1] if keyword in tail and tail.index(keyword) + 1 < len(tail) else ""

                read_view, write_view = option("read"), option("write")
                groups[name.casefold()] = AristaSNMPGroup(
                    name=name,
                    security_level=level,
                    read_view=read_view,
                    write_view=write_view,
                    evidence=(ConfigEvidence(
                        f"snmp-server group {name} v3 {level} read {read_view or '<default>'} "
                        f"write {write_view or '<none>'}",
                        self.config_filepath,
                        command.line_number,
                    ),),
                )
                continue

            if folded[offset : offset + 2] == ["snmp-server", "user"] and len(tokens) >= offset + 4:
                name, group_name = tokens[offset + 2], tokens[offset + 3]
                if removed:
                    raw_users.pop(name.casefold(), None)
                    continue
                tail = tokens[offset + 4 :]
                lowered = [token.casefold() for token in tail]
                if "v3" not in lowered:
                    continue

                def secret_option(keyword: str) -> tuple[str, str]:
                    if keyword not in lowered:
                        return "", "missing"
                    index = lowered.index(keyword) + 1
                    if index >= len(lowered):
                        return "", "unknown"
                    algorithm = lowered[index]
                    index += 1
                    if algorithm == "aes" and index < len(lowered) and lowered[index] in {"128", "192", "256"}:
                        algorithm = f"aes{lowered[index]}"
                        index += 1
                    if index < len(lowered) and lowered[index] in {"0", "7", "encrypted", "localized"}:
                        index += 1
                    state = "present" if index < len(lowered) and lowered[index] not in {"auth", "priv"} else "unknown"
                    return algorithm, state

                authentication, auth_state = secret_option("auth")
                privacy, privacy_state = secret_option("priv")
                raw_users[name.casefold()] = (
                    name,
                    group_name,
                    authentication,
                    privacy,
                    auth_state,
                    privacy_state,
                    ConfigEvidence(
                        f"snmp-server user {name} {group_name} v3 auth {authentication or 'none'} "
                        f"<key {auth_state}> priv {privacy or 'none'} <key {privacy_state}>",
                        self.config_filepath,
                        command.line_number,
                    ),
                )
                continue

            acl = re.fullmatch(
                r"(?:(?:no|default)\s+)?snmp-server\s+(?:ipv4|ipv6)\s+access-list\s+(\S+)(?:\s+vrf\s+(\S+))?",
                command.text,
                re.IGNORECASE,
            )
            if acl:
                vrf = (acl.group(2) or "default").casefold()
                if removed:
                    source_acls.pop(vrf, None)
                else:
                    source_acls[vrf] = self._evidence(command)
                continue

        by_view: dict[str, list[tuple[str, str, ConfigEvidence]]] = {}
        for (name, subtree), (inclusion, evidence) in view_entries.items():
            by_view.setdefault(name, []).append((subtree, inclusion, evidence))
        views = [
            AristaSNMPView(
                name=name,
                included_subtrees=tuple(item[0] for item in entries if item[1] == "included"),
                excluded_subtrees=tuple(item[0] for item in entries if item[1] == "excluded"),
                evidence=tuple(item[2] for item in entries),
            )
            for name, entries in by_view.items()
        ]
        users = []
        for name, group_name, authentication, privacy, auth_state, privacy_state, evidence in raw_users.values():
            group = groups.get(group_name.casefold())
            read_view = group.read_view if group else ""
            users.append(AristaSNMPUser(
                name=name,
                group=group_name,
                authentication=authentication,
                privacy=privacy,
                authentication_key_state=auth_state,
                privacy_key_state=privacy_state,
                group_security_level=group.security_level if group else "",
                group_resolved=group is not None,
                read_view=read_view,
                read_view_resolved=not read_view or read_view.casefold() in by_view,
                source_restricted="default" in source_acls,
                evidence=(evidence,) + (group.evidence if group else ()),
            ))
        return views, list(groups.values()), users if self.get_snmp_default_vrf_enabled() else []

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

    def get_ntp_keys(self) -> dict[str, AristaNTPKey]:
        configured: dict[str, tuple[str, bool, ConfigEvidence]] = {}
        trusted: set[str] = set()
        for command in self.commands:
            removed = re.fullmatch(r"(?:no|default) ntp authentication-key\s+(\S+)", command.text, re.IGNORECASE)
            key = re.fullmatch(r"ntp authentication-key\s+(\S+)\s+(\S+)\s+(\S+)", command.text, re.IGNORECASE)
            trust = re.fullmatch(r"(?P<no>(?:no|default)\s+)?ntp trusted(?:-key| key)\s+(\S+)", command.text, re.IGNORECASE)
            if removed:
                configured.pop(removed.group(1), None)
            elif key:
                key_id, algorithm, material = key.groups()
                configured[key_id] = (
                    algorithm.casefold(),
                    bool(material),
                    ConfigEvidence(
                        f"ntp authentication-key {key_id} {algorithm.casefold()} <key redacted>",
                        self.config_filepath,
                        command.line_number,
                    ),
                )
            elif trust:
                key_id = trust.group(2)
                if trust.group("no"):
                    trusted.discard(key_id)
                else:
                    trusted.add(key_id)
        return {
            key_id: AristaNTPKey(
                key_id=key_id,
                algorithm=algorithm,
                trusted=key_id in trusted,
                material_present=material,
                evidence=(evidence,),
            )
            for key_id, (algorithm, material, evidence) in configured.items()
        }

    def get_ntp_authentication_enabled(self) -> bool | None:
        enabled: bool | None = False if self._release_tuple() is not None else None
        for command in self.commands:
            if re.fullmatch(r"ntp authenticate", command.text, re.IGNORECASE):
                enabled = True
            elif re.fullmatch(r"(?:no|default) ntp authenticate", command.text, re.IGNORECASE):
                enabled = False
        return enabled

    def get_nts_profiles(self) -> dict[str, tuple[bool, tuple[ConfigEvidence, ...]]]:
        profiles: dict[str, tuple[bool, tuple[ConfigEvidence, ...]]] = {}
        for index, command in enumerate(self.commands):
            match = re.fullmatch(r"ssl profile\s+(\S+)", command.text, re.IGNORECASE)
            if not match:
                continue
            children = []
            for child in self.commands[index + 1 :]:
                if child.indent <= command.indent:
                    break
                children.append(child)
            trust_commands = [
                child
                for child in children
                if re.fullmatch(r"trust certificate\s+\S+", child.text, re.IGNORECASE)
            ]
            profiles[match.group(1).casefold()] = (
                bool(trust_commands),
                (self._evidence(command),) + tuple(self._evidence(item) for item in trust_commands),
            )
        return profiles

    @staticmethod
    def _ntp_server_parts(text: str) -> tuple[bool, str, str, str, str, bool] | None:
        tokens = text.split()
        if tokens[:2] == ["ntp", "server"]:
            removed = False
            index = 2
        elif tokens[:3] in (["no", "ntp", "server"], ["default", "ntp", "server"]):
            removed = True
            index = 3
        else:
            return None
        vrf = "default"
        if index < len(tokens) and tokens[index] == "vrf":
            if index + 2 >= len(tokens):
                return None
            vrf = tokens[index + 1]
            index += 2
        if index >= len(tokens):
            return None
        address = tokens[index]
        tail = tokens[index + 1 :]
        key_id = ""
        nts_profile = ""
        malformed = False
        if "key" in tail:
            key_index = tail.index("key")
            if key_index + 1 < len(tail) and tail[key_index + 1].isdigit():
                key_id = tail[key_index + 1]
            else:
                malformed = True
        if "ssl" in tail:
            ssl_index = tail.index("ssl")
            if ssl_index + 2 < len(tail) and tail[ssl_index + 1] == "profile":
                nts_profile = tail[ssl_index + 2]
            else:
                malformed = True
        return removed, vrf, address, key_id, nts_profile, malformed

    def get_ntp_associations(self) -> list[AristaNTPAssociation]:
        active: dict[tuple[str, str], tuple[str, str, bool, ConfigEvidence]] = {}
        for command in self.commands:
            parsed = self._ntp_server_parts(command.text.casefold())
            if parsed is None:
                continue
            removed, vrf, address, key_id, nts_profile, malformed = parsed
            identity = (vrf, address)
            if removed:
                active.pop(identity, None)
            else:
                active[identity] = (key_id, nts_profile, malformed, self._evidence(command))
        keys = self.get_ntp_keys()
        profiles = self.get_nts_profiles()
        global_auth = self.get_ntp_authentication_enabled()
        associations = []
        for (vrf, address), (key_id, nts_profile, malformed, server_evidence) in active.items():
            key = keys.get(key_id)
            profile = profiles.get(nts_profile)
            if malformed or (key_id and nts_profile):
                state = "unknown"
                algorithm = ""
            elif nts_profile:
                if not profile or not profile[0] or self.supports_nts() is False:
                    state = "unresolved"
                elif self.supports_nts() is None:
                    state = "unknown"
                else:
                    state = "authenticated"
                algorithm = "nts"
            elif not key_id:
                state = "unresolved" if global_auth is True else "unauthenticated"
                algorithm = ""
            elif global_auth is None:
                state = "unknown"
                algorithm = key.algorithm if key else ""
            elif not global_auth:
                state = "unauthenticated"
                algorithm = key.algorithm if key else ""
            elif key is None or not key.trusted or not key.material_present:
                state = "unresolved"
                algorithm = key.algorithm if key else ""
            else:
                state = "authenticated"
                algorithm = key.algorithm
            evidence = (server_evidence,) + (key.evidence if key else ())
            if profile:
                evidence += profile[1]
            associations.append(AristaNTPAssociation(
                address=address,
                vrf=vrf,
                key_id=key_id,
                nts_profile=nts_profile,
                authentication_state=state,
                algorithm=algorithm,
                evidence=evidence,
            ))
        return associations

    def get_ntp_servers(self) -> tuple[str, ...]:
        return tuple(item.address for item in self.get_ntp_associations())

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


__all__ = [
    "AristaAAAPolicy",
    "AristaAccountingPolicy",
    "AristaAdministrator",
    "AristaBannerPolicy",
    "AristaCommand",
    "AristaEAPIEndpoint",
    "AristaEOSParser",
    "AristaLockoutPolicy",
    "AristaManagementSession",
    "AristaNTPAssociation",
    "AristaNTPKey",
    "AristaSSLProfile",
    "AristaSSHSettings",
]
