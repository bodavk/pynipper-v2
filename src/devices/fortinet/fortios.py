"""FortiOS configuration parser and normalized model adapter."""

from dataclasses import dataclass
import re
import shlex
from typing import Dict, Iterator, List, Tuple, Union

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


FortiValue = Union[str, List[str], Dict[str, "FortiValue"]]
FortiDict = Dict[str, FortiValue]


class FortiOSParseError(ValueError):
    def __init__(self, source: str, line_number: int, message: str):
        self.source = source
        self.line_number = line_number
        self.message = message
        super().__init__(f"{source}:{line_number}: {message}")


@dataclass
class _Frame:
    kind: str
    name: str
    node: FortiDict


@dataclass(frozen=True)
class FortiAAAServerProfile:
    """Resolved FortiOS AAA server evidence without any shared-secret material."""

    scope: str
    name: str
    protocol: str
    transport: str
    servers: Tuple[str, ...]
    port: str | None
    ca_certificate: str | None
    client_certificate: str | None
    server_identity_check: str
    tls_minimum_version: str | None
    require_message_authenticator: str
    source_ip: str | None
    source_interface: str | None
    interface_select_method: str | None
    interface: str | None
    vrf: str | None
    administrator_groups: Tuple[str, ...]
    administrators: Tuple[str, ...]
    protected_path: bool
    radsec_supported: bool
    evidence: Tuple[ConfigEvidence, ...]

    @property
    def is_bound_for_administration(self) -> bool:
        return bool(self.administrators)


@dataclass(frozen=True)
class FortiInspectionProfile:
    profile_type: str
    name: str
    definition_scope: str
    resolution_state: str
    content_state: str
    actions: Tuple[str, ...]
    evidence: Tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class FortiSecurityInspection:
    policy_name: str
    scope: str
    attachment_mode: str
    attachment_name: str
    resolution_state: str
    profiles: Tuple[FortiInspectionProfile, ...]
    evidence: Tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class FortiLocalInPolicy:
    family: str
    scope: str
    name: str
    position: int
    enabled: bool
    interface: str
    sources: Tuple[str, ...]
    destinations: Tuple[str, ...]
    services: Tuple[str, ...]
    schedule: str
    action: str
    source_negated: bool
    destination_negated: bool
    service_negated: bool
    evidence: Tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class FortiIPSecTunnel:
    scope: str
    name: str
    phase1_name: str
    active: bool
    resolution_state: str
    ike_version: str
    phase1_proposals: Tuple[str, ...]
    phase1_dh_groups: Tuple[str, ...]
    phase2_proposals: Tuple[str, ...]
    pfs: str
    phase2_dh_groups: Tuple[str, ...]
    replay: str
    evidence: Tuple[ConfigEvidence, ...]


class FortiOSParser(BaseDeviceParser):

    device_type = "FORTIOS"
    _SECRET_FIELDS = {
        "auth-password",
        "auth-pwd",
        "key",
        "password",
        "passphrase",
        "passwd",
        "private-key",
        "priv-password",
        "priv-pwd",
        "psksecret",
        "secret",
    }
    _INSPECTION_PROFILE_SECTIONS = {
        "application-list": "application list",
        "av-profile": "antivirus profile",
        "cifs-profile": "cifs profile",
        "dlp-profile": "dlp profile",
        "dnsfilter-profile": "dnsfilter profile",
        "emailfilter-profile": "emailfilter profile",
        "file-filter-profile": "file-filter profile",
        "icap-profile": "icap profile",
        "ips-sensor": "ips sensor",
        "sctp-filter-profile": "sctp-filter profile",
        "ssh-filter-profile": "ssh-filter profile",
        "videofilter-profile": "videofilter profile",
        "waf-profile": "waf profile",
        "webfilter-profile": "webfilter profile",
    }

    def __init__(self, config_filepath: str):
        super().__init__(config_filepath)
        self.evidence: Dict[Tuple[str, ...], ConfigEvidence] = {}
        self.parse_diagnostics: List[str] = []
        self.metadata: Dict[str, str] = {}
        self.config = self._parse_config(config_filepath)

    @staticmethod
    def _tokens(line: str, source: str, line_number: int) -> List[str]:
        try:
            return shlex.split(line, comments=False, posix=True)
        except ValueError as exc:
            raise FortiOSParseError(source, line_number, f"Invalid quoting: {exc}") from exc

    @staticmethod
    def _value(tokens: List[str]) -> Union[str, List[str]]:
        if not tokens:
            return ""
        if len(tokens) == 1:
            return tokens[0]
        return tokens

    @staticmethod
    def _as_list(value: object) -> List[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item) for item in value]
        return [str(value)]

    def _record_evidence(self, path: Tuple[str, ...], text: str, line_number: int) -> None:
        tokens = text.split(None, 2)
        if (
            len(tokens) >= 2
            and tokens[0].lower() in {"set", "select", "append"}
            and tokens[1].lower() in self._SECRET_FIELDS
        ):
            text = f"{tokens[0]} {tokens[1]} <redacted>"
        self.evidence[path] = ConfigEvidence(
            text=text,
            source=self.config_filepath,
            line_number=line_number,
        )

    def _parse_header(self, line: str, line_number: int) -> None:
        match = re.match(
            r"^#config-version=(?P<model>[^-:]+)-(?P<version>\d+(?:\.\d+)+)",
            line,
        )
        if match:
            self.metadata.update(match.groupdict())
            self._record_evidence(("metadata", "version"), line, line_number)

    def _require_frame(self, frames: List[_Frame], kind: str, line_number: int, command: str) -> _Frame:
        if not frames or frames[-1].kind != kind:
            raise FortiOSParseError(
                self.config_filepath,
                line_number,
                f"'{command}' has no open {kind} block",
            )
        return frames[-1]

    def _reorder_object(
        self,
        node: FortiDict,
        object_name: str,
        relation: str,
        reference_name: str,
        line_number: int,
    ) -> None:
        if object_name not in node or reference_name not in node:
            self.parse_diagnostics.append(
                f"{self.config_filepath}:{line_number}: move references an unknown object"
            )
            return
        entries = list(node.items())
        moving = next(item for item in entries if item[0] == object_name)
        entries = [item for item in entries if item[0] != object_name]
        reference_index = next(i for i, item in enumerate(entries) if item[0] == reference_name)
        insert_at = reference_index if relation == "before" else reference_index + 1
        entries.insert(insert_at, moving)
        node.clear()
        node.update(entries)

    def _parse_config(self, filepath: str) -> FortiDict:
        config: FortiDict = {}
        frames: List[_Frame] = []

        with open(filepath, "r", encoding="utf-8", errors="replace") as config_file:
            for line_number, raw_line in enumerate(config_file, start=1):
                line = raw_line.strip()
                if not line:
                    continue
                if line.startswith("#"):
                    self._parse_header(line, line_number)
                    continue

                tokens = self._tokens(line, filepath, line_number)
                if not tokens:
                    continue
                command, arguments = tokens[0].lower(), tokens[1:]
                current = frames[-1].node if frames else config
                path = tuple(frame.name for frame in frames)

                if command == "config":
                    if not arguments:
                        raise FortiOSParseError(filepath, line_number, "config requires a section name")
                    section_name = " ".join(arguments)
                    existing = current.setdefault(section_name, {})
                    if not isinstance(existing, dict):
                        raise FortiOSParseError(
                            filepath, line_number, f"Section {section_name!r} conflicts with a value"
                        )
                    frames.append(_Frame("config", section_name, existing))
                    self._record_evidence(path + (section_name,), line, line_number)
                elif command == "edit":
                    self._require_frame(frames, "config", line_number, command)
                    if not arguments:
                        raise FortiOSParseError(filepath, line_number, "edit requires an object name")
                    object_name = " ".join(arguments)
                    existing = current.setdefault(object_name, {})
                    if not isinstance(existing, dict):
                        raise FortiOSParseError(
                            filepath, line_number, f"Object {object_name!r} conflicts with a value"
                        )
                    frames.append(_Frame("edit", object_name, existing))
                    self._record_evidence(path + (object_name,), line, line_number)
                elif command == "next":
                    self._require_frame(frames, "edit", line_number, command)
                    frames.pop()
                elif command == "end":
                    self._require_frame(frames, "config", line_number, command)
                    frames.pop()
                elif command in {"set", "select", "append", "unselect"}:
                    if not frames:
                        raise FortiOSParseError(filepath, line_number, f"'{command}' outside a config block")
                    if not arguments:
                        raise FortiOSParseError(filepath, line_number, f"{command} requires a field name")
                    key, values = arguments[0], arguments[1:]
                    if command in {"set", "select"}:
                        current[key] = self._value(values)
                    elif command == "append":
                        current[key] = self._as_list(current.get(key)) + values
                    else:
                        removed = set(values)
                        remaining = [item for item in self._as_list(current.get(key)) if item not in removed]
                        if remaining:
                            current[key] = remaining[0] if len(remaining) == 1 else remaining
                        else:
                            current.pop(key, None)
                    self._record_evidence(path + (key,), line, line_number)
                elif command in {"unset", "purge"}:
                    if not frames or not arguments:
                        raise FortiOSParseError(filepath, line_number, f"{command} requires a field")
                    current.pop(arguments[0], None)
                    self._record_evidence(path + (arguments[0],), line, line_number)
                elif command == "delete":
                    self._require_frame(frames, "config", line_number, command)
                    if not arguments:
                        raise FortiOSParseError(filepath, line_number, "delete requires an object name")
                    current.pop(" ".join(arguments), None)
                elif command == "rename":
                    self._require_frame(frames, "config", line_number, command)
                    if len(arguments) < 3 or "to" not in arguments:
                        raise FortiOSParseError(filepath, line_number, "rename requires '<old> to <new>'")
                    split_at = arguments.index("to")
                    old_name = " ".join(arguments[:split_at])
                    new_name = " ".join(arguments[split_at + 1:])
                    if old_name not in current:
                        self.parse_diagnostics.append(
                            f"{filepath}:{line_number}: rename references unknown object {old_name!r}"
                        )
                    else:
                        current[new_name] = current.pop(old_name)
                elif command == "move":
                    self._require_frame(frames, "config", line_number, command)
                    if len(arguments) != 3 or arguments[1] not in {"before", "after"}:
                        raise FortiOSParseError(
                            filepath, line_number, "move requires '<object> before|after <object>'"
                        )
                    self._reorder_object(current, arguments[0], arguments[1], arguments[2], line_number)
                else:
                    self.parse_diagnostics.append(
                        f"{filepath}:{line_number}: unsupported command {tokens[0]!r}"
                    )

        if frames:
            open_path = " / ".join(frame.name for frame in frames)
            raise FortiOSParseError(
                filepath,
                line_number if "line_number" in locals() else 1,
                f"Unexpected end of file; unclosed block: {open_path}",
            )
        return config

    def _scoped_sections(self, section_name: str) -> Iterator[Tuple[str, FortiDict, Tuple[str, ...]]]:
        direct = self.config.get(section_name)
        if isinstance(direct, dict):
            yield "root", direct, (section_name,)

        global_scope = self.config.get("global")
        if isinstance(global_scope, dict):
            section = global_scope.get(section_name)
            if isinstance(section, dict):
                yield "global", section, ("global", section_name)

        vdoms = self.config.get("vdom")
        if isinstance(vdoms, dict):
            for vdom_name, vdom_config in vdoms.items():
                if not isinstance(vdom_config, dict):
                    continue
                section = vdom_config.get(section_name)
                if isinstance(section, dict):
                    yield str(vdom_name), section, ("vdom", str(vdom_name), section_name)

    def iter_scoped_sections(
        self, section_name: str
    ) -> Iterator[Tuple[str, FortiDict, Tuple[str, ...]]]:
        """Yield root, global, and per-VDOM sections with their evidence path."""

        yield from self._scoped_sections(section_name)

    def _field_evidence(self, path: Tuple[str, ...]) -> Tuple[ConfigEvidence, ...]:
        item = self.evidence.get(path)
        return (item,) if item is not None else ()

    def field_evidence(self, path: Tuple[str, ...]) -> Tuple[ConfigEvidence, ...]:
        """Return already-redacted evidence for a parsed field or object."""

        return self._field_evidence(path)

    def iter_administrators(self):
        for scope, section, path in self._scoped_sections("system admin"):
            for username, settings in section.items():
                if isinstance(settings, dict):
                    yield scope, str(username), settings, path + (str(username),)

    def iter_interfaces(self):
        for scope, section, path in self._scoped_sections("system interface"):
            for name, settings in section.items():
                if isinstance(settings, dict):
                    yield scope, str(name), settings, path + (str(name),)

    def _supports_radsec(self) -> bool:
        numbers = re.findall(r"\d+", self.get_version())
        return len(numbers) >= 2 and (int(numbers[0]), int(numbers[1])) >= (7, 4)

    def get_aaa_server_profiles(self) -> Tuple[FortiAAAServerProfile, ...]:
        """Resolve RADIUS profiles through user groups to enabled remote administrators."""

        group_servers: Dict[Tuple[str, str], set[str]] = {}
        for scope, section, _ in self._scoped_sections("user group"):
            for group_name, settings in section.items():
                if not isinstance(settings, dict):
                    continue
                references = set(self._as_list(settings.get("member")))
                matches = settings.get("match")
                if isinstance(matches, dict):
                    for match in matches.values():
                        if isinstance(match, dict):
                            references.update(self._as_list(match.get("server-name")))
                group_servers[(scope, str(group_name))] = references

        admin_groups: Dict[str, Dict[str, set[str]]] = {}
        for scope, section, _ in self._scoped_sections("system admin"):
            for admin_name, settings in section.items():
                if not isinstance(settings, dict):
                    continue
                if settings.get("status", "enable") == "disable":
                    continue
                if settings.get("remote-auth") != "enable":
                    continue
                group = str(settings.get("remote-group", ""))
                if group:
                    admin_groups.setdefault(scope, {}).setdefault(group, set()).add(str(admin_name))

        profiles = []
        for scope, section, section_path in self._scoped_sections("user radius"):
            for name, settings in section.items():
                if not isinstance(settings, dict) or settings.get("status", "enable") == "disable":
                    continue
                profile_name = str(name)
                bound_groups = []
                bound_admins = set()
                for group, administrators in admin_groups.get(scope, {}).items():
                    references = group_servers.get((scope, group), set())
                    if profile_name in references or settings.get("all-usergroup") == "enable":
                        bound_groups.append(group)
                        bound_admins.update(administrators)

                path = section_path + (profile_name,)
                evidence = []
                for field in (
                    "server", "secondary-server", "tertiary-server", "radius-port",
                    "transport-protocol", "ca-cert", "client-cert", "server-identity-check",
                    "tls-min-proto-version", "require-message-authenticator", "source-ip",
                    "source-ip-interface", "interface-select-method", "interface", "vrf-select",
                ):
                    evidence.extend(self._field_evidence(path + (field,)))
                if not evidence:
                    evidence.extend(self._field_evidence(path))

                profiles.append(
                    FortiAAAServerProfile(
                        scope=scope,
                        name=profile_name,
                        protocol="radius",
                        transport=str(settings.get("transport-protocol", "udp")).lower(),
                        servers=tuple(
                            " ".join(self._as_list(settings[field]))
                            for field in ("server", "secondary-server", "tertiary-server")
                            if settings.get(field)
                        ),
                        port=str(settings.get("radius-port")) if settings.get("radius-port") else None,
                        ca_certificate=str(settings.get("ca-cert")) if settings.get("ca-cert") else None,
                        client_certificate=(
                            str(settings.get("client-cert")) if settings.get("client-cert") else None
                        ),
                        server_identity_check=str(
                            settings.get("server-identity-check", "enable")
                        ).lower(),
                        tls_minimum_version=(
                            str(settings.get("tls-min-proto-version"))
                            if settings.get("tls-min-proto-version") else None
                        ),
                        require_message_authenticator=str(
                            settings.get("require-message-authenticator", "enable")
                        ).lower(),
                        source_ip=str(settings.get("source-ip")) if settings.get("source-ip") else None,
                        source_interface=(
                            str(settings.get("source-ip-interface"))
                            if settings.get("source-ip-interface") else None
                        ),
                        interface_select_method=(
                            str(settings.get("interface-select-method"))
                            if settings.get("interface-select-method") else None
                        ),
                        interface=str(settings.get("interface")) if settings.get("interface") else None,
                        vrf=str(settings.get("vrf-select")) if settings.get("vrf-select") else None,
                        administrator_groups=tuple(sorted(bound_groups)),
                        administrators=tuple(sorted(bound_admins)),
                        protected_path=self.assessment_context.aaa_profile_has_protected_path(
                            scope, profile_name
                        ),
                        radsec_supported=self._supports_radsec(),
                        evidence=tuple(evidence),
                    )
                )
        return tuple(profiles)

    def get_hostname(self) -> str:
        for _, section, _ in self._scoped_sections("system global"):
            hostname = section.get("hostname")
            if isinstance(hostname, str) and hostname:
                return hostname
        return "fortigate-device"

    def get_version(self) -> str:
        return self.metadata.get("version", "?")

    def get_model(self) -> str:
        return self.metadata.get("model", "?")

    def get_users(self) -> list[dict]:
        users = []
        for scope, section, _ in self._scoped_sections("system admin"):
            for username, settings in section.items():
                if isinstance(settings, dict):
                    users.append(
                        {
                            "username": str(username),
                            "scope": scope,
                            "profile": settings.get("accprofile", ""),
                            "status": settings.get("status", "enable"),
                        }
                    )
        return users

    def get_services(self) -> dict:
        services = {"http": False, "https": False, "ssh": False, "telnet": False}
        for _, section, _ in self._scoped_sections("system interface"):
            for settings in section.values():
                if not isinstance(settings, dict):
                    continue
                if settings.get("status") == "down":
                    continue
                for protocol in self._as_list(settings.get("allowaccess")):
                    if protocol in services:
                        services[protocol] = True
        return services

    def get_administrator_trust(self) -> list[dict]:
        administrators = []
        for scope, section, path in self._scoped_sections("system admin"):
            for username, settings in section.items():
                if not isinstance(settings, dict):
                    continue
                trusted_hosts = []
                for key, value in settings.items():
                    if str(key).lower().startswith(("trusthost", "ip6-trusthost")):
                        trusted_hosts.append(" ".join(self._as_list(value)))
                administrators.append(
                    {
                        "username": str(username),
                        "scope": scope,
                        "enabled": settings.get("status", "enable") != "disable",
                        "trusted_hosts": tuple(trusted_hosts),
                        "evidence": self._field_evidence(path + (str(username),)),
                    }
                )
        return administrators

    def iter_firewall_policies(self):
        for scope, section, path in self._scoped_sections("firewall policy"):
            for position, (name, settings) in enumerate(section.items(), start=1):
                if isinstance(settings, dict):
                    yield scope, position, str(name), settings, path + (str(name),)

    def get_local_in_policies(self) -> Tuple[FortiLocalInPolicy, ...]:
        """Return local-device traffic rules separately from transit policies."""

        policies: List[FortiLocalInPolicy] = []
        for family, section_name in (
            ("ipv4", "firewall local-in-policy"),
            ("ipv6", "firewall local-in-policy6"),
        ):
            for scope, section, path in self._scoped_sections(section_name):
                for position, (name, settings) in enumerate(section.items(), start=1):
                    if not isinstance(settings, dict):
                        continue
                    object_path = path + (str(name),)
                    policies.append(
                        FortiLocalInPolicy(
                            family=family,
                            scope=scope,
                            name=str(name),
                            position=position,
                            enabled=str(settings.get("status", "enable")).casefold()
                            != "disable",
                            interface=str(settings.get("intf", "any")),
                            sources=tuple(self._as_list(settings.get("srcaddr"))),
                            destinations=tuple(self._as_list(settings.get("dstaddr"))),
                            services=tuple(self._as_list(settings.get("service"))),
                            schedule=str(settings.get("schedule", "")),
                            action=str(settings.get("action", "deny")).casefold(),
                            source_negated=str(
                                settings.get("srcaddr-negate", "disable")
                            ).casefold()
                            == "enable",
                            destination_negated=str(
                                settings.get("dstaddr-negate", "disable")
                            ).casefold()
                            == "enable",
                            service_negated=str(
                                settings.get("service-negate", "disable")
                            ).casefold()
                            == "enable",
                            evidence=self._field_evidence(object_path),
                        )
                    )
        return tuple(policies)

    def get_ipsec_tunnels(self) -> Tuple[FortiIPSecTunnel, ...]:
        """Resolve enabled phase2-to-phase1 bindings without claiming negotiation."""

        phase1: Dict[Tuple[str, str], Tuple[FortiDict, Tuple[str, ...]]] = {}
        for section_name in ("vpn ipsec phase1-interface", "vpn ipsec phase1"):
            for scope, section, path in self._scoped_sections(section_name):
                for name, settings in section.items():
                    if isinstance(settings, dict):
                        phase1[(scope, str(name))] = (settings, path + (str(name),))

        tunnels: List[FortiIPSecTunnel] = []
        for section_name in ("vpn ipsec phase2-interface", "vpn ipsec phase2"):
            for scope, section, path in self._scoped_sections(section_name):
                for name, settings in section.items():
                    if not isinstance(settings, dict):
                        continue
                    phase1_name = str(settings.get("phase1name", ""))
                    parent = phase1.get((scope, phase1_name))
                    phase2_enabled = str(settings.get("status", "enable")).casefold() != "disable"
                    phase1_enabled = bool(parent) and str(
                        parent[0].get("status", "enable")
                    ).casefold() != "disable"
                    if not phase1_name:
                        resolution_state = "unresolved"
                    elif parent is None:
                        resolution_state = "unresolved"
                    else:
                        resolution_state = "resolved"
                    evidence = self._field_evidence(path + (str(name),))
                    if parent is not None:
                        evidence += self._field_evidence(parent[1])
                    tunnels.append(
                        FortiIPSecTunnel(
                            scope=scope,
                            name=str(name),
                            phase1_name=phase1_name,
                            active=phase2_enabled and (parent is None or phase1_enabled),
                            resolution_state=resolution_state,
                            ike_version=str(parent[0].get("ike-version", "1"))
                            if parent
                            else "",
                            phase1_proposals=tuple(
                                self._as_list(parent[0].get("proposal"))
                            )
                            if parent
                            else (),
                            phase1_dh_groups=tuple(
                                self._as_list(parent[0].get("dhgrp"))
                            )
                            if parent
                            else (),
                            phase2_proposals=tuple(
                                self._as_list(settings.get("proposal"))
                            ),
                            pfs=str(settings.get("pfs", "enable")).casefold(),
                            phase2_dh_groups=tuple(
                                self._as_list(settings.get("dhgrp"))
                            ),
                            replay=str(settings.get("replay", "enable")).casefold(),
                            evidence=evidence,
                        )
                    )
        return tuple(tunnels)

    @classmethod
    def inspection_profile_fields(cls) -> Tuple[str, ...]:
        return tuple(cls._INSPECTION_PROFILE_SECTIONS)

    @property
    def fortimanager_inheritance_unknown(self) -> bool:
        for _, settings, _ in self._scoped_sections("system central-management"):
            if str(settings.get("type", "")).casefold() == "fortimanager":
                return True
        return False

    @staticmethod
    def _inspection_actions(settings: FortiDict) -> Tuple[str, ...]:
        actions: List[str] = []

        def visit(node: FortiValue) -> None:
            if not isinstance(node, dict):
                return
            for key, value in node.items():
                key_text = str(key).casefold()
                if key_text == "action":
                    actions.extend(item.casefold() for item in FortiOSParser._as_list(value))
                elif key_text == "default-action" and str(value).casefold() == "pass":
                    actions.append("pass")
                visit(value)

        visit(settings)
        return tuple(dict.fromkeys(actions))

    @staticmethod
    def _meaningful_profile_settings(settings: FortiDict) -> FortiDict:
        ignored = {"comment", "comments", "extended-log", "replacemsg-group"}
        return {
            str(key): value
            for key, value in settings.items()
            if str(key).casefold() not in ignored
        }

    def _profile_content_state(
        self, profile_type: str, settings: FortiDict
    ) -> Tuple[str, Tuple[str, ...]]:
        meaningful = self._meaningful_profile_settings(settings)
        if profile_type == "ips-sensor":
            entries = meaningful.get("entries")
            active_entries = []
            if isinstance(entries, dict):
                active_entries = [
                    entry
                    for entry in entries.values()
                    if isinstance(entry, dict)
                    and str(entry.get("status", "default")).casefold() != "disable"
                ]
            botnet = str(meaningful.get("scan-botnet-connections", "disable")).casefold()
            malicious_url = str(meaningful.get("block-malicious-url", "disable")).casefold()
            if not active_entries and botnet == "disable" and malicious_url != "enable":
                return "empty", ()
            entry_actions: List[str] = []
            for entry in active_entries:
                action = str(entry.get("action", "default")).casefold()
                default_action = str(entry.get("default-action", "all")).casefold()
                if action == "default" and default_action == "pass":
                    entry_actions.append("pass")
                elif action:
                    entry_actions.append(action)
            actions = tuple(dict.fromkeys(entry_actions))
            if botnet in {"monitor"}:
                actions = tuple(dict.fromkeys(actions + ("monitor",)))
            elif botnet == "block" or malicious_url == "enable":
                actions = tuple(dict.fromkeys(actions + ("block",)))
        else:
            if not meaningful:
                return "empty", ()
            actions = self._inspection_actions(meaningful)
        if actions and all(action in {"allow", "alert", "monitor", "pass"} for action in actions):
            return "nonblocking", actions
        return "configured", actions

    @staticmethod
    def _resolution_scopes(scope: str) -> Tuple[str, ...]:
        ordered = [scope]
        if scope != "global":
            ordered.append("global")
        if scope != "root":
            ordered.append("root")
        return tuple(dict.fromkeys(ordered))

    def _resolve_scoped_object(
        self, section_name: str, object_name: str, scope: str
    ) -> Tuple[str, FortiDict, Tuple[str, ...]] | None:
        sections = list(self._scoped_sections(section_name))
        for candidate_scope in self._resolution_scopes(scope):
            for found_scope, section, path in sections:
                settings = section.get(object_name)
                if found_scope == candidate_scope and isinstance(settings, dict):
                    return found_scope, settings, path + (object_name,)
        return None

    def _resolve_inspection_profile(
        self, profile_type: str, name: str, policy_scope: str
    ) -> FortiInspectionProfile:
        section_name = self._INSPECTION_PROFILE_SECTIONS[profile_type]
        resolved = self._resolve_scoped_object(section_name, name, policy_scope)
        if resolved is not None:
            scope, settings, path = resolved
            content_state, actions = self._profile_content_state(profile_type, settings)
            return FortiInspectionProfile(
                profile_type=profile_type,
                name=name,
                definition_scope=scope,
                resolution_state="resolved",
                content_state=content_state,
                actions=actions,
                evidence=self._field_evidence(path),
            )
        if name.casefold() in {"all_default", "default"}:
            return FortiInspectionProfile(
                profile_type=profile_type,
                name=name,
                definition_scope="builtin",
                resolution_state="builtin",
                content_state="vendor-default",
                actions=(),
                evidence=(),
            )
        state = "unknown-inherited" if self.fortimanager_inheritance_unknown else "unresolved"
        return FortiInspectionProfile(
            profile_type=profile_type,
            name=name,
            definition_scope="",
            resolution_state=state,
            content_state="unknown",
            actions=(),
            evidence=(),
        )

    def get_security_inspection(self) -> Tuple[FortiSecurityInspection, ...]:
        """Resolve UTM attachments for active accept policies by VDOM/global scope."""

        inspections: List[FortiSecurityInspection] = []
        for scope, _, name, settings, path in self.iter_firewall_policies():
            if str(settings.get("status", "enable")).casefold() == "disable":
                continue
            if str(settings.get("action", "deny")).casefold() != "accept":
                continue
            if str(settings.get("utm-status", "disable")).casefold() != "enable":
                continue
            evidence = self._field_evidence(path)
            if str(settings.get("profile-type", "single")).casefold() == "group":
                group_name = str(settings.get("profile-group", ""))
                if not group_name:
                    continue
                resolved_group = self._resolve_scoped_object(
                    "firewall profile-group", group_name, scope
                )
                if resolved_group is None:
                    state = (
                        "unknown-inherited"
                        if self.fortimanager_inheritance_unknown
                        else "unresolved"
                    )
                    profiles: Tuple[FortiInspectionProfile, ...] = ()
                    group_evidence: Tuple[ConfigEvidence, ...] = ()
                else:
                    _, group, group_path = resolved_group
                    members = [
                        (profile_type, str(group.get(profile_type, "")))
                        for profile_type in self._INSPECTION_PROFILE_SECTIONS
                        if str(group.get(profile_type, ""))
                    ]
                    state = "resolved" if members else "empty"
                    profiles = tuple(
                        self._resolve_inspection_profile(profile_type, member, scope)
                        for profile_type, member in members
                    )
                    group_evidence = self._field_evidence(group_path)
                inspections.append(
                    FortiSecurityInspection(
                        policy_name=name,
                        scope=scope,
                        attachment_mode="group",
                        attachment_name=group_name,
                        resolution_state=state,
                        profiles=profiles,
                        evidence=evidence + group_evidence,
                    )
                )
                continue

            members = [
                (profile_type, str(settings.get(profile_type, "")))
                for profile_type in self._INSPECTION_PROFILE_SECTIONS
                if str(settings.get(profile_type, ""))
            ]
            if members:
                inspections.append(
                    FortiSecurityInspection(
                        policy_name=name,
                        scope=scope,
                        attachment_mode="profiles",
                        attachment_name="individual profiles",
                        resolution_state="resolved",
                        profiles=tuple(
                            self._resolve_inspection_profile(profile_type, member, scope)
                            for profile_type, member in members
                        ),
                        evidence=evidence,
                    )
                )
        return tuple(inspections)

    def get_native_config(self) -> object:
        return self.config

    def get_normalized_config(self) -> NormalizedConfig:
        hostname = NormalizedValue.unknown("Hostname is absent")
        for _, section, path in self._scoped_sections("system global"):
            value = section.get("hostname")
            if isinstance(value, str) and value:
                hostname = NormalizedValue.known(value, *self._field_evidence(path + ("hostname",)))
                break

        version = NormalizedValue.unknown("FortiOS config-version header is absent")
        model = NormalizedValue.unknown("FortiGate model is absent from config-version header")
        if self.metadata.get("version"):
            version = NormalizedValue.known(
                self.metadata["version"], *self._field_evidence(("metadata", "version"))
            )
        if self.metadata.get("model"):
            model = NormalizedValue.known(
                self.metadata["model"], *self._field_evidence(("metadata", "version"))
            )

        management_services = []
        interfaces = []
        for scope, section, path in self._scoped_sections("system interface"):
            for name, settings in section.items():
                if not isinstance(settings, dict):
                    continue
                status = (
                    ConfigurationState.DISABLED
                    if settings.get("status") == "down"
                    else ConfigurationState.ENABLED
                )
                interfaces.append(
                    NetworkInterface(
                        name=str(name),
                        state=status,
                        zone=str(settings.get("role", "")) or None,
                        scope=scope,
                        addresses=tuple(self._as_list(settings.get("ip"))),
                        evidence=self._field_evidence(path + (str(name),)),
                    )
                )
                if status == ConfigurationState.ENABLED:
                    for protocol in self._as_list(settings.get("allowaccess")):
                        management_services.append(
                            ManagementService(
                                protocol=protocol,
                                state=ConfigurationState.ENABLED,
                                interface=str(name),
                                zone=str(settings.get("role", "")) or None,
                                scope=scope,
                                evidence=self._field_evidence(path + (str(name), "allowaccess")),
                            )
                        )

        users = []
        for scope, section, path in self._scoped_sections("system admin"):
            for username, settings in section.items():
                if not isinstance(settings, dict):
                    continue
                state = (
                    ConfigurationState.DISABLED
                    if settings.get("status") == "disable"
                    else ConfigurationState.ENABLED
                )
                users.append(
                    LocalUser(
                        username=str(username),
                        state=state,
                        role=str(settings.get("accprofile", "")) or None,
                        authentication="remote" if settings.get("remote-auth") == "enable" else "local",
                        scope=scope,
                        evidence=self._field_evidence(path + (str(username),)),
                    )
                )

        policies = []
        for scope, section, path in self._scoped_sections("firewall policy"):
            for position, (name, settings) in enumerate(section.items(), start=1):
                if not isinstance(settings, dict):
                    continue
                state = (
                    ConfigurationState.DISABLED
                    if settings.get("status") == "disable"
                    else ConfigurationState.ENABLED
                )
                policies.append(
                    SecurityPolicy(
                        name=str(name),
                        state=state,
                        action=str(settings.get("action", "deny")),
                        position=position,
                        scope=scope,
                        source_interfaces=tuple(self._as_list(settings.get("srcintf"))),
                        destination_interfaces=tuple(self._as_list(settings.get("dstintf"))),
                        sources=tuple(self._as_list(settings.get("srcaddr"))),
                        destinations=tuple(self._as_list(settings.get("dstaddr"))),
                        services=tuple(self._as_list(settings.get("service"))),
                        evidence=self._field_evidence(path + (str(name),)),
                    )
                )

        logging_destinations = []
        for section_name, destination_type in (
            ("log syslogd setting", "syslog"),
            ("log syslogd2 setting", "syslog2"),
            ("log syslogd3 setting", "syslog3"),
            ("log syslogd4 setting", "syslog4"),
            ("log fortianalyzer setting", "fortianalyzer"),
            ("log fortianalyzer2 setting", "fortianalyzer2"),
            ("log fortianalyzer3 setting", "fortianalyzer3"),
            ("log fortiguard setting", "forticloud"),
            ("system central-management", "fortimanager"),
        ):
            for scope, section, path in self._scoped_sections(section_name):
                enabled = section.get("status") == "enable"
                if destination_type == "fortimanager":
                    enabled = section.get("type") == "fortimanager"
                state = ConfigurationState.ENABLED if enabled else ConfigurationState.DISABLED
                logging_destinations.append(
                    LoggingDestination(
                        destination_type=destination_type,
                        state=state,
                        address=str(section.get("server", section.get("fmg", ""))) or None,
                        scope=scope,
                        evidence=self._field_evidence(path + ("status",)),
                    )
                )

        crypto_settings = []
        for scope, section, path in self._scoped_sections("system global"):
            for key in (
                "ssl-min-proto-version",
                "admin-https-ssl-versions",
                "strong-crypto",
                "ssl-static-key-ciphers",
                "dh-params",
                "admin-ssh-v1",
                "ssh-cbc-cipher",
                "ssh-enc-algo",
                "ssh-kex-algo",
                "ssh-mac-algo",
                "admin-server-cert",
            ):
                if key in section:
                    crypto_settings.append(
                        CryptoSetting(
                            name=key,
                            value=" ".join(self._as_list(section[key])),
                            state=ConfigurationState.CONFIGURED,
                            scope=scope,
                            evidence=self._field_evidence(path + (key,)),
                        )
                    )

        return NormalizedConfig(
            device_type=self.device_type,
            hostname=hostname,
            device_model=model,
            software_version=version,
            management_services=NormalizedCollection.known(*management_services),
            users=NormalizedCollection.known(*users),
            interfaces=NormalizedCollection.known(*interfaces),
            policies=NormalizedCollection.known(*policies),
            logging_destinations=NormalizedCollection.known(*logging_destinations),
            crypto_settings=NormalizedCollection.known(*crypto_settings),
        )


__all__ = ["FortiAAAServerProfile", "FortiOSParseError", "FortiOSParser"]
