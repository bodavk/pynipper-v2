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


__all__ = ["FortiOSParseError", "FortiOSParser"]
