"""FortiOS configuration parser and normalized model adapter."""

from dataclasses import dataclass
import hashlib
import ipaddress
import re
import shlex
from typing import Dict, Iterator, List, Tuple, Union

from src.common.certificates import (
    CertificateAssessment,
    CertificateMetadata,
    assess_public_certificate,
    certificate_metadata,
    load_public_certificate,
)
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.common.input_scope import contains_unresolved_template
from src.devices.common.source_lines import group_double_quoted_lines, single_line_evidence
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
from src.devices.common.policy_semantics import (
    AddressInterval,
    NetworkSemantics,
    ServiceInterval,
    ServiceSemantics,
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
class FortiAdministratorRole:
    scope: str
    administrator: str
    profile: str
    definition_scope: str
    resolution_state: str
    privileged_state: str
    writable_groups: Tuple[str, ...]
    evidence: Tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class FortiManagementCertificateBinding:
    """Resolved FortiOS administrative HTTPS certificate evidence."""

    scope: str
    certificate: str
    reference_state: str
    public_material_state: str
    metadata: CertificateMetadata | None
    assessment: CertificateAssessment | None
    evidence: Tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class FortiIPSSelector:
    name: str
    severities: Tuple[str, ...]
    action: str
    active_state: str
    broad_match: bool
    evidence: Tuple[ConfigEvidence, ...]
    exemptions: Tuple[ConfigEvidence, ...] = ()


@dataclass(frozen=True)
class FortiSyslogSink:
    name: str
    scope: str
    server: str
    mode: str
    encryption: str
    tls_minimum: str
    transport_state: str
    evidence: Tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class FortiInspectionProfile:
    profile_type: str
    name: str
    definition_scope: str
    resolution_state: str
    content_state: str
    actions: Tuple[str, ...]
    evidence: Tuple[ConfigEvidence, ...]
    ips_selectors: Tuple[FortiIPSSelector, ...] = ()


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
class FortiFirewallPolicy:
    """A transit policy adapted to the bounded shared containment model."""

    family: str
    scope: str
    name: str
    position: int
    enabled: bool
    action: str
    source_interfaces: Tuple[str, ...]
    destination_interfaces: Tuple[str, ...]
    source_networks: NetworkSemantics
    destination_networks: NetworkSemantics
    services: ServiceSemantics
    schedule: str
    source_negated: bool
    destination_negated: bool
    service_negated: bool
    unsupported_predicates: Tuple[str, ...]
    behavior_signature: Tuple[Tuple[str, str], ...]
    evidence: Tuple[ConfigEvidence, ...]

    @property
    def proof_eligible(self) -> bool:
        return (
            self.enabled
            and self.action in {"accept", "deny"}
            and self.schedule.casefold() == "always"
            and not self.source_negated
            and not self.destination_negated
            and not self.service_negated
            and not self.unsupported_predicates
        )


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


@dataclass(frozen=True)
class FortiDoSAnomaly:
    name: str
    enabled: bool
    action: str
    logging: bool
    threshold: str | None
    threshold_state: str
    evidence: Tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class FortiDoSPolicy:
    family: str
    scope: str
    name: str
    enabled: bool
    interfaces: Tuple[str, ...]
    sources: Tuple[str, ...]
    destinations: Tuple[str, ...]
    services: Tuple[str, ...]
    anomalies: Tuple[FortiDoSAnomaly, ...]
    evidence: Tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class FortiConfigurationBackup:
    """A sanitized FortiOS auto-script that invokes a configuration backup."""

    scope: str
    name: str
    backup_format: str
    protocol: str
    transport_security: str
    destination: str | None
    start_mode: str
    interval_seconds: int | None
    repeat_count: int | None
    schedule_state: str
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
    _PUBLIC_MATERIAL_FIELDS = {"ca", "certificate"}
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
    _BUILTIN_SERVICES = {
        "all_tcp": (("tcp", 0, 65535),),
        "all_udp": (("udp", 0, 65535),),
        "dns": (("tcp", 53, 53), ("udp", 53, 53)),
        "ftp": (("tcp", 21, 21),),
        "http": (("tcp", 80, 80),),
        "https": (("tcp", 443, 443),),
        "ping": (("icmp", 0, 65535),),
        "ssh": (("tcp", 22, 22),),
        "telnet": (("tcp", 23, 23),),
    }
    _POLICY_UNSUPPORTED_PREDICATES = {
        "devices",
        "dst-reputation",
        "fsso-groups",
        "geoip-match",
        "groups",
        "internet-service",
        "internet-service-custom",
        "internet-service-group",
        "internet-service-name",
        "internet-service-src",
        "internet-service-src-custom",
        "internet-service-src-group",
        "internet-service-src-name",
        "reputation-direction",
        "reputation-minimum",
        "src-device",
        "src-device-filter",
        "src-device-type",
        "src-device-vendor",
        "src-reputation",
        "src-vendor-mac",
        "users",
        "ztna-ems-tag",
        "ztna-tags-match-logic",
    }

    def __init__(self, config_filepath: str):
        super().__init__(config_filepath)
        self.evidence: Dict[Tuple[str, ...], ConfigEvidence] = {}
        self.parse_diagnostics: List[str] = []
        self.template_unresolved = False
        self.metadata: Dict[str, str] = {}
        # Logical statements spanning several physical lines (for example a
        # quoted PEM private key), keyed by first line -> last line.
        self._statement_end_lines: Dict[int, int] = {}
        self.config = self._parse_config(config_filepath)

    @staticmethod
    def _tokens(line: str, source: str, line_number: int) -> List[str]:
        public_material = re.fullmatch(
            r'\s*set\s+(certificate|ca)\s+"(.*)"\s*', line, re.IGNORECASE | re.DOTALL
        )
        if public_material:
            # FortiOS exports PEM values either on one line with escaped
            # newlines or as a quoted value spanning several physical lines.
            value = public_material.group(2).replace(r"\n", "\n").replace(r'\"', '"')
            return ["set", public_material.group(1), value]
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
        elif (
            len(tokens) >= 2
            and tokens[0].lower() in {"set", "select", "append"}
            and tokens[1].lower() in self._PUBLIC_MATERIAL_FIELDS
        ):
            text = f"{tokens[0]} {tokens[1]} <public certificate material omitted>"
        elif (
            path
            and path[-1].casefold() == "script"
            and re.search(r"\bexecute\s+backup\b", text, re.IGNORECASE)
        ):
            text = f"{tokens[0]} {tokens[1]} <backup command redacted>"
        text = single_line_evidence(text, self._statement_end_lines.get(line_number))
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
        source_digest = hashlib.sha256()

        with open(filepath, "r", encoding="utf-8", errors="replace") as config_file:
            content = config_file.read()
        source_digest.update(content.encode("utf-8"))
        grouping = group_double_quoted_lines(content.split("\n"), comment_prefixes=("#",))
        if grouping.unterminated_line is not None:
            raise FortiOSParseError(
                filepath, grouping.unterminated_line, "Invalid quoting: value is not closed before end of file"
            )
        for statement in grouping.lines:
            line_number = statement.start_line
            if statement.is_multiline:
                self._statement_end_lines[line_number] = statement.end_line
            line = statement.text.strip()
            if not line:
                continue
            if line.startswith("#"):
                self._parse_header(line, line_number)
                continue

            if contains_unresolved_template(line):
                self.template_unresolved = True

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
                # FortiOS permits saving an edited entry and its table
                # together. Only close this table, retaining outer VDOMs.
                if frames and frames[-1].kind == "edit":
                    frames.pop()
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
        self._source_digest = source_digest.hexdigest()
        return config

    def get_report_secret_lines(self) -> list[dict]:
        """Return current secret-field source lines only for explicit report opt-in."""
        with open(self.config_filepath, "r", encoding="utf-8", errors="replace") as source:
            original_lines = source.readlines()
        current_digest = hashlib.sha256(
            "".join(original_lines).encode("utf-8")
        ).hexdigest()
        if current_digest != self._source_digest:
            raise ValueError("configuration changed after FortiOS parsing; refusing secret report")

        entries: dict[int, dict] = {}

        def walk(node: FortiDict, path: Tuple[str, ...]) -> None:
            for name, value in node.items():
                field_path = path + (str(name),)
                if isinstance(value, dict):
                    walk(value, field_path)
                    continue
                if str(name).casefold() not in self._SECRET_FIELDS:
                    continue
                evidence = self.evidence.get(field_path)
                if evidence is None or evidence.line_number is None:
                    continue
                number = evidence.line_number
                if not 1 <= number <= len(original_lines) or "<redacted>" not in evidence.text:
                    continue
                end_line = self._statement_end_lines.get(number, number)
                raw_line = "".join(original_lines[number - 1:end_line]).strip()
                if re.match(r"(?i)^(?:set|append|select)\s+" + re.escape(str(name)) + r"\s+", raw_line):
                    entries[number] = {
                        "line-number": number,
                        "context": "configured_secret_field",
                        "source-line": raw_line,
                    }

        walk(self.config, ())
        return [entries[number] for number in sorted(entries)]

    _ADMIN_HASH_PREFIXES = ("SH2", "AK1", "PB2")

    def get_reversible_secret_evidence(self) -> list[ConfigEvidence]:
        """Secret fields stored as reversible ``ENC`` values (not administrator hashes).

        FG-IR-19-007: without ``private-data-encryption`` these values are encrypted
        with a key built into FortiOS, so anyone with the file can decrypt them.
        Administrator password hashes (``ENC SH2...``/``AK1``/``PB2``) are excluded.
        """
        found: list[ConfigEvidence] = []

        def walk(node: FortiDict, path: Tuple[str, ...]) -> None:
            for name, value in node.items():
                field_path = path + (str(name),)
                if isinstance(value, dict):
                    walk(value, field_path)
                    continue
                if str(name).casefold() not in self._SECRET_FIELDS:
                    continue
                words = self._as_list(value)
                if len(words) < 2 or words[0] != "ENC" or words[1].startswith(self._ADMIN_HASH_PREFIXES):
                    continue
                evidence = self.evidence.get(field_path)
                if evidence is not None:
                    found.append(evidence)

        walk(self.config, ())
        return sorted(found, key=lambda item: item.line_number or 0)

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

    @staticmethod
    def _integer(value: object) -> int | None:
        text = FortiOSParser._as_list(value)
        if len(text) != 1 or not text[0].isdigit():
            return None
        return int(text[0])

    @staticmethod
    def _sanitize_backup_destination(value: str | None) -> str | None:
        if value is None:
            return None
        value = re.sub(
            r"^([a-z][a-z0-9+.-]*://)[^/@\s]+@",
            r"\1<credentials>@",
            value,
            flags=re.IGNORECASE,
        )
        return re.sub(r"^[^/@\s]+@", "<credentials>@", value)

    @staticmethod
    def _backup_command(script: str) -> tuple[str, str, str | None] | None:
        """Return format, protocol and non-credential destination from a script."""

        try:
            tokens = shlex.split(script.replace("\\n", " "), comments=False, posix=True)
        except ValueError:
            tokens = script.replace("\\n", " ").split()
        lowered = [token.casefold() for token in tokens]
        formats = {
            "config",
            "full-config",
            "yaml-config",
            "obfuscated-config",
            "obfuscated-full-config",
            "obfuscated-yaml-config",
        }
        for index in range(max(0, len(tokens) - 3)):
            if lowered[index:index + 2] != ["execute", "backup"]:
                continue
            backup_format = lowered[index + 2]
            protocol = lowered[index + 3]
            if backup_format not in formats:
                continue
            if protocol in {"ftp", "sftp", "tftp"}:
                destination = FortiOSParser._sanitize_backup_destination(
                    tokens[index + 5] if len(tokens) > index + 5 else None
                )
            elif protocol in {"flash", "management-station", "usb", "usb-mode"}:
                destination = protocol
            else:
                destination = None
            return backup_format, protocol, destination
        return None

    def get_configuration_backups(self) -> Tuple[FortiConfigurationBackup, ...]:
        """Resolve exported backup auto-scripts without retaining their credentials."""

        backups: list[FortiConfigurationBackup] = []
        insecure = {"ftp", "tftp"}
        secure = {"sftp"}
        local = {"flash", "usb", "usb-mode"}
        managed = {"management-station"}
        for scope, section, path in self._scoped_sections("system auto-script"):
            for name, settings in section.items():
                if not isinstance(settings, dict):
                    continue
                script = " ".join(self._as_list(settings.get("script")))
                command = self._backup_command(script)
                if command is None:
                    continue
                backup_format, protocol, destination = command
                start_mode = " ".join(self._as_list(settings.get("start"))) or "manual"
                start_mode = start_mode.casefold()
                interval = self._integer(settings.get("interval", "0"))
                repeat = self._integer(settings.get("repeat", "1"))
                if start_mode != "auto":
                    schedule_state = "manual"
                elif interval is None or interval <= 0 or repeat is None:
                    schedule_state = "invalid"
                elif repeat == 0:
                    schedule_state = "effective"
                else:
                    schedule_state = "finite"
                transport_security = (
                    "insecure" if protocol in insecure
                    else "secure" if protocol in secure
                    else "local" if protocol in local
                    else "managed" if protocol in managed
                    else "unknown"
                )
                script_item = self.evidence.get(path + (str(name), "script"))
                evidence = [
                    item
                    for item in (
                        self.evidence.get(path + (str(name),)),
                        self.evidence.get(path + (str(name), "start")),
                        self.evidence.get(path + (str(name), "interval")),
                        self.evidence.get(path + (str(name), "repeat")),
                    )
                    if item is not None
                ]
                if script_item is not None:
                    summary_destination = destination or "<destination unavailable>"
                    evidence.append(ConfigEvidence(
                        text=(
                            f"set script execute backup {backup_format} {protocol} "
                            f"{summary_destination} <credentials redacted>"
                        ),
                        source=script_item.source,
                        line_number=script_item.line_number,
                    ))
                backups.append(FortiConfigurationBackup(
                    scope=scope,
                    name=str(name),
                    backup_format=backup_format,
                    protocol=protocol,
                    transport_security=transport_security,
                    destination=destination,
                    start_mode=start_mode,
                    interval_seconds=interval,
                    repeat_count=repeat,
                    schedule_state=schedule_state,
                    evidence=tuple(evidence),
                ))
        return tuple(backups)

    def iter_administrators(self):
        for scope, section, path in self._scoped_sections("system admin"):
            for username, settings in section.items():
                if isinstance(settings, dict):
                    yield scope, str(username), settings, path + (str(username),)

    def get_administrator_roles(self) -> Tuple[FortiAdministratorRole, ...]:
        """Bind enabled administrators to built-in or exported custom access profiles."""
        profiles = {
            (scope, str(name).casefold()): (settings, path + (str(name),))
            for scope, section, path in self._scoped_sections("system accprofile")
            for name, settings in section.items()
            if isinstance(settings, dict)
        }
        result = []
        permission_groups = {
            "sysgrp", "netgrp", "loggrp", "fwgrp", "authgrp", "vpngrp",
            "utmgrp", "wanoptgrp", "secfabgrp", "wifi", "ftviewgrp",
        }
        for scope, username, settings, path in self.iter_administrators():
            if str(settings.get("status", "enable")).casefold() == "disable":
                continue
            profile = str(settings.get("accprofile", "super_admin"))
            name = profile.casefold()
            evidence = list(self.field_evidence(path + ("accprofile",)))
            if name == "super_admin":
                state, privileged, definition, writable = "known", "privileged", "builtin", ()
            elif name in {"read_only", "prof_admin", "vdom_admin"}:
                # Other built-ins have release/VDOM-specific privileges; only
                # read_only is definitely non-writing in this bounded model.
                state, privileged, definition, writable = (
                    "known", "read-only" if name == "read_only" else "unknown", "builtin", ()
                )
            else:
                match = next(
                    ((candidate, profiles[(candidate, name)])
                     for candidate in (scope, "global", "root")
                     if (candidate, name) in profiles),
                    None,
                )
                if match is None:
                    state, privileged, definition, writable = "unresolved", "unknown", "", ()
                else:
                    definition, (values, profile_path) = match
                    writable_set = {
                        key for key in permission_groups
                        if str(values.get(key, "")).casefold() == "read-write"
                    }
                    for group in ("sysgrp", "netgrp", "loggrp", "fwgrp", "utmgrp"):
                        nested = values.get(group + "-permission")
                        if isinstance(nested, dict) and any(
                            str(value).casefold() == "read-write"
                            for value in nested.values() if isinstance(value, str)
                        ):
                            writable_set.add(group)
                    writable = tuple(sorted(writable_set))
                    state = "known"
                    privileged = "privileged" if writable else "unknown"
                    evidence.extend(self.field_evidence(profile_path))
                    for group in writable:
                        evidence.extend(self.field_evidence(profile_path + (group,)))
            result.append(FortiAdministratorRole(
                scope=scope,
                administrator=username,
                profile=profile,
                definition_scope=definition,
                resolution_state=state,
                privileged_state=privileged,
                writable_groups=writable,
                evidence=tuple(evidence),
            ))
        return tuple(result)

    def iter_interfaces(self):
        for scope, section, path in self._scoped_sections("system interface"):
            for name, settings in section.items():
                if isinstance(settings, dict):
                    yield scope, str(name), settings, path + (str(name),)

    def _supports_radsec(self) -> bool:
        numbers = re.findall(r"\d+", self.get_version())
        return len(numbers) >= 2 and (int(numbers[0]), int(numbers[1])) >= (7, 4)

    def get_sslvpn_settings(self) -> list[dict]:
        """``config vpn ssl settings`` per scope: active when enabled (default) and bound to a
        ``source-interface``. Values are the explicit ones; absent fields are ``None``."""
        results = []
        for scope, settings, path in self._scoped_sections("vpn ssl settings"):
            interfaces = self._as_list(settings.get("source-interface"))
            active = bool(interfaces) and str(settings.get("status", "enable")).lower() != "disable"
            values = {
                field: (" ".join(self._as_list(settings[field])) if field in settings else None)
                for field in ("ssl-min-proto-ver", "algorithm", "servercert", "login-attempt-limit")
            }
            results.append({
                "scope": scope,
                "active": active,
                "interfaces": tuple(interfaces),
                "values": values,
                "evidence": {field: self._field_evidence(path + (field,)) for field in values},
                "interface_evidence": self._field_evidence(path + ("source-interface",)),
            })
        return results

    def get_ldap_servers(self) -> list[dict]:
        """LDAP servers with their transport and the user groups that reference them.

        CLI reference (config user ldap): ``secure`` disable | starttls | ldaps, default
        disable (no TLS); ``server-identity-check`` default enable. A server is bound
        when a user group in the same scope lists it as a member or match server.
        """
        references: Dict[Tuple[str, str], list[str]] = {}
        for scope, section, _ in self._scoped_sections("user group"):
            for group_name, settings in section.items():
                if not isinstance(settings, dict):
                    continue
                names = set(self._as_list(settings.get("member")))
                matches = settings.get("match")
                if isinstance(matches, dict):
                    for match in matches.values():
                        if isinstance(match, dict):
                            names.update(self._as_list(match.get("server-name")))
                for name in names:
                    references.setdefault((scope, name), []).append(str(group_name))
        servers = []
        for scope, section, section_path in self._scoped_sections("user ldap"):
            for name, settings in section.items():
                if not isinstance(settings, dict):
                    continue
                path = section_path + (str(name),)
                secure_evidence = self._field_evidence(path + ("secure",))
                servers.append({
                    "scope": scope,
                    "name": str(name),
                    "secure": str(settings.get("secure", "disable")).lower(),
                    "secure_explicit": "secure" in settings,
                    "server_identity_check": str(settings.get("server-identity-check", "enable")).lower(),
                    "groups": tuple(sorted(references.get((scope, str(name)), []))),
                    "evidence": secure_evidence or self._field_evidence(path + ("server",)) or self._field_evidence(path),
                    "identity_evidence": self._field_evidence(path + ("server-identity-check",)),
                })
        return servers

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

    def get_management_certificate_bindings(
        self,
    ) -> Tuple[FortiManagementCertificateBinding, ...]:
        """Resolve admin-server-cert to supplied public local/CA material."""

        objects: list[dict] = []
        for section_name, field, kind in (
            ("vpn certificate local", "certificate", "identity"),
            ("certificate local", "certificate", "identity"),
            ("vpn certificate ca", "ca", "ca"),
            ("certificate ca", "ca", "ca"),
        ):
            for scope, section, path in self._scoped_sections(section_name):
                for name, settings in section.items():
                    if not isinstance(settings, dict):
                        continue
                    raw_material = settings.get(field)
                    material = " ".join(self._as_list(raw_material)).strip()
                    parsed = None
                    state = "missing"
                    if material:
                        try:
                            parsed = load_public_certificate(material)
                            state = "parsed"
                        except (TypeError, ValueError):
                            state = "malformed"
                    object_evidence = ConfigEvidence(
                        text=f"{section_name} {name} {field} <public material {state}>",
                        source=self.config_filepath,
                        line_number=(
                            self.evidence.get(path + (str(name), field)).line_number
                            if self.evidence.get(path + (str(name), field)) else None
                        ),
                    )
                    objects.append({
                        "scope": scope,
                        "name": str(name),
                        "kind": kind,
                        "state": state,
                        "certificate": parsed,
                        "evidence": object_evidence,
                    })

        bindings = []
        has_identity_inventory = any(item["kind"] == "identity" for item in objects)
        factory_names = {"fortinet_factory", "fortinet_gui_server", "self-sign"}
        for scope, settings, path in self._scoped_sections("system global"):
            selected = " ".join(self._as_list(settings.get("admin-server-cert"))).strip()
            if not selected or selected.casefold() in factory_names:
                continue
            candidates = [
                item for item in objects
                if item["kind"] == "identity"
                and item["name"].casefold() == selected.casefold()
                and item["scope"] in {scope, "global", "root"}
            ]
            candidates.sort(key=lambda item: (
                0 if item["scope"] == scope else 1 if item["scope"] == "global" else 2
            ))
            resolved = candidates[0] if candidates else None
            available = tuple(
                item["certificate"] for item in objects
                if item["certificate"] is not None
                and item["scope"] in {scope, "global", "root"}
            )
            metadata = None
            assessment = None
            if resolved is not None and resolved["certificate"] is not None:
                metadata = certificate_metadata(resolved["certificate"])
                assessment = assess_public_certificate(
                    resolved["certificate"],
                    available,
                    self.assessment_context.trusted_certificate_sha256,
                    self.assessment_context.management_identity_for_scope(scope),
                    self.assessment_context.assessment_datetime(),
                )
            evidence = list(self._field_evidence(path + ("admin-server-cert",)))
            if resolved is not None:
                evidence.append(resolved["evidence"])
            bindings.append(FortiManagementCertificateBinding(
                scope=scope,
                certificate=selected,
                reference_state=(
                    "resolved" if resolved is not None
                    else "unresolved" if has_identity_inventory
                    else "unavailable"
                ),
                public_material_state=(resolved["state"] if resolved is not None else "unknown"),
                metadata=metadata,
                assessment=assessment,
                evidence=tuple(evidence),
            ))
        return tuple(bindings)

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

    @staticmethod
    def _address_interval(value: object, family: int) -> AddressInterval | None:
        parts = FortiOSParser._as_list(value)
        try:
            if len(parts) == 1:
                network = ipaddress.ip_network(parts[0], strict=False)
            elif len(parts) == 2:
                network = ipaddress.ip_network(f"{parts[0]}/{parts[1]}", strict=False)
            else:
                return None
        except ValueError:
            return None
        if network.version != family:
            return None
        return AddressInterval(family, int(network.network_address), int(network.broadcast_address))

    @staticmethod
    def _range_interval(first: object, last: object, family: int) -> AddressInterval | None:
        first_values = FortiOSParser._as_list(first)
        last_values = FortiOSParser._as_list(last)
        if len(first_values) != 1 or len(last_values) != 1:
            return None
        try:
            start = ipaddress.ip_address(first_values[0])
            end = ipaddress.ip_address(last_values[0])
        except ValueError:
            return None
        if start.version != family or end.version != family or int(start) > int(end):
            return None
        return AddressInterval(family, int(start), int(end))

    def _resolve_policy_network_member(
        self,
        name: str,
        scope: str,
        family: int,
        stack: frozenset[tuple[str, str, int]],
        budget: list[int],
    ) -> NetworkSemantics:
        normalized = name.strip()
        lowered = normalized.casefold()
        if lowered in ({"all", "all_ipv4"} if family == 4 else {"all", "all_ipv6"}):
            return NetworkSemantics(any=True)

        literal = self._address_interval(normalized, family)
        if literal is not None:
            return NetworkSemantics(intervals=(literal,))

        key = (scope.casefold(), lowered, family)
        if key in stack or budget[0] <= 0:
            return NetworkSemantics(complete=False, unresolved=(normalized,))
        budget[0] -= 1
        next_stack = stack | {key}

        object_section = "firewall address" if family == 4 else "firewall address6"
        resolved = self._resolve_scoped_object(object_section, normalized, scope)
        if resolved is not None:
            _, settings, _ = resolved
            object_type = str(settings.get("type", "ipmask")).casefold()
            associated_interfaces = self._as_list(settings.get("associated-interface"))
            if associated_interfaces and any(
                value.casefold() != "any" for value in associated_interfaces
            ):
                return NetworkSemantics(complete=False, unresolved=(normalized,))
            if object_type == "ipmask":
                field = "subnet" if family == 4 else "ip6"
                interval = self._address_interval(settings.get(field), family)
            elif object_type == "iprange":
                interval = self._range_interval(
                    settings.get("start-ip"), settings.get("end-ip"), family
                )
            else:
                interval = None
            if interval is None:
                return NetworkSemantics(complete=False, unresolved=(normalized,))
            return NetworkSemantics(intervals=(interval,))

        group_section = "firewall addrgrp" if family == 4 else "firewall addrgrp6"
        resolved = self._resolve_scoped_object(group_section, normalized, scope)
        if resolved is None:
            return NetworkSemantics(complete=False, unresolved=(normalized,))
        definition_scope, settings, _ = resolved
        if (
            str(settings.get("exclude", "disable")).casefold() == "enable"
            or str(settings.get("category", "default")).casefold() != "default"
        ):
            return NetworkSemantics(complete=False, unresolved=(normalized,))
        members = self._as_list(settings.get("member"))
        if not members:
            return NetworkSemantics(complete=False, unresolved=(normalized,))
        return self._combine_network_members(
            members, definition_scope, family, next_stack, budget
        )

    def _combine_network_members(
        self,
        members: List[str],
        scope: str,
        family: int,
        stack: frozenset[tuple[str, str, int]] = frozenset(),
        budget: list[int] | None = None,
    ) -> NetworkSemantics:
        remaining = budget if budget is not None else [4096]
        intervals: list[AddressInterval] = []
        unresolved: list[str] = []
        for member in members:
            semantics = self._resolve_policy_network_member(
                str(member), scope, family, stack, remaining
            )
            if semantics.any:
                return NetworkSemantics(any=True)
            intervals.extend(semantics.intervals)
            unresolved.extend(semantics.unresolved)
            if not semantics.complete and not semantics.unresolved:
                unresolved.append(str(member))
        if unresolved or not intervals:
            return NetworkSemantics(
                intervals=tuple(sorted(set(intervals))),
                complete=False,
                unresolved=tuple(dict.fromkeys(unresolved or tuple(str(item) for item in members))),
            )
        return NetworkSemantics(intervals=tuple(sorted(set(intervals))))

    @staticmethod
    def _service_port_intervals(protocol: str, values: object) -> tuple[ServiceInterval, ...] | None:
        intervals: list[ServiceInterval] = []
        for raw_value in FortiOSParser._as_list(values):
            for raw_range in raw_value.split():
                if ":" in raw_range:
                    return None
                parts = raw_range.split("-", 1)
                if not all(part.isdigit() for part in parts):
                    return None
                first = int(parts[0])
                last = int(parts[-1])
                if not 0 <= first <= last <= 65535:
                    return None
                intervals.append(ServiceInterval(protocol, first, last))
        return tuple(intervals) if intervals else None

    def _resolve_policy_service_member(
        self,
        name: str,
        scope: str,
        stack: frozenset[tuple[str, str]],
        budget: list[int],
    ) -> ServiceSemantics:
        normalized = name.strip()
        lowered = normalized.casefold()
        if lowered == "all":
            return ServiceSemantics(any=True)
        builtin = self._BUILTIN_SERVICES.get(lowered)
        if builtin is not None:
            return ServiceSemantics(
                intervals=tuple(ServiceInterval(*values) for values in builtin)
            )

        key = (scope.casefold(), lowered)
        if key in stack or budget[0] <= 0:
            return ServiceSemantics(complete=False, unresolved=(normalized,))
        budget[0] -= 1
        next_stack = stack | {key}

        resolved = self._resolve_scoped_object("firewall service custom", normalized, scope)
        if resolved is not None:
            _, settings, _ = resolved
            if (
                str(settings.get("proxy", "disable")).casefold() == "enable"
                or str(settings.get("app-service-type", "disable")).casefold() != "disable"
                or settings.get("fqdn")
                or settings.get("iprange")
            ):
                return ServiceSemantics(complete=False, unresolved=(normalized,))
            protocol = str(settings.get("protocol", "TCP/UDP/SCTP")).casefold()
            intervals: list[ServiceInterval] = []
            if protocol == "tcp/udp/udp-lite/sctp" or protocol == "tcp/udp/sctp":
                for field, member_protocol in (
                    ("tcp-portrange", "tcp"),
                    ("udp-portrange", "udp"),
                ):
                    if field not in settings:
                        continue
                    parsed = self._service_port_intervals(member_protocol, settings[field])
                    if parsed is None:
                        return ServiceSemantics(complete=False, unresolved=(normalized,))
                    intervals.extend(parsed)
                if settings.get("sctp-portrange") or settings.get("udplite-portrange"):
                    return ServiceSemantics(complete=False, unresolved=(normalized,))
            elif protocol in {"icmp", "icmp6"}:
                if settings.get("icmpcode") not in {None, ""}:
                    return ServiceSemantics(complete=False, unresolved=(normalized,))
                raw_type = settings.get("icmptype")
                if raw_type in {None, ""}:
                    intervals.append(ServiceInterval(protocol, 0, 65535))
                else:
                    values = self._as_list(raw_type)
                    if len(values) != 1 or not values[0].isdigit():
                        return ServiceSemantics(complete=False, unresolved=(normalized,))
                    value = int(values[0])
                    if not 0 <= value <= 255:
                        return ServiceSemantics(complete=False, unresolved=(normalized,))
                    intervals.append(ServiceInterval(protocol, value, value))
            elif protocol == "ip":
                values = self._as_list(settings.get("protocol-number"))
                if len(values) != 1 or not values[0].isdigit():
                    return ServiceSemantics(complete=False, unresolved=(normalized,))
                number = int(values[0])
                if not 0 <= number <= 254:
                    return ServiceSemantics(complete=False, unresolved=(normalized,))
                protocol_name = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmp6"}.get(
                    number, f"ip-{number}"
                )
                intervals.append(ServiceInterval(protocol_name, 0, 65535))
            else:
                return ServiceSemantics(complete=False, unresolved=(normalized,))
            if not intervals:
                return ServiceSemantics(complete=False, unresolved=(normalized,))
            return ServiceSemantics(intervals=tuple(sorted(set(intervals))))

        resolved = self._resolve_scoped_object("firewall service group", normalized, scope)
        if resolved is None:
            return ServiceSemantics(complete=False, unresolved=(normalized,))
        definition_scope, settings, _ = resolved
        if str(settings.get("proxy", "disable")).casefold() == "enable":
            return ServiceSemantics(complete=False, unresolved=(normalized,))
        members = self._as_list(settings.get("member"))
        if not members:
            return ServiceSemantics(complete=False, unresolved=(normalized,))
        return self._combine_service_members(members, definition_scope, next_stack, budget)

    def _combine_service_members(
        self,
        members: List[str],
        scope: str,
        stack: frozenset[tuple[str, str]] = frozenset(),
        budget: list[int] | None = None,
    ) -> ServiceSemantics:
        remaining = budget if budget is not None else [4096]
        intervals: list[ServiceInterval] = []
        unresolved: list[str] = []
        for member in members:
            semantics = self._resolve_policy_service_member(
                str(member), scope, stack, remaining
            )
            if semantics.any:
                return ServiceSemantics(any=True)
            intervals.extend(semantics.intervals)
            unresolved.extend(semantics.unresolved)
            if not semantics.complete and not semantics.unresolved:
                unresolved.append(str(member))
        if unresolved or not intervals:
            return ServiceSemantics(
                intervals=tuple(sorted(set(intervals))),
                complete=False,
                unresolved=tuple(dict.fromkeys(unresolved or tuple(str(item) for item in members))),
            )
        return ServiceSemantics(intervals=tuple(sorted(set(intervals))))

    @staticmethod
    def _stable_policy_value(value: FortiValue) -> str:
        if isinstance(value, dict):
            return "{" + ",".join(
                f"{key}:{FortiOSParser._stable_policy_value(member)}"
                for key, member in sorted(value.items())
            ) + "}"
        if isinstance(value, list):
            return "[" + ",".join(str(item) for item in value) + "]"
        return str(value)

    def get_firewall_policy_semantics(self) -> Tuple[FortiFirewallPolicy, ...]:
        """Resolve only policy fields whose static semantics are safely comparable."""

        policies: list[FortiFirewallPolicy] = []
        dimensions = {
            "srcintf", "dstintf", "srcaddr", "dstaddr", "service", "schedule",
            "srcaddr-negate", "dstaddr-negate", "service-negate", "status",
            # Display metadata must not make otherwise equivalent rule behaviour
            # appear different during same-action redundancy proof.
            "name", "comments", "uuid",
        }
        for section_name, family, version in (
            ("firewall policy", "ipv4", 4),
            ("firewall policy6", "ipv6", 6),
        ):
            for scope, section, path in self._scoped_sections(section_name):
                for position, (name, settings) in enumerate(section.items(), start=1):
                    if not isinstance(settings, dict):
                        continue
                    unsupported = []
                    for field in self._POLICY_UNSUPPORTED_PREDICATES:
                        value = settings.get(field)
                        values = self._as_list(value)
                        if not values or all(item.casefold() == "disable" for item in values):
                            continue
                        unsupported.append(field)
                    behavior = tuple(
                        (str(field), self._stable_policy_value(value))
                        for field, value in sorted(settings.items())
                        if str(field) not in dimensions
                    )
                    object_path = path + (str(name),)
                    policies.append(FortiFirewallPolicy(
                        family=family,
                        scope=scope,
                        name=str(name),
                        position=position,
                        enabled=str(settings.get("status", "enable")).casefold() != "disable",
                        action=str(settings.get("action", "deny")).casefold(),
                        source_interfaces=tuple(self._as_list(settings.get("srcintf"))),
                        destination_interfaces=tuple(self._as_list(settings.get("dstintf"))),
                        source_networks=self._combine_network_members(
                            self._as_list(settings.get("srcaddr")), scope, version
                        ),
                        destination_networks=self._combine_network_members(
                            self._as_list(settings.get("dstaddr")), scope, version
                        ),
                        services=self._combine_service_members(
                            self._as_list(settings.get("service")), scope
                        ),
                        schedule=str(settings.get("schedule", "always")),
                        source_negated=str(settings.get("srcaddr-negate", "disable")).casefold() == "enable",
                        destination_negated=str(settings.get("dstaddr-negate", "disable")).casefold() == "enable",
                        service_negated=str(settings.get("service-negate", "disable")).casefold() == "enable",
                        unsupported_predicates=tuple(sorted(unsupported)),
                        behavior_signature=behavior,
                        evidence=self._field_evidence(object_path),
                    ))
        return tuple(policies)

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

    def get_dos_policies(self) -> Tuple[FortiDoSPolicy, ...]:
        """Return scoped DoS policies with every anomaly's effective exported state."""

        policies = []
        for section_name, family in (("firewall DoS-policy", "ipv4"), ("firewall DoS-policy6", "ipv6")):
            for scope, section, section_path in self._scoped_sections(section_name):
                for name, settings in section.items():
                    if not isinstance(settings, dict):
                        continue
                    policy_path = section_path + (str(name),)
                    anomaly_items = []
                    anomalies = settings.get("anomaly")
                    if isinstance(anomalies, dict):
                        for anomaly_name, anomaly in anomalies.items():
                            if not isinstance(anomaly, dict):
                                continue
                            anomaly_path = policy_path + ("anomaly", str(anomaly_name))
                            raw_threshold = anomaly.get("threshold")
                            threshold = (
                                " ".join(self._as_list(raw_threshold))
                                if raw_threshold is not None
                                else None
                            )
                            if threshold is None:
                                threshold_state = "platform-default"
                            elif threshold.isdigit() and 1 <= int(threshold) <= 2147483647:
                                threshold_state = "explicit"
                            else:
                                threshold_state = "invalid"
                            evidence = list(self._field_evidence(anomaly_path))
                            for field in ("status", "action", "log", "threshold"):
                                evidence.extend(self._field_evidence(anomaly_path + (field,)))
                            anomaly_items.append(FortiDoSAnomaly(
                                name=str(anomaly_name),
                                enabled=str(anomaly.get("status", "disable")).casefold() == "enable",
                                action=str(anomaly.get("action", "pass")).casefold(),
                                logging=str(anomaly.get("log", "disable")).casefold() == "enable",
                                threshold=threshold,
                                threshold_state=threshold_state,
                                evidence=tuple(dict.fromkeys(evidence)),
                            ))
                    evidence = list(self._field_evidence(policy_path))
                    for field in ("status", "interface", "srcaddr", "dstaddr", "service"):
                        evidence.extend(self._field_evidence(policy_path + (field,)))
                    policies.append(FortiDoSPolicy(
                        family=family,
                        scope=scope,
                        name=str(name),
                        enabled=str(settings.get("status", "enable")).casefold() != "disable",
                        interfaces=tuple(self._as_list(settings.get("interface"))),
                        sources=tuple(self._as_list(settings.get("srcaddr"))),
                        destinations=tuple(self._as_list(settings.get("dstaddr"))),
                        services=tuple(self._as_list(settings.get("service"))),
                        anomalies=tuple(anomaly_items),
                        evidence=tuple(dict.fromkeys(evidence)),
                    ))
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

    def _ips_selectors(
        self, settings: FortiDict, path: Tuple[str, ...]
    ) -> Tuple[FortiIPSSelector, ...]:
        entries = settings.get("entries")
        if not isinstance(entries, dict):
            return ()
        result: List[FortiIPSSelector] = []
        for name, entry in entries.items():
            if not isinstance(entry, dict):
                continue
            severities = tuple(value.casefold() for value in self._as_list(entry.get("severity")))
            action = " ".join(self._as_list(entry.get("action"))).casefold()
            status = str(entry.get("status", "default")).casefold()
            filter_fields = {
                "rule", "location", "protocol", "os", "application", "cve",
                "vuln-type", "last-modified",
            }
            non_filter_fields = {
                "severity", "action", "status", "log", "log-packet",
                "log-attack-context", "default-action", "default-status",
                "exempt-ip",
            }
            broad_match = all(
                field in filter_fields | non_filter_fields for field in entry
            ) and all(
                field not in entry or self._as_list(entry[field]) == ["all"]
                for field in filter_fields
            ) and all(
                str(entry.get(field, "all")).casefold() == "all"
                for field in ("default-action", "default-status")
            )
            evidence = (
                self._field_evidence(path + ("entries", str(name), "severity"))
                + self._field_evidence(path + ("entries", str(name), "action"))
                + self._field_evidence(path + ("entries", str(name), "status"))
            )
            exemptions: List[ConfigEvidence] = []
            exempt_entries = entry.get("exempt-ip")
            if isinstance(exempt_entries, dict):
                for exempt_name, exempt_entry in exempt_entries.items():
                    if not isinstance(exempt_entry, dict):
                        continue
                    for field in ("src-ip", "dst-ip"):
                        if field in exempt_entry:
                            exemptions.extend(self._field_evidence(
                                path + ("entries", str(name), "exempt-ip", str(exempt_name), field)
                            ))
            result.append(FortiIPSSelector(
                name=str(name), severities=severities, action=action,
                active_state=status, broad_match=broad_match, evidence=evidence,
                exemptions=tuple(exemptions),
            ))
        return tuple(result)

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
                ips_selectors=self._ips_selectors(settings, path) if profile_type == "ips-sensor" else (),
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

    def get_syslog_sinks(self) -> Tuple[FortiSyslogSink, ...]:
        """Explicit active remote syslog transport, including enabled VDOM overrides."""
        override_scopes = {
            scope for scope, settings, _ in self._scoped_sections("log setting")
            if str(settings.get("syslog-override", "")).casefold() == "enable"
        }
        result: List[FortiSyslogSink] = []
        for number in ("", "2", "3", "4"):
            base = f"log syslogd{number}"
            sections = (
                (f"{base} setting", False),
                (f"{base} override-setting", True),
            )
            for section_name, override in sections:
                for scope, settings, path in self._scoped_sections(section_name):
                    if override and scope not in override_scopes:
                        continue
                    if override and str(settings.get("override", "enable")).casefold() == "disable":
                        continue
                    if not override and scope in override_scopes:
                        continue
                    # A global sink's applicability to every VDOM cannot be
                    # established once an exported VDOM overrides syslog.
                    if not override and scope == "global" and override_scopes:
                        continue
                    if str(settings.get("status", "")).casefold() != "enable":
                        continue
                    server = " ".join(self._as_list(settings.get("server")))
                    if not server:
                        continue
                    mode = str(settings.get("mode", "")).casefold()
                    encryption = str(settings.get("enc-algorithm", "")).casefold()
                    tls_minimum = str(settings.get("ssl-min-proto-version", "")).casefold()
                    if encryption == "disable":
                        state = "explicit-cleartext"
                    elif encryption in {"high", "high-medium", "low"} and mode in {
                        "reliable", "legacy-reliable"
                    }:
                        state = (
                            "explicit-weak-tls"
                            if encryption == "low" or tls_minimum in {
                                "sslv3", "tlsv1", "tlsv1-1"
                            }
                            else "explicit-tls"
                        )
                    else:
                        state = "unknown"
                    result.append(FortiSyslogSink(
                        name=section_name,
                        scope=scope,
                        server=server,
                        mode=mode,
                        encryption=encryption,
                        tls_minimum=tls_minimum,
                        transport_state=state,
                        evidence=(
                            self._field_evidence(path + ("status",))
                            + self._field_evidence(path + ("server",))
                            + self._field_evidence(path + ("mode",))
                            + self._field_evidence(path + ("enc-algorithm",))
                            + self._field_evidence(path + ("ssl-min-proto-version",))
                        ),
                    ))
        return tuple(result)

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
        for section_name in ("firewall policy", "firewall policy6"):
            for scope, section, path in self._scoped_sections(section_name):
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
                            tracking=(
                                "all"
                                if str(settings.get("logtraffic", "disable")).casefold()
                                == "all"
                                else str(settings.get("logtraffic", "")) or None
                            ),
                            evidence=self._field_evidence(path + (str(name),)),
                        )
                    )

        logging_destinations = []
        for section_name, destination_type in (
            ("log disk setting", "local-disk"),
            ("log memory setting", "local-memory"),
        ):
            for scope, section, path in self._scoped_sections(section_name):
                state = {
                    "enable": ConfigurationState.ENABLED,
                    "disable": ConfigurationState.DISABLED,
                }.get(str(section.get("status", "")).casefold(), ConfigurationState.UNKNOWN)
                logging_destinations.append(LoggingDestination(
                    destination_type=destination_type,
                    state=state,
                    scope=scope,
                    evidence=self._field_evidence(path + ("status",)),
                ))
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


__all__ = [
    "FortiAAAServerProfile",
    "FortiConfigurationBackup",
    "FortiFirewallPolicy",
    "FortiOSParseError",
    "FortiOSParser",
]
