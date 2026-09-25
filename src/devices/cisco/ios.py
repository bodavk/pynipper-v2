import ipaddress
import base64
import re
import shlex
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional
from ciscoconfparse import CiscoConfParse
from src.common.certificates import (
    CertificateAssessment,
    CertificateMetadata,
    assess_public_certificate,
    certificate_metadata,
    load_public_certificate,
)
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.common.models import (
    BlocklistCredentialAssessment,
    ConfigEvidence,
    ConfigurationState as NormalizedConfigurationState,
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


class ConfigurationState(str, Enum):
    """State of an IOS feature visible in the supplied configuration."""

    ENABLED = "enabled"
    DISABLED = "disabled"
    ABSENT = "absent"


@dataclass(frozen=True)
class NumericSetting:
    value: Optional[int]
    configured: bool
    raw_line: str = ""
    parse_error: str = ""


@dataclass(frozen=True)
class VTYProfile:
    line: str
    transports: tuple[str, ...]
    ipv4_access_class: str = ""
    ipv6_access_class: str = ""

    @property
    def permits_ssh(self) -> bool:
        return "ssh" in self.transports or "all" in self.transports

    @property
    def permits_telnet(self) -> bool:
        return "telnet" in self.transports or "all" in self.transports

    @property
    def has_inbound_access_class(self) -> bool:
        return bool(self.ipv4_access_class or self.ipv6_access_class)


@dataclass(frozen=True)
class IOSAAAMethodList:
    service: str
    name: str
    privilege_level: Optional[int]
    methods: tuple[str, ...]
    evidence: ConfigEvidence


@dataclass(frozen=True)
class IOSAAAAccountingList:
    service: str
    name: str
    privilege_level: Optional[int]
    record_type: str
    methods: tuple[str, ...]
    evidence: ConfigEvidence


@dataclass(frozen=True)
class IOSAAAServerGroup:
    name: str
    protocol: str
    members: tuple[str, ...]
    evidence: ConfigEvidence


@dataclass(frozen=True)
class IOSVTYAAABinding:
    line: str
    active: bool
    login_kind: Optional[str]
    login_list: Optional[str]
    exec_authorization_list: Optional[str]
    command_authorization_list: Optional[str]
    exec_accounting_list: Optional[str]
    command_accounting_list: Optional[str]
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class IOSManagementLine:
    line: str
    line_type: str
    transports: Optional[tuple[str, ...]]
    output_transports: Optional[tuple[str, ...]]
    exec_enabled: Optional[bool]
    timeout_minutes: Optional[int]
    timeout_seconds: Optional[int]
    timeout_configured: bool
    timeout_parse_error: str
    login_kind: Optional[str]
    login_list: Optional[str]
    ipv4_access_class: str
    ipv6_access_class: str
    exec_authorization_list: Optional[str]
    command_authorization: tuple[tuple[int, str], ...]
    evidence: tuple[ConfigEvidence, ...]

    @property
    def accepts_inbound_connections(self) -> Optional[bool]:
        if self.exec_enabled is False:
            return False
        if self.transports is None:
            return None
        return bool(set(self.transports) - {"none"})


@dataclass(frozen=True)
class IOSLineTimeoutPolicy:
    line: str
    line_type: str
    start: int
    end: int
    active: Optional[bool]
    timeout_minutes: Optional[int]
    timeout_seconds: Optional[int]
    timeout_configured: bool
    timeout_parse_error: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class IOSSSHAlgorithmPolicy:
    category: str
    algorithms: Optional[tuple[str, ...]]
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class IOSNTPAssociation:
    role: str
    address: str
    vrf: str
    key_id: str
    authentication_state: str
    algorithm: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class IOSBGPNeighbor:
    """Effective, secret-free BGP neighbor state in one address-family/VRF."""

    address: str
    local_as: str
    remote_as: str
    peer_role: str
    vrf: str
    address_family: str
    active: bool
    authentication_state: str
    authentication_method: str
    inbound_policy: bool
    outbound_policy: bool
    policy_references: tuple[tuple[str, str, str], ...]
    prefix_limit: bool
    inheritance_unknown: bool
    evidence: tuple[ConfigEvidence, ...]
    # EOS `maximum-routes`: "0" means no limit; "" when not explicitly configured.
    maximum_routes: str = ""


@dataclass(frozen=True)
class IOSOSPFInterface:
    """Effective OSPFv2 adjacency/authentication state for an IOS interface."""

    process_id: str
    interface: str
    area: str
    vrf: str
    passive: bool
    shutdown: bool
    authentication_state: str
    authentication_method: str
    key_reference: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class IOSRIPInterface:
    interface: str
    network: str
    active: bool
    passive: bool
    receive_version: str
    authentication_state: str
    authentication_mode: str
    key_reference: str
    evidence: tuple[ConfigEvidence, ...]
    vrf: str = "default"


@dataclass(frozen=True)
class IOSEIGRPInterface:
    interface: str
    autonomous_system: str
    active: bool
    passive: bool
    authentication_state: str
    key_reference: str
    evidence: tuple[ConfigEvidence, ...]
    named_instance: str = ""


@dataclass(frozen=True)
class IOSConfigRetrieval:
    """Explicit network boot-config retrieval without retaining endpoint details."""

    kind: str
    protocol: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class IOSHTTPSCertificate:
    """Public identity material selected by the active HTTPS trustpoint."""

    trustpoint: str
    metadata: CertificateMetadata
    assessment: CertificateAssessment
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class IOSDiscoveryInterface:
    interface: str
    protocol: str
    transmit: bool
    receive: bool
    active: bool
    role: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class IOSSwitchEdgeInterface:
    interface: str
    mode: str
    access_vlan: int | None
    active: bool
    role: str
    dhcp_snooping: bool
    dhcp_trusted: bool
    arp_inspection: bool
    arp_trusted: bool
    source_guard: bool
    port_security: bool
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class IOSAccessAdmission:
    interface: str
    role: str
    active: bool
    mode: str
    global_dot1x: bool | None
    port_control: str | None
    open_access: bool | None
    aaa_state: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class IOSBpduGuardPolicy:
    interface: str
    role: str
    active: bool
    mode: str
    lag_member: bool
    portfast: bool | None
    guard_enabled: bool | None
    guard_state: str
    filter_enabled: bool | None
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class IOSControlPlaneClass:
    name: str
    selectors: tuple[str, ...]
    selector_references: tuple[str, ...]
    selector_resolution: str
    actions: tuple[str, ...]
    policing: bool
    discarding: bool
    logging: bool
    enforcement_state: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class IOSControlPlanePolicy:
    name: str
    scope: str
    direction: str
    policy_resolved: bool
    protection_state: str
    classes: tuple[IOSControlPlaneClass, ...]
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class IOSConfigurationManagement:
    archive_configured: bool
    destination: str
    protocol: str
    transport_security: str
    write_memory: bool
    time_period_minutes: int | None
    schedule_state: str
    maximum_versions: int | None
    change_logging: bool
    hide_keys: bool
    notify_syslog: bool
    persistent_logging: bool
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class IOSSNMPView:
    name: str
    included_subtrees: tuple[str, ...]
    excluded_subtrees: tuple[str, ...]
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class IOSSNMPGroup:
    name: str
    security_level: str
    read_view: str
    write_view: str
    access_list: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class IOSSNMPUser:
    name: str
    group: str
    authentication: str
    privacy: str
    authentication_key_state: str
    privacy_key_state: str
    access_list: str
    group_security_level: str
    group_resolved: bool
    read_view: str
    read_view_resolved: bool
    source_restricted: bool
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class IOSACLRule:
    name: str
    family: str
    scope: str
    position: int
    action: str
    source_networks: NetworkSemantics
    destination_networks: NetworkSemantics
    services: ServiceSemantics
    behavior_signature: tuple[tuple[str, str], ...]
    evidence: tuple[ConfigEvidence, ...]

    @property
    def proof_eligible(self) -> bool:
        return (
            self.action in {"permit", "deny"}
            and self.source_networks.complete
            and self.destination_networks.complete
            and self.services.complete
        )


class CiscoIOSParser(BaseDeviceParser):

    device_type = "IOS_ROUTER"

    # IOS shows the ETX delimiter as the two characters "^C"; a raw startup
    # configuration may contain the control character itself.
    _BANNER_START = re.compile(r"^banner\s+\S+\s+(?P<rest>\S.*)$", re.IGNORECASE)

    def __init__(self, config_filepath: str):
        super().__init__(config_filepath)
        with open(config_filepath, "r", encoding="utf-8-sig", errors="replace") as source:
            physical_lines = source.read().splitlines()
        # Line-oriented readers must never treat banner text as commands.
        self._source_lines = self._mask_multiline_text(physical_lines)
        # CiscoConfParse drops blank lines, which would shift every evidence
        # line number after them. A comment placeholder keeps positions equal
        # to physical line numbers.
        self.parser = CiscoConfParse(
            [line if line.strip() else "!" for line in self._source_lines],
            syntax='ios',
        )

    @classmethod
    def _mask_multiline_text(cls, lines: list[str]) -> list[str]:
        """Blank the body of delimited ``banner`` text, keeping line numbers.

        The banner command line is kept (so banner presence is still known)
        and the closing line is reduced to its delimiter so CiscoConfParse
        still sees a closed banner. An unclosed banner is left unchanged.
        """

        masked = list(lines)
        index = 0
        while index < len(masked):
            match = cls._BANNER_START.match(masked[index].strip())
            if not match:
                index += 1
                continue
            rest = match.group("rest")
            delimiter = "^C" if rest.startswith("^C") else rest[0]
            if delimiter in rest[len(delimiter):]:
                index += 1
                continue
            closing = next(
                (number for number in range(index + 1, len(masked)) if delimiter in masked[number]),
                None,
            )
            if closing is None:
                break
            for number in range(index + 1, closing):
                masked[number] = ""
            masked[closing] = delimiter
            index = closing + 1
        return masked

    def get_hostname(self) -> str:
        host = self.parser.find_objects("^hostname")
        if len(host) > 0:
            return host[0].re_match_typed(r'^hostname\s+(\S+)', default='')
        return "?"

    def get_version(self) -> str:
        version = self.parser.find_objects(r"^version(?:\s|$)")
        if version:
            # Preserve the supplied release token exactly. Advisory matching may
            # normalize it later, but the parser must never invent a build.
            return version[0].re_match_typed(r"^version\s+(\S+)", default="") or "?"
        return "?"

    def get_explicit_boot_config_retrievals(self) -> list[IOSConfigRetrieval]:
        """Return current explicit boot host/network fetches on qualified releases."""
        version = re.match(r"^(\d+)\.(\d+)", self.get_version())
        if not version or int(version.group(1)) < 15:
            return []  # Older/ambiguous service-config interactions need separate qualification.
        configured: dict[str, list[tuple[str, str, ConfigEvidence]]] = {"host": [], "network": []}
        for line_number, raw in enumerate(self.parser.ioscfg, 1):
            if raw[:1].isspace():
                continue
            command = raw.strip()
            match = re.fullmatch(r"(no )?boot (host|network)(?: (\S+))?", command, re.IGNORECASE)
            if not match:
                continue
            removal, kind, target = match.groups()
            kind = kind.casefold()
            if removal:
                if target is None:
                    configured[kind].clear()
                else:
                    configured[kind] = [
                        item for item in configured[kind] if item[0].casefold() != target.casefold()
                    ]
                continue
            if not target:
                continue
            protocol = target.split(":", 1)[0].casefold() if ":" in target else "unknown"
            if protocol not in {"tftp", "ftp", "rcp"}:
                protocol = "unknown"
            evidence = ConfigEvidence(
                f"boot {kind} {protocol}:<endpoint redacted>",
                self.config_filepath, line_number,
            )
            configured[kind].append((target, protocol, evidence))
        return [
            IOSConfigRetrieval(kind, protocol, (evidence,))
            for kind, entries in configured.items() for _, protocol, evidence in entries
        ]

    def get_cns_config_retrievals(self) -> list[IOSConfigRetrieval]:
        """Return effective CNS configuration-agent retrievals without endpoint details.

        ``cns config initial|partial <host> [encrypt] ...`` fetches configuration
        from a CNS server; without ``encrypt`` the transfer uses HTTP (default
        port 80), with it SSL. ``no cns config initial|partial`` removes the
        agent. Only the kind and transport cross the parser boundary.
        """
        configured: dict[str, IOSConfigRetrieval] = {}
        for line_number, raw in enumerate(self.parser.ioscfg, 1):
            if raw[:1].isspace():
                continue
            match = re.fullmatch(
                r"(no )?cns config (initial|partial)(?: (\S+)(.*))?", raw.strip(), re.IGNORECASE
            )
            if not match:
                continue
            removal, kind, host, options = match.groups()
            kind = f"cns {kind.casefold()}"
            if removal:
                configured.pop(kind, None)
                continue
            if not host:
                continue
            encrypted = "encrypt" in (options or "").casefold().split()
            protocol = "https" if encrypted else "http"
            configured[kind] = IOSConfigRetrieval(kind, protocol, (ConfigEvidence(
                f"cns config {kind.split()[1]} <endpoint redacted>{' encrypt' if encrypted else ''}",
                self.config_filepath, line_number,
            ),))
        return list(configured.values())

    def _global_lines(self) -> list[str]:
        """Return top-level commands in source order with whitespace removed."""

        return [
            line.strip()
            for line in self.parser.ioscfg
            if line.strip() and not line[:1].isspace()
        ]

    def _last_global_match(self, pattern: str) -> Optional[re.Match]:
        expression = re.compile(pattern)
        match = None
        for line in self._global_lines():
            candidate = expression.fullmatch(line)
            if candidate:
                match = candidate
        return match

    def _routing_evidence(self, text: str, line_number: int) -> ConfigEvidence:
        """Create routing evidence while discarding all supplied key material."""

        redacted = re.sub(
            r"(?i)(\b(?:password|authentication-key|authentication-key-chain|"
            r"message-digest-key\s+\S+\s+\S+|key-string)\s+)(\S+)",
            r"\1<redacted>",
            text.strip(),
        )
        # EIGRP named mode carries the key inline: authentication mode hmac-sha-256 [0|7] <key>.
        redacted = re.sub(r"(?i)(\bhmac-sha-256\s+)(?:[07]\s+)?\S+", r"\1<redacted>", redacted)
        return ConfigEvidence(redacted, self.config_filepath, line_number)

    def _indented_blocks(self, prefix: str) -> list[tuple[str, int, list[tuple[int, int, str]]]]:
        """Return IOS top-level blocks as (header, line, indented lines)."""

        blocks = []
        lines = self.parser.ioscfg
        for index, raw in enumerate(lines):
            if raw[:1].isspace() or not raw.strip().startswith(prefix):
                continue
            children = []
            cursor = index + 1
            while cursor < len(lines) and lines[cursor][:1].isspace():
                item = lines[cursor]
                children.append((cursor + 1, len(item) - len(item.lstrip()), item.strip()))
                cursor += 1
            blocks.append((raw.strip(), index + 1, children))
        return blocks

    @staticmethod
    def _credential_storage(
        storage_type: str, value: str
    ) -> CredentialStorageAssessment:
        if not value:
            return CredentialStorageAssessment.EMPTY
        if storage_type == "0":
            return CredentialStorageAssessment.PLAINTEXT
        if storage_type == "7":
            return (
                CredentialStorageAssessment.WEAK_REVERSIBLE
                if re.fullmatch(r"(?:0[0-9]|1[0-5])[0-9A-Fa-f]+", value)
                else CredentialStorageAssessment.MALFORMED
            )
        hash_types = {
            "4": ("$4$", CredentialStorageAssessment.WEAK_HASH),
            "5": ("$1$", CredentialStorageAssessment.WEAK_HASH),
            "8": ("$8$", CredentialStorageAssessment.APPROVED_HASH),
            "9": ("$9$", CredentialStorageAssessment.APPROVED_HASH),
        }
        if storage_type in hash_types:
            prefix, assessment = hash_types[storage_type]
            return (
                assessment
                if value.startswith(prefix) and len(value) > len(prefix)
                else CredentialStorageAssessment.MALFORMED
            )
        if storage_type == "6":
            return CredentialStorageAssessment.APPROVED_REVERSIBLE
        return CredentialStorageAssessment.UNKNOWN

    @staticmethod
    def _default_assessment(
        storage: CredentialStorageAssessment, value: str
    ) -> DefaultCredentialAssessment:
        if storage == CredentialStorageAssessment.EMPTY:
            return DefaultCredentialAssessment.MATCH
        if storage != CredentialStorageAssessment.PLAINTEXT:
            return DefaultCredentialAssessment.NOT_EVALUATED
        return (
            DefaultCredentialAssessment.MATCH
            if value.casefold() in {"admin", "cisco", "cisco123", "password"}
            else DefaultCredentialAssessment.NO_MATCH
        )

    @staticmethod
    def _credential_parts(tokens: list[str]) -> Optional[tuple[str, str, str]]:
        lowered = [token.casefold() for token in tokens]
        method_index = next(
            (index for index, token in enumerate(lowered) if token in {"password", "secret"}),
            None,
        )
        if method_index is None:
            return None
        method = lowered[method_index]
        value_index = method_index + 1
        storage_type = "0"
        if value_index < len(tokens) and tokens[value_index].isdigit():
            storage_type = tokens[value_index]
            value_index += 1
        elif "algorithm-type" in lowered[:method_index]:
            algorithm_index = lowered.index("algorithm-type")
            algorithm = lowered[algorithm_index + 1] if algorithm_index + 1 < len(tokens) else ""
            storage_type = {"sha256": "8", "scrypt": "9"}.get(algorithm, f"algorithm:{algorithm or 'unknown'}")
        value = tokens[value_index] if value_index < len(tokens) else ""
        return method, storage_type, value

    def get_credential_metadata(self) -> list[CredentialMetadata]:
        """Return effective local/enable credential properties without values."""

        users: dict[str, CredentialMetadata] = {}
        enable: Optional[CredentialMetadata] = None
        for line_number, raw_line in enumerate(self._source_lines, start=1):
            if raw_line[:1].isspace():
                continue
            line = raw_line.strip()
            try:
                tokens = shlex.split(line)
            except ValueError:
                continue
            if not tokens:
                continue
            lowered = [token.casefold() for token in tokens]
            if lowered[:2] in (["no", "username"], ["default", "username"]):
                if len(tokens) > 2:
                    users.pop(tokens[2].casefold(), None)
                continue
            if lowered[0] == "username" and len(tokens) > 1:
                account = tokens[1]
                parts = self._credential_parts(tokens[2:])
                if parts is None:
                    users.pop(account.casefold(), None)
                    continue
                method, storage_type, value = parts
                storage = self._credential_storage(storage_type, value)
                users[account.casefold()] = CredentialMetadata(
                    account=account,
                    context="local_user",
                    method=method,
                    storage_type=storage_type,
                    storage_assessment=storage,
                    default_assessment=self._default_assessment(storage, value),
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
                        line_number,
                    ),),
                )
                continue
            if lowered[:2] in (["no", "enable"], ["default", "enable"]):
                enable = None
                continue
            if lowered[0] == "enable":
                parts = self._credential_parts(tokens[1:])
                if parts is None:
                    continue
                method, storage_type, value = parts
                storage = self._credential_storage(storage_type, value)
                enable = CredentialMetadata(
                    account="enable",
                    context="enable",
                    method=method,
                    storage_type=storage_type,
                    storage_assessment=storage,
                    default_assessment=self._default_assessment(storage, value),
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
                        f"enable {method} {storage_type} <credential redacted>",
                        self.config_filepath,
                        line_number,
                    ),),
                )
        return [*users.values(), *([enable] if enable else [])]

    def get_additional_credential_metadata(self) -> list[CredentialMetadata]:
        """Return effective RADIUS and line secrets as value-free metadata."""

        credentials: dict[str, CredentialMetadata] = {}

        def record(key: str, context: str, account: str, method: str,
                   storage_type: str, value: str, line_number: int) -> None:
            storage = (
                CredentialStorageAssessment.UNKNOWN
                if not value or value.casefold() in {"<redacted>", "redacted", "<hidden>", "***"}
                else self._credential_storage(storage_type, value)
            )
            credentials[key] = CredentialMetadata(
                account=account,
                context=context,
                method=method,
                storage_type=storage_type,
                storage_assessment=storage,
                default_assessment=(
                    self._default_assessment(storage, value)
                    if context == "line_password"
                    else DefaultCredentialAssessment.NOT_EVALUATED
                ),
                plaintext_length=len(value) if storage == CredentialStorageAssessment.PLAINTEXT else None,
                evidence=(ConfigEvidence(
                    f"{account} {method} {storage_type} <credential redacted>",
                    self.config_filepath, line_number,
                ),),
            )

        parent = ""
        parent_indent = 0
        for line_number, raw in enumerate(self._source_lines, start=1):
            line = raw.strip()
            if not line or line == "!":
                continue
            indent = len(raw) - len(raw.lstrip())
            if indent <= parent_indent:
                parent = ""
            try:
                tokens = shlex.split(line)
            except ValueError:
                continue
            if not tokens:
                continue
            lowered = [token.casefold() for token in tokens]
            if indent == 0 and (lowered[:2] == ["radius", "server"] or lowered[0] == "line"):
                parent = line
                parent_indent = indent
                continue
            if parent and indent > parent_indent:
                if lowered[:2] in (["no", "key"], ["default", "key"],
                                   ["no", "password"], ["default", "password"]):
                    credentials.pop(parent.casefold(), None)
                    continue
                if lowered[0] in {"key", "password"} and len(tokens) >= 2:
                    marker = tokens[1] if tokens[1].isdigit() else "0"
                    value_index = 2 if tokens[1].isdigit() else 1
                    if lowered[0] == "password" and not parent.startswith("line "):
                        continue
                    if lowered[0] == "key" and not parent.startswith("radius server "):
                        continue
                    record(parent.casefold(), "line_password" if lowered[0] == "password" else "radius_key",
                           parent, lowered[0], marker, tokens[value_index] if len(tokens) > value_index else "", line_number)
                continue
            if lowered[:2] in (["no", "radius-server"], ["default", "radius-server"]):
                if lowered[2:3] == ["key"]:
                    credentials.pop("radius-server key", None)
                elif lowered[2:3] == ["host"] and len(tokens) > 3:
                    credentials.pop(f"radius-server host {tokens[3].casefold()}", None)
                continue
            if lowered[:2] == ["radius-server", "key"]:
                marker = tokens[2] if len(tokens) > 2 and tokens[2].isdigit() else "0"
                value_index = 3 if len(tokens) > 2 and tokens[2].isdigit() else 2
                record("radius-server key", "radius_key", "radius-server", "key", marker,
                       tokens[value_index] if len(tokens) > value_index else "", line_number)
            elif lowered[:2] == ["radius-server", "host"] and len(tokens) > 3:
                key_index = lowered.index("key", 3) if "key" in lowered[3:] else -1
                if key_index < 0:
                    continue
                marker = tokens[key_index + 1] if len(tokens) > key_index + 1 and tokens[key_index + 1].isdigit() else "0"
                value_index = key_index + (2 if len(tokens) > key_index + 1 and tokens[key_index + 1].isdigit() else 1)
                account = f"radius-server host {tokens[2]}"
                record(account.casefold(), "radius_key", account, "key", marker,
                       tokens[value_index] if len(tokens) > value_index else "", line_number)
        return list(credentials.values())

    _SECRET_EVIDENCE_MARKER = re.compile(r"<(?:key |credential )?redacted>|<key present>")

    def get_report_secret_evidence(self) -> list[tuple[str, ConfigEvidence]]:
        """Effective secret-bearing directives beyond credential metadata.

        Only for the opt-in ``--show-secrets`` appendix. Each item comes from a
        typed parser record that already resolved ordering, removal and binding,
        so removed or unbound secrets are not returned. The evidence text is
        sanitized; the report adapter reads the original line separately.
        """
        sources: tuple[tuple[str, list[ConfigEvidence]], ...] = (
            ("snmp_community", [item for _, _, item in self.get_snmp_community_metadata()]),
            ("snmpv3_user_key", [item for user in self.get_snmpv3_relationships()[2] for item in user.evidence]),
            ("ntp_key", [item for association in self.get_ntp_associations() for item in association.evidence]),
            ("bgp_password", [item for peer in self.get_bgp_neighbors() for item in peer.evidence]),
            ("ospf_key", [item for record in self.get_ospf_interfaces() for item in record.evidence]),
            ("rip_key", [item for record in self.get_rip_interfaces() for item in record.evidence]),
            ("eigrp_key", [item for record in self.get_eigrp_interfaces() for item in record.evidence]),
        )
        selected: dict[int, tuple[str, ConfigEvidence]] = {}
        for context, evidence in sources:
            for item in evidence:
                if (item.line_number is not None and item.source == self.config_filepath
                        and self._SECRET_EVIDENCE_MARKER.search(item.text)):
                    selected.setdefault(item.line_number, (context, item))
        for context, item in self._key_directive_evidence():
            selected.setdefault(item.line_number, (context, item))
        return [selected[number] for number in sorted(selected)]

    def _key_directive_evidence(self) -> list[tuple[str, ConfigEvidence]]:
        """Effective TACACS+ and IKE pre-shared key directives (appendix only).

        Global ``tacacs-server key`` and ``crypto isakmp key ... address``
        follow last-value and ``no`` removal; ``tacacs server`` and
        ``crypto keyring`` child keys disappear with their removed parent.
        """
        global_keys: dict[str, tuple[str, int]] = {}
        block_keys: dict[str, dict[str, tuple[str, int]]] = {}
        parent: str | None = None
        for number, raw in enumerate(self._source_lines, start=1):
            line = raw.strip()
            if not line or line == "!":
                continue
            folded = line.casefold()
            if not raw[:1].isspace():
                parent = None
                removal = re.fullmatch(r"(?:no|default) (tacacs server \S+|crypto keyring \S+)", folded)
                if removal:
                    block_keys.pop(removal.group(1), None)
                    continue
                if re.fullmatch(r"(tacacs server|crypto keyring) \S+(?: .*)?", folded):
                    parent = " ".join(folded.split()[:3])
                    block_keys[parent] = {}
                    continue
                if re.fullmatch(r"(?:no|default) tacacs-server key(?: .*)?", folded):
                    global_keys.pop("tacacs-server key", None)
                elif folded.startswith("tacacs-server key "):
                    global_keys["tacacs-server key"] = ("tacacs_key", number)
                else:
                    isakmp = re.fullmatch(r"(no )?crypto isakmp key (?:\d+ )?\S+ (address|hostname) (\S+)(?: .*)?", folded)
                    if isakmp:
                        identity = f"isakmp {isakmp.group(2)} {isakmp.group(3)}"
                        if isakmp.group(1):
                            global_keys.pop(identity, None)
                        else:
                            global_keys[identity] = ("isakmp_pre_shared_key", number)
                continue
            if parent is None:
                continue
            if parent.startswith("tacacs server"):
                if re.fullmatch(r"(?:no|default) key(?: .*)?", folded):
                    block_keys[parent].pop("key", None)
                elif folded.startswith("key "):
                    block_keys[parent]["key"] = ("tacacs_key", number)
            else:
                psk = re.fullmatch(r"(no )?pre-shared-key (address|hostname) (\S+)(?: \S+)?(?: key .*)?", folded)
                if psk:
                    identity = f"{psk.group(2)} {psk.group(3)}"
                    if psk.group(1):
                        block_keys[parent].pop(identity, None)
                    elif " key " in f" {folded} ":
                        block_keys[parent][identity] = ("keyring_pre_shared_key", number)
        found = list(global_keys.values()) + [
            item for keys in block_keys.values() for item in keys.values()
        ]
        return [
            (context, ConfigEvidence(f"{context.replace('_', ' ')} <redacted>", self.config_filepath, number))
            for context, number in found
        ]

    def get_snmp_community_metadata(self) -> list[tuple[str, str, ConfigEvidence]]:
        """Effective v1/v2c communities; names stay inside this parser boundary."""

        communities: dict[str, tuple[str, str, ConfigEvidence]] = {}
        for line_number, raw in enumerate(self._source_lines, start=1):
            if raw[:1].isspace():
                continue
            try:
                tokens = shlex.split(raw.strip())
            except ValueError:
                continue
            lowered = [token.casefold() for token in tokens]
            if lowered[:3] in (["no", "snmp-server", "community"],
                               ["default", "snmp-server", "community"]):
                if len(tokens) > 3:
                    communities.pop(tokens[3].casefold(), None)
                else:
                    communities.clear()
            elif lowered[:2] == ["snmp-server", "community"] and len(tokens) > 2:
                name = tokens[2]
                access = "rw" if "rw" in lowered[3:] else "ro"
                communities[name.casefold()] = (
                    name, access,
                    ConfigEvidence(f"snmp-server community <redacted> {access}",
                                   self.config_filepath, line_number),
                )
        return list(communities.values())

    def get_http_server_state(self) -> ConfigurationState:
        match = self._last_global_match(r"(?P<disabled>no )?ip http server")
        if match is None:
            # Defaults vary across old IOS trains. Absence is deliberately kept
            # distinct instead of being converted into an enabled assertion.
            return ConfigurationState.ABSENT
        return (
            ConfigurationState.DISABLED
            if match.group("disabled")
            else ConfigurationState.ENABLED
        )

    def get_https_server_state(self) -> ConfigurationState:
        match = self._last_global_match(r"(?P<disabled>no )?ip http secure-server")
        if match is None:
            return ConfigurationState.ABSENT
        return (
            ConfigurationState.DISABLED
            if match.group("disabled")
            else ConfigurationState.ENABLED
        )

    def get_https_selected_public_certificate(self) -> IOSHTTPSCertificate | None:
        """Assess only exported public material for an explicitly selected HTTPS trustpoint."""
        if self.get_https_server_state() != ConfigurationState.ENABLED:
            return None
        selected = ""
        selection_evidence = None
        for number, raw in enumerate(self.parser.ioscfg, 1):
            if raw[:1].isspace():
                continue
            line = raw.strip()
            match = re.fullmatch(r"ip http secure-trustpoint (\S+)", line, re.IGNORECASE)
            removed = re.fullmatch(r"no ip http secure-trustpoint(?: \S+)?", line, re.IGNORECASE)
            if match:
                selected = match.group(1)
                selection_evidence = self._routing_evidence(line, number)
            elif removed:
                selected = ""
                selection_evidence = None
        if not selected or selection_evidence is None:
            return None  # Primary/self-signed implicit selection requires separate qualification.

        chains: dict[str, list[tuple[bool, str]]] = {}
        current_chain = ""
        current_kind = ""
        hexadecimal: list[str] = []

        def flush() -> None:
            nonlocal current_kind, hexadecimal
            if current_chain and current_kind and hexadecimal:
                chains.setdefault(current_chain, []).append((
                    current_kind == "ca", "".join(hexadecimal),
                ))
            current_kind = ""
            hexadecimal = []

        for raw in self.parser.ioscfg:
            stripped = raw.strip()
            header = re.fullmatch(r"crypto pki certificate chain (\S+)", stripped, re.IGNORECASE)
            if header and not raw[:1].isspace():
                flush()
                current_chain = header.group(1).casefold()
                chains.setdefault(current_chain, [])
                continue
            if current_chain and raw[:1].isspace():
                certificate = re.fullmatch(
                    r"certificate (?:(ca|self-signed|rollover)(?: ca)? )?\S+",
                    stripped, re.IGNORECASE,
                )
                if certificate:
                    flush()
                    qualifier = (certificate.group(1) or "").casefold()
                    current_kind = "ca" if qualifier == "ca" else "identity" if qualifier != "rollover" else ""
                elif current_kind and re.fullmatch(r"[0-9A-Fa-f ]+", stripped):
                    hexadecimal.append(stripped.replace(" ", ""))
                continue
            flush()
            current_chain = ""
        flush()

        parsed: dict[str, list[tuple[bool, object]]] = {}
        for name, entries in chains.items():
            for is_ca, hex_value in entries:
                try:
                    certificate = load_public_certificate(
                        base64.b64encode(bytes.fromhex(hex_value)).decode("ascii")
                    )
                except (TypeError, ValueError):
                    continue
                parsed.setdefault(name, []).append((is_ca, certificate))
        identities = [
            certificate for is_ca, certificate in parsed.get(selected.casefold(), [])
            if not is_ca
        ]
        if len(identities) != 1:
            return None
        identity = identities[0]
        all_certificates = tuple(
            certificate for entries in parsed.values() for _, certificate in entries
        )
        assessment = assess_public_certificate(
            identity, all_certificates,
            self.assessment_context.trusted_certificate_sha256,
            self.assessment_context.management_identity_for_scope("ios-https"),
            self.assessment_context.assessment_datetime(),
        )
        return IOSHTTPSCertificate(
            trustpoint=selected,
            metadata=certificate_metadata(identity),
            assessment=assessment,
            evidence=(selection_evidence,),
        )

    def get_http_access_class(self) -> Optional[str]:
        value: Optional[str] = None
        expression = re.compile(r"(?:(?P<disabled>no)\s+)?ip http access-class(?:\s+(?P<value>\S+))?")
        for line in self._global_lines():
            match = expression.fullmatch(line)
            if match:
                value = None if match.group("disabled") else match.group("value")
        return value

    def get_http_authentication(self) -> Optional[str]:
        value: Optional[str] = None
        expression = re.compile(
            r"(?:(?P<disabled>no)\s+)?ip http auth(?:entication)?(?:\s+(?P<value>.+))?"
        )
        for line in self._global_lines():
            match = expression.fullmatch(line)
            if match:
                value = None if match.group("disabled") else match.group("value")
        return value

    def get_ssh_state(self) -> ConfigurationState:
        ssh_commands = [
            line
            for line in self._global_lines()
            if re.fullmatch(r"(?:no )?ip ssh(?:\s+.*)?", line)
        ]
        if ssh_commands and ssh_commands[-1] == "no ip ssh":
            return ConfigurationState.DISABLED

        profiles = self.get_vty_profiles()
        if any(profile.permits_ssh for profile in profiles):
            return ConfigurationState.ENABLED

        # An SSH-specific global command shows configuration intent, but a VTY
        # which explicitly excludes SSH makes the service unreachable.
        has_ssh_configuration = bool(ssh_commands and not ssh_commands[-1].startswith("no "))
        if has_ssh_configuration and not profiles:
            return ConfigurationState.ENABLED
        return ConfigurationState.ABSENT

    def get_ssh_version(self) -> Optional[str]:
        value: Optional[str] = None
        expression = re.compile(r"(?:(?P<disabled>no)\s+)?ip ssh version(?:\s+(?P<value>\S+))?")
        for line in self._global_lines():
            match = expression.fullmatch(line)
            if match:
                value = None if match.group("disabled") else match.group("value")
        return value

    def _get_numeric_ssh_setting(
        self,
        command: str,
        default: int,
    ) -> NumericSetting:
        selected_line = ""
        selected_value: Optional[str] = None
        configured = False
        command_pattern = (
            r"ip\ ssh\ time-?out"
            if command == "ip ssh time-out"
            else re.escape(command)
        )
        expression = re.compile(
            rf"(?:(?P<disabled>no)\s+)?{command_pattern}(?:\s+(?P<value>\S+))?"
        )
        for line in self._global_lines():
            match = expression.fullmatch(line)
            if not match:
                continue
            selected_line = line
            if match.group("disabled"):
                configured = False
                selected_value = None
            else:
                configured = True
                selected_value = match.group("value")

        if not configured:
            return NumericSetting(default, False, selected_line)
        if selected_value is None:
            return NumericSetting(
                None,
                True,
                selected_line,
                f"{command} is missing its numeric value",
            )
        try:
            return NumericSetting(int(selected_value), True, selected_line)
        except ValueError:
            return NumericSetting(
                None,
                True,
                selected_line,
                f"invalid numeric value {selected_value!r}",
            )

    def get_ssh_authentication_retries(self) -> NumericSetting:
        return self._get_numeric_ssh_setting("ip ssh authentication-retries", 3)

    def get_ssh_timeout(self) -> NumericSetting:
        return self._get_numeric_ssh_setting("ip ssh time-out", 120)

    def get_vty_profiles(self) -> list[VTYProfile]:
        profiles = []
        for line in self.get_management_lines("vty"):
            profiles.append(
                VTYProfile(
                    line=line.line,
                    transports=line.transports or (),
                    ipv4_access_class=line.ipv4_access_class,
                    ipv6_access_class=line.ipv6_access_class,
                )
            )
        return profiles

    def get_aaa_method_lists(self) -> list[IOSAAAMethodList]:
        """Return effective login/EXEC/command authorization method lists."""

        method_lists: dict[tuple[str, str, Optional[int]], IOSAAAMethodList] = {}
        patterns = (
            ("login_authentication", re.compile(r"aaa authentication login\s+(\S+)\s+(.+)")),
            ("exec_authorization", re.compile(r"aaa authorization exec\s+(\S+)\s+(.+)")),
            ("command_authorization", re.compile(r"aaa authorization commands\s+(\d+)\s+(\S+)\s+(.+)")),
        )
        for line_number, raw_line in enumerate(self.parser.ioscfg, start=1):
            if raw_line[:1].isspace():
                continue
            line = raw_line.strip()
            removal = re.fullmatch(
                r"(?:no|default) aaa (authentication login|authorization exec|authorization commands)\s+(.+)",
                line,
            )
            if removal:
                tail = removal.group(2).split()
                service = removal.group(1)
                if service == "authentication login" and tail:
                    method_lists.pop(("login_authentication", tail[0], None), None)
                elif service == "authorization exec" and tail:
                    method_lists.pop(("exec_authorization", tail[0], None), None)
                elif service == "authorization commands" and len(tail) >= 2:
                    level = int(tail[0]) if tail[0].isdigit() else None
                    method_lists.pop(("command_authorization", tail[1], level), None)
                continue
            for service, expression in patterns:
                match = expression.fullmatch(line)
                if not match:
                    continue
                if service == "command_authorization":
                    level = int(match.group(1))
                    name = match.group(2)
                    methods = tuple(match.group(3).split())
                else:
                    level = None
                    name = match.group(1)
                    methods = tuple(match.group(2).split())
                method_lists[(service, name, level)] = IOSAAAMethodList(
                    service=service,
                    name=name,
                    privilege_level=level,
                    methods=methods,
                    evidence=ConfigEvidence(line, self.config_filepath, line_number),
                )
                break
        return list(method_lists.values())

    def get_aaa_accounting_lists(self) -> list[IOSAAAAccountingList]:
        """Return effective EXEC and command accounting lists in source order."""
        lists: dict[tuple[str, str, Optional[int]], IOSAAAAccountingList] = {}
        expression = re.compile(
            r"aaa accounting (exec|commands\s+(\d+))\s+(\S+)\s+"
            r"(start-stop|stop-only|none)(?:\s+(.+))?"
        )
        removal = re.compile(
            r"(?:no|default) aaa accounting (exec|commands\s+(\d+))\s+(\S+)(?:\s+.*)?"
        )
        for line_number, raw in enumerate(self._source_lines, start=1):
            if raw[:1].isspace():
                continue
            line = raw.strip()
            match = removal.fullmatch(line)
            if match:
                service = "commands" if match.group(2) else "exec"
                level = int(match.group(2)) if match.group(2) else None
                lists.pop((service, match.group(3), level), None)
                continue
            match = expression.fullmatch(line)
            if not match:
                continue
            service = "commands" if match.group(2) else "exec"
            level = int(match.group(2)) if match.group(2) else None
            name = match.group(3)
            lists[(service, name, level)] = IOSAAAAccountingList(
                service=service,
                name=name,
                privilege_level=level,
                record_type=match.group(4),
                methods=tuple((match.group(5) or "").split()),
                evidence=ConfigEvidence(line, self.config_filepath, line_number),
            )
        return list(lists.values())

    def get_aaa_server_group_records(self) -> tuple[IOSAAAServerGroup, ...]:
        """Distinguish an explicitly empty named group from a referenced group."""
        groups: dict[tuple[str, str], dict] = {}
        active: tuple[str, str] | None = None
        expression = re.compile(r"aaa group server (radius|tacacs\+)\s+(\S+)")
        for line_number, raw in enumerate(self._source_lines, start=1):
            line = raw.strip()
            if not line or line == "!":
                if line == "!":
                    active = None
                continue
            if not raw[:1].isspace():
                active = None
                removed = re.fullmatch(r"(?:no|default) (aaa group server (?:radius|tacacs\+)\s+\S+)", line)
                if removed:
                    match = expression.fullmatch(removed.group(1))
                    if match:
                        groups.pop((match.group(1), match.group(2)), None)
                    continue
                match = expression.fullmatch(line)
                if match:
                    active = (match.group(1), match.group(2))
                    groups.setdefault(active, {
                        "members": set(),
                        "evidence": ConfigEvidence(line, self.config_filepath, line_number),
                    })
                continue
            if active is None:
                continue
            member = re.fullmatch(r"server(?:-private)?\s+(?:name\s+)?(\S+)(?:\s+.*)?", line)
            removal = re.fullmatch(r"(?:no|default) server(?:-private)?\s+(?:name\s+)?(\S+)(?:\s+.*)?", line)
            if member:
                groups[active]["members"].add(member.group(1))
            elif removal:
                groups[active]["members"].discard(removal.group(1))
        return tuple(
            IOSAAAServerGroup(name=name, protocol=protocol,
                              members=tuple(sorted(data["members"])),
                              evidence=data["evidence"])
            for (protocol, name), data in groups.items()
        )

    def get_effective_vty_aaa(self) -> tuple[IOSVTYAAABinding, ...]:
        """Overlay AAA-related VTY mutations on physical line numbers."""
        states: dict[int, dict] = {}
        for parent in self.parser.find_objects(r"^line vty(?:\s|$)"):
            match = re.fullmatch(r"line vty\s+(\d+)(?:\s+(\d+))?", parent.text.strip())
            if not match:
                continue
            first, last = int(match.group(1)), int(match.group(2) or match.group(1))
            if last < first or last - first > 4096:
                continue
            for number in range(first, last + 1):
                state = states.setdefault(number, {
                    "active": True, "login_kind": None, "login_list": None,
                    "exec_authorization_list": None, "command_authorization_list": None,
                    "exec_accounting_list": None, "command_accounting_list": None,
                    "evidence": [],
                })
                for child in parent.children:
                    command = child.text.strip()
                    mutation: dict[str, object] = {}
                    if command in {"no exec", "default exec", "exec"}:
                        mutation["active"] = command != "no exec"
                    elif re.fullmatch(r"transport input\s+none", command):
                        mutation["active"] = False
                    elif re.fullmatch(r"transport input\s+.+", command):
                        mutation["active"] = True
                    elif re.fullmatch(r"(?:no|default) transport input(?:\s+.*)?", command):
                        mutation["active"] = True
                    elif command == "login local":
                        mutation.update(login_kind="local", login_list=None)
                    elif command == "no login":
                        mutation.update(login_kind="none", login_list=None)
                    elif command == "login":
                        mutation.update(login_kind="line_password", login_list=None)
                    else:
                        for pattern, field in (
                            (r"login authentication\s+(\S+)", "login_list"),
                            (r"authorization exec\s+(\S+)", "exec_authorization_list"),
                            (r"authorization commands\s+15\s+(\S+)", "command_authorization_list"),
                            (r"accounting exec\s+(\S+)", "exec_accounting_list"),
                            (r"accounting commands\s+15\s+(\S+)", "command_accounting_list"),
                        ):
                            found = re.fullmatch(pattern, command)
                            if found:
                                mutation[field] = found.group(1)
                                if field == "login_list":
                                    mutation["login_kind"] = "aaa"
                                break
                        if not mutation:
                            reset = re.fullmatch(
                                r"(?:no|default) (login authentication|authorization exec|"
                                r"authorization commands 15|accounting exec|accounting commands 15)(?:\s+\S+)?",
                                command,
                            )
                            if reset:
                                field = {
                                    "login authentication": "login_list",
                                    "authorization exec": "exec_authorization_list",
                                    "authorization commands 15": "command_authorization_list",
                                    "accounting exec": "exec_accounting_list",
                                    "accounting commands 15": "command_accounting_list",
                                }[reset.group(1)]
                                mutation[field] = None
                                if field == "login_list":
                                    mutation["login_kind"] = None
                    if mutation:
                        state.update(mutation)
                        index = getattr(child, "linenum", None)
                        state["evidence"].append(ConfigEvidence(
                            command, self.config_filepath,
                            index + 1 if isinstance(index, int) else None,
                        ))
        rows = sorted(states.items())
        result = []
        index = 0
        fields = (
            "active", "login_kind", "login_list", "exec_authorization_list",
            "command_authorization_list", "exec_accounting_list", "command_accounting_list",
        )
        while index < len(rows):
            first, state = rows[index]
            last = first
            signature = tuple(state[field] for field in fields) + (tuple(state["evidence"]),)
            index += 1
            while index < len(rows):
                number, following = rows[index]
                candidate = tuple(following[field] for field in fields) + (tuple(following["evidence"]),)
                if number != last + 1 or candidate != signature:
                    break
                last = number
                index += 1
            label = f"line vty {first}" + (f" {last}" if first != last else "")
            result.append(IOSVTYAAABinding(
                line=label, active=state["active"],
                login_kind=state["login_kind"], login_list=state["login_list"],
                exec_authorization_list=state["exec_authorization_list"],
                command_authorization_list=state["command_authorization_list"],
                exec_accounting_list=state["exec_accounting_list"],
                command_accounting_list=state["command_accounting_list"],
                evidence=(ConfigEvidence(label, self.config_filepath), *state["evidence"]),
            ))
        return tuple(result)

    def get_aaa_server_groups(self) -> set[str]:
        groups: set[str] = set()
        expression = re.compile(r"aaa group server (?:radius|tacacs\+)\s+(\S+)")
        removal = re.compile(r"(?:no|default) aaa group server (?:radius|tacacs\+)\s+(\S+)")
        for line in self._global_lines():
            removed = removal.fullmatch(line)
            configured = expression.fullmatch(line)
            if removed:
                groups.discard(removed.group(1))
            elif configured:
                groups.add(configured.group(1))
        return groups

    def get_management_lines(self, line_type: Optional[str] = None) -> list[IOSManagementLine]:
        """Return typed effective state for console, AUX, TTY, and VTY blocks."""

        profiles: list[IOSManagementLine] = []
        for parent in self.parser.find_objects(r"^line (?:con(?:sole)?|aux|tty|vty)(?:\s|$)"):
            parent_line = parent.text.strip()
            kind_match = re.match(r"line\s+(con(?:sole)?|aux|tty|vty)(?:\s|$)", parent_line)
            kind = (kind_match.group(1) if kind_match else "").casefold()
            if kind.startswith("con"):
                kind = "console"
            if line_type is not None and kind != line_type:
                continue

            transports: Optional[tuple[str, ...]] = None
            output_transports: Optional[tuple[str, ...]] = None
            exec_enabled: Optional[bool] = None
            timeout_minutes: Optional[int] = None
            timeout_seconds: Optional[int] = None
            timeout_configured = False
            timeout_parse_error = ""
            login_kind: Optional[str] = None
            login_list: Optional[str] = None
            ipv4_access_class = ""
            ipv6_access_class = ""
            exec_authorization_list: Optional[str] = None
            command_authorization: dict[int, str] = {}
            parent_index = getattr(parent, "linenum", None)
            parent_number = parent_index + 1 if isinstance(parent_index, int) else None
            evidence = [ConfigEvidence(parent_line, self.config_filepath, parent_number)]

            for child in parent.children:
                command = child.text.strip()
                child_index = getattr(child, "linenum", None)
                child_number = child_index + 1 if isinstance(child_index, int) else None
                command_evidence = ConfigEvidence(command, self.config_filepath, child_number)
                transport = re.fullmatch(r"transport (input|output)(?:\s+(.+))?", command)
                if transport:
                    value = tuple((transport.group(2) or "").casefold().split())
                    if transport.group(1) == "input":
                        transports = value
                    else:
                        output_transports = value
                    evidence.append(command_evidence)
                    continue
                reset_transport = re.fullmatch(r"(?:no|default) transport (input|output)(?:\s+.*)?", command)
                if reset_transport:
                    if reset_transport.group(1) == "input":
                        transports = None
                    else:
                        output_transports = None
                    evidence.append(command_evidence)
                    continue
                if command == "exec":
                    exec_enabled = True
                    evidence.append(command_evidence)
                    continue
                if command in {"no exec", "default exec"}:
                    exec_enabled = False if command == "no exec" else None
                    evidence.append(command_evidence)
                    continue
                timeout = re.fullmatch(r"exec-timeout(?:\s+(\S+))?(?:\s+(\S+))?", command)
                if timeout:
                    timeout_configured = True
                    evidence.append(command_evidence)
                    try:
                        timeout_minutes = int(timeout.group(1)) if timeout.group(1) is not None else None
                        timeout_seconds = int(timeout.group(2) or 0) if timeout_minutes is not None else None
                        if timeout_minutes is None or timeout_minutes < 0 or timeout_seconds is None or not 0 <= timeout_seconds <= 59:
                            raise ValueError
                    except ValueError:
                        timeout_minutes = None
                        timeout_seconds = None
                        timeout_parse_error = "invalid exec-timeout"
                    continue
                if re.fullmatch(r"(?:no|default) exec-timeout(?:\s+.*)?", command):
                    timeout_minutes = None
                    timeout_seconds = None
                    timeout_configured = False
                    timeout_parse_error = ""
                    evidence.append(command_evidence)
                    continue
                login_auth = re.fullmatch(r"login authentication\s+(\S+)", command)
                if login_auth:
                    login_kind = "aaa"
                    login_list = login_auth.group(1)
                    evidence.append(command_evidence)
                    continue
                if command == "login local":
                    login_kind = "local"
                    login_list = None
                    evidence.append(command_evidence)
                    continue
                if command == "login":
                    login_kind = "line_password"
                    login_list = None
                    evidence.append(command_evidence)
                    continue
                if command == "no login":
                    login_kind = "none"
                    login_list = None
                    evidence.append(command_evidence)
                    continue
                if re.fullmatch(r"(?:no|default) login authentication(?:\s+\S+)?", command):
                    login_kind = None
                    login_list = None
                    evidence.append(command_evidence)
                    continue
                exec_auth = re.fullmatch(r"authorization exec\s+(\S+)", command)
                if exec_auth:
                    exec_authorization_list = exec_auth.group(1)
                    evidence.append(command_evidence)
                    continue
                if re.fullmatch(r"(?:no|default) authorization exec(?:\s+\S+)?", command):
                    exec_authorization_list = None
                    evidence.append(command_evidence)
                    continue
                command_auth = re.fullmatch(r"authorization commands\s+(\d+)\s+(\S+)", command)
                if command_auth:
                    command_authorization[int(command_auth.group(1))] = command_auth.group(2)
                    evidence.append(command_evidence)
                    continue
                command_auth_reset = re.fullmatch(r"(?:no|default) authorization commands\s+(\d+)(?:\s+\S+)?", command)
                if command_auth_reset:
                    command_authorization.pop(int(command_auth_reset.group(1)), None)
                    evidence.append(command_evidence)
                    continue
                access_class = re.fullmatch(r"access-class\s+(\S+)\s+in(?:\s+vrf-also)?", command)
                if access_class:
                    ipv4_access_class = access_class.group(1)
                    evidence.append(command_evidence)
                    continue
                if re.fullmatch(r"(?:no|default) access-class(?:\s+.*)?", command):
                    ipv4_access_class = ""
                    evidence.append(command_evidence)
                    continue
                ipv6_access = re.fullmatch(r"ipv6 access-class\s+(\S+)\s+in", command)
                if ipv6_access:
                    ipv6_access_class = ipv6_access.group(1)
                    evidence.append(command_evidence)
                    continue
                if re.fullmatch(r"(?:no|default) ipv6 access-class(?:\s+.*)?", command):
                    ipv6_access_class = ""
                    evidence.append(command_evidence)

            profiles.append(IOSManagementLine(
                line=parent_line,
                line_type=kind,
                transports=transports,
                output_transports=output_transports,
                exec_enabled=exec_enabled,
                timeout_minutes=timeout_minutes,
                timeout_seconds=timeout_seconds,
                timeout_configured=timeout_configured,
                timeout_parse_error=timeout_parse_error,
                login_kind=login_kind,
                login_list=login_list,
                ipv4_access_class=ipv4_access_class,
                ipv6_access_class=ipv6_access_class,
                exec_authorization_list=exec_authorization_list,
                command_authorization=tuple(sorted(command_authorization.items())),
                evidence=tuple(evidence),
            ))
        return profiles

    def get_effective_line_timeouts(self) -> tuple[IOSLineTimeoutPolicy, ...]:
        """Overlay line-range timeout and activation mutations in source order."""
        states: dict[tuple[str, int], dict] = {}
        for profile in self.get_management_lines():
            match = re.fullmatch(
                r"line\s+(con(?:sole)?|aux|tty|vty)\s+(\d+)(?:\s+(\d+))?",
                profile.line,
                re.IGNORECASE,
            )
            if not match:
                continue
            kind = match.group(1).casefold()
            if kind.startswith("con"):
                kind = "console"
            start = int(match.group(2))
            end = int(match.group(3) or start)
            if end < start or end - start > 4096:
                continue
            commands = tuple(item.text for item in profile.evidence[1:])
            timeout_reset = any(re.fullmatch(r"(?:no|default) exec-timeout(?:\s+.*)?", item) for item in commands)
            exec_reset = "default exec" in commands
            transport_reset = any(re.fullmatch(r"(?:no|default) transport input(?:\s+.*)?", item) for item in commands)
            mutation_evidence = tuple(
                item for item in profile.evidence[1:]
                if re.fullmatch(
                    r"(?:exec-timeout|(?:no|default) exec-timeout|exec|no exec|default exec|"
                    r"transport input|(?:no|default) transport input)(?:\s+.*)?",
                    item.text,
                )
            )
            for number in range(start, end + 1):
                state = states.setdefault((kind, number), {
                    "exec": None,
                    "transports": None,
                    "minutes": None,
                    "seconds": None,
                    "configured": False,
                    "error": "",
                    "evidence": [],
                })
                if profile.timeout_configured or profile.timeout_parse_error:
                    state.update(
                        minutes=profile.timeout_minutes,
                        seconds=profile.timeout_seconds,
                        configured=profile.timeout_configured,
                        error=profile.timeout_parse_error,
                    )
                elif timeout_reset:
                    state.update(minutes=None, seconds=None, configured=False, error="")
                if profile.exec_enabled is not None:
                    state["exec"] = profile.exec_enabled
                elif exec_reset:
                    state["exec"] = None
                if profile.transports is not None:
                    state["transports"] = profile.transports
                elif transport_reset:
                    state["transports"] = None
                state["evidence"].extend(mutation_evidence)

        rows = []
        for (kind, number), state in sorted(states.items()):
            active = False if (
                state["exec"] is False or state["transports"] == ("none",)
            ) else None if kind in {"vty", "tty"} and state["transports"] is None else True
            rows.append((kind, number, active, state))

        results: list[IOSLineTimeoutPolicy] = []
        index = 0
        while index < len(rows):
            kind, start, active, state = rows[index]
            end = start
            signature = (
                active, state["minutes"], state["seconds"], state["configured"],
                state["error"], tuple(state["evidence"]),
            )
            index += 1
            while index < len(rows):
                next_kind, number, next_active, next_state = rows[index]
                next_signature = (
                    next_active, next_state["minutes"], next_state["seconds"],
                    next_state["configured"], next_state["error"], tuple(next_state["evidence"]),
                )
                if next_kind != kind or number != end + 1 or next_signature != signature:
                    break
                end = number
                index += 1
            label = f"line {'con' if kind == 'console' else kind} {start}"
            if end != start:
                label += f" {end}"
            results.append(IOSLineTimeoutPolicy(
                line=label,
                line_type=kind,
                start=start,
                end=end,
                active=active,
                timeout_minutes=state["minutes"],
                timeout_seconds=state["seconds"],
                timeout_configured=state["configured"],
                timeout_parse_error=state["error"],
                evidence=(ConfigEvidence(label, self.config_filepath), *tuple(state["evidence"])),
            ))
        return tuple(results)

    def get_ssh_server_algorithms(self) -> list[IOSSSHAlgorithmPolicy]:
        categories = ("encryption", "mac", "kex", "hostkey")
        state: dict[str, Optional[tuple[str, ...]]] = {category: None for category in categories}
        evidence: dict[str, list[ConfigEvidence]] = {category: [] for category in categories}
        expression = re.compile(
            r"(?:(no|default)\s+)?ip ssh server algorithm "
            r"(encryption|mac|kex|hostkey)(?:\s+(.+))?"
        )
        for line_number, raw_line in enumerate(self.parser.ioscfg, start=1):
            if raw_line[:1].isspace():
                continue
            line = raw_line.strip()
            match = expression.fullmatch(line)
            if not match:
                continue
            operation, category, values = match.groups()
            item = ConfigEvidence(line, self.config_filepath, line_number)
            evidence[category].append(item)
            if operation == "default" or (operation == "no" and not values):
                state[category] = None
            elif operation == "no":
                if state[category] is not None:
                    removed = set(values.casefold().split())
                    state[category] = tuple(value for value in state[category] or () if value not in removed)
            else:
                state[category] = tuple((values or "").casefold().split())
        return [
            IOSSSHAlgorithmPolicy(category, state[category], tuple(evidence[category]))
            for category in categories
        ]

    def get_ssh_rsa_key_modulus(self) -> NumericSetting:
        selected = ""
        value: Optional[int] = None
        configured = False
        parse_error = ""
        expression = re.compile(r"crypto key generate rsa(?:\s+general-keys)?(?:\s+modulus\s+(\S+))?.*")
        for line in self._global_lines():
            match = expression.fullmatch(line)
            if not match:
                continue
            selected = line
            configured = True
            try:
                value = int(match.group(1)) if match.group(1) is not None else None
                if value is None or value <= 0:
                    raise ValueError
            except ValueError:
                value = None
                parse_error = "invalid RSA modulus"
        return NumericSetting(value, configured, selected, parse_error)

    def get_ntp_associations(self) -> list[IOSNTPAssociation]:
        authentication = False
        trusted: set[str] = set()
        keys: dict[str, tuple[str, ConfigEvidence]] = {}
        configured: dict[tuple[str, str, str], tuple[str, ConfigEvidence]] = {}
        for line_number, raw_line in enumerate(self.parser.ioscfg, start=1):
            if raw_line[:1].isspace():
                continue
            line = raw_line.strip()
            if line == "ntp authenticate":
                authentication = True
                continue
            if line in {"no ntp authenticate", "default ntp authenticate"}:
                authentication = False
                continue
            trust = re.fullmatch(r"(?P<no>(?:no|default)\s+)?ntp trusted-key\s+(\S+)", line)
            if trust:
                key_id = trust.group(2)
                if trust.group("no"):
                    trusted.discard(key_id)
                else:
                    trusted.add(key_id)
                continue
            removed_key = re.fullmatch(r"(?:no|default) ntp authentication-key\s+(\S+)(?:\s+.*)?", line)
            key = re.fullmatch(r"ntp authentication-key\s+(\S+)\s+(\S+)\s+(?:0\s+|7\s+)?(\S+)", line)
            if removed_key:
                keys.pop(removed_key.group(1), None)
                continue
            if key:
                key_id, algorithm, _ = key.groups()
                keys[key_id] = (
                    algorithm.casefold(),
                    ConfigEvidence(
                        f"ntp authentication-key {key_id} {algorithm.casefold()} <key redacted>",
                        self.config_filepath,
                        line_number,
                    ),
                )
                continue
            tokens = line.casefold().split()
            offset = 0
            if tokens[:2] in (["ntp", "server"], ["ntp", "peer"]):
                removed = False
            elif tokens[:3] in (
                ["no", "ntp", "server"],
                ["no", "ntp", "peer"],
                ["default", "ntp", "server"],
                ["default", "ntp", "peer"],
            ):
                removed = True
                offset = 1
            else:
                continue
            role = tokens[1 + offset]
            index = 2 + offset
            vrf = "default"
            if index < len(tokens) and tokens[index] == "vrf":
                if index + 2 >= len(tokens):
                    continue
                vrf = tokens[index + 1]
                index += 2
            if index >= len(tokens):
                continue
            address = tokens[index]
            tail = tokens[index + 1 :]
            identity = (role, vrf, address)
            if removed:
                configured.pop(identity, None)
                continue
            key_id = tail[tail.index("key") + 1] if "key" in tail and tail.index("key") + 1 < len(tail) else ""
            configured[identity] = (
                key_id,
                ConfigEvidence(line, self.config_filepath, line_number),
            )
        associations = []
        for (role, vrf, address), (key_id, server_evidence) in configured.items():
            key = keys.get(key_id)
            if not authentication or not key_id:
                state = "unauthenticated"
            elif key is None or key_id not in trusted:
                state = "unresolved"
            else:
                state = "authenticated"
            associations.append(IOSNTPAssociation(
                role=role,
                address=address,
                vrf=vrf,
                key_id=key_id,
                authentication_state=state,
                algorithm=key[0] if key else "",
                evidence=(server_evidence,) + ((key[1],) if key else ()),
            ))
        return associations

    def get_snmpv3_relationships(
        self,
    ) -> tuple[list[IOSSNMPView], list[IOSSNMPGroup], list[IOSSNMPUser]]:
        """Return effective IOS SNMPv3 view/group/user relationships.

        Passwords and localized keys are reduced to presence state while the
        command is parsed. They are never retained in evidence.
        """

        view_entries: dict[tuple[str, str], tuple[str, ConfigEvidence]] = {}
        groups: dict[str, IOSSNMPGroup] = {}
        raw_users: dict[
            str, tuple[str, str, str, str, str, str, str, ConfigEvidence]
        ] = {}

        for line_number, raw_line in enumerate(self.parser.ioscfg, start=1):
            if raw_line[:1].isspace():
                continue
            line = raw_line.strip()
            try:
                tokens = shlex.split(line)
            except ValueError:
                continue
            lowered = [token.casefold() for token in tokens]

            view_offset = (
                0
                if lowered[:2] == ["snmp-server", "view"]
                else 1
                if len(lowered) >= 3
                and lowered[0] in {"no", "default"}
                and lowered[1:3] == ["snmp-server", "view"]
                else None
            )
            if view_offset is not None:
                offset = view_offset
                if len(tokens) < offset + 4:
                    continue
                name = tokens[offset + 2]
                subtree = tokens[offset + 3]
                key = (name.casefold(), subtree.casefold())
                if offset:
                    view_entries.pop(key, None)
                    continue
                inclusion = lowered[offset + 4] if len(tokens) > offset + 4 else "included"
                if inclusion not in {"included", "excluded"}:
                    continue
                view_entries[key] = (
                    inclusion,
                    ConfigEvidence(
                        f"snmp-server view {name} {subtree} {inclusion}",
                        self.config_filepath,
                        line_number,
                    ),
                )
                continue

            group_offset = (
                0
                if lowered[:2] == ["snmp-server", "group"]
                else 1
                if len(lowered) >= 3
                and lowered[0] in {"no", "default"}
                and lowered[1:3] == ["snmp-server", "group"]
                else None
            )
            if group_offset is not None:
                offset = group_offset
                if len(tokens) < offset + 3:
                    continue
                name = tokens[offset + 2]
                if offset:
                    groups.pop(name.casefold(), None)
                    continue
                tail = lowered[offset + 3 :]
                if "v3" not in tail:
                    continue
                v3_index = tail.index("v3")
                security_level = tail[v3_index + 1] if v3_index + 1 < len(tail) and tail[v3_index + 1] in {"noauth", "auth", "priv"} else "noauth"

                def option(name: str) -> str:
                    return tail[tail.index(name) + 1] if name in tail and tail.index(name) + 1 < len(tail) else ""

                read_view = option("read")
                write_view = option("write")
                access_list = option("access")
                groups[name.casefold()] = IOSSNMPGroup(
                    name=name,
                    security_level=security_level,
                    read_view=read_view,
                    write_view=write_view,
                    access_list=access_list,
                    evidence=(ConfigEvidence(
                        f"snmp-server group {name} v3 {security_level}"
                        f" read {read_view or '<default>'}"
                        f" access {access_list or '<unrestricted>'}",
                        self.config_filepath,
                        line_number,
                    ),),
                )
                continue

            offset = 0
            if lowered[:2] == ["snmp-server", "user"]:
                removed = False
            elif len(lowered) >= 3 and lowered[0] in {"no", "default"} and lowered[1:3] == ["snmp-server", "user"]:
                removed = True
                offset = 1
            else:
                continue
            if len(tokens) < offset + 4:
                continue
            name, group = tokens[offset + 2], tokens[offset + 3]
            if removed:
                raw_users.pop(name.casefold(), None)
                continue
            tail = tokens[offset + 4 :]
            folded = [token.casefold() for token in tail]
            if "v3" not in folded:
                continue

            def parse_secret_option(keyword: str) -> tuple[str, str]:
                if keyword not in folded:
                    return "", "missing"
                index = folded.index(keyword) + 1
                if index >= len(folded):
                    return "", "unknown"
                algorithm = folded[index]
                index += 1
                if algorithm == "sha-2" and index < len(folded) and folded[index] in {"256", "384", "512"}:
                    algorithm = f"sha-{folded[index]}"
                    index += 1
                elif algorithm == "aes" and index < len(folded) and folded[index] in {"128", "192", "256"}:
                    algorithm = f"aes-{folded[index]}"
                    index += 1
                if index < len(folded) and folded[index] in {"0", "6", "7", "encrypted"}:
                    index += 1
                key_state = (
                    "present"
                    if index < len(folded) and folded[index] not in {"auth", "priv", "access"}
                    else "unknown"
                )
                return algorithm, key_state

            authentication, auth_key_state = parse_secret_option("auth")
            privacy, privacy_key_state = parse_secret_option("priv")
            access_list = ""
            if "access" in folded and folded.index("access") + 1 < len(folded):
                access_index = folded.index("access") + 1
                if folded[access_index] == "ipv6" and access_index + 1 < len(folded):
                    access_index += 1
                access_list = tail[access_index]
            raw_users[name.casefold()] = (
                name,
                group,
                authentication,
                privacy,
                auth_key_state,
                privacy_key_state,
                access_list,
                ConfigEvidence(
                    f"snmp-server user {name} {group} v3 auth {authentication or 'none'} "
                    f"<key {auth_key_state}> priv {privacy or 'none'} <key {privacy_key_state}> "
                    f"access {access_list or '<group-or-unrestricted>'}",
                    self.config_filepath,
                    line_number,
                ),
            )

        by_view: dict[str, list[tuple[str, str, ConfigEvidence]]] = {}
        for (view_name, subtree), (inclusion, evidence) in view_entries.items():
            by_view.setdefault(view_name, []).append((subtree, inclusion, evidence))
        views = [
            IOSSNMPView(
                name=name,
                included_subtrees=tuple(item[0] for item in entries if item[1] == "included"),
                excluded_subtrees=tuple(item[0] for item in entries if item[1] == "excluded"),
                evidence=tuple(item[2] for item in entries),
            )
            for name, entries in by_view.items()
        ]
        view_names = set(by_view)
        users = []
        for (
            name,
            group_name,
            authentication,
            privacy,
            auth_state,
            privacy_state,
            access_list,
            user_evidence,
        ) in raw_users.values():
            group = groups.get(group_name.casefold())
            read_view = group.read_view if group else ""
            users.append(IOSSNMPUser(
                name=name,
                group=group_name,
                authentication=authentication,
                privacy=privacy,
                authentication_key_state=auth_state,
                privacy_key_state=privacy_state,
                access_list=access_list,
                group_security_level=group.security_level if group else "",
                group_resolved=group is not None,
                read_view=read_view,
                read_view_resolved=not read_view or read_view.casefold() in view_names,
                source_restricted=bool(
                    group and group.access_list or access_list
                ),
                evidence=(user_evidence,) + (group.evidence if group else ()),
            ))
        return views, list(groups.values()), users

    def get_bgp_neighbors(self) -> list[IOSBGPNeighbor]:
        """Resolve IOS BGP peer-group inheritance and per-AF protection state."""

        return self._bgp_neighbors(self._indented_blocks("router bgp "))

    def _bgp_neighbors(self, blocks) -> list[IOSBGPNeighbor]:
        results: list[IOSBGPNeighbor] = []
        policy_commands = {"route-map", "prefix-list", "filter-list", "distribute-list"}
        for header, header_line, children in blocks:
            local_as = header.split(maxsplit=2)[-1]
            global_lines: list[tuple[int, str]] = []
            af_lines: dict[tuple[str, str], list[tuple[int, str]]] = {}
            current_af: Optional[tuple[str, str]] = None
            af_indent = 0
            default_ipv4 = True
            for line_number, indent, command in children:
                if command.startswith("address-family "):
                    tokens = command.split()
                    family = " ".join(tokens[1:3]) if len(tokens) > 2 and tokens[2] not in {"vrf"} else tokens[1]
                    vrf = tokens[tokens.index("vrf") + 1] if "vrf" in tokens and tokens.index("vrf") + 1 < len(tokens) else "default"
                    current_af = (family, vrf)
                    af_indent = indent
                    af_lines.setdefault(current_af, [])
                    continue
                if current_af is not None and indent <= af_indent:
                    current_af = None
                if current_af is None:
                    global_lines.append((line_number, command))
                    if command == "no bgp default ipv4-unicast":
                        default_ipv4 = False
                    elif command in {"bgp default ipv4-unicast", "default bgp default ipv4-unicast"}:
                        default_ipv4 = True
                else:
                    af_lines[current_af].append((line_number, command))

            groups: set[str] = set()
            assignments: dict[str, str] = {}
            remote_as: dict[str, str] = {}
            props: dict[str, dict[str, object]] = {}
            evidence: dict[str, list[ConfigEvidence]] = {}

            def apply_peer_line(line_number: int, command: str, target_props: dict[str, dict[str, object]], target_evidence: dict[str, list[ConfigEvidence]]) -> None:
                match = re.fullmatch(r"(?:(no|default)\s+)?neighbor\s+(\S+)\s+(.+)", command)
                if not match:
                    return
                removal, name, tail = bool(match.group(1)), match.group(2), match.group(3)
                # EOS spells peer groups "peer group" (two words).
                tail = re.sub(r"^peer group\b", "peer-group", tail, flags=re.IGNORECASE)
                tokens = tail.split()
                folded = [token.casefold() for token in tokens]
                data = target_props.setdefault(name, {})
                target_evidence.setdefault(name, []).append(self._routing_evidence(command, line_number))
                if folded == ["peer-group"]:
                    if not removal:
                        groups.add(name)
                    return
                if folded[:1] == ["peer-group"] and len(tokens) > 1:
                    if removal:
                        assignments.pop(name, None)
                    else:
                        assignments[name] = tokens[1]
                    return
                if folded[:1] == ["remote-as"] and len(tokens) > 1:
                    if removal:
                        remote_as.pop(name, None)
                    else:
                        remote_as[name] = tokens[1]
                    return
                if folded[:1] == ["password"]:
                    data["password"] = not removal and len(tokens) > 1
                    data["auth_method"] = "md5" if data["password"] else ""
                elif folded[:1] in (["tcp-ao"], ["ao"]):
                    data["password"] = not removal
                    data["auth_method"] = "tcp-ao" if not removal else ""
                elif folded[:1] == ["shutdown"]:
                    data["shutdown"] = not removal
                elif folded[:1] == ["activate"]:
                    data["activate"] = not removal
                elif folded[:1] == ["maximum-prefix"]:
                    data["limit"] = not removal
                elif folded[:1] == ["maximum-routes"]:
                    data["limit"] = not removal and folded[1:2] != ["0"]
                    data["maximum_routes"] = "" if removal else (tokens[1] if len(tokens) > 1 else "")
                elif folded and folded[0] in policy_commands and folded[-1:] in (["in"], ["out"]):
                    data[folded[-1]] = not removal
                    if len(tokens) >= 3:
                        data[f"policy_{folded[0]}_{folded[-1]}"] = tokens[1] if not removal else False

            for line_number, command in global_lines:
                apply_peer_line(line_number, command, props, evidence)

            identities = set(remote_as) | set(assignments)
            identities -= groups
            contexts: list[tuple[tuple[str, str], dict[str, dict[str, object]], dict[str, list[ConfigEvidence]]]] = []
            if default_ipv4:
                contexts.append((("ipv4 unicast", "default"), {}, {}))
            for context, lines in af_lines.items():
                scoped_props: dict[str, dict[str, object]] = {}
                scoped_evidence: dict[str, list[ConfigEvidence]] = {}
                for line_number, command in lines:
                    apply_peer_line(line_number, command, scoped_props, scoped_evidence)
                contexts.append((context, scoped_props, scoped_evidence))

            for (family, vrf), scoped_props, scoped_evidence in contexts:
                for name in sorted(identities | set(scoped_props)):
                    group = assignments.get(name, "")
                    group_global = props.get(group, {})
                    direct_global = props.get(name, {})
                    group_scoped = scoped_props.get(group, {})
                    direct_scoped = scoped_props.get(name, {})

                    def effective(field: str, default=False):
                        for source in (direct_scoped, group_scoped, direct_global, group_global):
                            if field in source and source[field] not in {None, ""}:
                                return source[field]
                        return default

                    explicit_activate = effective("activate", None)
                    active = bool(default_ipv4 and family == "ipv4 unicast" and vrf == "default") if explicit_activate is None else bool(explicit_activate)
                    if (family, vrf) in af_lines and explicit_activate is None:
                        # AF presence alone does not activate an individual neighbor.
                        active = False
                    resolved_remote = remote_as.get(name) or remote_as.get(group, "")
                    if not resolved_remote and name not in scoped_props:
                        continue
                    role = (
                        "internal" if resolved_remote == local_as
                        else "external" if resolved_remote and resolved_remote.isdigit() and local_as.isdigit()
                        else "unknown"
                    )
                    auth_present = bool(effective("password"))
                    auth_method = str(effective("auth_method", ""))
                    policy_references = tuple(
                        (direction, kind, reference)
                        for direction in ("in", "out")
                        for kind in sorted(policy_commands)
                        if isinstance(reference := effective(f"policy_{kind}_{direction}"), str)
                        and reference
                    )
                    all_evidence = [self._routing_evidence(header, header_line)]
                    for source_name in (group, name):
                        if source_name:
                            all_evidence.extend(evidence.get(source_name, ()))
                            all_evidence.extend(scoped_evidence.get(source_name, ()))
                    results.append(IOSBGPNeighbor(
                        address=name,
                        local_as=local_as,
                        remote_as=resolved_remote,
                        peer_role=role,
                        vrf=vrf,
                        address_family=family,
                        active=active and not bool(effective("shutdown")),
                        authentication_state="authenticated" if auth_present else "unauthenticated",
                        authentication_method=auth_method,
                        inbound_policy=any(direction == "in" for direction, _, _ in policy_references),
                        outbound_policy=any(direction == "out" for direction, _, _ in policy_references),
                        policy_references=policy_references,
                        prefix_limit=bool(effective("limit")),
                        inheritance_unknown=any("inherit peer" in command.casefold() or "template peer" in command.casefold() for _, command in global_lines),
                        evidence=tuple(dict.fromkeys(all_evidence)),
                        maximum_routes=str(effective("maximum_routes", "")),
                    ))
        return results

    def get_bgp_ipv4_prefix_list_effects(self) -> dict[str, tuple[str, tuple[ConfigEvidence, ...]]]:
        """Classify only literal standalone IPv4 prefix lists with a provable permit-all rule."""
        lists: dict[str, dict[str, object]] = {}
        for line_number, raw in enumerate(self.parser.ioscfg, 1):
            if raw[:1].isspace():
                continue
            command = raw.strip()
            description = re.fullmatch(r"ip prefix-list (\S+) description .+", command, re.IGNORECASE)
            if description:
                lists.setdefault(description.group(1).casefold(), {
                    "rules": {}, "unknown": False, "evidence": [],
                })["evidence"].append(self._routing_evidence(command, line_number))
                continue
            match = re.fullmatch(
                r"(no )?ip prefix-list (\S+)(?: seq (\d+))?(?: (permit|deny) (\S+)(.*))?",
                command, re.IGNORECASE,
            )
            if not match:
                continue
            removal, name, sequence, action, prefix, suffix = match.groups()
            key = name.casefold()
            if removal and sequence is None and action is None:
                lists.pop(key, None)
                continue
            data = lists.setdefault(key, {"rules": {}, "unknown": False, "evidence": []})
            evidence = self._routing_evidence(command, line_number)
            data["evidence"].append(evidence)
            if action is None:
                data["unknown"] = True
                continue
            rule_id = sequence or f"unsequenced:{line_number}"
            if removal:
                if sequence:
                    data["rules"].pop(rule_id, None)
                else:
                    data["unknown"] = True
                continue
            data["rules"][rule_id] = (action.casefold(), prefix, suffix.strip().casefold())
        effects: dict[str, tuple[str, tuple[ConfigEvidence, ...]]] = {}
        for name, data in lists.items():
            rules = list(data["rules"].values())
            permit_all = (
                not data["unknown"] and len(rules) == 1
                and rules[0] == ("permit", "0.0.0.0/0", "le 32")
            )
            effects[name] = (
                "permit-all" if permit_all else "unknown",
                tuple(data["evidence"]),
            )
        return effects

    def get_bgp_route_map_effects(self) -> dict[str, tuple[str, tuple[ConfigEvidence, ...]]]:
        """Recognize only a sole empty permit clause as an unrestricted route map."""
        maps: dict[str, dict[str, object]] = {}
        events: list[tuple[int, str, str, str, list[tuple[int, int, str]]]] = []
        for header, line_number, children in self._indented_blocks("route-map "):
            match = re.fullmatch(r"route-map (\S+) (permit|deny) (\d+)", header, re.IGNORECASE)
            if match:
                events.append((line_number, "define", match.group(1), match.group(3), children))
        for line_number, raw in enumerate(self.parser.ioscfg, 1):
            if raw[:1].isspace():
                continue
            match = re.fullmatch(
                r"no route-map (\S+)(?: (?:permit|deny) (\d+))?",
                raw.strip(), re.IGNORECASE,
            )
            if match:
                events.append((line_number, "remove", match.group(1), match.group(2) or "", []))
        for line_number, action, name, sequence, children in sorted(events):
            key = name.casefold()
            if action == "remove" and not sequence:
                maps.pop(key, None)
                continue
            data = maps.setdefault(key, {"sequences": {}, "evidence": []})
            if action == "remove":
                data["sequences"].pop(sequence, None)
                continue
            header = self.parser.ioscfg[line_number - 1].strip()
            evidence = [self._routing_evidence(header, line_number)]
            evidence.extend(self._routing_evidence(command, number) for number, _, command in children)
            data["sequences"][sequence] = (
                header.split()[2].casefold(), not children, evidence,
            )
            data["evidence"].extend(evidence)
        effects: dict[str, tuple[str, tuple[ConfigEvidence, ...]]] = {}
        for name, data in maps.items():
            sequences = list(data["sequences"].values())
            sole_empty_permit = (
                len(sequences) == 1
                and sequences[0][0] == "permit"
                and sequences[0][1]
            )
            effects[name] = (
                "permit-all" if sole_empty_permit else "unknown",
                tuple(dict.fromkeys(data["evidence"])),
            )
        return effects

    def get_bgp_as_path_filter_effects(self) -> dict[str, tuple[str, tuple[ConfigEvidence, ...]]]:
        """Classify only sole universal-permit AS-path filter lists."""
        lists: dict[str, list[tuple[str, str, ConfigEvidence]]] = {}
        for line_number, raw in enumerate(self.parser.ioscfg, 1):
            if raw[:1].isspace():
                continue
            command = raw.strip()
            removed = re.fullmatch(r"no ip as-path access-list (\d+)", command, re.IGNORECASE)
            if removed:
                lists.pop(removed.group(1), None)
                continue
            match = re.fullmatch(
                r"ip as-path access-list (\d+) (permit|deny) (.+)",
                command, re.IGNORECASE,
            )
            if match:
                lists.setdefault(match.group(1), []).append((
                    match.group(2).casefold(), match.group(3).strip(),
                    self._routing_evidence(command, line_number),
                ))
        return {
            name: (
                "permit-all" if len(rules) == 1
                and rules[0][:2] in {("permit", ".*"), ("permit", "^.*$")}
                else "unknown",
                tuple(rule[2] for rule in rules),
            )
            for name, rules in lists.items()
        }

    def get_ospf_interfaces(self) -> list[IOSOSPFInterface]:
        """Resolve explicit IOS OSPFv2 interface membership and auth overrides."""

        processes: dict[str, dict[str, object]] = {}
        for header, header_line, children in self._indented_blocks("router ospf "):
            tokens = header.split()
            process_id = tokens[2] if len(tokens) > 2 else ""
            vrf = tokens[tokens.index("vrf") + 1] if "vrf" in tokens and tokens.index("vrf") + 1 < len(tokens) else "default"
            data: dict[str, object] = {"vrf": vrf, "areas": {}, "passive_default": False, "passive": set(), "active": set(), "evidence": [self._routing_evidence(header, header_line)]}
            for line_number, _, command in children:
                ev = self._routing_evidence(command, line_number)
                data["evidence"].append(ev)
                area = re.fullmatch(r"area\s+(\S+)\s+authentication(?:\s+(message-digest))?", command)
                if area:
                    data["areas"][area.group(1)] = "message-digest" if area.group(2) else "simple"
                elif command == "passive-interface default":
                    data["passive_default"] = True
                elif command == "no passive-interface default":
                    data["passive_default"] = False
                elif command.startswith("passive-interface "):
                    data["passive"].add(command.split(maxsplit=1)[1])
                elif command.startswith("no passive-interface "):
                    name = command.split(maxsplit=2)[2]
                    data["passive"].discard(name)
                    data["active"].add(name)
            processes[process_id] = data

        keychains: dict[str, tuple[int, set[str], list[ConfigEvidence]]] = {}
        for header, header_line, children in self._indented_blocks("key chain "):
            name = header.split(maxsplit=2)[-1]
            key_count = 0
            algorithms: set[str] = set()
            evidence = [self._routing_evidence(header, header_line)]
            for line_number, _, command in children:
                evidence.append(
                    ConfigEvidence("key-string <redacted>", self.config_filepath, line_number)
                    if command.casefold().startswith("key-string ") else
                    self._routing_evidence(command, line_number)
                )
                if re.fullmatch(r"key\s+\S+", command):
                    key_count += 1
                algorithm = re.search(r"cryptographic-algorithm\s+(\S+)", command)
                if algorithm:
                    algorithms.add(algorithm.group(1).casefold())
            keychains[name] = (key_count, algorithms, evidence)

        records: list[IOSOSPFInterface] = []
        for header, header_line, children in self._indented_blocks("interface "):
            interface = header.split(maxsplit=1)[1]
            shutdown = False
            memberships: dict[str, str] = {}
            auth_mode = ""
            key_reference = ""
            key_present = False
            evidence = [self._routing_evidence(header, header_line)]
            for line_number, _, command in children:
                ev = self._routing_evidence(command, line_number)
                if command == "shutdown":
                    shutdown = True
                elif command == "no shutdown":
                    shutdown = False
                member = re.fullmatch(r"ip ospf\s+(\S+)\s+area\s+(\S+)", command)
                if member:
                    memberships[member.group(1)] = member.group(2)
                    evidence.append(ev)
                    continue
                auth = re.fullmatch(r"ip ospf authentication(?:\s+(.*))?", command)
                if auth:
                    value = (auth.group(1) or "simple").split()
                    auth_mode = value[0].casefold()
                    if auth_mode == "key-chain" and len(value) > 1:
                        key_reference = value[1]
                    evidence.append(ev)
                elif command.startswith("ip ospf authentication-key "):
                    key_present = True
                    auth_mode = auth_mode or "simple"
                    evidence.append(ev)
                elif command.startswith("ip ospf message-digest-key "):
                    key_present = True
                    auth_mode = "message-digest"
                    evidence.append(ev)
            for process_id, area in memberships.items():
                process = processes.get(process_id)
                if process is None:
                    continue
                mode = auth_mode or process["areas"].get(area, "")
                if mode == "null" or not mode:
                    state = "unauthenticated"
                elif mode == "simple":
                    state = "weak" if key_present else "unresolved"
                elif mode == "message-digest":
                    state = "authenticated" if key_present else "unresolved"
                elif mode == "key-chain":
                    chain = keychains.get(key_reference)
                    if not chain or chain[0] == 0:
                        state = "unresolved"
                    elif chain[1] and not chain[1].issubset({"hmac-sha-1", "hmac-sha-256", "hmac-sha-384", "hmac-sha-512", "md5"}):
                        state = "unknown"
                    else:
                        state = "authenticated"
                    if chain:
                        evidence.extend(chain[2])
                else:
                    state = "unknown"
                passive = bool(process["passive_default"])
                if interface in process["active"]:
                    passive = False
                elif interface in process["passive"]:
                    passive = True
                records.append(IOSOSPFInterface(
                    process_id=process_id,
                    interface=interface,
                    area=area,
                    vrf=str(process["vrf"]),
                    passive=passive,
                    shutdown=shutdown,
                    authentication_state=state,
                    authentication_method=mode,
                    key_reference=key_reference,
                    evidence=tuple(dict.fromkeys(evidence + process["evidence"])),
                ))
        return records

    def _routing_key_chains(self) -> dict[str, tuple[dict[str, bool], list[ConfigEvidence]]]:
        """Resolve exported key presence without retaining secret values."""
        chain_events: list[tuple[int, str, list[tuple[int, int, str]] | None]] = [
            (line_number, header.split(maxsplit=2)[2], children)
            for header, line_number, children in self._indented_blocks("key chain ")
        ]
        chain_events.extend(
            (number, line.strip().split(maxsplit=3)[3], None)
            for number, line in enumerate(self.parser.ioscfg, 1)
            if not line[:1].isspace()
            and re.fullmatch(r"no key chain \S+", line.strip(), re.IGNORECASE)
        )
        chains: dict[str, tuple[dict[str, bool], list[ConfigEvidence]]] = {}
        for number, name, chain_lines in sorted(chain_events, key=lambda item: item[0]):
            key = name.casefold()
            if chain_lines is None:
                chains.pop(key, None)
                continue
            keys, evidence = chains.setdefault(key, ({}, []))
            evidence.append(self._routing_evidence(f"key chain {name}", number))
            current_key = ""
            for line_number, _, command in chain_lines:
                text = command.casefold()
                match = re.fullmatch(r"key (\S+)", text)
                removed = re.fullmatch(r"no key (\S+)", text)
                if match:
                    current_key = match.group(1)
                    keys.setdefault(current_key, False)
                elif removed:
                    keys.pop(removed.group(1), None)
                    current_key = ""
                elif current_key and text.startswith("key-string "):
                    keys[current_key] = True
                elif current_key and text == "no key-string":
                    keys[current_key] = False
                else:
                    continue
                evidence.append(
                    ConfigEvidence("key-string <redacted>", self.config_filepath, line_number)
                    if text.startswith("key-string ") else
                    self._routing_evidence(command, line_number)
                )
        return chains

    def get_routing_key_lifetime_states(self) -> dict[str, tuple[str, tuple[ConfigEvidence, ...]]]:
        """Assess key-chain send/accept viability only with explicit UTC clock and audit time."""
        assessment_time = self.assessment_context.assessment_datetime()
        if assessment_time is None:
            return {}
        clock_lines = self._global_lines()
        timezone_commands = [line.casefold() for line in clock_lines if line.casefold().startswith("clock timezone ")]
        if (not timezone_commands or
                not re.fullmatch(r"clock timezone utc 0(?: 0)?", timezone_commands[-1]) or
                any(line.casefold().startswith("clock summer-time ") for line in clock_lines)):
            return {}
        instant = assessment_time.astimezone(timezone.utc)

        def parse_lifetime(command: str) -> bool | None:
            tokens = command.split()[1:]
            if tokens[:1] == ["local"]:
                tokens = tokens[1:]
            if len(tokens) < 5:
                return None

            def parse_date(parts: list[str]) -> datetime | None:
                if len(parts) != 4:
                    return None
                for pattern in ("%H:%M:%S %b %d %Y", "%H:%M:%S %d %b %Y"):
                    try:
                        return datetime.strptime(" ".join(parts), pattern).replace(tzinfo=timezone.utc)
                    except ValueError:
                        pass
                return None

            start = parse_date(tokens[:4])
            if start is None:
                return None
            tail = tokens[4:]
            if tail == ["infinite"]:
                end = None
            elif len(tail) == 2 and tail[0] == "duration" and tail[1].isdigit():
                try:
                    end = start + timedelta(seconds=int(tail[1]))
                except (OverflowError, ValueError):
                    return None
            else:
                end = parse_date(tail)
                if end is None or end <= start:
                    return None
            return instant >= start and (end is None or instant <= end)

        events: list[tuple[int, str, list[tuple[int, int, str]] | None]] = [
            (number, header.split(maxsplit=2)[2], children)
            for header, number, children in self._indented_blocks("key chain ")
        ]
        events.extend(
            (number, line.strip().split(maxsplit=3)[3], None)
            for number, line in enumerate(self.parser.ioscfg, 1)
            if not line[:1].isspace()
            and re.fullmatch(r"no key chain \S+", line.strip(), re.IGNORECASE)
        )
        chains: dict[str, dict[str, object]] = {}
        for number, name, children in sorted(events, key=lambda item: item[0]):
            key = name.casefold()
            if children is None:
                chains.pop(key, None)
                continue
            data = chains.setdefault(key, {"keys": {}, "evidence": []})
            data["evidence"].append(self._routing_evidence(f"key chain {name}", number))
            current = ""
            for line_number, _, command in children:
                folded = command.casefold()
                declared = re.fullmatch(r"key (\S+)", folded)
                removed = re.fullmatch(r"no key (\S+)", folded)
                if declared:
                    current = declared.group(1)
                    data["keys"].setdefault(current, {"material": False, "send": True, "accept": True})
                    data["evidence"].append(self._routing_evidence(command, line_number))
                elif removed:
                    data["keys"].pop(removed.group(1), None)
                    current = ""
                elif current and folded.startswith("key-string "):
                    data["keys"][current]["material"] = True
                elif current and folded == "no key-string":
                    data["keys"][current]["material"] = False
                elif current and folded in {"no send-lifetime", "no accept-lifetime"}:
                    data["keys"][current][folded.split()[1].split("-")[0]] = True
                    data["evidence"].append(self._routing_evidence(command, line_number))
                elif current and (folded.startswith("send-lifetime ") or folded.startswith("accept-lifetime ")):
                    kind = folded.split("-", 1)[0]
                    data["keys"][current][kind] = parse_lifetime(folded)
                    data["evidence"].append(self._routing_evidence(command, line_number))
        results = {}
        for name, data in chains.items():
            keys = [item for item in data["keys"].values() if item["material"]]
            if not keys:
                continue
            sends = [item["send"] for item in keys]
            accepts = [item["accept"] for item in keys]
            if any(value is True for value in sends) and any(value is True for value in accepts):
                state = "usable"
            elif (all(value is False for value in sends) or all(value is False for value in accepts)):
                state = "unusable"
            else:
                state = "unknown"
            results[name] = (state, tuple(dict.fromkeys(data["evidence"])))
        return results

    def get_rip_interfaces(self) -> list[IOSRIPInterface]:
        """Resolve bounded classic IPv4 RIP network attachments (default VRF and, SC-005, VRF address families with their own ``version 2``)."""
        def classful_network(value: str) -> ipaddress.IPv4Network | None:
            try:
                address = ipaddress.IPv4Address(value)
            except ipaddress.AddressValueError:
                return None
            first = int(value.split(".")[0])
            prefix = 8 if first < 128 else 16 if first < 192 else 24 if first < 224 else None
            if prefix is None:
                return None
            network = ipaddress.IPv4Network((address, prefix), strict=False)
            return network if network.network_address == address else None

        rip_blocks = self._indented_blocks("router rip")
        last_removal = max((
            number for number, line in enumerate(self.parser.ioscfg, 1)
            if not line[:1].isspace() and line.strip().casefold() == "no router rip"
        ), default=0)
        selected = [block for block in rip_blocks if block[0].casefold() == "router rip" and block[1] > last_removal]
        if not selected:
            return []
        children = [item for _, _, block_children in selected for item in block_children]
        # scope -> [version, networks, passive_default, passive_overrides, evidence]
        process_evidence = [self._routing_evidence(header, header_line) for header, header_line, _ in selected]
        scopes: dict[str, list] = {"default": ["unknown", {}, False, {}, list(process_evidence)]}
        current = "default"
        af_indent = None
        for line_number, indent, command in children:
            text = command.casefold()
            if af_indent is not None and indent <= af_indent:
                current, af_indent = "default", None
            if text.startswith("address-family "):
                # SC-005 VRF stage: `address-family ipv4 vrf <name>` is assessed only when it
                # sets its own `version 2` (Cisco's example does; inheritance is not documented).
                match = re.fullmatch(r"address-family ipv4 vrf (\S+)", text)
                current = f"vrf:{match.group(1)}" if match else "unsupported"
                af_indent = indent
                scopes.setdefault(current, ["unknown", {}, False, {}, list(process_evidence)])
                scopes[current][4].append(self._routing_evidence(command, line_number))
                continue
            if text == "exit-address-family":
                current, af_indent = "default", None
                continue
            scope = scopes[current]
            if text in {"version 1", "version 2"}:
                scope[0] = text[-1]
            elif text == "no version":
                scope[0] = "unknown"
            elif text == "passive-interface default":
                scope[2] = True
                scope[3].clear()
            elif text == "no passive-interface default":
                scope[2] = False
                scope[3].clear()
            elif text.startswith("passive-interface "):
                scope[3][text.split(maxsplit=1)[1]] = True
            elif text.startswith("no passive-interface "):
                scope[3][text.split(maxsplit=2)[2]] = False
            else:
                match = re.fullmatch(r"(no )?network (\S+)", text)
                if match:
                    network = classful_network(match.group(2))
                    if network is not None:
                        if match.group(1):
                            scope[1].pop(str(network), None)
                        else:
                            scope[1][str(network)] = network
                else:
                    continue
            scope[4].append(self._routing_evidence(command, line_number))
        scopes.pop("unsupported", None)
        scopes = {name: scope for name, scope in scopes.items() if scope[0] == "2" and scope[1]}
        if not scopes:
            return []

        chains = self._routing_key_chains()
        records: list[IOSRIPInterface] = []
        for header, header_line, children in self._indented_blocks("interface "):
            interface = header.split(maxsplit=1)[1]
            active = True
            vrf = "default"
            addresses: set[ipaddress.IPv4Address] = set()
            receive_version = "unknown"
            mode = "text"  # Documented RIPv2 mode when a key chain is bound.
            key_reference = ""
            binding_invalid = False
            evidence = [self._routing_evidence(header, header_line)]
            for line_number, _, command in children:
                text = command.casefold()
                if text == "shutdown":
                    active = False
                elif text == "no shutdown":
                    active = True
                elif re.fullmatch(r"(?:ip )?vrf forwarding \S+", text):
                    vrf = text.split()[-1]
                elif text in {"no ip vrf forwarding", "no vrf forwarding"}:
                    vrf = "default"
                elif text == "no ip address":
                    addresses.clear()
                elif re.fullmatch(r"ip address \S+ \S+(?: secondary)?", text):
                    try:
                        addresses.add(ipaddress.IPv4Address(text.split()[2]))
                    except ipaddress.AddressValueError:
                        pass
                elif re.fullmatch(r"no ip address \S+ \S+", text):
                    try:
                        addresses.discard(ipaddress.IPv4Address(text.split()[3]))
                    except ipaddress.AddressValueError:
                        pass
                elif re.fullmatch(r"ip rip receive version [12](?: [12])?", text):
                    receive_version = "1-accepted" if "1" in text.split()[4:] else "2"
                elif text == "no ip rip receive version":
                    receive_version = "unknown"
                elif text in {"ip rip authentication mode text", "ip rip authentication mode md5"}:
                    mode = text.split()[-1]
                elif text == "no ip rip authentication mode":
                    mode = "text"
                elif text.startswith("ip rip authentication mode "):
                    mode = "unknown"
                elif re.fullmatch(r"ip rip authentication key-chain \S+", text):
                    key_reference = command.split()[-1]
                    binding_invalid = False
                elif re.fullmatch(r"no ip rip authentication key-chain(?: \S+)?", text):
                    key_reference = ""
                    binding_invalid = False
                elif text.startswith("ip rip authentication key-chain"):
                    binding_invalid = True
                else:
                    continue
                evidence.append(self._routing_evidence(command, line_number))
            scope_name = "default" if vrf == "default" else f"vrf:{vrf}"
            if not active or not addresses or scope_name not in scopes:
                continue
            _, networks, passive_default, passive_overrides, process_evidence = scopes[scope_name]
            matched = [network for network in networks.values() if any(address in network for address in addresses)]
            if not matched:
                continue
            chain = chains.get(key_reference.casefold()) if key_reference else None
            if receive_version == "1-accepted":
                state = "version1-accepted"
            elif binding_invalid or mode == "unknown":
                state = "unknown"
            elif not key_reference:
                state = "unauthenticated"
            elif chain is None or not any(chain[0].values()):
                state = "unresolved"
            elif mode == "text":
                state = "weak-cleartext"
            elif mode == "md5":
                state = "configured-md5" if receive_version == "2" else "unknown"
            else:
                state = "unknown"
            all_evidence = evidence + process_evidence
            if chain:
                all_evidence.extend(chain[1])
            records.append(IOSRIPInterface(
                interface=interface,
                network=str(matched[0]),
                active=True,
                passive=passive_overrides.get(interface.casefold(), passive_default),
                receive_version=receive_version,
                authentication_state=state,
                authentication_mode=mode,
                key_reference=key_reference,
                evidence=tuple(dict.fromkeys(all_evidence)),
                vrf=vrf,
            ))
        return records

    def _named_eigrp_processes(self) -> dict[tuple[str, str], dict]:
        """Default-VRF IPv4 EIGRP named-mode address families (SC-005).

        ``router eigrp <name>`` / ``address-family ipv4 [unicast] autonomous-system <n>``.
        Per Cisco's EIGRP command reference, ``af-interface default`` applies to every
        interface of the address family and a specific ``af-interface`` overrides it.
        VRF, multicast and IPv6 address families are out of scope.
        """
        processes: dict[tuple[str, str], dict] = {}
        for header, header_line, children in self._indented_blocks("router eigrp "):
            match = re.fullmatch(r"router eigrp (\S+)", header, re.IGNORECASE)
            if not match:
                continue
            instance = match.group(1)
            last_removal = max((
                number for number, line in enumerate(self.parser.ioscfg, 1)
                if not line[:1].isspace()
                and line.strip().casefold() == f"no router eigrp {instance.casefold()}"
            ), default=0)
            if header_line <= last_removal:
                continue
            process = None
            af_indent = None
            sub_indent = None
            settings = None
            for line_number, indent, command in children:
                text = command.casefold()
                if af_indent is not None and indent <= af_indent:
                    process, af_indent, sub_indent, settings = None, None, None, None
                if sub_indent is not None and indent <= sub_indent:
                    sub_indent, settings = None, None
                if text.startswith("address-family "):
                    af = re.fullmatch(r"address-family ipv4(?: unicast)? autonomous-system (\d+)", text)
                    af_indent = indent
                    if af:
                        process = processes.setdefault((instance, af.group(1)), {
                            "networks": [], "default": {}, "interfaces": {},
                            "evidence": [self._routing_evidence(header, header_line)],
                        })
                        process["evidence"].append(self._routing_evidence(command, line_number))
                    continue
                if process is None:
                    continue
                if text == "exit-address-family":
                    process, af_indent, sub_indent, settings = None, None, None, None
                    continue
                if sub_indent is None:
                    target = re.fullmatch(r"af-interface (.+)", command.strip(), re.IGNORECASE)
                    if target:
                        name = re.sub(r"\s+", "", target.group(1)).casefold()
                        settings = (
                            process["default"] if name == "default"
                            else process["interfaces"].setdefault(name, {})
                        )
                        sub_indent = indent
                        settings.setdefault("_evidence", []).append(self._routing_evidence(command, line_number))
                        continue
                    network = re.fullmatch(r"(no )?network (\S+)(?: (\S+))?", text)
                    if network:
                        try:
                            selector = (
                                ipaddress.IPv4Address(network.group(2)),
                                ipaddress.IPv4Address(network.group(3)) if network.group(3) else None,
                            )
                        except ipaddress.AddressValueError:
                            continue
                        if network.group(1):
                            process["networks"] = [item for item in process["networks"] if item != selector]
                        elif selector not in process["networks"]:
                            process["networks"].append(selector)
                        process["evidence"].append(self._routing_evidence(command, line_number))
                    elif not text.startswith("exit-"):
                        sub_indent = indent  # topology or other sub-mode: not interpreted
                    continue
                if settings is None or text == "exit-af-interface":
                    continue
                negated = text.startswith("no ")
                body = text[3:] if negated else text
                key = None
                if body == "shutdown":
                    key, value = "shutdown", not negated
                elif body == "passive-interface":
                    key, value = "passive", not negated
                elif body.startswith("authentication mode"):
                    key = "mode"
                    tokens = body.split()
                    if negated:
                        value = "no"
                    elif tokens[2:3] == ["md5"] and len(tokens) == 3:
                        value = "md5"
                    elif tokens[2:3] == ["hmac-sha-256"] and len(tokens) in {4, 5}:
                        value = "hmac-sha-256"
                    else:
                        value = "unknown"
                elif body.startswith("authentication key-chain"):
                    key = "chain"
                    tokens = command.strip().split()
                    value = "no" if negated else tokens[2] if len(tokens) == 3 else "unknown"
                if key is None:
                    continue
                if negated and key in {"mode", "chain"} and settings is process["default"]:
                    settings.pop(key, None)
                else:
                    settings[key] = value
                settings["_evidence"].append(self._routing_evidence(command, line_number))
        return {key: value for key, value in processes.items() if value["networks"]}

    def get_eigrp_interfaces(self) -> list[IOSEIGRPInterface]:
        """Resolve default-VRF IPv4 EIGRP interface authentication (classic and named mode)."""
        processes: dict[str, tuple[list[tuple[ipaddress.IPv4Address, ipaddress.IPv4Address | None]], bool, dict[str, bool], list[ConfigEvidence]]] = {}
        blocks = self._indented_blocks("router eigrp ")
        for header, header_line, children in blocks:
            match = re.fullmatch(r"router eigrp (\d+)", header, re.IGNORECASE)
            if not match or any(command.casefold().startswith("address-family ") for _, _, command in children):
                continue
            as_number = match.group(1)
            last_removal = max((
                number for number, line in enumerate(self.parser.ioscfg, 1)
                if not line[:1].isspace()
                and line.strip().casefold() == f"no router eigrp {as_number}"
            ), default=0)
            if header_line <= last_removal:
                continue
            networks, passive_default, overrides, evidence = processes.get(
                as_number, ([], False, {}, [])
            )
            evidence.append(self._routing_evidence(header, header_line))
            for line_number, _, command in children:
                text = command.casefold()
                if text == "passive-interface default":
                    passive_default = True
                    overrides.clear()
                elif text == "no passive-interface default":
                    passive_default = False
                    overrides.clear()
                elif text.startswith("passive-interface "):
                    overrides[text.split(maxsplit=1)[1]] = True
                elif text.startswith("no passive-interface "):
                    overrides[text.split(maxsplit=2)[2]] = False
                else:
                    network_match = re.fullmatch(r"(no )?network (\S+)(?: (\S+))?", text)
                    if not network_match:
                        continue
                    try:
                        address = ipaddress.IPv4Address(network_match.group(2))
                        wildcard = (
                            ipaddress.IPv4Address(network_match.group(3))
                            if network_match.group(3) else None
                        )
                    except ipaddress.AddressValueError:
                        continue
                    selector = (address, wildcard)
                    if network_match.group(1):
                        networks = [item for item in networks if item != selector]
                    elif selector not in networks:
                        networks.append(selector)
                evidence.append(self._routing_evidence(command, line_number))
            processes[as_number] = (networks, passive_default, overrides, evidence)
        named = self._named_eigrp_processes()
        if not processes and not named:
            return []

        def matches(address: ipaddress.IPv4Address, selector: tuple[ipaddress.IPv4Address, ipaddress.IPv4Address | None]) -> bool:
            target, wildcard = selector
            if wildcard is not None:
                mask = 0xFFFFFFFF ^ int(wildcard)
                return int(address) & mask == int(target) & mask
            first = int(target) >> 24
            prefix = 8 if first < 128 else 16 if first < 192 else 24 if first < 224 else None
            if prefix is None:
                return False
            return address in ipaddress.IPv4Network((target, prefix), strict=False)

        chains = self._routing_key_chains()
        records: list[IOSEIGRPInterface] = []
        for header, header_line, children in self._indented_blocks("interface "):
            interface = header.split(maxsplit=1)[1]
            active = True
            vrf = "default"
            addresses: set[ipaddress.IPv4Address] = set()
            modes: dict[str, bool | None] = {}
            references: dict[str, str] = {}
            invalid: set[str] = set()
            evidence = [self._routing_evidence(header, header_line)]
            for line_number, _, command in children:
                text = command.casefold()
                if text == "shutdown":
                    active = False
                elif text == "no shutdown":
                    active = True
                elif re.fullmatch(r"(?:ip )?vrf forwarding \S+", text):
                    vrf = text.split()[-1]
                elif text in {"no ip vrf forwarding", "no vrf forwarding"}:
                    vrf = "default"
                elif text == "no ip address":
                    addresses.clear()
                elif re.fullmatch(r"ip address \S+ \S+(?: secondary)?", text):
                    try:
                        addresses.add(ipaddress.IPv4Address(text.split()[2]))
                    except ipaddress.AddressValueError:
                        pass
                elif re.fullmatch(r"no ip address \S+ \S+", text):
                    try:
                        addresses.discard(ipaddress.IPv4Address(text.split()[3]))
                    except ipaddress.AddressValueError:
                        pass
                else:
                    mode = re.fullmatch(r"(no )?ip authentication mode eigrp (\d+)(?: (\S+))?", text)
                    chain = re.fullmatch(r"(no )?ip authentication key-chain eigrp (\d+)(?: (\S+))?", text)
                    if mode:
                        as_number = mode.group(2)
                        modes[as_number] = False if mode.group(1) else True if mode.group(3) == "md5" else None
                        invalid.discard(as_number)
                    elif chain:
                        as_number = chain.group(2)
                        references[as_number] = "" if chain.group(1) else (command.split()[-1] if chain.group(3) else "")
                        if not chain.group(1) and not chain.group(3):
                            invalid.add(as_number)
                        else:
                            invalid.discard(as_number)
                    else:
                        continue
                evidence.append(self._routing_evidence(command, line_number))
            if not active or vrf != "default" or not addresses:
                continue
            for as_number, (networks, passive_default, overrides, process_evidence) in processes.items():
                if not networks or not any(matches(address, selector) for address in addresses for selector in networks):
                    continue
                passive = overrides.get(interface.casefold(), passive_default)
                if passive:
                    continue  # EIGRP passive interfaces do not receive adjacency updates.
                key_reference = references.get(as_number, "")
                chain = chains.get(key_reference.casefold()) if key_reference else None
                if as_number in invalid or modes.get(as_number, False) is None:
                    state = "unknown"
                elif modes.get(as_number) is not True:
                    state = "unauthenticated"
                elif not key_reference or chain is None or not any(chain[0].values()):
                    state = "unresolved"
                else:
                    state = "configured-md5"
                all_evidence = evidence + process_evidence
                if chain:
                    all_evidence.extend(chain[1])
                records.append(IOSEIGRPInterface(
                    interface=interface,
                    autonomous_system=as_number,
                    active=True,
                    passive=False,
                    authentication_state=state,
                    key_reference=key_reference,
                    evidence=tuple(dict.fromkeys(all_evidence)),
                ))
            for (instance, as_number), process in named.items():
                if not any(matches(address, selector) for address in addresses for selector in process["networks"]):
                    continue
                default = process["default"]
                specific = process["interfaces"].get(re.sub(r"\s+", "", interface).casefold(), {})

                def resolved(key):
                    return specific[key] if key in specific else default.get(key)

                if resolved("shutdown") or resolved("passive"):
                    continue
                mode, key_reference = resolved("mode"), resolved("chain")
                # A specific "no authentication ..." against an inherited default is not
                # documented precisely enough to decide; keep it unknown.
                if (mode == "no" and "mode" in default) or (key_reference == "no" and "chain" in default):
                    mode = "unknown"
                key_reference = "" if key_reference in {None, "no", "unknown"} else key_reference
                chain = chains.get(key_reference.casefold()) if key_reference else None
                if mode in {None, "no"}:
                    state = "unauthenticated"
                elif mode == "unknown" or resolved("chain") == "unknown":
                    state = "unknown"
                elif mode == "hmac-sha-256":
                    state = "configured-hmac-sha-256"
                elif not key_reference or chain is None or not any(chain[0].values()):
                    state = "unresolved"
                else:
                    state = "configured-md5"
                all_evidence = (
                    evidence + process["evidence"] + default.get("_evidence", [])
                    + specific.get("_evidence", [])
                )
                if chain and state == "configured-md5":
                    all_evidence.extend(chain[1])
                records.append(IOSEIGRPInterface(
                    interface=interface,
                    autonomous_system=as_number,
                    active=True,
                    passive=False,
                    authentication_state=state,
                    key_reference=key_reference if state != "configured-hmac-sha-256" else "",
                    evidence=tuple(dict.fromkeys(all_evidence)),
                    named_instance=instance,
                ))
        return records

    def get_discovery_interfaces(self) -> list[IOSDiscoveryInterface]:
        """Return effective CDP/LLDP direction state for configured interfaces."""

        cdp_enabled = True
        lldp_enabled = False
        global_evidence: dict[str, list[ConfigEvidence]] = {"cdp": [], "lldp": []}
        for line_number, raw_line in enumerate(self.parser.ioscfg, 1):
            if raw_line[:1].isspace():
                continue
            command = raw_line.strip()
            if command == "no cdp run":
                cdp_enabled = False
                global_evidence["cdp"].append(ConfigEvidence(command, self.config_filepath, line_number))
            elif command == "cdp run":
                cdp_enabled = True
                global_evidence["cdp"].append(ConfigEvidence(command, self.config_filepath, line_number))
            elif command == "lldp run":
                lldp_enabled = True
                global_evidence["lldp"].append(ConfigEvidence(command, self.config_filepath, line_number))
            elif command == "no lldp run":
                lldp_enabled = False
                global_evidence["lldp"].append(ConfigEvidence(command, self.config_filepath, line_number))

        records = []
        for header, header_line, children in self._indented_blocks("interface "):
            interface = header.split(maxsplit=1)[1]
            role = self.assessment_context.role_for_interface(interface)
            shutdown = False
            cdp = cdp_enabled
            lldp_tx = lldp_enabled
            lldp_rx = lldp_enabled
            evidence = [ConfigEvidence(header, self.config_filepath, header_line)]
            for line_number, _, command in children:
                if command == "shutdown":
                    shutdown = True
                elif command == "no shutdown":
                    shutdown = False
                elif command == "cdp enable":
                    cdp = cdp_enabled
                elif command == "no cdp enable":
                    cdp = False
                elif command == "lldp transmit":
                    lldp_tx = lldp_enabled
                elif command == "no lldp transmit":
                    lldp_tx = False
                elif command == "lldp receive":
                    lldp_rx = lldp_enabled
                elif command == "no lldp receive":
                    lldp_rx = False
                else:
                    continue
                evidence.append(ConfigEvidence(command, self.config_filepath, line_number))
            common = tuple(evidence)
            records.append(IOSDiscoveryInterface(
                interface=interface, protocol="cdp", transmit=cdp,
                receive=cdp, active=not shutdown, role=role,
                evidence=tuple(global_evidence["cdp"]) + common,
            ))
            records.append(IOSDiscoveryInterface(
                interface=interface, protocol="lldp", transmit=lldp_tx,
                receive=lldp_rx, active=not shutdown, role=role,
                evidence=tuple(global_evidence["lldp"]) + common,
            ))
        return records

    def get_switch_edge_interfaces(self) -> list[IOSSwitchEdgeInterface]:
        """Resolve switchport role, VLAN, trust and access-edge protections."""

        dhcp_global = False
        dhcp_vlans: set[int] = set()
        arp_vlans: set[int] = set()
        global_evidence = []
        for line_number, raw_line in enumerate(self.parser.ioscfg, 1):
            if raw_line[:1].isspace():
                continue
            command = raw_line.strip()
            if command == "ip dhcp snooping":
                dhcp_global = True
            elif command == "no ip dhcp snooping":
                dhcp_global = False
                dhcp_vlans.clear()
            else:
                dhcp = re.fullmatch(r"(?:(no)\s+)?ip dhcp snooping vlan\s+(.+)", command)
                arp = re.fullmatch(r"(?:(no)\s+)?ip arp inspection vlan\s+(.+)", command)
                match, target = (dhcp, dhcp_vlans) if dhcp else (arp, arp_vlans)
                if match:
                    values = set()
                    for part in match.group(2).replace(" ", "").split(","):
                        try:
                            if "-" in part:
                                start, end = map(int, part.split("-", 1))
                                if 1 <= start <= end <= 4094:
                                    values.update(range(start, end + 1))
                            else:
                                value = int(part)
                                if 1 <= value <= 4094:
                                    values.add(value)
                        except ValueError:
                            continue
                    target.difference_update(values) if match.group(1) else target.update(values)
                else:
                    continue
            global_evidence.append(ConfigEvidence(command, self.config_filepath, line_number))

        records = []
        for header, header_line, children in self._indented_blocks("interface "):
            interface = header.split(maxsplit=1)[1]
            mode = "unknown"
            access_vlan = None
            active = True
            dhcp_trusted = False
            arp_trusted = False
            source_guard = False
            port_security = False
            evidence = [ConfigEvidence(header, self.config_filepath, header_line)]
            for line_number, _, command in children:
                if command == "shutdown":
                    active = False
                elif command == "no shutdown":
                    active = True
                elif command == "no switchport":
                    mode = "routed"
                elif command == "switchport":
                    mode = "switchport"
                elif command.startswith("switchport mode "):
                    mode = command.split()[2].casefold()
                elif command.startswith("switchport access vlan "):
                    value = command.split()[-1]
                    access_vlan = int(value) if value.isdigit() and 1 <= int(value) <= 4094 else None
                elif command == "ip dhcp snooping trust":
                    dhcp_trusted = True
                elif command == "no ip dhcp snooping trust":
                    dhcp_trusted = False
                elif command == "ip arp inspection trust":
                    arp_trusted = True
                elif command == "no ip arp inspection trust":
                    arp_trusted = False
                elif command.startswith("ip verify source"):
                    source_guard = True
                elif command.startswith("no ip verify source"):
                    source_guard = False
                elif command == "switchport port-security" or command.startswith("switchport port-security "):
                    port_security = True
                elif command == "no switchport port-security":
                    port_security = False
                else:
                    continue
                evidence.append(ConfigEvidence(command, self.config_filepath, line_number))
            if mode == "unknown" and access_vlan is not None:
                mode = "access"
            records.append(IOSSwitchEdgeInterface(
                interface=interface,
                mode=mode,
                access_vlan=access_vlan,
                active=active,
                role=self.assessment_context.role_for_interface(interface),
                dhcp_snooping=bool(dhcp_global and access_vlan in dhcp_vlans),
                dhcp_trusted=dhcp_trusted,
                arp_inspection=bool(access_vlan in arp_vlans),
                arp_trusted=arp_trusted,
                source_guard=source_guard,
                port_security=port_security,
                evidence=tuple(global_evidence + evidence),
            ))
        return records

    def get_access_admission_interfaces(self) -> list[IOSAccessAdmission]:
        """Resolve explicit 802.1X admission on assessed switchports only."""
        global_dot1x: bool | None = None
        aaa_state = "unknown"
        global_evidence: list[ConfigEvidence] = []
        for line_number, raw_line in enumerate(self.parser.ioscfg, 1):
            if raw_line[:1].isspace():
                continue
            command = raw_line.strip().casefold()
            if command in {"dot1x system-auth-control", "no dot1x system-auth-control"}:
                global_dot1x = not command.startswith("no ")
            elif command.startswith("aaa authentication dot1x default "):
                methods = command.split()[4:]
                aaa_state = "configured-external" if "group" in methods else "non-external"
            elif command == "no aaa authentication dot1x default":
                aaa_state = "removed"
            else:
                continue
            global_evidence.append(ConfigEvidence(raw_line.strip(), self.config_filepath, line_number))

        records: list[IOSAccessAdmission] = []
        for header, header_line, children in self._indented_blocks("interface "):
            interface = header.split(maxsplit=1)[1]
            mode = "unknown"
            active = True
            port_control: str | None = None
            open_access: bool | None = None
            evidence = [ConfigEvidence(header, self.config_filepath, header_line)]
            for line_number, _, command in children:
                text = command.casefold()
                if text == "shutdown":
                    active = False
                elif text == "no shutdown":
                    active = True
                elif text == "no switchport":
                    mode = "routed"
                elif text == "switchport":
                    mode = "switchport"
                elif text.startswith("switchport mode "):
                    mode = text.split()[2]
                elif text.startswith("switchport access vlan ") and mode == "unknown":
                    mode = "access"
                else:
                    control = re.fullmatch(
                        r"(?:authentication|dot1x|access-session) port-control "
                        r"(auto|force-authorized|force-unauthorized)", text,
                    )
                    if control:
                        port_control = control.group(1)
                    elif re.fullmatch(
                        r"no (?:authentication|dot1x|access-session) port-control(?: .*)?", text
                    ):
                        port_control = None
                    elif text in {"authentication open", "access-session open"}:
                        open_access = True
                    elif text in {"no authentication open", "no access-session open"}:
                        open_access = False
                    else:
                        continue
                evidence.append(ConfigEvidence(command, self.config_filepath, line_number))
            records.append(IOSAccessAdmission(
                interface=interface,
                role=self.assessment_context.role_for_interface(interface),
                active=active,
                mode=mode,
                global_dot1x=global_dot1x,
                port_control=port_control,
                open_access=open_access,
                aaa_state=aaa_state,
                evidence=tuple(global_evidence + evidence),
            ))
        return records

    def get_bpdu_guard_policies(self) -> list[IOSBpduGuardPolicy]:
        """Resolve PortFast-dependent global BPDU guard and local overrides."""
        portfast_default: bool | None = None
        guard_default: bool | None = None
        global_evidence: list[ConfigEvidence] = []
        for line_number, raw_line in enumerate(self.parser.ioscfg, 1):
            if raw_line[:1].isspace():
                continue
            text = raw_line.strip().casefold()
            if text in {
                "spanning-tree portfast default", "spanning-tree portfast edge default",
            }:
                portfast_default = True
            elif text in {
                "no spanning-tree portfast default", "no spanning-tree portfast edge default",
            }:
                portfast_default = False
            elif text in {
                "spanning-tree portfast bpduguard default",
                "spanning-tree portfast edge bpduguard default",
            }:
                guard_default = True
            elif text in {
                "no spanning-tree portfast bpduguard default",
                "no spanning-tree portfast edge bpduguard default",
            }:
                guard_default = False
            else:
                continue
            global_evidence.append(ConfigEvidence(raw_line.strip(), self.config_filepath, line_number))

        records: list[IOSBpduGuardPolicy] = []
        for header, header_line, children in self._indented_blocks("interface "):
            interface = header.split(maxsplit=1)[1]
            active = True
            mode = "unknown"
            lag_member = False
            local_portfast: bool | None = None
            local_guard: bool | None = None
            filter_enabled: bool | None = None
            evidence = [ConfigEvidence(header, self.config_filepath, header_line)]
            for line_number, _, command in children:
                text = command.casefold()
                if text == "shutdown":
                    active = False
                elif text == "no shutdown":
                    active = True
                elif text == "no switchport":
                    mode = "routed"
                elif text == "switchport":
                    mode = "switchport"
                elif text.startswith("switchport mode "):
                    mode = text.split()[2]
                elif text.startswith("switchport access vlan ") and mode == "unknown":
                    mode = "access"
                elif re.fullmatch(r"channel-group \d+ mode \S+", text):
                    lag_member = True
                elif re.fullmatch(r"no channel-group(?: \d+)?", text):
                    lag_member = False
                elif text in {"spanning-tree portfast", "spanning-tree portfast edge"}:
                    local_portfast = True
                elif text in {
                    "spanning-tree portfast disable", "spanning-tree portfast normal",
                    "spanning-tree portfast network",
                }:
                    local_portfast = False
                elif text in {"no spanning-tree portfast", "no spanning-tree portfast edge"}:
                    local_portfast = None
                elif text == "spanning-tree bpduguard enable":
                    local_guard = True
                elif text == "spanning-tree bpduguard disable":
                    local_guard = False
                elif text == "no spanning-tree bpduguard":
                    local_guard = None
                elif text == "spanning-tree bpdufilter enable":
                    filter_enabled = True
                elif text in {"no spanning-tree bpdufilter", "spanning-tree bpdufilter disable"}:
                    filter_enabled = False
                else:
                    continue
                evidence.append(ConfigEvidence(command, self.config_filepath, line_number))
            portfast = local_portfast if local_portfast is not None else portfast_default
            if local_guard is True:
                guard_enabled, guard_state = True, "local-enabled"
            elif local_guard is False:
                guard_enabled, guard_state = False, "local-disabled"
            elif guard_default is True and portfast is True:
                guard_enabled, guard_state = True, "inherited-enabled"
            elif guard_default is False and portfast is True:
                guard_enabled, guard_state = False, "global-disabled"
            elif guard_default is True and portfast is False:
                guard_enabled, guard_state = False, "portfast-disabled"
            else:
                guard_enabled, guard_state = None, "unknown"
            records.append(IOSBpduGuardPolicy(
                interface=interface,
                role=self.assessment_context.role_for_interface(interface),
                active=active,
                mode=mode,
                lag_member=lag_member or interface.casefold().startswith("port-channel"),
                portfast=portfast,
                guard_enabled=guard_enabled,
                guard_state=guard_state,
                filter_enabled=filter_enabled,
                evidence=tuple(global_evidence + evidence),
            ))
        return records

    def get_control_plane_policies(self) -> list[IOSControlPlanePolicy]:
        """Resolve input control-plane attachments through MQC definitions."""

        def evidence(text: str, line_number: int) -> ConfigEvidence:
            return ConfigEvidence(text, self.config_filepath, line_number)

        acl_events: list[tuple[int, str, bool, bool, bool]] = []
        for header, header_line, children in self._indented_blocks("ip access-list "):
            match = re.fullmatch(r"ip access-list\s+(?:standard|extended)\s+(\S+)", header)
            if match:
                has_entries = any(
                    re.match(r"(?:\d+\s+)?(?:permit|deny)\s+", command)
                    for _, _, command in children
                )
                has_logging = any(
                    re.search(r"(?:^|\s)(?:log|log-input)(?:\s|$)", command)
                    for _, _, command in children
                )
                acl_events.append((
                    header_line, match.group(1).casefold(), True, has_entries, has_logging
                ))
        for header, header_line, children in self._indented_blocks("ipv6 access-list "):
            match = re.fullmatch(r"ipv6 access-list\s+(\S+)", header)
            if match:
                has_entries = any(
                    re.match(r"(?:sequence\s+\d+\s+)?(?:permit|deny)\s+", command)
                    for _, _, command in children
                )
                has_logging = any(
                    re.search(r"(?:^|\s)(?:log|log-input)(?:\s|$)", command)
                    for _, _, command in children
                )
                acl_events.append((
                    header_line, match.group(1).casefold(), True, has_entries, has_logging
                ))
        for line_number, raw_line in enumerate(self.parser.ioscfg, 1):
            if raw_line[:1].isspace():
                continue
            line = raw_line.strip()
            match = re.fullmatch(r"access-list\s+(\S+)\s+.+", line)
            if match:
                acl_events.append((
                    line_number,
                    match.group(1).casefold(),
                    True,
                    True,
                    bool(re.search(r"(?:^|\s)(?:log|log-input)(?:\s|$)", line)),
                ))
                continue
            removed = re.fullmatch(
                r"no\s+(?:ip\s+access-list\s+(?:standard|extended)\s+|"
                r"ipv6\s+access-list\s+|access-list\s+)(\S+)",
                line,
            )
            if removed:
                acl_events.append((
                    line_number, removed.group(1).casefold(), False, False, False
                ))
        acl_state: dict[str, tuple[bool, bool, bool]] = {}
        for _, name, present, has_entries, has_logging in sorted(acl_events):
            acl_state[name] = (present, has_entries, has_logging)

        class_maps: dict[str, dict] = {}
        for header, header_line, children in self._indented_blocks("class-map "):
            match = re.fullmatch(r"class-map(?:\s+match-(?:all|any))?\s+(\S+)", header)
            if not match:
                continue
            name = match.group(1)
            data = class_maps.setdefault(
                name.casefold(),
                {"name": name, "selectors": [], "evidence": [], "last_line": 0},
            )
            data["last_line"] = header_line
            data["evidence"].append(evidence(header, header_line))
            for line_number, _, command in children:
                if command.startswith("match "):
                    if command not in data["selectors"]:
                        data["selectors"].append(command)
                    data["evidence"].append(evidence(command, line_number))
                elif command.startswith("no match "):
                    positive = command[3:]
                    data["selectors"] = [
                        item for item in data["selectors"] if item != positive
                    ]
                    data["evidence"].append(evidence(command, line_number))

        policy_maps: dict[str, dict] = {}
        for header, header_line, children in self._indented_blocks("policy-map "):
            match = re.fullmatch(r"policy-map\s+(\S+)", header)
            if not match:
                continue
            name = match.group(1)
            policy = policy_maps.setdefault(
                name.casefold(),
                {"name": name, "classes": {}, "evidence": [], "last_line": 0},
            )
            policy["last_line"] = header_line
            policy["evidence"].append(evidence(header, header_line))
            if not children:
                continue
            direct_indent = min(item[1] for item in children)
            current_class: str | None = None
            for line_number, indent, command in children:
                class_match = re.fullmatch(r"class\s+(\S+)", command)
                removed_class = re.fullmatch(r"no\s+class\s+(\S+)", command)
                if indent == direct_indent and removed_class:
                    policy["classes"].pop(removed_class.group(1).casefold(), None)
                    current_class = None
                    policy["evidence"].append(evidence(command, line_number))
                    continue
                if indent == direct_indent and class_match:
                    class_name = class_match.group(1)
                    current_class = class_name.casefold()
                    item = policy["classes"].setdefault(
                        current_class,
                        {"name": class_name, "actions": [], "evidence": []},
                    )
                    item["evidence"].append(evidence(command, line_number))
                    continue
                if current_class is None or indent <= direct_indent:
                    continue
                item = policy["classes"][current_class]
                item["evidence"].append(evidence(command, line_number))
                if command.startswith("no police"):
                    item["actions"] = [
                        action for action in item["actions"]
                        if not action.startswith("police")
                    ]
                elif command == "no drop":
                    item["actions"] = [action for action in item["actions"] if action != "drop"]
                elif command.startswith("police") or command == "drop":
                    item["actions"].append(command)
                elif command.startswith(("shape", "bandwidth", "priority", "set ")):
                    item["actions"].append(command)

        for line_number, raw_line in enumerate(self.parser.ioscfg, 1):
            if raw_line[:1].isspace():
                continue
            line = raw_line.strip()
            removed_class = re.fullmatch(
                r"no\s+class-map(?:\s+match-(?:all|any))?\s+(\S+)", line
            )
            if removed_class:
                key = removed_class.group(1).casefold()
                if key in class_maps and line_number > class_maps[key]["last_line"]:
                    class_maps.pop(key)
            removed_policy = re.fullmatch(r"no\s+policy-map\s+(\S+)", line)
            if removed_policy:
                key = removed_policy.group(1).casefold()
                if key in policy_maps and line_number > policy_maps[key]["last_line"]:
                    policy_maps.pop(key)

        def resolved_class(data: dict) -> IOSControlPlaneClass:
            name = data["name"]
            actions = tuple(data["actions"])
            if name.casefold() == "class-default":
                selectors = ("class-default",)
                references: tuple[str, ...] = ()
                selector_resolution = "implicit-all"
                class_evidence: tuple[ConfigEvidence, ...] = ()
            else:
                class_map = class_maps.get(name.casefold())
                if class_map is None:
                    selectors = ()
                    references = ()
                    selector_resolution = "undefined-class"
                    class_evidence = ()
                else:
                    selectors = tuple(class_map["selectors"])
                    references = tuple(
                        match.group(1)
                        for selector in selectors
                        if (match := re.fullmatch(
                            r"match\s+(?:ip\s+|ipv6\s+)?access-group(?:\s+name)?\s+(\S+)",
                            selector,
                        ))
                    )
                    if not selectors:
                        selector_resolution = "empty-class"
                    elif any(
                        not acl_state.get(reference.casefold(), (False, False, False))[0]
                        or not acl_state.get(reference.casefold(), (False, False, False))[1]
                        for reference in references
                    ):
                        selector_resolution = "unresolved-selector"
                    else:
                        selector_resolution = "resolved"
                    class_evidence = tuple(class_map["evidence"])

            police_commands = [action for action in actions if action.startswith("police")]
            policing = any(re.search(r"(?:^|\s)\d+(?:\s|$)", action) for action in police_commands)
            discarding = "drop" in actions or any(
                re.search(r"(?:conform|exceed|violate)-action\s+drop", action)
                for action in police_commands
            )
            logging = any(
                acl_state.get(reference.casefold(), (False, False, False))[2]
                for reference in references
            )
            enforcement_state = (
                "enforcing"
                if policing or discarding
                else "invalid-policer"
                if police_commands
                else "no-enforcement"
            )
            return IOSControlPlaneClass(
                name=name,
                selectors=selectors,
                selector_references=references,
                selector_resolution=selector_resolution,
                actions=actions,
                policing=policing,
                discarding=discarding,
                logging=logging,
                enforcement_state=enforcement_state,
                evidence=tuple(data["evidence"]) + class_evidence,
            )

        attachments: dict[tuple[str, str], tuple[str, list[ConfigEvidence]]] = {}
        for header, header_line, children in self._indented_blocks("control-plane"):
            match = re.fullmatch(r"control-plane(?:\s+(host|transit|cef-exception))?", header)
            if not match:
                continue
            scope = match.group(1) or "aggregate"
            for line_number, indent, command in children:
                if indent != min((item[1] for item in children), default=indent):
                    continue
                attached = re.fullmatch(r"service-policy\s+(input|output)\s+(\S+)", command)
                removed = re.fullmatch(r"no\s+service-policy\s+(input|output)(?:\s+\S+)?", command)
                key = (scope, (attached or removed).group(1) if attached or removed else "")
                if attached:
                    attachments[key] = (
                        attached.group(2),
                        [evidence(header, header_line), evidence(command, line_number)],
                    )
                elif removed:
                    attachments.pop(key, None)

        records = []
        for (scope, direction), (name, attachment_evidence) in attachments.items():
            policy = policy_maps.get(name.casefold())
            if policy is None:
                platform_managed = (
                    self.device_type == "IOS_XE"
                    and name.casefold() == "system-cpp-policy"
                )
                records.append(IOSControlPlanePolicy(
                    name,
                    scope,
                    direction,
                    platform_managed,
                    "platform-managed" if platform_managed else "undefined-policy",
                    (),
                    tuple(attachment_evidence),
                ))
                continue
            classes = tuple(resolved_class(item) for item in policy["classes"].values())
            if not classes:
                state = "empty-policy"
            elif any(
                item.enforcement_state == "enforcing"
                and item.selector_resolution in {"resolved", "implicit-all"}
                for item in classes
            ):
                state = "effective"
            else:
                state = "no-enforcement"
            records.append(IOSControlPlanePolicy(
                name=name,
                scope=scope,
                direction=direction,
                policy_resolved=True,
                protection_state=state,
                classes=classes,
                evidence=tuple(attachment_evidence)
                + tuple(policy["evidence"])
                + tuple(item for policy_class in classes for item in policy_class.evidence),
            ))
        return records

    @staticmethod
    def _sanitize_archive_destination(destination: str) -> str:
        return re.sub(
            r"(?i)([a-z][a-z0-9+.-]*://)[^/@\s]+@",
            r"\1<credentials>@",
            destination,
        )

    def get_configuration_management(self) -> IOSConfigurationManagement:
        """Resolve archive scheduling and configuration-change logging without secrets."""

        destination = ""
        protocol = ""
        write_memory = False
        time_period: int | None = None
        invalid_time_period = False
        maximum: int | None = None
        change_logging = False
        hide_keys = False
        notify_syslog = False
        persistent_logging = False
        evidence: list[ConfigEvidence] = []
        archive_configured = False

        for header, header_line, children in self._indented_blocks("archive"):
            if header.casefold() != "archive":
                continue
            evidence.append(ConfigEvidence(header, self.config_filepath, header_line))
            for line_number, _, text in children:
                folded = text.casefold()
                sanitized = text
                if folded.startswith("path "):
                    archive_configured = True
                    raw_destination = text.split(maxsplit=1)[1]
                    destination = self._sanitize_archive_destination(raw_destination)
                    protocol = (
                        raw_destination.split(":", 1)[0].casefold()
                        if ":" in raw_destination
                        else "file"
                    )
                    sanitized = f"path {destination}"
                elif re.fullmatch(r"(?:no|default)\s+path(?:\s+.*)?", text, re.IGNORECASE):
                    archive_configured = True
                    destination = ""
                    protocol = ""
                elif re.fullmatch(r"write-memory", text, re.IGNORECASE):
                    archive_configured = True
                    write_memory = True
                elif re.fullmatch(r"(?:no|default)\s+write-memory", text, re.IGNORECASE):
                    archive_configured = True
                    write_memory = False
                elif match := re.fullmatch(r"time-period\s+(\S+)", text, re.IGNORECASE):
                    archive_configured = True
                    invalid_time_period = not match.group(1).isdigit() or int(match.group(1)) <= 0
                    time_period = int(match.group(1)) if not invalid_time_period else None
                elif re.fullmatch(r"(?:no|default)\s+time-period(?:\s+.*)?", text, re.IGNORECASE):
                    archive_configured = True
                    time_period = None
                    invalid_time_period = False
                elif match := re.fullmatch(r"maximum\s+(\d+)", text, re.IGNORECASE):
                    archive_configured = True
                    maximum = int(match.group(1))
                elif re.fullmatch(r"(?:no|default)\s+maximum(?:\s+.*)?", text, re.IGNORECASE):
                    archive_configured = True
                    maximum = None
                elif re.fullmatch(r"logging\s+enable", text, re.IGNORECASE):
                    change_logging = True
                elif re.fullmatch(r"(?:no|default)\s+logging\s+enable", text, re.IGNORECASE):
                    change_logging = False
                elif re.fullmatch(r"hidekeys", text, re.IGNORECASE):
                    hide_keys = True
                elif re.fullmatch(r"(?:no|default)\s+hidekeys", text, re.IGNORECASE):
                    hide_keys = False
                elif re.fullmatch(r"notify\s+syslog(?:\s+.*)?", text, re.IGNORECASE):
                    notify_syslog = True
                elif re.fullmatch(r"(?:no|default)\s+notify\s+syslog(?:\s+.*)?", text, re.IGNORECASE):
                    notify_syslog = False
                elif re.fullmatch(r"logging\s+persistent(?:\s+.*)?", text, re.IGNORECASE):
                    persistent_logging = True
                elif re.fullmatch(r"(?:no|default)\s+logging\s+persistent(?:\s+.*)?", text, re.IGNORECASE):
                    persistent_logging = False
                evidence.append(ConfigEvidence(sanitized, self.config_filepath, line_number))

        insecure = {"ftp", "tftp", "rcp", "http"}
        secure = {"scp", "sftp", "https"}
        local = {
            "file", "flash", "bootflash", "disk0", "disk1", "harddisk",
            "nvram", "pram", "usb0", "usb1", "slavedisk0", "slavedisk1",
        }
        transport_security = (
            "insecure" if protocol in insecure
            else "secure" if protocol in secure
            else "local" if protocol in local
            else "unknown"
        )
        schedule_state = (
            "effective" if write_memory or time_period is not None
            else "invalid" if invalid_time_period
            else "missing"
        )
        return IOSConfigurationManagement(
            archive_configured=archive_configured,
            destination=destination,
            protocol=protocol,
            transport_security=transport_security,
            write_memory=write_memory,
            time_period_minutes=time_period,
            schedule_state=schedule_state,
            maximum_versions=maximum,
            change_logging=change_logging,
            hide_keys=hide_keys,
            notify_syslog=notify_syslog,
            persistent_logging=persistent_logging,
            evidence=tuple(evidence),
        )

    def get_users(self) -> list[dict]:
        users = []
        user_lines = self.parser.find_objects("^username")
        for line in user_lines:
            text = line.text
            # Simple match for username and optional privilege/password
            match_name = re.search(r'^username\s+(\S+)', text)
            if match_name:
                name = match_name.group(1)
                priv_match = re.search(r'privilege\s+(\d+)', text)
                priv = int(priv_match.group(1)) if priv_match else 1
                users.append({
                    "username": name,
                    "privilege": priv,
                    "raw_line": f"username {name} <credential redacted>"
                })
        return users

    def get_services(self) -> dict:
        profiles = self.get_vty_profiles()
        return {
            "telnet": any(profile.permits_telnet for profile in profiles),
            "ssh": self.get_ssh_state() == ConfigurationState.ENABLED,
            "http": self.get_http_server_state() == ConfigurationState.ENABLED,
            "https": self.get_https_server_state() == ConfigurationState.ENABLED,
        }

    def _normalized_interfaces(self) -> list[NetworkInterface]:
        """Return explicitly exported IOS interface state without assuming defaults."""

        records: dict[str, dict] = {}
        events: list[tuple[int, str, object]] = []
        for header, header_line, children in self._indented_blocks("interface "):
            name = header.split(maxsplit=1)[1] if " " in header else ""
            if name:
                events.append((header_line, "block", (name, header, children)))
        for line_number, raw_line in enumerate(self._source_lines, start=1):
            if raw_line[:1].isspace():
                continue
            reset = re.fullmatch(r"(?:no|default) interface\s+(\S+)", raw_line.strip())
            if reset:
                events.append((line_number, "reset", reset.group(1)))

        for _, operation, payload in sorted(events, key=lambda item: item[0]):
            if operation == "reset":
                records.pop(str(payload).casefold(), None)
                continue
            name, header, children = payload
            key = name.casefold()
            data = records.setdefault(key, {
                "name": name,
                "state": NormalizedConfigurationState.UNKNOWN,
                "addresses": [],
                "scope": None,
                "evidence": [],
            })
            data["name"] = name
            data["evidence"].append(ConfigEvidence(header, self.config_filepath, _))
            for line_number, _indent, command in children:
                evidence = ConfigEvidence(command, self.config_filepath, line_number)
                if command == "shutdown":
                    data["state"] = NormalizedConfigurationState.DISABLED
                elif command == "no shutdown":
                    data["state"] = NormalizedConfigurationState.ENABLED
                else:
                    vrf = re.fullmatch(r"(?:ip )?vrf forwarding\s+(\S+)", command)
                    if vrf:
                        data["scope"] = vrf.group(1)
                    elif re.fullmatch(r"no (?:ip )?vrf forwarding(?:\s+\S+)?", command):
                        data["scope"] = None
                    ipv4 = re.fullmatch(
                        r"ip address\s+(\S+)(?:\s+(\S+))?(?:\s+(?:secondary|route-tag\s+\S+))*",
                        command,
                    )
                    if ipv4:
                        value = " ".join(item for item in ipv4.groups() if item)
                        if value not in data["addresses"]:
                            data["addresses"].append(value)
                    elif command == "no ip address":
                        data["addresses"] = [
                            value for value in data["addresses"] if ":" in value
                        ]
                    else:
                        remove_ipv4 = re.fullmatch(r"no ip address\s+(\S+)(?:\s+(\S+))?.*", command)
                        if remove_ipv4:
                            prefix = " ".join(
                                item for item in remove_ipv4.groups() if item
                            )
                            data["addresses"] = [
                                value for value in data["addresses"]
                                if not value.startswith(prefix)
                            ]
                        ipv6 = re.fullmatch(
                            r"ipv6 address\s+(\S+)(?:\s+(?:eui-64|link-local|anycast))?",
                            command,
                        )
                        if ipv6 and ipv6.group(1) not in data["addresses"]:
                            data["addresses"].append(ipv6.group(1))
                        elif command == "no ipv6 address":
                            data["addresses"] = [
                                value for value in data["addresses"] if ":" not in value
                            ]
                        else:
                            remove_ipv6 = re.fullmatch(r"no ipv6 address\s+(\S+).*", command)
                            if remove_ipv6:
                                data["addresses"] = [
                                    value for value in data["addresses"]
                                    if value != remove_ipv6.group(1)
                                ]
                data["evidence"].append(evidence)

        return [
            NetworkInterface(
                name=data["name"],
                state=data["state"],
                scope=data["scope"] or "global",
                addresses=tuple(data["addresses"]),
                evidence=tuple(data["evidence"]),
            )
            for data in records.values()
        ]

    @staticmethod
    def _acl_address(tokens: list[str], index: int) -> tuple[str, int]:
        if index >= len(tokens):
            return "", index
        token = tokens[index]
        folded = token.casefold()
        if folded in {"any", "any4", "any6"}:
            return token, index + 1
        if folded in {"host", "object", "object-group", "interface"} and index + 1 < len(tokens):
            return f"{token} {tokens[index + 1]}", index + 2
        if index + 1 < len(tokens):
            try:
                if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", token) and re.fullmatch(
                    r"\d+\.\d+\.\d+\.\d+", tokens[index + 1]
                ):
                    return f"{token} {tokens[index + 1]}", index + 2
            except TypeError:
                pass
        return token, index + 1

    def _normalized_acl_policies(self) -> list[SecurityPolicy]:
        """Inventory only ACL rules with an exported effective attachment."""

        definitions: dict[str, dict] = {}

        def parse_entry(command: str, kind: str, evidence: ConfigEvidence) -> dict | None:
            tokens = command.split()
            sequence = ""
            if tokens and tokens[0].isdigit():
                sequence, tokens = tokens[0], tokens[1:]
            elif len(tokens) > 1 and tokens[0].casefold() == "sequence" and tokens[1].isdigit():
                sequence, tokens = tokens[1], tokens[2:]
            if not tokens or tokens[0].casefold() not in {"permit", "deny"}:
                return None
            action = tokens.pop(0).casefold()
            tracking = None
            if tokens and tokens[-1].casefold() in {"log", "log-input"}:
                tracking = tokens.pop().casefold()
            sources: tuple[str, ...] = ()
            destinations: tuple[str, ...] = ()
            services: tuple[str, ...] = ()
            if kind == "standard":
                sources = (" ".join(tokens) or "unknown",)
            elif tokens:
                protocol = tokens[0]
                source, cursor = self._acl_address(tokens, 1)
                destination, cursor = self._acl_address(tokens, cursor)
                sources = (source,) if source else ()
                destinations = (destination,) if destination else ()
                service = " ".join([protocol, *tokens[cursor:]])
                services = (service,)
            return {
                "sequence": sequence,
                "action": action,
                "sources": sources,
                "destinations": destinations,
                "services": services,
                "tracking": tracking,
                "evidence": evidence,
                "canonical": " ".join(command.split()).casefold(),
            }

        named_events: list[tuple[int, str, str, list[tuple[int, int, str]]]] = []
        for prefix, family in (("ip access-list ", "ipv4"), ("ipv6 access-list ", "ipv6")):
            for header, line_number, children in self._indented_blocks(prefix):
                if family == "ipv4":
                    match = re.fullmatch(r"ip access-list\s+(standard|extended)\s+(\S+)", header)
                    if not match:
                        continue
                    kind, name = match.groups()
                else:
                    match = re.fullmatch(r"ipv6 access-list\s+(\S+)", header)
                    if not match:
                        continue
                    name, kind = match.group(1), "extended"
                named_events.append((line_number, name, f"{family}:{kind}", children))

        for line_number, name, flavor, children in sorted(named_events):
            family, kind = flavor.split(":", 1)
            data = definitions.setdefault(name.casefold(), {
                "name": name, "family": family, "kind": kind, "entries": []
            })
            for child_line, _indent, command in children:
                removed_sequence = re.fullmatch(r"no (?:sequence\s+)?(\d+)", command)
                if removed_sequence:
                    data["entries"] = [
                        item for item in data["entries"]
                        if item["sequence"] != removed_sequence.group(1)
                    ]
                    continue
                if command.startswith(("no ", "default ")):
                    target = " ".join(command.split()[1:]).casefold()
                    data["entries"] = [
                        item for item in data["entries"]
                        if item["canonical"] != target
                    ]
                    continue
                entry = parse_entry(
                    command, kind,
                    ConfigEvidence(command, self.config_filepath, child_line),
                )
                if entry:
                    if entry["sequence"]:
                        data["entries"] = [
                            item for item in data["entries"]
                            if item["sequence"] != entry["sequence"]
                        ]
                    data["entries"].append(entry)

        for line_number, raw_line in enumerate(self._source_lines, start=1):
            if raw_line[:1].isspace():
                continue
            line = raw_line.strip()
            removed = re.fullmatch(
                r"(?:no|default) (?:ip access-list (?:standard|extended) |ipv6 access-list |access-list )(\S+)",
                line,
            )
            if removed:
                definitions.pop(removed.group(1).casefold(), None)
                continue
            match = re.fullmatch(r"access-list\s+(\S+)\s+(.+)", line)
            if not match:
                continue
            name, command = match.groups()
            numeric = int(name) if name.isdigit() else None
            kind = (
                "standard"
                if numeric is not None and (1 <= numeric <= 99 or 1300 <= numeric <= 1999)
                else "extended"
            )
            data = definitions.setdefault(name.casefold(), {
                "name": name, "family": "ipv4", "kind": kind, "entries": []
            })
            entry = parse_entry(
                command, kind, ConfigEvidence(line, self.config_filepath, line_number)
            )
            if entry:
                data["entries"].append(entry)

        attachments: dict[tuple[str, str, str], tuple[str, ConfigEvidence]] = {}
        for header, header_line, children in self._indented_blocks("interface "):
            interface = header.split(maxsplit=1)[1] if " " in header else ""
            for line_number, _indent, command in children:
                attached = re.fullmatch(r"ip access-group\s+(\S+)\s+(in|out)", command)
                attached_v6 = re.fullmatch(r"ipv6 traffic-filter\s+(\S+)\s+(in|out)", command)
                removed = re.fullmatch(r"(?:no|default) ip access-group(?:\s+\S+)?(?:\s+(in|out))?", command)
                removed_v6 = re.fullmatch(r"(?:no|default) ipv6 traffic-filter(?:\s+\S+)?(?:\s+(in|out))?", command)
                if attached or attached_v6:
                    match = attached or attached_v6
                    family = "ipv4" if attached else "ipv6"
                    attachments[(interface, family, match.group(2))] = (
                        match.group(1),
                        ConfigEvidence(command, self.config_filepath, line_number),
                    )
                elif removed or removed_v6:
                    family = "ipv4" if removed else "ipv6"
                    direction = (removed or removed_v6).group(1)
                    keys = [
                        key for key in attachments
                        if key[0] == interface and key[1] == family
                        and (direction is None or key[2] == direction)
                    ]
                    for key in keys:
                        attachments.pop(key, None)

        policies: list[SecurityPolicy] = []
        for (interface, family, direction), (name, attachment_evidence) in attachments.items():
            definition = definitions.get(name.casefold())
            scope = f"{interface}:{direction}:{family}"
            if definition is None or definition["family"] != family:
                policies.append(SecurityPolicy(
                    name=f"{name}@{scope}",
                    state=NormalizedConfigurationState.UNKNOWN,
                    action="unknown",
                    scope=scope,
                    source_interfaces=(interface,) if direction == "in" else (),
                    destination_interfaces=(interface,) if direction == "out" else (),
                    evidence=(attachment_evidence,),
                ))
                continue
            entries = definition["entries"]
            if entries and all(entry["sequence"] for entry in entries):
                entries = sorted(entries, key=lambda entry: int(entry["sequence"]))
            for position, entry in enumerate(entries, start=1):
                policies.append(SecurityPolicy(
                    name=f"{name}:{entry['sequence'] or position}@{scope}",
                    state=NormalizedConfigurationState.ENABLED,
                    action=entry["action"],
                    position=position,
                    scope=scope,
                    source_interfaces=(interface,) if direction == "in" else (),
                    destination_interfaces=(interface,) if direction == "out" else (),
                    sources=entry["sources"],
                    destinations=entry["destinations"],
                    services=entry["services"],
                    tracking=entry["tracking"],
                    evidence=(attachment_evidence, entry["evidence"]),
                ))

        for policy in self.get_control_plane_policies():
            for position, policy_class in enumerate(policy.classes, start=1):
                policies.append(SecurityPolicy(
                    name=f"{policy.name}/{policy_class.name}",
                    state=(
                        NormalizedConfigurationState.ENABLED
                        if policy.policy_resolved
                        else NormalizedConfigurationState.UNKNOWN
                    ),
                    action=policy_class.enforcement_state,
                    position=position,
                    scope=f"control-plane:{policy.scope}:{policy.direction}",
                    services=policy_class.selectors,
                    tracking="log" if policy_class.logging else None,
                    evidence=policy.evidence + policy_class.evidence,
                ))
        return policies

    @staticmethod
    def _acl_network_semantics(selector: str, family: str) -> NetworkSemantics:
        tokens = selector.split()
        folded = [token.casefold() for token in tokens]
        version = 6 if family == "ipv6" else 4
        if folded in (["any"], ["any4"], ["any6"]):
            return NetworkSemantics(any=True)
        if len(tokens) == 2 and folded[0] == "host":
            try:
                address = ipaddress.ip_address(tokens[1])
            except ValueError:
                return NetworkSemantics(complete=False, unresolved=(selector,))
            if address.version != version:
                return NetworkSemantics(complete=False, unresolved=(selector,))
            return NetworkSemantics(intervals=(
                AddressInterval(version, int(address), int(address)),
            ))
        if folded[:1] in (["object"], ["object-group"], ["interface"]):
            return NetworkSemantics(complete=False, unresolved=(selector,))
        try:
            if version == 6 and len(tokens) == 1:
                network = ipaddress.ip_network(tokens[0], strict=False)
                if network.version != 6:
                    raise ValueError
                return NetworkSemantics(intervals=(AddressInterval(
                    6, int(network.network_address), int(network.broadcast_address)
                ),))
            if version == 4 and len(tokens) == 1:
                address = ipaddress.IPv4Address(tokens[0])
                return NetworkSemantics(intervals=(AddressInterval(
                    4, int(address), int(address)
                ),))
            if version == 4 and len(tokens) == 2:
                address = ipaddress.IPv4Address(tokens[0])
                wildcard = int(ipaddress.IPv4Address(tokens[1]))
                netmask = (~wildcard) & 0xFFFFFFFF
                network = ipaddress.IPv4Network(
                    (int(address) & netmask, str(ipaddress.IPv4Address(netmask))),
                    strict=False,
                )
                return NetworkSemantics(intervals=(AddressInterval(
                    4, int(network.network_address), int(network.broadcast_address)
                ),))
        except (ValueError, ipaddress.NetmaskValueError):
            pass
        return NetworkSemantics(complete=False, unresolved=(selector or "<empty-address>",))

    @staticmethod
    def _acl_service_semantics(selector: str) -> ServiceSemantics:
        tokens = selector.split()
        if not tokens:
            return ServiceSemantics(any=True)
        protocol = tokens.pop(0).casefold()
        if protocol in {"ip", "ipv6"} and not tokens:
            return ServiceSemantics(any=True)
        aliases = {
            "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25,
            "domain": 53, "dns": 53, "www": 80, "http": 80,
            "pop3": 110, "imap": 143, "https": 443, "snmp": 161,
            "snmptrap": 162, "bgp": 179, "ntp": 123,
        }

        def port(value: str) -> int | None:
            if value.isdigit() and 0 <= int(value) <= 65535:
                return int(value)
            return aliases.get(value.casefold())

        if protocol in {"tcp", "udp"}:
            if not tokens:
                return ServiceSemantics(intervals=(ServiceInterval(protocol, 0, 65535),))
            operator = tokens.pop(0).casefold()
            if operator == "eq" and tokens:
                ports = [port(value) for value in tokens]
                if all(value is not None for value in ports):
                    return ServiceSemantics(intervals=tuple(
                        ServiceInterval(protocol, value, value)
                        for value in ports if value is not None
                    ))
            if operator == "range" and len(tokens) == 2:
                first, last = port(tokens[0]), port(tokens[1])
                if first is not None and last is not None and first <= last:
                    return ServiceSemantics(intervals=(ServiceInterval(protocol, first, last),))
            if operator in {"lt", "gt"} and len(tokens) == 1:
                value = port(tokens[0])
                if value is not None:
                    first, last = (0, value - 1) if operator == "lt" else (value + 1, 65535)
                    if first <= last:
                        return ServiceSemantics(intervals=(ServiceInterval(protocol, first, last),))
            if operator == "neq" and len(tokens) == 1:
                value = port(tokens[0])
                if value is not None:
                    intervals = []
                    if value > 0:
                        intervals.append(ServiceInterval(protocol, 0, value - 1))
                    if value < 65535:
                        intervals.append(ServiceInterval(protocol, value + 1, 65535))
                    return ServiceSemantics(intervals=tuple(intervals))
            return ServiceSemantics(complete=False, unresolved=(selector,))
        if not tokens and protocol in {"icmp", "icmpv6", "gre", "esp", "ah", "ospf", "eigrp"}:
            return ServiceSemantics(intervals=(ServiceInterval(protocol, 0, 65535),))
        if not tokens and protocol.isdigit() and 0 <= int(protocol) <= 255:
            return ServiceSemantics(intervals=(ServiceInterval(f"ip-{protocol}", 0, 65535),))
        return ServiceSemantics(complete=False, unresolved=(selector,))

    def get_attached_acl_semantics(self) -> tuple[IOSACLRule, ...]:
        """Adapt only effective interface ACL entries with fully static selectors."""
        rules = []
        for policy in self._normalized_acl_policies():
            if policy.scope is None or policy.scope.startswith("control-plane:"):
                continue
            family = policy.scope.rsplit(":", 1)[-1]
            standard = not policy.destinations and not policy.services
            source = policy.sources[0] if policy.sources else ""
            destination = "any" if standard else (
                policy.destinations[0] if policy.destinations else ""
            )
            service = "" if standard else (
                policy.services[0] if policy.services else "<unknown-service>"
            )
            rules.append(IOSACLRule(
                name=policy.name,
                family=family,
                scope=policy.scope,
                position=policy.position or len(rules) + 1,
                action=policy.action,
                source_networks=self._acl_network_semantics(source, family),
                destination_networks=self._acl_network_semantics(destination, family),
                services=(
                    ServiceSemantics(any=True)
                    if standard
                    else self._acl_service_semantics(service)
                ),
                behavior_signature=(("tracking", policy.tracking or "none"),),
                evidence=policy.evidence,
            ))
        return tuple(rules)

    def _normalized_logging_destinations(self) -> list[LoggingDestination]:
        destinations: dict[tuple[str, str], LoggingDestination] = {}
        severity: str | None = None
        for line_number, raw_line in enumerate(self._source_lines, start=1):
            if raw_line[:1].isspace():
                continue
            line = raw_line.strip()
            trap = re.fullmatch(r"logging trap\s+(\S+)", line)
            if trap:
                severity = trap.group(1)
                continue
            if re.fullmatch(r"(?:no|default) logging trap(?:\s+\S+)?", line):
                severity = None
                continue
            match = re.fullmatch(r"(?:(no|default) )?logging (?:host|server)\s*(.*)", line)
            if not match:
                continue
            operation, remainder = match.groups()
            try:
                tokens = shlex.split(remainder)
            except ValueError:
                continue
            scope = "global"
            if tokens[:1] == ["vrf"] and len(tokens) >= 3:
                scope, tokens = tokens[1], tokens[2:]
            if tokens[:1] == ["ipv6"]:
                tokens = tokens[1:]
            if not tokens:
                if operation:
                    destinations.clear()
                continue
            address = tokens[0]
            key = (scope.casefold(), address.casefold())
            if operation:
                destinations.pop(key, None)
            else:
                destinations[key] = LoggingDestination(
                    destination_type="syslog",
                    state=NormalizedConfigurationState.ENABLED,
                    address=address,
                    severity=severity,
                    scope=scope,
                    evidence=(ConfigEvidence(line, self.config_filepath, line_number),),
                )
        if severity is not None:
            destinations = {
                key: LoggingDestination(
                    destination_type=item.destination_type,
                    state=item.state,
                    address=item.address,
                    severity=severity,
                    scope=item.scope,
                    evidence=item.evidence,
                )
                for key, item in destinations.items()
            }
        return list(destinations.values())

    def get_normalized_config(self) -> NormalizedConfig:
        """Expose bounded IOS/IOS-XE state already reconstructed by native methods."""

        hostname = self.get_hostname()
        version = self.get_version()

        management_services: list[ManagementService] = []
        for line in self.get_management_lines("vty"):
            if line.exec_enabled is False or line.transports is None:
                continue
            permitted = tuple(
                value for value in (
                    f"ipv4-acl:{line.ipv4_access_class}" if line.ipv4_access_class else "",
                    f"ipv6-acl:{line.ipv6_access_class}" if line.ipv6_access_class else "",
                ) if value
            )
            for protocol in ("ssh", "telnet"):
                if protocol in line.transports or "all" in line.transports:
                    management_services.append(ManagementService(
                        protocol=protocol,
                        state=NormalizedConfigurationState.ENABLED,
                        interface=line.line,
                        scope="management-lines",
                        permitted_sources=permitted,
                        evidence=line.evidence,
                    ))
        if (
            self.get_ssh_state() == ConfigurationState.ENABLED
            and not any(item.protocol == "ssh" for item in management_services)
        ):
            management_services.append(ManagementService(
                protocol="ssh",
                state=NormalizedConfigurationState.ENABLED,
                scope="global-explicit",
                evidence=(ConfigEvidence("explicit SSH configuration", self.config_filepath),),
            ))
        http_acl = self.get_http_access_class()
        for protocol, state in (
            ("http", self.get_http_server_state()),
            ("https", self.get_https_server_state()),
        ):
            if state == ConfigurationState.ENABLED:
                management_services.append(ManagementService(
                    protocol=protocol,
                    state=NormalizedConfigurationState.ENABLED,
                    scope="global",
                    permitted_sources=(f"ipv4-acl:{http_acl}",) if http_acl else (),
                    evidence=(ConfigEvidence(f"ip http {'secure-' if protocol == 'https' else ''}server", self.config_filepath),),
                ))

        credential_by_user = {
            item.account.casefold(): item
            for item in self.get_credential_metadata()
            if item.context == "local_user"
        }
        normalized_users = []
        for user in self.get_users():
            metadata = credential_by_user.get(user["username"].casefold())
            normalized_users.append(LocalUser(
                username=user["username"],
                state=NormalizedConfigurationState.CONFIGURED,
                privilege=user["privilege"],
                authentication=metadata.method if metadata else None,
                evidence=(
                    metadata.evidence
                    if metadata
                    else (ConfigEvidence(user["raw_line"], self.config_filepath),)
                ),
            ))

        crypto_settings: list[CryptoSetting] = []
        ssh_version = self.get_ssh_version()
        if ssh_version:
            crypto_settings.append(CryptoSetting(
                name="ssh-version",
                value=ssh_version,
                state=NormalizedConfigurationState.CONFIGURED,
                scope="management-ssh",
                evidence=(ConfigEvidence(f"ip ssh version {ssh_version}", self.config_filepath),),
            ))
        for policy in self.get_ssh_server_algorithms():
            if policy.algorithms is not None:
                crypto_settings.append(CryptoSetting(
                    name=f"ssh-{policy.category}",
                    value=" ".join(policy.algorithms),
                    state=NormalizedConfigurationState.CONFIGURED,
                    scope="management-ssh",
                    evidence=policy.evidence,
                ))
        modulus = self.get_ssh_rsa_key_modulus()
        if modulus.configured and modulus.value is not None:
            crypto_settings.append(CryptoSetting(
                name="ssh-rsa-key-modulus",
                value=str(modulus.value),
                state=NormalizedConfigurationState.CONFIGURED,
                scope="management-ssh",
                evidence=(ConfigEvidence(modulus.raw_line, self.config_filepath),),
            ))

        return NormalizedConfig(
            device_type=self.device_type,
            hostname=(
                NormalizedValue.known(hostname)
                if hostname != "?"
                else NormalizedValue.unknown("Hostname is absent")
            ),
            device_model=NormalizedValue.unknown(
                "IOS running configuration does not provide reliable model metadata"
            ),
            software_version=(
                NormalizedValue.known(version)
                if version != "?"
                else NormalizedValue.unknown("IOS version is absent")
            ),
            management_services=NormalizedCollection.known(*management_services),
            users=NormalizedCollection.known(*normalized_users),
            interfaces=NormalizedCollection.known(*self._normalized_interfaces()),
            policies=NormalizedCollection.known(*self._normalized_acl_policies()),
            logging_destinations=NormalizedCollection.known(
                *self._normalized_logging_destinations()
            ),
            crypto_settings=NormalizedCollection.known(*crypto_settings),
        )

    def get_native_config(self) -> CiscoConfParse:
        return self.parser

    # Keep classic helper functions as methods of the parser to facilitate transition
    def get_passwd_enc(self) -> bool:
        passwd_enc = self.parser.find_objects("no service password-encryption")
        return len(passwd_enc) > 0

    def get_passwd_length(self) -> str:
        passwd_length = self.parser.find_objects("security passwords min-length")
        if len(passwd_length) > 0:
            return passwd_length[0].re_match_typed(r'^security passwords min-length\s+(\S+)', default='')
        return "No specified"

    def get_ip_source_routing(self) -> bool:
        ip_src_routing = self.parser.find_objects("no ip source routing")
        return len(ip_src_routing) == 0

    def get_bootp(self) -> bool:
        bootp_server = self.parser.find_objects("no ip bootp server")
        return len(bootp_server) == 0

    def get_tcp_keep_alives_in(self) -> bool:
        keep_alives_in = self.parser.find_objects("service tcp-keepalives-in")
        return len(keep_alives_in) > 0

    def get_tcp_keep_alives_out(self) -> bool:
        keep_alives_out = self.parser.find_objects("service tcp-keepalives-out")
        return len(keep_alives_out) > 0
