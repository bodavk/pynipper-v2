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
class IOSPPTPDialin:
    """A VPDN group that accepts PPTP dial-in while VPDN is globally enabled."""

    group: str
    virtual_template: Optional[str]
    authentication: tuple[str, ...]
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class IOSPPPPapInterface:
    """An active PPP link interface that uses or sends PAP credentials."""

    interface: str
    methods: tuple[str, ...]
    sends_pap: bool
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class IOSLoggingTLSProfile:
    """A ``logging tls-profile`` bound to a ``logging host ... transport tls`` destination."""

    host: str
    profile: str
    weak_versions: tuple[str, ...]
    weak_ciphers: tuple[str, ...]
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class IOSLDAPServer:
    """A named ``ldap server`` and its effective secure-mode state."""

    name: str
    secure: bool
    port: Optional[str]
    evidence: tuple[ConfigEvidence, ...]


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
    send_version: str
    authentication_state: str
    authentication_mode: str
    key_reference: str
    evidence: tuple[ConfigEvidence, ...]
    vrf: str = "default"


@dataclass(frozen=True)
class IOSISISAuthentication:
    instance: str
    interface: str
    level: str
    scope: str  # hello or database
    state: str  # send-only, text-mode, unresolved, configured-md5, unknown
    key_reference: str
    evidence: tuple[ConfigEvidence, ...]


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


@dataclass(frozen=True)
class IOSManagementACL:
    name: str
    state: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class IOSProgrammabilityAPI:
    service: str
    transport: str
    ipv4_acl: str | None
    ipv6_acl: str | None
    port: int | None
    evidence: tuple[ConfigEvidence, ...]


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

    def get_train(self) -> Optional[tuple[int, int]]:
        """``major.minor`` from the ``version`` line (SC-044); None when missing.

        The running configuration names only the train (``12.4``, ``15.2``, ``17.9``),
        so gates inside a train (12.1(5), 15.4(3)M4, 16.6.4) cannot be decided here.
        """
        match = re.match(r"^(\d+)\.(\d+)", self.get_version())
        return (int(match.group(1)), int(match.group(2))) if match else None

    def is_iosxe(self) -> bool:
        """IOS-XE device type or an IOS-XE 16+ train (IOS-XE 3.x reports 15.x trains)."""
        train = self.get_train()
        return self.device_type == "IOS_XE" or bool(train and train[0] >= 16)

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

    def get_tacacs_servers(self) -> tuple[bool, list[tuple[str, str, bool, ConfigEvidence]]]:
        """TACACS+ servers and whether each has its own key.

        Returns (global ``tacacs-server key`` present, [(name, address, has_key, evidence)]).
        Named ``tacacs server`` blocks and legacy ``tacacs-server host`` lines follow
        ``no`` removal. Key values stay inside the parser.
        """
        keyed = {account.casefold() for context, account, _, _, _ in self._key_directive_records()
                 if context == "tacacs_key"}
        global_key = "tacacs-server" in keyed
        servers: dict[str, list] = {}
        parent: Optional[str] = None
        for number, raw in enumerate(self._source_lines, start=1):
            line = raw.strip()
            if not line or line == "!":
                continue
            folded = line.casefold()
            if not raw[:1].isspace():
                parent = None
                removed = re.fullmatch(r"(?:no|default) tacacs server (\S+)", folded)
                removed_host = re.fullmatch(r"(?:no|default) tacacs-server host (\S+)(?: .*)?", folded)
                if removed:
                    servers.pop(f"tacacs server {removed.group(1)}", None)
                elif removed_host:
                    servers.pop(f"tacacs-server host {removed_host.group(1)}", None)
                elif re.fullmatch(r"tacacs server \S+", folded):
                    parent = " ".join(folded.split()[:3])
                    servers[parent] = [line.split()[2], "", ConfigEvidence(line, self.config_filepath, number)]
                elif folded.startswith("tacacs-server host "):
                    address = line.split()[2]
                    servers[f"tacacs-server host {address.casefold()}"] = [
                        address, address, ConfigEvidence(
                            re.sub(r"(?i)( key)( \d)? \S+.*$", r"\1 <redacted>", line),
                            self.config_filepath, number)]
                continue
            if parent and parent in servers:
                address = re.fullmatch(r"address ipv[46] (\S+)", folded)
                if address:
                    servers[parent][1] = address.group(1)
        result = []
        for key, (name, address, evidence) in servers.items():
            account = key if key.startswith("tacacs server") else f"tacacs-server host {address}".casefold()
            result.append((name, address, account in keyed, evidence))
        return global_key, result

    def get_ikev1_aggressive_mode(self) -> tuple[bool, tuple[ConfigEvidence, ...]]:
        """Whether IKEv1 aggressive mode is accepted for effective pre-shared keys.

        Without ``crypto isakmp aggressive-mode disable`` IOS processes all incoming
        aggressive-mode SAs (Security Command Reference). Returns (accepted, evidence of
        the pre-shared keys); accepted is False when disabled or no IKEv1 key exists.
        """
        disabled = self._effective_global_toggle("crypto isakmp aggressive-mode disable")
        keys = [record for record in self._key_directive_records()
                if record[0] in {"isakmp_pre_shared_key", "keyring_pre_shared_key"}]
        if disabled or not keys:
            return False, ()
        return True, tuple(
            ConfigEvidence(f"{account} pre-shared key <redacted>", self.config_filepath, number)
            for _, account, _, _, number in keys
        )

    def _effective_global_toggle(self, command: str) -> bool:
        state = False
        for line in self._global_lines():
            folded = line.casefold()
            if folded == command:
                state = True
            elif folded in {f"no {command}", f"default {command}"}:
                state = False
        return state

    _LEGACY_SERVICE_TOGGLES = {
        "service finger": "finger", "ip finger": "finger",
        "service tcp-small-servers": "tcp-small-servers",
        "service udp-small-servers": "udp-small-servers",
        "ip bootp server": "bootp server", "service pad": "pad", "ip identd": "identd",
    }

    def get_legacy_services(self) -> list[tuple[str, ConfigEvidence]]:
        """Explicitly enabled legacy services after ``no`` removal (SC-026).

        Only explicit enabling commands count: defaults differ by release (Cisco
        hardening guide), so a missing line stays unknown. ``mop enabled`` counts on
        interfaces that are not shut down.
        """
        state: dict[str, Optional[ConfigEvidence]] = {}
        for number, raw in enumerate(self._source_lines, start=1):
            if raw[:1].isspace():
                continue
            line = raw.strip()
            folded = re.sub(r"\s+", " ", line.casefold())
            negated = folded.startswith(("no ", "default "))
            command = folded.split(" ", 1)[1] if negated else folded
            # `ip finger rfc-compliant` still enables finger
            base = "ip finger" if command.startswith("ip finger") else command
            name = self._LEGACY_SERVICE_TOGGLES.get(base)
            if name:
                state[name] = None if negated else ConfigEvidence(line, self.config_filepath, number)
        result = [(name, evidence) for name, evidence in state.items() if evidence is not None]
        for header, _, children in self._indented_blocks("interface "):
            shutdown = False
            mop = None
            for line_number, _, command in children:
                if command == "shutdown":
                    shutdown = True
                elif command == "no shutdown":
                    shutdown = False
                elif command == "mop enabled":
                    mop = ConfigEvidence("mop enabled", self.config_filepath, line_number)
                elif command == "no mop enabled":
                    mop = None
            if mop and not shutdown:
                result.append(("mop", mop))
        return result

    def get_legacy_default_services(self) -> list[tuple[str, str]]:
        """Services enabled by default on old trains that the export does not disable (SC-044).

        Cisco hardening guide: finger is disabled by default only in releases later than
        12.1(5), and the TCP/UDP small servers only from 12.0. A ``version`` line states
        just major.minor, so only trains that are entirely older qualify: finger for
        11.x/12.0 and the small servers for 11.x. Returns (service, reason).
        """
        train = self.get_train()
        if not train:
            return []
        disabled = set()
        for line in self._global_lines():
            folded = re.sub(r"\s+", " ", line.casefold())
            if folded in {"no service finger", "no ip finger"}:
                disabled.add("finger")
            elif folded in {"no service tcp-small-servers", "no service udp-small-servers"}:
                disabled.add(folded.split()[2])
        explicit = {name for name, _ in self.get_legacy_services()}
        result = []
        if train < (12, 1) and "finger" not in disabled and "finger" not in explicit:
            result.append(("finger", f"enabled by default before 12.1(5); train {train[0]}.{train[1]}"))
        elif train == (16, 1) and "finger" not in disabled and "finger" not in explicit:
            # SC-044 IOS-02: IOS XE hardening guide, releases 'later than 16.1' disable finger.
            result.append(("finger", "enabled by default in IOS XE 16.1; train 16.1"))
        for service in ("tcp-small-servers", "udp-small-servers"):
            if service in disabled or service in explicit:
                continue
            if train < (12, 0):
                result.append((service, f"enabled by default before 12.0; train {train[0]}.{train[1]}"))
            elif (16, 0) <= train < (16, 6):
                # SC-044 IOS-01: IOS XE hardening guide, disabled by default from 16.6.4.
                result.append((service, f"enabled by default before IOS XE 16.6.4; train {train[0]}.{train[1]}"))
        return result

    def get_default_enabled_services(self) -> list[tuple[str, str]]:
        """Services on by default in every documented release that the export leaves on (SC-044).

        IOS-05 ``service pad`` (WAN command reference: all PAD commands and connections
        are enabled), IOS-11 ``ip bootp server`` (Fundamentals command reference: enabled,
        and ``no ip bootp server`` appears when disabled) and IOS-10 ``mop enabled`` on
        routed Ethernet interfaces of classic IOS (Interface command reference: enabled on
        Ethernet interfaces). Explicitly enabled services are reported by
        :meth:`get_legacy_services`. Returns (service, reason).
        """
        state: dict[str, bool] = {}
        for line in self._global_lines():
            folded = re.sub(r"\s+", " ", line.casefold())
            negated = folded.startswith(("no ", "default "))
            command = folded.split(" ", 1)[1] if negated else folded
            if command in {"service pad", "ip bootp server"}:
                state[command] = not negated
            elif command == "ip dhcp bootp ignore":
                state["bootp ignore"] = not negated
        result = []
        if "service pad" not in state:
            result.append(("pad", "'no service pad' absent; PAD is enabled by default"))
        if "ip bootp server" not in state and not state.get("bootp ignore"):
            result.append(("bootp server", "'no ip bootp server' absent; BOOTP service is enabled by default"))
        if not self.is_iosxe():
            mop = []
            for header, _, children in self._indented_blocks("interface "):
                name = header.split(None, 1)[1] if " " in header else header
                if not re.match(r"(?i)(?:fast|gigabit|tengigabit|ten|fortygigabit|hundredgig\w*)?ethernet", name):
                    continue
                enabled, shutdown, routed = True, False, False
                for _, _, command in children:
                    if command == "shutdown":
                        shutdown = True
                    elif command == "no shutdown":
                        shutdown = False
                    elif command == "no mop enabled":
                        enabled = False
                    elif command == "mop enabled":
                        enabled = False  # explicit form is reported by get_legacy_services
                    elif command.startswith("ip address ") and "negotiated" not in command:
                        routed = True
                if enabled and routed and not shutdown:
                    mop.append(name)
            if mop:
                result.append(("mop", "'no mop enabled' absent on Ethernet interface(s) " + ", ".join(mop)))
        return result

    def get_file_and_shell_servers(self) -> list[tuple[str, ConfigEvidence]]:
        """Effective ``ip rcmd rsh-enable``/``rcp-enable`` and ``tftp-server`` lines.

        rsh/rcp servers are disabled by default (IOS XE File Transfer Services guide).
        """
        found: dict[str, tuple[str, ConfigEvidence]] = {}
        for number, raw in enumerate(self._source_lines, start=1):
            if raw[:1].isspace():
                continue
            line = raw.strip()
            folded = re.sub(r"\s+", " ", line.casefold())
            for command, kind in (("ip rcmd rsh-enable", "rsh"), ("ip rcmd rcp-enable", "rcp")):
                if folded == command:
                    found[kind] = (kind, ConfigEvidence(line, self.config_filepath, number))
                elif folded in {f"no {command}", f"default {command}"}:
                    found.pop(kind, None)
            tftp = re.fullmatch(r"(no )?tftp-server (\S+)(?: .*)?", folded)
            if tftp:
                key = f"tftp {tftp.group(2)}"
                if tftp.group(1):
                    found.pop(key, None)
                else:
                    found[key] = ("tftp", ConfigEvidence(line, self.config_filepath, number))
        return list(found.values())

    def get_gnmi_insecure_server(self) -> Optional[ConfigEvidence]:
        """IOS-XE ``gnxi server`` (insecure gNMI, default port 50052) while ``gnxi`` is on."""
        enabled = False
        server: Optional[ConfigEvidence] = None
        for number, raw in enumerate(self._source_lines, start=1):
            if raw[:1].isspace():
                continue
            folded = raw.strip().casefold()
            if folded == "gnxi":
                enabled = True
            elif folded == "no gnxi":
                enabled = False
            elif folded == "gnxi server":
                server = ConfigEvidence(raw.strip(), self.config_filepath, number)
            elif folded == "no gnxi server":
                server = None
        return server if enabled else None

    def get_smart_install(self) -> tuple[Optional[bool], tuple[str, ...]]:
        """Effective Smart Install (`vstack`) state from explicit global commands.

        Releases with Cisco bug CSCvd36820 show `vstack` when the client is enabled and
        `no vstack` when it is disabled; older releases showed neither, so absence is
        unknown (cisco-sa-20180409-smi). Returns (state, evidence lines in effect).
        """
        state: Optional[bool] = None
        evidence: list[str] = []
        for line in self._global_lines():
            if line == "no vstack":
                state, evidence = False, [line]
            elif line == "vstack" or line.startswith("vstack "):
                if state is not True:
                    evidence = []
                state = True
                evidence.append(line)
        return state, tuple(evidence)

    def get_pptp_dialin_groups(self) -> list[IOSPPTPDialin]:
        """SC-013: VPDN groups accepting PPTP (``protocol pptp`` or ``any``) dial-in.

        Syntax per Cisco "Configuring the Cisco Router and VPN Clients Using PPTP and
        MPPE": global ``vpdn enable``, ``vpdn-group`` > ``accept-dialin`` > ``protocol
        pptp`` and ``virtual-template``. VPDN is disabled unless ``vpdn enable`` is in
        effect. ``authentication`` is the cloned Virtual-Template's explicit
        ``ppp authentication`` method list (empty when absent or unresolved).
        """
        enabled = None
        for number, raw in enumerate(self.parser.ioscfg, start=1):
            if raw[:1].isspace():
                continue
            folded = raw.strip().lower()
            if folded == "vpdn enable":
                enabled = ConfigEvidence(raw.strip(), self.config_filepath, number)
            elif folded == "no vpdn enable":
                enabled = None
        if enabled is None:
            return []
        templates: dict[str, tuple[str, ...]] = {}
        for header, _, children in self._indented_blocks("interface "):
            match = re.fullmatch(r"interface\s+virtual-template\s*(\d+)", header, re.IGNORECASE)
            if not match:
                continue
            methods: tuple[str, ...] = ()
            for _, _, child in children:
                tokens = child.lower().split()
                if tokens[:2] == ["ppp", "authentication"]:
                    methods = tuple(token for token in tokens[2:] if token in {"pap", "chap", "ms-chap", "ms-chap-v2", "eap"})
                elif tokens[:3] == ["no", "ppp", "authentication"]:
                    methods = ()
            templates[match.group(1)] = methods
        groups = []
        for header, line, children in self._indented_blocks("vpdn-group "):
            in_dialin, dialin_indent, pptp, template = False, 0, None, None
            evidence = [enabled, ConfigEvidence(header, self.config_filepath, line)]
            for number, indent, child in children:
                folded = child.lower()
                if folded == "accept-dialin":
                    in_dialin, dialin_indent = True, indent
                    evidence.append(ConfigEvidence(child, self.config_filepath, number))
                    continue
                if in_dialin and indent <= dialin_indent:
                    in_dialin = False
                if not in_dialin:
                    continue
                if folded in {"protocol pptp", "protocol any"}:
                    pptp = ConfigEvidence(child, self.config_filepath, number)
                elif folded.startswith("protocol "):
                    pptp = None
                elif re.fullmatch(r"virtual-template\s+\d+", folded):
                    template = folded.split()[1]
                    evidence.append(ConfigEvidence(child, self.config_filepath, number))
            if pptp is None:
                continue
            evidence.insert(3, pptp)
            groups.append(IOSPPTPDialin(
                group=header.split(None, 1)[1],
                virtual_template=template,
                authentication=templates.get(template, ()) if template else (),
                evidence=tuple(evidence),
            ))
        return groups

    _PPP_LINK_INTERFACE = re.compile(
        r"interface\s+((?:serial|dialer|async|bri|multilink)\S*)", re.IGNORECASE
    )

    def get_ppp_pap_interfaces(self) -> list[IOSPPPPapInterface]:
        """SC-013: PAP on active physical/dialer PPP links.

        Virtual-Template/Virtual-Access interfaces are excluded because their PPP
        session may run inside a protected tunnel. ``ppp pap sent-username`` lines are
        represented with the credential redacted.
        """
        records = []
        for header, line, children in self._indented_blocks("interface "):
            match = self._PPP_LINK_INTERFACE.fullmatch(header)
            if not match:
                continue
            shutdown, ppp, methods, sends = False, False, (), None
            auth_evidence = None
            for number, _, child in children:
                tokens = child.lower().split()
                if tokens == ["shutdown"]:
                    shutdown = True
                elif tokens == ["no", "shutdown"]:
                    shutdown = False
                elif tokens[:2] == ["encapsulation", "ppp"]:
                    ppp = True
                elif tokens[:1] == ["encapsulation"]:
                    ppp = False
                elif tokens[:2] == ["ppp", "authentication"]:
                    methods = tuple(t for t in tokens[2:] if t in {"pap", "chap", "ms-chap", "ms-chap-v2", "eap"})
                    auth_evidence = ConfigEvidence(child, self.config_filepath, number)
                elif tokens[:3] == ["no", "ppp", "authentication"]:
                    methods, auth_evidence = (), None
                elif tokens[:3] == ["ppp", "pap", "sent-username"]:
                    sends = ConfigEvidence("ppp pap sent-username <redacted>", self.config_filepath, number)
                elif tokens[:4] == ["no", "ppp", "pap", "sent-username"]:
                    sends = None
            if shutdown or not ppp or ("pap" not in methods and sends is None):
                continue
            evidence = [ConfigEvidence(header, self.config_filepath, line)]
            if "pap" in methods and auth_evidence is not None:
                evidence.append(auth_evidence)
            if sends is not None:
                evidence.append(sends)
            records.append(IOSPPPPapInterface(
                interface=match.group(1),
                methods=methods if "pap" in methods else (),
                sends_pap=sends is not None,
                evidence=tuple(evidence),
            ))
        return records

    _WEAK_LOGGING_TLS_VERSIONS = {"tlsv1.0", "tlsv1.1", "tlsv1"}

    def get_logging_tls_profiles(self) -> list[IOSLoggingTLSProfile]:
        """Bound syslog TLS profiles with TLS 1.0/1.1 or CBC-SHA1 cipher suites.

        Syntax: ``logging host <addr> ... transport tls profile <name>`` and a
        ``logging tls-profile <name>`` block with ``tls-version`` / ``ciphersuite``
        (Cisco IOS XE TLS syslog configuration example; weak values per the Cisco
        Resilient Infrastructure IOS XE Security Warnings Reference).
        """
        profiles: dict[str, tuple[ConfigEvidence, list[tuple[str, ConfigEvidence]]]] = {}
        for header, line, children in self._indented_blocks("logging tls-profile "):
            name = header.split()[2] if len(header.split()) > 2 else ""
            if name:
                profiles[name] = (
                    ConfigEvidence(header, self.config_filepath, line),
                    [(child.lower(), ConfigEvidence(child, self.config_filepath, number))
                     for number, _, child in children],
                )
        records = []
        for number, raw in enumerate(self.parser.ioscfg, start=1):
            if raw[:1].isspace():
                continue
            tokens = raw.split()
            folded = [token.lower() for token in tokens]
            if folded[:2] != ["logging", "host"] or "tls" not in folded or "profile" not in folded:
                continue
            index = folded.index("profile")
            if index + 1 >= len(tokens) or tokens[index + 1] not in profiles:
                continue
            name = tokens[index + 1]
            header_evidence, children = profiles[name]
            versions, ciphers, evidence = [], [], []
            for text, item in children:
                parts = text.split()
                if parts[:1] == ["tls-version"]:
                    weak = [part for part in parts[1:] if part in self._WEAK_LOGGING_TLS_VERSIONS]
                    if weak:
                        versions.extend(weak)
                        evidence.append(item)
                elif parts[:1] == ["ciphersuite"]:
                    weak = [part for part in parts[1:] if "cbc" in part and part.endswith("-sha")]
                    if weak:
                        ciphers.extend(weak)
                        evidence.append(item)
            if not versions and not ciphers:
                continue
            records.append(IOSLoggingTLSProfile(
                host=tokens[2] if len(tokens) > 2 else "",
                profile=name,
                weak_versions=tuple(versions),
                weak_ciphers=tuple(ciphers),
                evidence=(ConfigEvidence(raw.strip(), self.config_filepath, number), header_evidence, *evidence),
            ))
        return records

    def get_xe_insecure_feature_lines(self) -> dict[str, tuple[ConfigEvidence, ...]]:
        """Explicit commands Cisco's IOS XE security-warnings reference marks insecure.

        ``router odr`` and ``secure-webauth-disable`` are effective top-level
        toggles (last statement wins); ``key-hash ssh-rsa`` entries with a 32-hex
        (MD5) fingerprint under ``ip ssh pubkey-chain`` are listed individually.
        """
        found: dict[str, tuple[ConfigEvidence, ...]] = {}
        for command in ("router odr", "secure-webauth-disable"):
            state = None
            for number, raw in enumerate(self.parser.ioscfg, start=1):
                if raw[:1].isspace():
                    continue
                folded = " ".join(raw.split()).lower()
                if folded == command or folded.startswith(command + " "):
                    state = ConfigEvidence(raw.strip(), self.config_filepath, number)
                elif folded == "no " + command:
                    state = None
            if state is not None:
                found[command] = (state,)
        hashes = []
        for header, _, children in self._indented_blocks("ip ssh pubkey-chain"):
            for number, _, child in children:
                match = re.fullmatch(r"key-hash\s+ssh-rsa\s+([0-9a-fA-F]{32})(?:\s+\S+)?", child)
                if match:
                    hashes.append(ConfigEvidence(child, self.config_filepath, number))
        if hashes:
            found["key-hash md5"] = tuple(hashes)
        return found

    def get_aaa_servers_without_tls(self) -> dict[str, list[ConfigEvidence]]:
        """RADIUS/TACACS+/LDAP server definitions without TLS/DTLS (IOS XE security warnings).

        Named ``radius server``/``tacacs server`` blocks without a ``tls``/``dtls``
        sub-command, ``ldap server`` blocks without ``mode secure`` and legacy
        ``radius-server host``/``tacacs-server host`` lines. Only header lines are
        returned, so no keys are exposed.
        """
        found: dict[str, list[ConfigEvidence]] = {"RADIUS": [], "TACACS+": [], "LDAP": []}
        for prefix, protocol, marker in (("radius server ", "RADIUS", ("tls", "dtls")),
                                         ("tacacs server ", "TACACS+", ("tls",)),
                                         ("ldap server ", "LDAP", ("mode secure",))):
            for header, line, children in self._indented_blocks(prefix):
                if not any(child.lower() == m or child.lower().startswith(m + " ")
                           for _, _, child in children for m in marker):
                    found[protocol].append(ConfigEvidence(header, self.config_filepath, line))
        for number, raw in enumerate(self.parser.ioscfg, start=1):
            if raw[:1].isspace():
                continue
            tokens = raw.split()
            for command, protocol in (("radius-server", "RADIUS"), ("tacacs-server", "TACACS+")):
                if tokens[:2] == [command, "host"] and len(tokens) > 2:
                    found[protocol].append(ConfigEvidence(" ".join(tokens[:3]), self.config_filepath, number))
        return {protocol: items for protocol, items in found.items() if items}

    def get_ldap_servers(self) -> tuple[list[IOSLDAPServer], dict[str, tuple[str, ...]]]:
        """LDAP servers and ``aaa group server ldap`` memberships.

        Per the Cisco IOS "Configuring LDAP" guide, ``mode secure`` makes the router
        initiate TLS; ``transport port`` changes the port. Bind credentials are never
        copied into evidence.
        """
        servers = []
        for header, line, children in self._indented_blocks("ldap server "):
            parts = header.split()
            if len(parts) < 3:
                continue
            secure, port = False, None
            evidence = [ConfigEvidence(header, self.config_filepath, line)]
            for number, _, child in children:
                folded = child.lower().split()
                if folded[:2] == ["mode", "secure"]:
                    secure = True
                    evidence.append(ConfigEvidence(child, self.config_filepath, number))
                elif folded[:3] == ["no", "mode", "secure"]:
                    secure = False
                elif folded[:2] == ["transport", "port"] and len(folded) > 2:
                    port = folded[2]
                    evidence.append(ConfigEvidence(child, self.config_filepath, number))
                elif folded[:1] == ["ipv4"] or folded[:1] == ["ipv6"]:
                    evidence.append(ConfigEvidence(child, self.config_filepath, number))
            servers.append(IOSLDAPServer(parts[2], secure, port, tuple(evidence)))
        groups: dict[str, tuple[str, ...]] = {}
        for header, _, children in self._indented_blocks("aaa group server ldap "):
            parts = header.split()
            if len(parts) < 5:
                continue
            groups[parts[4]] = tuple(
                child.split()[1] for _, _, child in children
                if child.lower().startswith("server ") and len(child.split()) > 1
            )
        return servers, groups

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
            r"(?i)(\b(?:isis password|area-password|domain-password)\s+)(?:[07]\s+)?\S+",
            r"\1<redacted>", text.strip(),
        )
        redacted = re.sub(
            r"(?i)(\b(?:password|area-password|domain-password|authentication-key|authentication-key-chain|"
            r"message-digest-key\s+\S+\s+\S+|key-string)\s+)(\S+)",
            r"\1<redacted>",
            redacted,
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
        """Return effective RADIUS, TACACS+, IKE pre-shared-key and line secrets as value-free metadata."""

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
        for context, account, storage_type, value, number in self._key_directive_records():
            record(f"{context} {account}".casefold(), context, account, "key", storage_type, value, number)
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

    @staticmethod
    def _typed_key(tokens: list[str]) -> tuple[str, str]:
        """Split ``[type] value`` after a key keyword; no type means clear text (0)."""
        if not tokens:
            return "0", ""
        if tokens[0].isdigit() and len(tokens) > 1:
            return tokens[0], tokens[1]
        return "0", tokens[0]

    def _key_directive_records(self) -> list[tuple[str, str, str, str, int]]:
        """Effective TACACS+ and IKE pre-shared key directives.

        Returns (context, account, storage type, value, line number). Global
        ``tacacs-server key``/``tacacs-server host ... key`` and ``crypto isakmp key``
        follow last-value and ``no`` removal; ``tacacs server`` and ``crypto keyring``
        child keys disappear with their removed parent. Values never leave the parser.
        """
        global_keys: dict[str, tuple[str, str, str, str, int]] = {}
        block_keys: dict[str, dict[str, tuple[str, str, str, str, int]]] = {}
        parent: str | None = None
        for number, raw in enumerate(self._source_lines, start=1):
            line = raw.strip()
            if not line or line == "!":
                continue
            folded = line.casefold()
            words = line.split()
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
                    storage, value = self._typed_key(words[2:])
                    global_keys["tacacs-server key"] = ("tacacs_key", "tacacs-server", storage, value, number)
                elif re.fullmatch(r"(?:no|default) tacacs-server host \S+(?: .*)?", folded):
                    global_keys.pop(f"tacacs-server host {folded.split()[3]}", None)
                elif folded.startswith("tacacs-server host ") and " key " in f" {folded} ":
                    index = [word.casefold() for word in words].index("key", 3)
                    storage, value = self._typed_key(words[index + 1:])
                    account = f"tacacs-server host {words[2]}"
                    global_keys[account.casefold()] = ("tacacs_key", account, storage, value, number)
                else:
                    isakmp = re.fullmatch(r"(no )?crypto isakmp key (?:(\d) )?(\S+) (address|hostname) (\S+)(?: .*)?", line, re.IGNORECASE)
                    if isakmp:
                        identity = f"isakmp {isakmp.group(4).casefold()} {isakmp.group(5).casefold()}"
                        if isakmp.group(1):
                            global_keys.pop(identity, None)
                        else:
                            global_keys[identity] = ("isakmp_pre_shared_key", f"isakmp peer {isakmp.group(5)}",
                                                     isakmp.group(2) or "0", isakmp.group(3), number)
                continue
            if parent is None:
                continue
            if parent.startswith("tacacs server"):
                if re.fullmatch(r"(?:no|default) key(?: .*)?", folded):
                    block_keys[parent].pop("key", None)
                elif folded.startswith("key "):
                    storage, value = self._typed_key(words[1:])
                    block_keys[parent]["key"] = ("tacacs_key", parent, storage, value, number)
            else:
                psk = re.fullmatch(r"(no )?pre-shared-key (address|hostname) (\S+)(?: \S+)?(?: key .*)?", folded)
                if psk:
                    identity = f"{psk.group(2)} {psk.group(3)}"
                    if psk.group(1):
                        block_keys[parent].pop(identity, None)
                    elif " key " in f" {folded} ":
                        index = [word.casefold() for word in words].index("key", 2)
                        storage, value = self._typed_key(words[index + 1:])
                        block_keys[parent][identity] = ("keyring_pre_shared_key", f"{parent.removeprefix('crypto ')} peer {psk.group(3)}",
                                                        storage, value, number)
        return list(global_keys.values()) + [
            item for keys in block_keys.values() for item in keys.values()
        ]

    def _key_directive_evidence(self) -> list[tuple[str, ConfigEvidence]]:
        """Effective TACACS+ and IKE pre-shared key directive lines (appendix only)."""
        return [
            (context, ConfigEvidence(f"{context.replace('_', ' ')} <redacted>", self.config_filepath, number))
            for context, _, _, _, number in self._key_directive_records()
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

    def get_ntp_service_exposure(self) -> tuple[bool, tuple[ConfigEvidence, ...]]:
        """NTP is running (server, peer or master configured) without any ``ntp access-group``.

        Basic System Management Command Reference: without access groups there is no
        access control and full access (time requests and control queries) is granted.
        """
        running: list[ConfigEvidence] = []
        access_group = False
        for number, raw in enumerate(self._source_lines, start=1):
            if raw[:1].isspace():
                continue
            folded = re.sub(r"\s+", " ", raw.strip().casefold())
            if re.match(r"ntp (server|peer|master)\b", folded):
                running.append(ConfigEvidence(re.sub(r"(?i) key \S+", " key <redacted>", raw.strip()),
                                              self.config_filepath, number))
            elif re.match(r"ntp access-group (ipv[46] )?(peer|query-only|serve|serve-only)\b", folded):
                access_group = True
            elif re.match(r"no ntp access-group\b", folded):
                access_group = False
        return bool(running) and not access_group, tuple(running[:3])

    def get_fhrp_groups(self) -> list[dict]:
        """HSRP, VRRPv2 and GLBP groups on interfaces that are not shut down (SC-028).

        Each record: protocol, group, interface, auth (``md5``, ``text`` or ``none``) and
        evidence with key material redacted. VRRPv3 (``vrrp N address-family``) has no
        authentication and is not returned.
        """
        records = []
        expression = re.compile(r"(standby|vrrp|glbp)(?:\s+(\d+))?\s+(ip|authentication)\b\s*(.*)", re.IGNORECASE)
        for header, _, children in self._indented_blocks("interface "):
            shutdown = False
            groups: dict[tuple[str, str], dict] = {}
            for line_number, _, command in children:
                if command == "shutdown":
                    shutdown = True
                    continue
                if command == "no shutdown":
                    shutdown = False
                    continue
                match = expression.fullmatch(command)
                if not match:
                    continue
                protocol = match.group(1).casefold()
                group = match.group(2) or "0"
                data = groups.setdefault((protocol, group), {
                    "protocol": protocol, "group": group, "interface": header.split(maxsplit=1)[1],
                    "has_address": False, "auth": "none",
                    "evidence": [], "auth_evidence": None,
                })
                if match.group(3).casefold() == "ip":
                    data["has_address"] = True
                    data["evidence"].append(ConfigEvidence(command, self.config_filepath, line_number))
                else:
                    rest = match.group(4).split()
                    data["auth"] = "md5" if rest[:1] and rest[0].casefold() == "md5" else "text"
                    shown = " ".join(rest[:1]) if data["auth"] == "md5" else "text"
                    data["auth_evidence"] = ConfigEvidence(
                        f"{protocol} {group} authentication {shown} <redacted>", self.config_filepath, line_number)
            if shutdown:
                continue
            for data in groups.values():
                if data["has_address"]:
                    records.append(data)
        return records

    def get_snmp_notification_hosts(self) -> list[tuple[str, str, ConfigEvidence]]:
        """Effective ``snmp-server host`` targets as (address, version, evidence).

        The version is 1 when no ``version`` keyword is given (IOS default); the
        community or user name is redacted.
        """
        hosts: dict[str, tuple[str, str, ConfigEvidence]] = {}
        for line_number, raw in enumerate(self._source_lines, start=1):
            if raw[:1].isspace():
                continue
            words = raw.split()
            lowered = [word.casefold() for word in words]
            removal = lowered[:1] in (["no"], ["default"])
            body = words[1:] if removal else words
            low = lowered[1:] if removal else lowered
            if low[:2] != ["snmp-server", "host"] or len(body) < 3:
                continue
            address = body[2]
            key = address.casefold()
            if removal:
                hosts.pop(key, None)
                continue
            version = "1"
            if "version" in low[3:]:
                index = low.index("version", 3)
                version = low[index + 1] if index + 1 < len(low) else "unknown"
            hosts[key] = (address, version, ConfigEvidence(
                f"snmp-server host {address} version {version} <community or user redacted>",
                self.config_filepath, line_number))
        return list(hosts.values())

    _WEAK_TLS_CIPHER = re.compile(r"(?:^|-)(?:rc4|des|3des|md5|null|export)(?:-|$)|-sha$")

    def get_http_tls_settings(self) -> dict[str, object]:
        """Explicit ``ip http tls-version`` and ``ip http secure-ciphersuite`` for the HTTPS server."""
        version = self._last_global_match(r"ip http tls-version\s+(\S+)")
        suites = self._last_global_match(r"ip http secure-ciphersuite\s+(.+)")
        result: dict[str, object] = {"https": self.get_https_server_state() == ConfigurationState.ENABLED}
        if version:
            result["tls_version"] = version.group(1)
            result["tls_evidence"] = ConfigEvidence(version.group(0), self.config_filepath, None)
        if suites:
            names = suites.group(1).split()
            result["weak_suites"] = [name for name in names if self._WEAK_TLS_CIPHER.search(name.casefold())]
            result["suite_evidence"] = ConfigEvidence(suites.group(0), self.config_filepath, None)
        return result

    _URL_CREDENTIAL = re.compile(r"(?i)\b((?:ftp|http|https|scp|sftp|rcp)://)([^:/@\s]+):([^@\s]+)@")

    def get_embedded_credentials(self) -> list[tuple[str, ConfigEvidence]]:
        """Clear-text client credentials outside the credential stores (SC-036).

        ``ip ftp password``, ``ip http client password`` and ``user:password@`` in any
        file-transfer URL. Evidence has the secret replaced.
        """
        found: dict[str, tuple[str, ConfigEvidence]] = {}
        for line_number, raw in enumerate(self._source_lines, start=1):
            line = raw.strip()
            folded = re.sub(r"\s+", " ", line.casefold())
            for command, kind in (("ip ftp password", "ftp_client"), ("ip http client password", "http_client")):
                if folded.startswith(command + " ") and not raw[:1].isspace():
                    found[command] = (kind, ConfigEvidence(f"{command} <redacted>", self.config_filepath, line_number))
                elif folded in {f"no {command}", f"default {command}"} or folded.startswith(f"no {command} "):
                    found.pop(command, None)
            if self._URL_CREDENTIAL.search(line):
                redacted = self._URL_CREDENTIAL.sub(lambda m: f"{m.group(1)}{m.group(2)}:<redacted>@", line)
                found[f"url {line_number}"] = ("url", ConfigEvidence(redacted, self.config_filepath, line_number))
        return list(found.values())

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

    _CLUSTERING_HTTP_MODEL = re.compile(
        r"(?i)^(?:switch \d+ provision ws-c(?P<stack>2950|3550|3560|3750|37\d\d)\S*"
        r"|boot system \S*?c(?P<image>2950|3550|3560|3750)-\S+)"
    )

    def get_http_platform_default(self) -> Optional[ConfigEvidence]:
        """Evidence that an absent ``ip http server`` means enabled on this platform (SC-044 IOS-14).

        HTTP Services command reference: 'The HTTP server is enabled for clustering on the
        following Cisco switches: Catalyst 3700 series, Catalyst 3750 series, Catalyst 3550
        series, Catalyst 3560 series, and Catalyst 2950 series.' The model must be named by a
        stack ``switch N provision`` or a ``boot system`` image line of a classic IOS train.
        """
        train = self.get_train()
        if not train or train[0] >= 16 or self.device_type == "IOS_XE":
            return None
        for number, raw in enumerate(self._source_lines, start=1):
            if raw[:1].isspace():
                continue
            match = self._CLUSTERING_HTTP_MODEL.match(raw.strip())
            if match:
                model = match.group("stack") or match.group("image")
                return ConfigEvidence(f"Catalyst {model} platform: {raw.strip()}", self.config_filepath, number)
        return None

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
        expression = re.compile(r"(?:(?P<disabled>no|default)\s+)?ip http access-class(?:\s+ipv4)?(?:\s+(?P<value>\S+))?")
        for line in self._global_lines():
            match = expression.fullmatch(line)
            if match:
                value = None if match.group("disabled") else match.group("value")
        return value

    def get_http_ipv6_access_class(self) -> Optional[str]:
        """Return the explicit IOS-XE IPv6 WebUI ACL binding, independently of IPv4."""
        value: Optional[str] = None
        for line in self._global_lines():
            match = re.fullmatch(r"ip http access-class ipv6 (\S+)", line)
            if match:
                value = match.group(1)
            elif re.fullmatch(r"(?:no|default) ip http access-class(?: ipv6(?: \S+)?)?", line):
                if "ipv6" in line or line.endswith("access-class"):
                    value = None
        return value

    def has_qualified_ipv6_web_listener(self) -> bool:
        """Bound IOS-XE 17.x IPv6 WebUI applicability to explicit interface state.

        Cisco documents a dual-stack HTTP(S) listener when the server is on and
        the device has an IPv6 address. An explicitly enabled interface with a
        configured non-link-local IPv6 address is positive configuration
        evidence; operational reachability remains outside this export.
        """
        if self.device_type != "IOS_XE" or not re.fullmatch(r"17\.\d+(?:\.\S+)?", self.get_version()):
            return False
        if not any(state == ConfigurationState.ENABLED for state in (
            self.get_http_server_state(), self.get_https_server_state(),
        )):
            return False
        for interface in self._normalized_interfaces():
            if interface.state != NormalizedConfigurationState.ENABLED:
                continue
            for value in interface.addresses:
                try:
                    address = ipaddress.IPv6Interface(value).ip
                except ValueError:
                    continue
                if not (address.is_link_local or address.is_unspecified or address.is_multicast):
                    return True
        return False

    def get_programmability_apis(self) -> tuple[IOSProgrammabilityAPI, ...]:
        """Explicit IOS-XE NETCONF/RESTCONF listeners and service ACL bindings."""
        if self.device_type != "IOS_XE":
            return ()
        enabled = {"netconf": False, "restconf": False}
        bindings: dict[str, dict[str, str | None]] = {
            service: {"ipv4": None, "ipv6": None} for service in enabled
        }
        binding_evidence: dict[str, dict[str, ConfigEvidence | None]] = {
            service: {"ipv4": None, "ipv6": None} for service in enabled
        }
        enable_evidence: dict[str, ConfigEvidence | None] = {
            service: None for service in enabled
        }
        port: int | None = None
        port_evidence: ConfigEvidence | None = None
        external_disabled = False
        external_evidence: ConfigEvidence | None = None
        for number, raw in enumerate(self._source_lines, 1):
            if raw[:1].isspace():
                continue
            line = raw.strip()
            lowered = line.casefold()
            if lowered in {"netconf-yang", "no netconf-yang", "default netconf-yang"}:
                enabled["netconf"] = lowered == "netconf-yang"
                enable_evidence["netconf"] = (
                    ConfigEvidence(line, self.config_filepath, number) if enabled["netconf"] else None
                )
                continue
            if lowered in {"restconf", "no restconf", "default restconf"}:
                enabled["restconf"] = lowered == "restconf"
                enable_evidence["restconf"] = (
                    ConfigEvidence(line, self.config_filepath, number) if enabled["restconf"] else None
                )
                continue
            if lowered in {"netconf-yang ssh port disable", "netconf-yang ssh port-disable"}:
                external_disabled = True
                external_evidence = ConfigEvidence(line, self.config_filepath, number)
                continue
            if lowered in {"no netconf-yang ssh port disable", "no netconf-yang ssh port-disable"}:
                external_disabled = False
                external_evidence = ConfigEvidence(line, self.config_filepath, number)
                continue
            port_match = re.fullmatch(r"netconf-yang ssh port (\d+)", lowered)
            if port_match:
                raw_port = port_match.group(1)
                port = int(raw_port) if len(raw_port) <= 5 and 1 <= int(raw_port) <= 65535 else None
                port_evidence = ConfigEvidence(line, self.config_filepath, number)
                continue
            if re.fullmatch(r"(?:no|default) netconf-yang ssh port(?: \d+)?", lowered):
                port = None
                port_evidence = None
                continue
            match = re.fullmatch(
                r"(?:(no|default) )?(netconf-yang ssh|restconf) (ipv4|ipv6) access-list(?: name)?(?: (\S+))?",
                line, re.IGNORECASE,
            )
            if match:
                service = "netconf" if match.group(2).casefold().startswith("netconf") else "restconf"
                family = match.group(3).casefold()
                bindings[service][family] = None if match.group(1) else match.group(4)
                binding_evidence[service][family] = (
                    None if match.group(1) else ConfigEvidence(line, self.config_filepath, number)
                )
        def active_evidence(service: str) -> tuple[ConfigEvidence, ...]:
            parts = [enable_evidence[service], *binding_evidence[service].values()]
            if service == "netconf":
                parts.extend((port_evidence, external_evidence))
            return tuple(item for item in parts if item is not None)
        records = []
        if enabled["netconf"] and not external_disabled:
            records.append(IOSProgrammabilityAPI(
                "NETCONF", "SSH", bindings["netconf"]["ipv4"],
                bindings["netconf"]["ipv6"], port, active_evidence("netconf"),
            ))
        if enabled["restconf"] and self.get_https_server_state() == ConfigurationState.ENABLED:
            records.append(IOSProgrammabilityAPI(
                "RESTCONF", "HTTPS", bindings["restconf"]["ipv4"],
                bindings["restconf"]["ipv6"], None, active_evidence("restconf"),
            ))
        return tuple(records)

    def get_management_ipv6_acl(self, name: str) -> IOSManagementACL:
        """Prove only first-match, universal IPv6 source permits in a named ACL.

        Unsupported protocol, address, port or time predicates stop the proof.
        IPv4 ACL contents never satisfy this address-family assessment.
        """
        entries: list[tuple[str, str, ConfigEvidence]] = []
        defined = False
        current = False
        key = name.casefold()
        for number, raw in enumerate(self._source_lines, 1):
            line = raw.strip()
            if not line or line.startswith("!"):
                continue
            if not raw[:1].isspace():
                current = False
                removed = re.fullmatch(r"(?:no|default) ipv6 access-list (\S+)", line)
                if removed and removed.group(1).casefold() == key:
                    entries, defined = [], False
                    continue
                header = re.fullmatch(r"ipv6 access-list (\S+)", line)
                if header and header.group(1).casefold() == key:
                    current, defined = True, True
                continue
            if not current or line.startswith(("remark ", "!")):
                continue
            removal = re.fullmatch(r"no (\d+)", line)
            if removal:
                entries = [item for item in entries if item[0] != removal.group(1)]
                continue
            if line.startswith("no "):
                entries = [item for item in entries if item[1] != line[3:]]
                continue
            leading = re.fullmatch(r"(\d+) (.+)", line)
            trailing = re.fullmatch(r"(.+) sequence (\d+)", line)
            if leading and trailing:
                return IOSManagementACL(name, "unsupported", tuple(item[2] for item in entries))
            sequence = leading.group(1) if leading else trailing.group(2) if trailing else ""
            body = leading.group(2) if leading else trailing.group(1) if trailing else line
            if body.startswith("remark "):
                continue
            if sequence:
                entries = [item for item in entries if item[0] != sequence]
            entries.append((sequence, body, ConfigEvidence(line, self.config_filepath, number)))
        evidence = tuple(item[2] for item in entries)
        if not defined:
            return IOSManagementACL(name, "unresolved", evidence)
        if not entries:
            return IOSManagementACL(name, "unsupported", evidence)
        if all(item[0] for item in entries):
            if any(len(item[0]) > 10 or not item[0].isascii() for item in entries):
                return IOSManagementACL(name, "unsupported", evidence)
            entries.sort(key=lambda item: int(item[0]))
        elif any(item[0] for item in entries):
            return IOSManagementACL(name, "unsupported", evidence)
        if len(entries) > 512:
            return IOSManagementACL(name, "unsupported", evidence)
        source_rules: list[tuple[str, NetworkSemantics]] = []
        for _, body, _ in entries:
            match = re.fullmatch(r"(permit|deny) (.+?)(?: log(?:-input)?)?", body)
            if not match:
                return IOSManagementACL(name, "unsupported", evidence)
            action, selector = match.groups()
            tokens = selector.split()
            if tokens[:1] in (["ipv6"], ["tcp"]):
                tokens = tokens[1:]
            source, index = self._acl_address(tokens, 0)
            destination, index = self._acl_address(tokens, index)
            if index != len(tokens) or not source or not destination:
                return IOSManagementACL(name, "unsupported", evidence)
            if source in {"any4", "any6"} or destination in {"any4", "any6"}:
                return IOSManagementACL(name, "unsupported", evidence)
            destination_network = self._acl_network_semantics(destination, "ipv6")
            if not destination_network.complete or not (
                destination_network.any or any(
                    item.first == 0 and item.last == (1 << 128) - 1
                    for item in destination_network.intervals
                )
            ):
                return IOSManagementACL(name, "unsupported", evidence)
            source_network = self._acl_network_semantics(source, "ipv6")
            if not source_network.complete:
                return IOSManagementACL(name, "unsupported", evidence)
            source_rules.append((action, source_network))
            if action == "permit" and self._management_acl_source_union(source_rules, 6) == "permit-all":
                return IOSManagementACL(name, "permit-all", evidence)
        return IOSManagementACL(name, self._management_acl_source_union(source_rules, 6), evidence)

    @staticmethod
    def _management_acl_source_union(
        rules: list[tuple[str, NetworkSemantics]], family: int,
    ) -> str:
        """Prove every source reaches a permit before any effective deny.

        IPv4 standard and the bounded management extended grammar already
        qualify destination/protocol predicates before calling this helper.
        Unsupported ranges or excessive splitting remain unassessed.
        """
        maximum = (1 << (32 if family == 4 else 128)) - 1
        unmatched = [(0, maximum)]
        for action, network in rules:
            if not network.complete or not (network.any or network.intervals):
                return "unsupported"
            ranges = ((0, maximum),) if network.any else tuple(
                (item.first, item.last) for item in network.intervals if item.family == family
            )
            if not ranges:
                return "unsupported"
            for first, last in ranges:
                next_unmatched = []
                for start, end in unmatched:
                    low, high = max(start, first), min(end, last)
                    if low > high:
                        next_unmatched.append((start, end))
                        continue
                    if action == "deny":
                        return "restrictive"
                    if start < low:
                        next_unmatched.append((start, low - 1))
                    if high < end:
                        next_unmatched.append((high + 1, end))
                unmatched = next_unmatched
                if len(unmatched) > 512:
                    return "unsupported"
                if not unmatched:
                    return "permit-all"
        return "restrictive"

    def get_management_ipv4_acl(self, name: str, *, allow_extended: bool = False) -> IOSManagementACL:
        """Bounded source restriction proof, in effective order.

        VTY callers may opt into extended IP/TCP rules with universal destinations
        and no port predicates. HTTP callers retain standard-only semantics.
        Unsupported entries block proof; IPv6 semantics are not inferred.
        """
        entries: list[tuple[str, str, ConfigEvidence]] = []
        defined = False
        supported = True
        kind: str | None = None
        current = False
        key = name.casefold()
        for number, raw in enumerate(self._source_lines, 1):
            line = raw.strip()
            if not line or line.startswith("!"):
                continue
            evidence = ConfigEvidence(line, self.config_filepath, number)
            if not raw[:1].isspace():
                current = False
                removed = re.fullmatch(r"(?:no|default) (?:ip access-list (?:standard|extended) |access-list )(\S+)", line)
                if removed and removed.group(1).casefold() == key:
                    entries, defined, supported, kind = [], False, True, None
                    continue
                remove_entry = re.fullmatch(r"no access-list (\S+) (.+)", line)
                if remove_entry and remove_entry.group(1).casefold() == key:
                    entries = [item for item in entries if item[1] != remove_entry.group(2)]
                    continue
                header = re.fullmatch(r"ip access-list (standard|extended) (\S+)", line)
                if header and header.group(2).casefold() == key:
                    current, defined = True, True
                    selected_kind = header.group(1)
                    supported = supported and kind in {None, selected_kind}
                    kind = selected_kind
                    continue
                numbered = re.fullmatch(r"access-list (\S+) (.+)", line)
                if not numbered or numbered.group(1).casefold() != key:
                    continue
                defined = True
                # Bound conversion of untrusted identifiers before calling int.
                numeric = int(name) if name.isascii() and name.isdigit() and len(name) <= 4 else 0
                selected_kind = (
                    "standard" if 1 <= numeric <= 99 or 1300 <= numeric <= 1999
                    else "extended" if 100 <= numeric <= 199 or 2000 <= numeric <= 2699
                    else None
                )
                supported = supported and selected_kind is not None and kind in {None, selected_kind}
                kind = selected_kind
                command = numbered.group(2)
            elif current:
                command = line
            else:
                continue
            if command.startswith(("remark ", "!")):
                continue
            remove = re.fullmatch(r"no (\d+)", command)
            if remove:
                entries = [item for item in entries if item[0] != remove.group(1)]
                continue
            if command.startswith("no "):
                target = command[3:]
                entries = [item for item in entries if item[1] != target]
                continue
            match = re.fullmatch(r"(?:(\d+)\s+)?(.+)", command)
            sequence, body = match.groups()
            if body.startswith("remark "):
                continue
            if sequence:
                entries = [item for item in entries if item[0] != sequence]
            entries.append((sequence or "", body, evidence))
        evidence = tuple(item[2] for item in entries)
        if not defined:
            return IOSManagementACL(name, "unresolved", evidence)
        if not supported or not entries or (kind == "extended" and not allow_extended):
            return IOSManagementACL(name, "unsupported", evidence)
        if all(item[0] for item in entries):
            if any(len(item[0]) > 10 or not item[0].isascii() for item in entries):
                return IOSManagementACL(name, "unsupported", evidence)
            entries.sort(key=lambda item: int(item[0]))
        elif any(item[0] for item in entries):
            return IOSManagementACL(name, "unsupported", evidence)
        if len(entries) > 512:
            return IOSManagementACL(name, "unsupported", evidence)
        source_rules: list[tuple[str, NetworkSemantics]] = []
        for _, body, _ in entries:
            match = re.fullmatch(r"(permit|deny) (.+?)(?: log(?:-input)?)?", body)
            if not match:
                return IOSManagementACL(name, "unsupported", evidence)
            action, selector = match.groups()
            if kind == "extended":
                tokens = selector.split()
                if not tokens or tokens[0] not in {"ip", "tcp"}:
                    return IOSManagementACL(name, "unsupported", evidence)
                selector, index = self._acl_address(tokens, 1)
                destination, index = self._acl_address(tokens, index)
                if len(selector.split()) == 1 and selector != "any":
                    return IOSManagementACL(name, "unsupported", evidence)
                # Destination-specific VTY behavior varies by release (CSCuw89081).
                # Port, state, time and other predicates need separate qualification.
                destination_network = self._acl_network_semantics(destination, "ipv4")
                if (index != len(tokens) or destination in {"any4", "any6"}
                        or not destination_network.complete
                        or not (destination_network.any or any(
                            item.first == 0 and item.last == (1 << 32) - 1
                            for item in destination_network.intervals))):
                    return IOSManagementACL(name, "unsupported", evidence)
            if selector in {"any4", "any6"}:
                return IOSManagementACL(name, "unsupported", evidence)
            network = self._acl_network_semantics(selector, "ipv4")
            if not network.complete:
                return IOSManagementACL(name, "unsupported", evidence)
            source_rules.append((action, network))
            if action == "permit" and self._management_acl_source_union(source_rules, 4) == "permit-all":
                return IOSManagementACL(name, "permit-all", evidence)
        return IOSManagementACL(name, self._management_acl_source_union(source_rules, 4), evidence)

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

    @property
    def diagnostics(self) -> list[str]:
        """Report bounded management ACL gaps without claiming exposure or safety.

        Compute from effective bindings on every read, independently of plugin
        execution order. Never copy ACL identifiers, raw entries or credentials
        into this report-facing channel.
        """
        diagnostics: list[str] = []

        def describe(service: str, scope: str, acl: IOSManagementACL, family: str = "IPv4") -> None:
            if acl.state not in {"unresolved", "unsupported"}:
                return
            reason = (
                f"the attached {family} ACL definition was not resolved from this export"
                if acl.state == "unresolved"
                else f"the attached {family} ACL is empty or outside the supported evaluation grammar"
            )
            diagnostics.append(
                f"Management ACL assessment incomplete: {service} ({scope}): {reason}. "
                "Source restriction is unassessed, not proven secure or unrestricted; manual review is required."
            )

        if self.get_ssh_state() == ConfigurationState.ENABLED:
            for profile in self.get_management_acl_vty_profiles():
                if (profile.permits_ssh and profile.ipv4_access_class and
                        self.assessment_context.permits_rule("cisco.ios.ssh.unrestricted_sources")):
                    describe("SSH", profile.line, self.get_management_ipv4_acl(
                        profile.ipv4_access_class, allow_extended=True,
                    ))
                if (profile.permits_ssh and profile.ipv6_access_class and
                        self.assessment_context.permits_rule("cisco.ios.ssh.ipv6_unrestricted_sources")):
                    describe("SSH", profile.line, self.get_management_ipv6_acl(
                        profile.ipv6_access_class,
                    ), "IPv6")
        name = self.get_http_access_class()
        if name and self.assessment_context.permits_rule("cisco.ios.http.unrestricted_sources"):
            acl = self.get_management_ipv4_acl(name)
            for service, state in (
                ("HTTP", self.get_http_server_state()),
                ("HTTPS", self.get_https_server_state()),
            ):
                if state == ConfigurationState.ENABLED:
                    describe(service, "global listener", acl)
        if (self.device_type == "IOS_XE" and
                self.assessment_context.permits_rule("cisco.ios.http.ipv6_unrestricted_sources")):
            name6 = self.get_http_ipv6_access_class()
            if name6:
                acl6 = self.get_management_ipv6_acl(name6)
                for service, state in (
                    ("HTTP", self.get_http_server_state()),
                    ("HTTPS", self.get_https_server_state()),
                ):
                    if state == ConfigurationState.ENABLED:
                        describe(service, "global listener", acl6, "IPv6")
            elif self.has_qualified_ipv6_web_listener():
                for service, state in (
                    ("HTTP", self.get_http_server_state()),
                    ("HTTPS", self.get_https_server_state()),
                ):
                    if state == ConfigurationState.ENABLED:
                        diagnostics.append(
                            f"Management ACL assessment incomplete: {service} (global IPv6 listener): "
                            "an IOS-XE 17.x export has an explicitly enabled interface with a "
                            "configured IPv6 address but no IPv6 WebUI access-class binding. "
                            "An IPv4 ACL does not establish IPv6 source restriction; external "
                            "reachability and upstream controls require manual review."
                        )
        for api in self.get_programmability_apis():
            service = api.service.casefold()
            for family, name in (("ipv4", api.ipv4_acl), ("ipv6", api.ipv6_acl)):
                rule_id = (f"cisco.ios.management.{service}_unrestricted_sources"
                           if family == "ipv4" else
                           f"cisco.ios.management.{service}_ipv6_unrestricted_sources")
                if not name or not self.assessment_context.permits_rule(rule_id):
                    continue
                acl = (self.get_management_ipv4_acl(name, allow_extended=True)
                       if family == "ipv4" else self.get_management_ipv6_acl(name))
                describe(api.service, "service-level listener", acl, family.upper())
        return diagnostics

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

    def get_management_acl_vty_profiles(self) -> tuple[VTYProfile, ...]:
        """Overlay transport and ACL mutations across overlapping VTY ranges."""
        states = {}
        for profile in self.get_management_lines("vty"):
            match = re.fullmatch(r"line vty (\d+)(?: (\d+))?", profile.line)
            if not match:
                continue
            first, last = int(match[1]), int(match[2] or match[1])
            if last < first or last - first > 4096:
                continue
            for number in range(first, last + 1):
                state = states.setdefault(number, {"transports": (), "acl": "", "acl6": "", "exec": True})
                for evidence in profile.evidence[1:]:
                    command = evidence.text.strip()
                    if command.startswith("transport input "):
                        state["transports"] = tuple(command.split()[2:])
                    elif re.fullmatch(r"(?:no|default) transport input(?: .*)?", command):
                        state["transports"] = ()
                    elif command in {"no exec", "exec", "default exec"}:
                        state["exec"] = command != "no exec"
                    else:
                        acl = re.fullmatch(r"access-class (\S+) in(?: vrf-also)?", command)
                        if acl:
                            state["acl"] = acl[1]
                        elif re.fullmatch(r"(?:no|default) access-class(?: \S+)? in(?: vrf-also)?", command):
                            state["acl"] = ""
                        acl6 = re.fullmatch(r"ipv6 access-class (\S+) in", command)
                        if acl6:
                            state["acl6"] = acl6[1]
                        elif re.fullmatch(r"(?:no|default) ipv6 access-class(?: \S+)? in", command):
                            state["acl6"] = ""
        grouped = {}
        for number, state in sorted(states.items()):
            if state["exec"]:
                grouped.setdefault((state["transports"], state["acl"], state["acl6"]), []).append(number)
        return tuple(VTYProfile(
            line="VTY lines " + ", ".join(map(str, numbers)),
            transports=transports, ipv4_access_class=acl, ipv6_access_class=acl6,
        ) for (transports, acl, acl6), numbers in grouped.items())

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

    def get_isis_authentication(self) -> list[IOSISISAuthentication]:
        """Resolve explicit IOS IS-IS hello/database authentication on active IPv4 bindings.

        An explicit process ``is-type`` is required: multi-area defaults differ,
        and an unqualified level must not be turned into an absence finding.
        """
        levels = ("level-1", "level-2")

        def new_settings() -> dict[str, dict[str, object]]:
            return {level: {"mode": "", "chain": "", "legacy": False, "send_only": False}
                    for level in levels}

        def selected(suffix: str) -> tuple[str, ...]:
            return (suffix,) if suffix in levels else levels

        def apply_auth(settings: dict[str, dict[str, object]], text: str, *, interface: bool) -> bool:
            body = text
            if interface:
                body = body.replace("no isis ", "no ", 1) if body.startswith("no isis ") else body.removeprefix("isis ")
            chain_removal = re.fullmatch(r"no authentication key-chain(?: (level-[12]))?", body)
            if chain_removal:
                for level in selected(chain_removal.group(1) or ""):
                    settings[level]["chain"] = ""
                return True
            for field, pattern in (
                ("mode", r"(no )?authentication mode(?: (md5|text))?(?: (level-[12]))?"),
                ("chain", r"(no )?authentication key-chain(?: (\S+))?(?: (level-[12]))?"),
                ("send_only", r"(no )?authentication send-only(?: (level-[12]))?"),
            ):
                match = re.fullmatch(pattern, body)
                if not match:
                    continue
                if field == "send_only":
                    for level in selected(match.group(2) or ""):
                        settings[level][field] = not bool(match.group(1))
                else:
                    for level in selected(match.group(3) or ""):
                        settings[level][field] = "" if match.group(1) else (match.group(2) or "")
                return True
            if interface:
                legacy = re.fullmatch(r"(no )?isis password(?: .+?)?(?: (level-[12]))?", text)
                if legacy:
                    for level in selected(legacy.group(2) or ""):
                        settings[level]["legacy"] = not bool(legacy.group(1))
                    return True
            else:
                legacy = re.match(r"(no )?(area-password|domain-password)(?:\s|$)", text)
                if legacy:
                    level = "level-1" if legacy.group(2) == "area-password" else "level-2"
                    settings[level]["legacy"] = not bool(legacy.group(1))
                    return True
            return False

        def auth_state(data: dict[str, object], chains: dict) -> str:
            mode, chain = data["mode"], data["chain"]
            if data["send_only"] and (mode or chain or data["legacy"]):
                return "send-only"
            if mode == "text" or (data["legacy"] and not mode):
                return "text-mode"
            if mode == "md5" and not data["legacy"]:
                keys = chains.get(str(chain).casefold()) if chain else None
                return "configured-md5" if keys and any(keys[0].values()) else "unresolved"
            return "unknown"

        processes: dict[str, dict[str, object]] = {}
        events = [(number, header, children) for header, number, children
                  in self._indented_blocks("router isis")
                  if re.fullmatch(r"router isis(?: \S+)?", header, re.IGNORECASE)]
        events.extend((number, line.strip(), None)
                      for number, line in enumerate(self.parser.ioscfg, 1)
                      if not line[:1].isspace()
                      and re.fullmatch(r"no router isis(?: \S+)?", line.strip(), re.IGNORECASE))
        for number, header, children in sorted(events, key=lambda item: item[0]):
            words = header.casefold().split()
            tag = words[-1] if len(words) in {3, 4} and words[-1] != "isis" else ""
            if children is None:
                processes.pop(tag, None)
                continue
            data: dict[str, object] = {"net": False, "is_type": "", "passive_default": False,
                                       "passive": {}, "auth": new_settings(),
                                       "evidence": [self._routing_evidence(header, number)]}
            for line_number, _, command in children:
                text = command.casefold()
                if text.startswith("net "):
                    data["net"] = True
                elif text.startswith("no net"):
                    data["net"] = False
                elif re.fullmatch(r"is-type level-(?:1|1-2|2-only)", text):
                    data["is_type"] = text.split()[-1]
                elif text.startswith("no is-type"):
                    data["is_type"] = ""
                elif text == "passive-interface default":
                    data["passive_default"] = True
                    data["passive"].clear()
                elif text == "no passive-interface default":
                    data["passive_default"] = False
                    data["passive"].clear()
                elif text.startswith("passive-interface "):
                    data["passive"][text.split(maxsplit=1)[1]] = True
                elif text.startswith("no passive-interface "):
                    data["passive"][text.split(maxsplit=2)[2]] = False
                apply_auth(data["auth"], text, interface=False)
                data["evidence"].append(self._routing_evidence(command, line_number))
            processes[tag] = data

        chains = self._routing_key_chains()
        records: list[IOSISISAuthentication] = []
        database_seen: set[tuple[str, str]] = set()
        for header, header_line, children in self._indented_blocks("interface "):
            name = header.split(maxsplit=1)[1]
            bound = ""
            is_bound = False
            shutdown = False
            circuit = ""
            auth = new_settings()
            evidence = [self._routing_evidence(header, header_line)]
            for line_number, _, command in children:
                text = command.casefold()
                match = re.fullmatch(r"ip router isis(?: (\S+))?", text)
                if match:
                    bound, is_bound = match.group(1) or "", True
                elif re.fullmatch(r"no ip router isis(?: \S+)?", text):
                    bound, is_bound = "", False
                elif text == "shutdown":
                    shutdown = True
                elif text == "no shutdown":
                    shutdown = False
                elif re.fullmatch(r"isis circuit-type level-(?:1|1-2|2-only)", text):
                    circuit = text.split()[-1]
                elif text == "no isis circuit-type":
                    circuit = ""
                apply_auth(auth, text, interface=True)
                evidence.append(self._routing_evidence(command, line_number))
            process = processes.get(bound) if is_bound and not shutdown else None
            if not process or not process["net"] or not process["is_type"]:
                continue
            if process["passive"].get(name.casefold(), process["passive_default"]):
                continue
            process_levels = selected(process["is_type"] if process["is_type"] != "level-2-only" else "level-2")
            circuit_levels = selected(circuit if circuit != "level-2-only" else "level-2")
            for level in levels:
                if level not in process_levels or level not in circuit_levels:
                    continue
                hello = auth[level]
                records.append(IOSISISAuthentication(
                    bound, name, level, "hello", auth_state(hello, chains),
                    str(hello["chain"]), tuple(dict.fromkeys(evidence + process["evidence"])),
                ))
                if (bound, level) not in database_seen:
                    database_seen.add((bound, level))
                    database = process["auth"][level]
                    records.append(IOSISISAuthentication(
                        bound, name, level, "database", auth_state(database, chains),
                        str(database["chain"]), tuple(dict.fromkeys(process["evidence"] + evidence)),
                    ))
        return records

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
        """Resolve explicit IPv4 RIP versions on bound default/VRF interfaces."""
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
        scopes = {name: scope for name, scope in scopes.items() if scope[1]}
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
            receive_declared = False
            send_version = "unknown"
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
                    receive_declared = True
                elif text == "no ip rip receive version":
                    receive_version = "unknown"
                    receive_declared = False
                elif re.fullmatch(r"ip rip send version [12](?: [12])?", text):
                    send_version = "1-included" if "1" in text.split()[4:] else "2"
                elif text == "no ip rip send version":
                    send_version = "unknown"
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
            process_version, networks, passive_default, passive_overrides, process_evidence = scopes[scope_name]
            if process_version == "unknown" and (vrf != "default" or not (
                receive_version == "1-accepted" or send_version == "1-included"
            )):
                continue
            matched = [network for network in networks.values() if any(address in network for address in addresses)]
            if not matched:
                continue
            chain = chains.get(key_reference.casefold()) if key_reference else None
            if receive_version == "unknown" and process_version in {"1", "2"}:
                receive_version = "1-accepted" if process_version == "1" else "2"
            if send_version == "unknown" and process_version in {"1", "2"}:
                send_version = "1-included" if process_version == "1" else "2"
            if receive_version == "1-accepted":
                state = "version1-accepted"
            elif process_version != "2":
                # An explicit RIPv1 send command is assessable without assuming
                # how a release handles omitted/default receive authentication.
                state = "unknown"
            elif binding_invalid or mode == "unknown":
                state = "unknown"
            elif not key_reference:
                state = "unauthenticated"
            elif chain is None or not any(chain[0].values()):
                state = "unresolved"
            elif mode == "text":
                state = "weak-cleartext"
            elif mode == "md5":
                state = "configured-md5" if receive_declared and receive_version == "2" else "unknown"
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
                send_version=send_version,
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
        http_acl6 = self.get_http_ipv6_access_class() if self.device_type == "IOS_XE" else None
        for protocol, state in (
            ("http", self.get_http_server_state()),
            ("https", self.get_https_server_state()),
        ):
            if state == ConfigurationState.ENABLED:
                management_services.append(ManagementService(
                    protocol=protocol,
                    state=NormalizedConfigurationState.ENABLED,
                    scope="global",
                    permitted_sources=tuple(item for item in (
                        f"ipv4-acl:{http_acl}" if http_acl else "",
                        f"ipv6-acl:{http_acl6}" if http_acl6 else "",
                    ) if item),
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
