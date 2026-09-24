import re
import shlex
import base64
import ipaddress
from dataclasses import dataclass
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
from src.devices.common.policy_semantics import (
    AddressInterval,
    NetworkSemantics,
    ServiceInterval,
    ServiceSemantics,
)
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


@dataclass(frozen=True)
class ASAManagementGrant:
    protocol: str
    source: str
    mask: str
    interface: str
    address_family: str
    raw_line: str

    @property
    def is_any_source(self) -> bool:
        return (
            self.address_family == "ipv4"
            and self.source == "0.0.0.0"
            and self.mask == "0.0.0.0"
        ) or (self.address_family == "ipv6" and self.source in {"::/0", "0::/0"})


ASACredential = CredentialMetadata


@dataclass(frozen=True)
class ASANumericSetting:
    value: Optional[int]
    configured: bool
    known_default: bool
    raw_line: str = ""
    parse_error: str = ""


@dataclass(frozen=True)
class ASAASDMIdlePolicy:
    minutes: Optional[float]
    resolution_state: str
    source: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class ASAAAAdministrativeBinding:
    binding_type: str
    protocol: str
    server_group: str
    local_fallback: bool
    resolved: bool
    raw_line: str


@dataclass(frozen=True)
class ASASSHPolicy:
    version: Optional[str]
    version_source: str
    encryption: Optional[tuple[str, ...]]
    integrity: Optional[tuple[str, ...]]
    key_exchange: Optional[str]
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class ASANTPAssociation:
    address: str
    source_interface: str
    key_id: str
    authentication_state: str
    algorithm: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class ASAConnectionLimitPolicy:
    """Effective MPF connection limits from an attached ASA policy class."""

    policy_name: str
    policy_type: str
    class_name: str
    attachment_scopes: tuple[str, ...]
    limits: tuple[tuple[str, int | None], ...]
    invalid_values: tuple[str, ...]
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class ASAManagementCertificateBinding:
    trustpoint: str
    interface: str | None
    trustpoint_configured: bool
    identity_certificate_present: bool
    certificate_chain_present: bool
    public_material_state: str
    metadata: CertificateMetadata | None
    assessment: CertificateAssessment | None
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class ASAActiveIKEGroup:
    """Explicit DH alternative in an enabled IKE policy family."""

    version: str
    priority: str
    group: str
    interfaces: tuple[str, ...]
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class ASASelectableWebVPNProfile:
    """Explicitly selectable remote-access profile on an enabled WebVPN listener."""

    name: str
    listener_interfaces: tuple[str, ...]
    authentication: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class ASASNMPCommunity:
    name: str
    access: str
    raw_line_redacted: str

    @property
    def is_default(self) -> bool:
        return self.name.casefold() in {"public", "private"}


@dataclass(frozen=True)
class ASASNMPHost:
    interface: str
    address: str
    version: str
    community_configured: bool
    principal: str
    raw_line_redacted: str


@dataclass(frozen=True)
class ASASNMPGroup:
    name: str
    security_level: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class ASASNMPUser:
    name: str
    group: str
    authentication: str
    privacy: str
    authentication_key_state: str
    privacy_key_state: str
    group_security_level: str
    group_resolved: bool
    host_scopes: tuple[str, ...]
    active: bool
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class ASAACLEntry:
    acl_name: str
    action: str
    protocol: str
    source: str
    destination: str
    inactive: bool
    raw_line: str
    service_qualifiers: tuple[str, ...] = ()
    time_range: str = ""
    logging: bool = False
    behavior_signature: tuple[str, ...] = ()
    unsupported_predicates: tuple[str, ...] = ()
    configured_line: Optional[int] = None
    sequence: int = 0

    @property
    def is_broad_permit(self) -> bool:
        any_values = {"any", "any4", "any6"}
        return (
            not self.inactive
            and self.action == "permit"
            and self.source in any_values
            and self.destination in any_values
        )


@dataclass(frozen=True)
class ASAIPsecTransformBinding:
    transform_name: str
    declaration: str | None
    map_binding: str
    map_attachment: str
    interface: str


@dataclass(frozen=True)
class ASASSLServicePolicy:
    active_interfaces: tuple[str, ...]
    server_minimum: str | None
    server_minimum_valid: bool
    client_minimum: str | None
    weak_cipher_commands: tuple[str, ...]
    unknown_cipher_commands: tuple[str, ...]
    evidence: tuple[ConfigEvidence, ...]


class CiscoASAParser(BaseDeviceParser):

    device_type = "ASA"
    _MAX_ACL_OBJECT_EXPANSION = 4096
    _ASA_PROTOCOLS = {
        "ah", "eigrp", "esp", "gre", "icmp", "icmp6", "igmp", "igrp",
        "ipinip", "ipsec", "nos", "ospf", "pcp", "pim", "pptp", "sctp",
        "snp", "tcp", "udp",
    }
    _ASA_PORTS = {
        "ftp-data": 20,
        "ftp": 21,
        "ssh": 22,
        "telnet": 23,
        "smtp": 25,
        "domain": 53,
        "dns": 53,
        "www": 80,
        "http": 80,
        "pop3": 110,
        "ntp": 123,
        "imap4": 143,
        "snmp": 161,
        "snmptrap": 162,
        "https": 443,
        "isakmp": 500,
        "ldap": 389,
        "ldaps": 636,
        "syslog": 514,
    }

    def __init__(self, config_filepath: str):
        super().__init__(config_filepath)
        with open(config_filepath, "r", encoding="utf-8-sig", errors="replace") as source:
            self._source_lines = source.read().splitlines()
        # CiscoConfParse drops blank lines, which would shift every evidence
        # line number after them. A comment placeholder keeps positions equal
        # to physical line numbers. ASA banners are single-line commands.
        self.parser = CiscoConfParse(
            [line if line.strip() else "!" for line in self._source_lines],
            syntax='asa',
        )
        self._acl_object_cache: Optional[dict[str, dict]] = None

    def get_hostname(self) -> str:
        host = self.parser.find_objects("^hostname")
        if len(host) > 0:
            return host[0].re_match_typed(r'^hostname\s+(\S+)', default='')
        return "?"

    def get_version(self) -> str:
        # ASA version is typically at the top, e.g., "ASA Version 9.12(4)" or "version 9.12"
        version_line = self.parser.find_objects("^ASA Version")
        if len(version_line) > 0:
            return version_line[0].re_match_typed(r'^ASA Version\s+(\S+)', default='')
        
        # Fallback to standard version command
        version_line = self.parser.find_objects("^version")
        if len(version_line) > 0:
            return version_line[0].re_match_typed(r'^version\s+(\S+)', default='')
        
        return "?"

    def get_users(self) -> list[dict]:
        users = []
        user_lines = self.parser.find_objects("^username")
        for line in user_lines:
            text = line.text
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
        return {
            "telnet": bool(self.get_management_grants("telnet")),
            "ssh": bool(self.get_management_grants("ssh")),
            # ASA's `http` management grant controls HTTPS/ASDM, not clear-text HTTP.
            "http": self.get_http_server_enabled(),
        }

    def get_native_config(self) -> CiscoConfParse:
        return self.parser

    def get_selectable_webvpn_profiles(self) -> tuple[ASASelectableWebVPNProfile, ...]:
        """Bind explicit group URLs to enabled WebVPN and remote-access auth mode."""
        release = self._release_tuple(self.get_version())
        if release is None or release < (9, 16):
            return ()
        listeners: dict[str, ConfigEvidence] = {}
        types: dict[str, bool] = {}
        profiles: dict[str, dict[str, object]] = {}
        current_kind = ""
        current_name = ""
        for number, raw in enumerate(self._source_lines, 1):
            command = raw.strip()
            if not command or command.startswith("!"):
                continue
            if not raw[:1].isspace():
                current_kind = ""
                current_name = ""
                if command.casefold() == "webvpn":
                    current_kind = "webvpn"
                    continue
                if command.casefold() == "no webvpn":
                    listeners.clear()
                    continue
                removed_group = re.fullmatch(r"no tunnel-group (\S+)", command, re.IGNORECASE)
                if removed_group:
                    name = removed_group.group(1).casefold()
                    types.pop(name, None)
                    profiles.pop(name, None)
                    continue
                group_type = re.fullmatch(
                    r"(no )?tunnel-group (\S+) type (remote-access|ipsec-l2l)",
                    command, re.IGNORECASE,
                )
                if group_type:
                    types[group_type.group(2).casefold()] = (
                        not group_type.group(1)
                        and group_type.group(3).casefold() == "remote-access"
                    )
                    continue
                attributes = re.fullmatch(
                    r"tunnel-group (\S+) webvpn-attributes", command, re.IGNORECASE,
                )
                if attributes:
                    current_kind = "profile"
                    current_name = attributes.group(1)
                    data = profiles.setdefault(current_name.casefold(), {
                        "name": current_name, "authentication": "unknown",
                        "urls": {}, "evidence": [],
                    })
                    data["evidence"].append(ConfigEvidence(
                        f"tunnel-group {current_name} webvpn-attributes",
                        self.config_filepath, number,
                    ))
                continue
            if current_kind == "webvpn":
                listener = re.fullmatch(r"(no )?enable (\S+)", command, re.IGNORECASE)
                if listener:
                    interface = listener.group(2).casefold()
                    if listener.group(1):
                        listeners.pop(interface, None)
                    else:
                        listeners[interface] = ConfigEvidence(
                            f"webvpn enable {interface}", self.config_filepath, number,
                        )
                continue
            if current_kind != "profile":
                continue
            data = profiles[current_name.casefold()]
            if command.casefold() in {"no authentication", "default authentication"}:
                data["authentication"] = "unknown"
                continue
            authentication = re.fullmatch(r"authentication (.+)", command, re.IGNORECASE)
            url = re.fullmatch(r"(no )?group-url (\S+)(?: (enable|disable))?", command, re.IGNORECASE)
            if authentication:
                mode = authentication.group(1).casefold()
                data["authentication"] = mode
                data["evidence"].append(ConfigEvidence(
                    f"authentication {mode}", self.config_filepath, number,
                ))
            elif url:
                target = url.group(2).casefold()
                if url.group(1):
                    data["urls"].pop(target, None)
                else:
                    enabled = (url.group(3) or "enable").casefold() == "enable"
                    data["urls"][target] = enabled
                    data["evidence"].append(ConfigEvidence(
                        f"group-url <redacted> {'enable' if enabled else 'disable'}",
                        self.config_filepath, number,
                    ))
        if not listeners:
            return ()
        records = []
        for name, data in profiles.items():
            if not types.get(name) or not any(data["urls"].values()):
                continue
            records.append(ASASelectableWebVPNProfile(
                name=data["name"],
                listener_interfaces=tuple(sorted(listeners)),
                authentication=data["authentication"],
                evidence=tuple(data["evidence"])
                + tuple(listeners[item] for item in sorted(listeners)),
            ))
        return tuple(records)

    def get_active_ike_dh_groups(self) -> tuple[ASAActiveIKEGroup, ...]:
        """Resolve explicit IKE policy DH alternatives only for enabled interfaces."""
        enabled: dict[str, dict[str, ConfigEvidence]] = {"ikev1": {}, "ikev2": {}}
        policies: dict[tuple[str, str], tuple[tuple[str, ...], list[ConfigEvidence]]] = {}
        current: tuple[str, str] | None = None
        for number, raw in enumerate(self._source_lines, 1):
            command = raw.strip()
            if not command or command.startswith("!"):
                continue
            if not raw[:1].isspace():
                current = None
                activation = re.fullmatch(
                    r"(no )?crypto (ikev[12]) enable (\S+)", command, re.IGNORECASE,
                )
                if activation:
                    _, version, interface = activation.groups()
                    if activation.group(1):
                        enabled[version.casefold()].pop(interface.casefold(), None)
                    else:
                        enabled[version.casefold()][interface.casefold()] = ConfigEvidence(
                            f"crypto {version.casefold()} enable {interface}", self.config_filepath, number,
                        )
                    continue
                removal = re.fullmatch(
                    r"no crypto (ikev[12]) policy (\d+)", command, re.IGNORECASE,
                )
                if removal:
                    policies.pop((removal.group(1).casefold(), removal.group(2)), None)
                    continue
                policy = re.fullmatch(
                    r"crypto (ikev[12]) policy (\d+)", command, re.IGNORECASE,
                )
                if policy:
                    current = (policy.group(1).casefold(), policy.group(2))
                    policies[current] = ((), [ConfigEvidence(command, self.config_filepath, number)])
                continue
            if current is None:
                continue
            group = re.fullmatch(r"group ((?:\d+)(?: \d+)*)", command, re.IGNORECASE)
            if group:
                policies[current] = (
                    tuple(group.group(1).split()),
                    policies[current][1] + [ConfigEvidence(command, self.config_filepath, number)],
                )
            elif command.casefold() == "no group":
                policies[current] = ((), policies[current][1] + [
                    ConfigEvidence(command, self.config_filepath, number),
                ])
        records = []
        for (version, priority), (groups, evidence) in policies.items():
            if not enabled[version]:
                continue
            interfaces = tuple(sorted(enabled[version]))
            activation_evidence = tuple(enabled[version][name] for name in interfaces)
            for group in groups:
                records.append(ASAActiveIKEGroup(
                    version, priority, group, interfaces,
                    tuple(evidence) + activation_evidence,
                ))
        return tuple(records)

    def get_active_ipsec_transform_bindings(self) -> tuple[ASAIPsecTransformBinding, ...]:
        """Resolve declared transforms through effective, interface-attached crypto maps."""
        declarations: dict[str, str] = {}
        transform_refs: dict[tuple[str, str, str], tuple[tuple[str, ...], str]] = {}
        dynamic_refs: dict[tuple[str, str], tuple[str, str]] = {}
        attachments: dict[tuple[str, str], str] = {}
        for source_line in self._source_lines:
            line = source_line.strip()
            if not line or line.startswith("!"):
                continue
            words = line.split()
            removal = words[0].lower() == "no"
            body = words[1:] if removal else words
            lower = [word.lower() for word in body]
            if len(body) >= 4 and lower[:3] == ["crypto", "ipsec", "transform-set"]:
                key = body[3].casefold()
                if removal:
                    declarations.pop(key, None)
                else:
                    declarations[key] = line
            elif len(body) >= 5 and lower[:4] == ["crypto", "ipsec", "ikev1", "transform-set"]:
                key = body[4].casefold()
                if removal:
                    declarations.pop(key, None)
                else:
                    declarations[key] = line
            elif len(body) >= 3 and lower[:2] == ["crypto", "map"]:
                map_name = body[2].casefold()
                if len(body) >= 5 and lower[3] == "interface":
                    key = (map_name, body[4].casefold())
                    if removal:
                        attachments.pop(key, None)
                    else:
                        attachments[key] = line
                elif len(body) >= 4:
                    sequence = body[3]
                    if removal and len(body) == 4:
                        for key in tuple(transform_refs):
                            if key[0] == "static" and key[1:3] == (map_name, sequence):
                                transform_refs.pop(key)
                        dynamic_refs.pop((map_name, sequence), None)
                    elif len(body) >= 8 and lower[4:7] == ["set", "ikev1", "transform-set"]:
                        key = ("static", map_name, sequence)
                        if removal:
                            transform_refs.pop(key, None)
                        else:
                            transform_refs[key] = (tuple(body[7:]), line)
                    elif len(body) >= 7 and lower[4:6] == ["ipsec-isakmp", "dynamic"]:
                        key = (map_name, sequence)
                        if removal:
                            dynamic_refs.pop(key, None)
                        else:
                            dynamic_refs[key] = (body[6].casefold(), line)
            elif len(body) >= 4 and lower[:2] == ["crypto", "dynamic-map"]:
                key = ("dynamic", body[2].casefold(), body[3])
                if removal and len(body) == 4:
                    transform_refs.pop(key, None)
                elif len(body) >= 8 and lower[4:7] == ["set", "ikev1", "transform-set"]:
                    if removal:
                        transform_refs.pop(key, None)
                    else:
                        transform_refs[key] = (tuple(body[7:]), line)

        results: list[ASAIPsecTransformBinding] = []
        for (map_name, interface), attachment in attachments.items():
            for (kind, candidate_map, sequence), (names, binding) in transform_refs.items():
                if kind != "static" or candidate_map != map_name:
                    continue
                for name in names:
                    declaration = declarations.get(name.casefold())
                    results.append(ASAIPsecTransformBinding(name, declaration, binding, attachment, interface))
            for (candidate_map, _), (dynamic_map, parent_binding) in dynamic_refs.items():
                if candidate_map != map_name:
                    continue
                for (kind, candidate_dynamic, _), (names, binding) in transform_refs.items():
                    if kind != "dynamic" or candidate_dynamic != dynamic_map:
                        continue
                    for name in names:
                        declaration = declarations.get(name.casefold())
                        results.append(ASAIPsecTransformBinding(
                            name, declaration, f"{parent_binding}; {binding}", attachment, interface,
                        ))
        return tuple(results)

    def _global_lines(self) -> list[str]:
        return [line.strip() for line in self.parser.ioscfg if line.strip()]

    def get_http_server_enabled(self) -> bool:
        enabled = False
        for line in self._global_lines():
            if re.fullmatch(r"http server enable(?:\s+\d+)?", line):
                enabled = True
            elif re.fullmatch(r"no http server enable(?:\s+\d+)?", line):
                enabled = False
        return enabled

    def get_management_certificate_bindings(self) -> tuple[ASAManagementCertificateBinding, ...]:
        """Resolve effective SSL assignments to trustpoint and certificate-chain objects."""

        trustpoints: set[str] = set()
        for line in self._global_lines():
            remove = re.fullmatch(r"no crypto ca trustpoint\s+(\S+)", line, re.IGNORECASE)
            if remove:
                trustpoints.discard(remove.group(1))
                continue
            match = re.fullmatch(r"crypto ca trustpoint\s+(\S+)", line, re.IGNORECASE)
            if match:
                trustpoints.add(match.group(1))
        chains: dict[str, list[tuple[bool, str]]] = {}
        current_chain = None
        current_is_ca = None
        current_hex: list[str] = []

        def flush_certificate() -> None:
            nonlocal current_is_ca, current_hex
            if current_chain is not None and current_is_ca is not None:
                chains.setdefault(current_chain, []).append((current_is_ca, "".join(current_hex)))
            current_is_ca = None
            current_hex = []

        for raw_line in self.parser.ioscfg:
            stripped = raw_line.strip()
            match = re.fullmatch(
                r"crypto ca certificate chain\s+(\S+)", stripped, re.IGNORECASE
            )
            if match:
                flush_certificate()
                current_chain = match.group(1)
                chains.setdefault(current_chain, [])
                continue
            if current_chain and raw_line[:1].isspace():
                certificate_line = re.fullmatch(
                    r"certificate\s+(?:(ca)\s+)?\S+", stripped, re.IGNORECASE
                )
                if certificate_line:
                    flush_certificate()
                    current_is_ca = bool(certificate_line.group(1))
                elif current_is_ca is not None and re.fullmatch(r"[0-9A-Fa-f ]+", stripped):
                    current_hex.append(stripped.replace(" ", ""))
                continue
            flush_certificate()
            current_chain = None
        flush_certificate()

        parsed_by_chain: dict[str, list[tuple[bool, object]]] = {}
        material_state: dict[str, str] = {}
        for name, entries in chains.items():
            parsed_entries = []
            saw_identity = False
            malformed_identity = False
            for is_ca, hexadecimal in entries:
                if is_ca:
                    pass
                else:
                    saw_identity = True
                if not hexadecimal:
                    continue
                try:
                    encoded = base64.b64encode(bytes.fromhex(hexadecimal)).decode("ascii")
                    parsed_entries.append((is_ca, load_public_certificate(encoded)))
                except (TypeError, ValueError):
                    if not is_ca:
                        malformed_identity = True
            parsed_by_chain[name] = parsed_entries
            if any(not is_ca for is_ca, _ in parsed_entries):
                material_state[name] = "parsed"
            elif malformed_identity:
                material_state[name] = "malformed"
            elif saw_identity:
                material_state[name] = "missing"
            else:
                material_state[name] = "missing"

        all_certificates = tuple(
            certificate for entries in parsed_by_chain.values() for _, certificate in entries
        )

        assignments: dict[str | None, tuple[str, str]] = {}
        for line in self._global_lines():
            remove = re.fullmatch(
                r"no ssl trust-point(?:\s+(\S+))?(?:\s+(\S+))?", line, re.IGNORECASE
            )
            if remove:
                interface = remove.group(2)
                if interface:
                    assignments.pop(interface, None)
                else:
                    assignments.clear()
                continue
            match = re.fullmatch(r"ssl trust-point\s+(\S+)(?:\s+(\S+))?", line, re.IGNORECASE)
            if match:
                assignments[match.group(2)] = (match.group(1), line)

        bindings = []
        for interface, (name, line) in assignments.items():
            parsed_identity = next(
                (certificate for is_ca, certificate in parsed_by_chain.get(name, []) if not is_ca),
                None,
            )
            assessment = None
            metadata = None
            if parsed_identity is not None:
                metadata = certificate_metadata(parsed_identity)
                assessment = assess_public_certificate(
                    parsed_identity,
                    all_certificates,
                    self.assessment_context.trusted_certificate_sha256,
                    self.assessment_context.management_identity_for_scope(interface or "default"),
                    self.assessment_context.assessment_datetime(),
                )
            bindings.append(ASAManagementCertificateBinding(
                trustpoint=name,
                interface=interface,
                trustpoint_configured=name in trustpoints,
                identity_certificate_present=any(
                    not is_ca for is_ca, _ in chains.get(name, [])
                ),
                certificate_chain_present=name in chains,
                public_material_state=material_state.get(name, "unknown"),
                metadata=metadata,
                assessment=assessment,
                evidence=(ConfigEvidence(line, self.config_filepath, None),),
            ))
        return tuple(bindings)

    def get_aaa_server_groups(self) -> dict[str, str]:
        groups: dict[str, str] = {}
        for line in self._global_lines():
            configured = re.fullmatch(r"aaa-server\s+(\S+)\s+protocol\s+(radius|tacacs\+|ldap|kerberos)", line, re.IGNORECASE)
            removed = re.fullmatch(r"no aaa-server\s+(\S+)", line, re.IGNORECASE)
            if configured:
                groups[configured.group(1).casefold()] = configured.group(2).casefold()
            elif removed:
                groups.pop(removed.group(1).casefold(), None)
        return groups

    def get_administrative_aaa_bindings(self) -> list[ASAAAAdministrativeBinding]:
        groups = self.get_aaa_server_groups()
        has_local_user = bool(self.get_users())
        bindings: dict[tuple[str, str], ASAAAAdministrativeBinding] = {}
        for line in self._global_lines():
            removed = re.fullmatch(
                r"no aaa (authentication|accounting) (serial|ssh|telnet|http|enable) console(?:\s+.*)?",
                line,
                re.IGNORECASE,
            )
            if removed:
                bindings.pop((removed.group(1).casefold(), removed.group(2).casefold()), None)
                continue
            authentication = re.fullmatch(
                r"aaa authentication (serial|ssh|telnet|http|enable) console\s+(.+)",
                line,
                re.IGNORECASE,
            )
            if authentication:
                protocol = authentication.group(1).casefold()
                methods = authentication.group(2).split()
                group = methods[0]
                local_only = group.casefold() == "local"
                bindings[("authentication", protocol)] = ASAAAAdministrativeBinding(
                    binding_type="authentication",
                    protocol=protocol,
                    server_group=group,
                    local_fallback=local_only or any(item.casefold() == "local" for item in methods[1:]),
                    resolved=(has_local_user if local_only else group.casefold() in groups),
                    raw_line=line,
                )
                continue
            accounting = re.fullmatch(
                r"aaa accounting (serial|ssh|telnet|enable) console\s+(\S+)",
                line,
                re.IGNORECASE,
            )
            if accounting:
                protocol = accounting.group(1).casefold()
                group = accounting.group(2)
                bindings[("accounting", protocol)] = ASAAAAdministrativeBinding(
                    binding_type="accounting",
                    protocol=protocol,
                    server_group=group,
                    local_fallback=False,
                    resolved=group.casefold() in groups,
                    raw_line=line,
                )
        return list(bindings.values())

    @staticmethod
    def _release_tuple(version: str) -> Optional[tuple[int, int]]:
        match = re.match(r"(\d+)\.(\d+)", version)
        return (int(match.group(1)), int(match.group(2))) if match else None

    def get_console_timeout(self) -> ASANumericSetting:
        value: Optional[int] = 0
        configured = False
        known_default = True
        raw_line = ""
        parse_error = ""
        for line in self._global_lines():
            match = re.fullmatch(r"console timeout(?:\s+(\S+))?", line)
            if match:
                configured = True
                known_default = False
                raw_line = line
                try:
                    value = int(match.group(1)) if match.group(1) is not None else 0
                    if not 0 <= value <= 60:
                        raise ValueError
                    parse_error = ""
                except ValueError:
                    value = None
                    parse_error = "invalid console timeout"
            elif re.fullmatch(r"no console timeout(?:\s+.*)?", line):
                value = 0
                configured = False
                known_default = True
                raw_line = line
                parse_error = ""
        return ASANumericSetting(value, configured, known_default, raw_line, parse_error)

    def get_ssh_timeout(self) -> ASANumericSetting:
        value: Optional[int] = 5
        configured = False
        known_default = True
        raw_line = ""
        parse_error = ""
        for line in self._global_lines():
            match = re.fullmatch(r"ssh timeout(?:\s+(\S+))?", line)
            if match:
                configured = True
                known_default = False
                raw_line = line
                try:
                    value = int(match.group(1)) if match.group(1) is not None else None
                    if value is None or not 1 <= value <= 60:
                        raise ValueError
                    parse_error = ""
                except ValueError:
                    value = None
                    parse_error = "invalid SSH timeout"
            elif re.fullmatch(r"no ssh timeout(?:\s+.*)?", line):
                value = 5
                configured = False
                known_default = True
                raw_line = line
                parse_error = ""
        return ASANumericSetting(value, configured, known_default, raw_line, parse_error)

    def get_local_lockout_limit(self) -> ASANumericSetting:
        """ASA local-database max-fail; omitted and reset mean no limit."""
        value: Optional[int] = None
        configured = False
        known_default = self._release_tuple(self.get_version()) is not None
        evidence = ""
        error = ""
        for line in self._global_lines():
            match = re.fullmatch(r"aaa local authentication attempts max-fail(?:\s+(\S+))?", line)
            if match:
                configured, known_default, evidence = True, False, line
                try:
                    value = int(match.group(1)) if match.group(1) is not None else None
                    if value is None or not 1 <= value <= 16:
                        raise ValueError
                    error = ""
                except ValueError:
                    value, error = None, "invalid local lockout limit"
            elif re.fullmatch(r"(?:no|default) aaa local authentication attempts max-fail(?:\s+.*)?", line):
                value, configured, known_default, evidence, error = None, False, True, line, ""
        return ASANumericSetting(value, configured, known_default, evidence, error)

    def get_local_password_minimum(self) -> ASANumericSetting:
        """Explicit ASA local-administrator password minimum; no inferred finding."""
        release = self._release_tuple(self.get_version())
        supported = release is not None and release >= (9, 1)
        value: Optional[int] = 3 if supported else None
        configured = False
        evidence = ""
        error = ""
        for line in self._global_lines():
            match = re.fullmatch(r"password-policy minimum-length(?:\s+(\S+))?", line)
            if match:
                configured, evidence = True, line
                try:
                    value = int(match.group(1)) if match.group(1) is not None else None
                    if value is None or not 3 <= value <= 64:
                        raise ValueError
                    error = ""
                except ValueError:
                    value, error = None, "invalid local password minimum"
            elif re.fullmatch(r"(?:no|default) password-policy minimum-length(?:\s+.*)?", line):
                value, configured, evidence, error = (3 if supported else None), False, line, ""
        return ASANumericSetting(value, configured, supported, evidence, error)

    def get_asdm_idle_policy(self) -> ASAASDMIdlePolicy:
        """Explicit ASDM idle setting; newer connection-wide timeout takes precedence."""
        multiple_context = any(
            re.fullmatch(r"mode multiple", line, re.IGNORECASE)
            for line in self._global_lines()
        )
        settings: dict[str, ASAASDMIdlePolicy] = {}
        for line_number, raw in enumerate(self._source_lines, start=1):
            if raw[:1].isspace():
                continue
            line = raw.strip()
            match = re.fullmatch(r"http server idle-timeout(?:\s+(\S+))?", line)
            connection = re.fullmatch(r"http connection idle-timeout(?:\s+(\S+))?", line)
            if match or connection:
                selected = connection or match
                source = "http connection idle-timeout" if connection else "http server idle-timeout"
                evidence = (ConfigEvidence(line, self.config_filepath, line_number),)
                release = self._release_tuple(self.get_version())
                if (release is None or release < ((9, 14) if connection else (8, 2))
                        or (multiple_context and not connection)):
                    settings[source] = ASAASDMIdlePolicy(None, "unsupported-release", source, evidence)
                    continue
                try:
                    value = int(selected.group(1)) if selected.group(1) is not None else None
                    if value is None or not (10 <= value <= 86400 if connection else 1 <= value <= 1440):
                        raise ValueError
                    settings[source] = ASAASDMIdlePolicy(
                        value / 60 if connection else float(value), "explicit", source, evidence
                    )
                except ValueError:
                    settings[source] = ASAASDMIdlePolicy(None, "invalid", source, evidence)
            else:
                reset = re.fullmatch(
                    r"(?:no|default) (http (?:server|connection) idle-timeout)(?:\s+.*)?", line
                )
                if reset:
                    settings.pop(reset.group(1), None)
        return (
            settings.get("http connection idle-timeout")
            or settings.get("http server idle-timeout")
            or ASAASDMIdlePolicy(None, "unknown", "", ())
        )

    def get_ssh_policy(self) -> ASASSHPolicy:
        release = self._release_tuple(self.get_version())
        version: Optional[str] = None
        if release is not None and release >= (9, 9):
            version = "2"
        elif release is not None and release >= (7, 0):
            version = "1,2"
        version_source = "release-default" if version is not None else "unknown"
        encryption: Optional[tuple[str, ...]] = None
        integrity: Optional[tuple[str, ...]] = None
        key_exchange: Optional[str] = None
        evidence: list[ConfigEvidence] = []
        for line_number, raw_line in enumerate(self.parser.ioscfg, start=1):
            line = raw_line.strip()
            version_match = re.fullmatch(r"ssh version\s+(.+)", line)
            if version_match:
                version = ",".join(version_match.group(1).replace(",", " ").split())
                version_source = "explicit"
                evidence.append(ConfigEvidence(line, self.config_filepath, line_number))
                continue
            if re.fullmatch(r"no ssh version(?:\s+.*)?", line):
                if release is not None and release >= (9, 9):
                    version = "2"
                elif release is not None and release >= (7, 0):
                    version = "1,2"
                else:
                    version = None
                version_source = "release-default" if version is not None else "unknown"
                evidence.append(ConfigEvidence(line, self.config_filepath, line_number))
                continue
            cipher = re.fullmatch(r"ssh cipher (encryption|integrity)\s+(.+)", line)
            if cipher:
                values = tuple(
                    value.casefold()
                    for value in cipher.group(2).replace(":", " ").split()
                )
                if cipher.group(1) == "encryption":
                    encryption = values
                else:
                    integrity = values
                evidence.append(ConfigEvidence(line, self.config_filepath, line_number))
                continue
            cipher_reset = re.fullmatch(r"no ssh cipher (encryption|integrity)(?:\s+.*)?", line)
            if cipher_reset:
                if cipher_reset.group(1) == "encryption":
                    encryption = None
                else:
                    integrity = None
                evidence.append(ConfigEvidence(line, self.config_filepath, line_number))
                continue
            key_exchange_match = re.fullmatch(r"ssh key-exchange group\s+(\S+)", line)
            if key_exchange_match:
                key_exchange = key_exchange_match.group(1).casefold()
                evidence.append(ConfigEvidence(line, self.config_filepath, line_number))
            elif re.fullmatch(r"no ssh key-exchange group(?:\s+.*)?", line):
                key_exchange = None
                evidence.append(ConfigEvidence(line, self.config_filepath, line_number))
        return ASASSHPolicy(
            version=version,
            version_source=version_source,
            encryption=encryption,
            integrity=integrity,
            key_exchange=key_exchange,
            evidence=tuple(evidence),
        )

    def get_ntp_associations(self) -> list[ASANTPAssociation]:
        authentication = False
        trusted: set[str] = set()
        keys: dict[str, tuple[str, ConfigEvidence]] = {}
        servers: dict[str, tuple[str, str, ConfigEvidence]] = {}
        for line_number, raw_line in enumerate(self.parser.ioscfg, start=1):
            line = raw_line.strip()
            if line == "ntp authenticate":
                authentication = True
                continue
            if line == "no ntp authenticate":
                authentication = False
                continue
            trusted_match = re.fullmatch(r"(?P<no>no\s+)?ntp trusted-key\s+(\S+)", line)
            if trusted_match:
                key_id = trusted_match.group(2)
                if trusted_match.group("no"):
                    trusted.discard(key_id)
                else:
                    trusted.add(key_id)
                continue
            removed_key = re.fullmatch(r"no ntp authentication-key\s+(\S+)(?:\s+.*)?", line)
            configured_key = re.fullmatch(
                r"ntp authentication-key\s+(\S+)\s+(md5|sha1|sha256|sha512|cmac)\s+(?:0\s+|8\s+)?(\S+)",
                line,
                re.IGNORECASE,
            )
            if removed_key:
                keys.pop(removed_key.group(1), None)
                continue
            if configured_key:
                key_id, algorithm, _ = configured_key.groups()
                keys[key_id] = (
                    algorithm.casefold(),
                    ConfigEvidence(
                        f"ntp authentication-key {key_id} {algorithm.casefold()} <key redacted>",
                        self.config_filepath,
                        line_number,
                    ),
                )
                continue
            removed_server = re.fullmatch(r"no ntp server\s+(\S+)(?:\s+.*)?", line)
            server = re.fullmatch(r"ntp server\s+(\S+)(?:\s+(.+))?", line)
            if removed_server:
                servers.pop(removed_server.group(1).casefold(), None)
            elif server:
                address = server.group(1)
                tail = (server.group(2) or "").split()
                key_id = tail[tail.index("key") + 1] if "key" in tail and tail.index("key") + 1 < len(tail) else ""
                source = tail[tail.index("source") + 1] if "source" in tail and tail.index("source") + 1 < len(tail) else ""
                servers[address.casefold()] = (
                    source,
                    key_id,
                    ConfigEvidence(line, self.config_filepath, line_number),
                )
        associations = []
        for address, (source, key_id, server_evidence) in servers.items():
            key = keys.get(key_id)
            if not authentication or not key_id:
                state = "unauthenticated"
            elif key is None or key_id not in trusted:
                state = "unresolved"
            else:
                state = "authenticated"
            associations.append(ASANTPAssociation(
                address=address,
                source_interface=source,
                key_id=key_id,
                authentication_state=state,
                algorithm=key[0] if key else "",
                evidence=(server_evidence,) + ((key[1],) if key else ()),
            ))
        return associations

    def get_connection_limit_policies(self) -> tuple[ASAConnectionLimitPolicy, ...]:
        """Resolve configured MPF limits only when their policy is attached.

        ASA uses zero for an unlimited connection value.  This accessor does
        not invent a suitable nonzero rate or treat an unattached policy map as
        effective configuration.
        """

        attachments: dict[str, dict[str, str]] = {}
        for line in self._global_lines():
            removed = re.fullmatch(
                r"no service-policy\s+(\S+)\s+(global|interface\s+\S+|\S+)",
                line,
                re.IGNORECASE,
            )
            if removed:
                name = removed.group(1).casefold()
                scope = removed.group(2).casefold()
                if scope != "global" and not scope.startswith("interface "):
                    scope = f"interface {scope}"
                attachments.setdefault(name, {}).pop(scope, None)
                continue
            configured = re.fullmatch(
                r"service-policy\s+(\S+)\s+(global|interface\s+\S+|\S+)",
                line,
                re.IGNORECASE,
            )
            if configured:
                name = configured.group(1).casefold()
                scope = configured.group(2).casefold()
                if scope != "global" and not scope.startswith("interface "):
                    scope = f"interface {scope}"
                attachments.setdefault(name, {})[scope] = line

        limit_names = {
            "conn-max",
            "embryonic-conn-max",
            "per-client-embryonic-max",
            "per-client-max",
        }
        policies: list[ASAConnectionLimitPolicy] = []
        current_policy: tuple[str, str] | None = None
        current_class = ""
        for line_number, raw_line in enumerate(self._source_lines, start=1):
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("!"):
                continue
            if not raw_line[:1].isspace():
                match = re.fullmatch(
                    r"policy-map(?:\s+type\s+(management)(?:\s+first-match)?)?\s+(\S+)",
                    stripped,
                    re.IGNORECASE,
                )
                current_policy = (
                    (match.group(1) or "regular").casefold(),
                    match.group(2),
                ) if match else None
                current_class = ""
                continue
            if current_policy is None:
                continue
            class_match = re.fullmatch(r"class\s+(\S+)", stripped, re.IGNORECASE)
            if class_match:
                current_class = class_match.group(1)
                continue
            if not current_class or not stripped.casefold().startswith("set connection "):
                continue
            tokens = stripped.split()[2:]
            limits: list[tuple[str, int | None]] = []
            invalid: list[str] = []
            index = 0
            while index < len(tokens):
                keyword = tokens[index].casefold()
                if keyword not in limit_names:
                    index += 1
                    continue
                raw_value = tokens[index + 1] if index + 1 < len(tokens) else ""
                value = int(raw_value) if raw_value.isdigit() else None
                if value is None or not 0 <= value <= 2_000_000:
                    invalid.append(f"{keyword} {raw_value or '<missing>'}")
                    value = None
                limits.append((keyword, value))
                index += 2
            if not limits and not invalid:
                continue
            policy_type, policy_name = current_policy
            scopes = tuple(attachments.get(policy_name.casefold(), ()))
            if not scopes:
                continue
            evidence = [ConfigEvidence(stripped, self.config_filepath, line_number)]
            evidence.extend(
                ConfigEvidence(text, self.config_filepath, None)
                for text in attachments[policy_name.casefold()].values()
            )
            policies.append(ASAConnectionLimitPolicy(
                policy_name=policy_name,
                policy_type=policy_type,
                class_name=current_class,
                attachment_scopes=scopes,
                limits=tuple(limits),
                invalid_values=tuple(invalid),
                evidence=tuple(evidence),
            ))
        return tuple(policies)

    # Helper methods specific to ASA audit checks
    def get_enable_password(self) -> str:
        """Compatibility accessor that never returns credential material."""

        return "<redacted>" if self.get_enable_credential() else ""

    @staticmethod
    def _credential_assessment(marker: str, value: str) -> CredentialStorageAssessment:
        if not value:
            return CredentialStorageAssessment.EMPTY
        if marker == "plaintext":
            return CredentialStorageAssessment.PLAINTEXT
        if marker == "encrypted":
            return CredentialStorageAssessment.WEAK_HASH
        if marker == "pbkdf2":
            return CredentialStorageAssessment.APPROVED_HASH
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
            if value.casefold() in {"cisco", "cisco123", "admin", "password"}
            else DefaultCredentialAssessment.NO_MATCH
        )

    def get_enable_credential(self) -> Optional[ASACredential]:
        selected: Optional[ASACredential] = None
        for line_number, line in enumerate(self._source_lines, start=1):
            stripped = line.strip()
            if stripped == "no enable password":
                selected = None
                continue
            match = re.fullmatch(r"enable password(?:\s+(\S+))?(?:\s+(encrypted|pbkdf2))?", stripped)
            if not match:
                continue
            value = match.group(1) or ""
            marker = (match.group(2) or "").lower()
            storage_type = marker or "plaintext"
            storage = self._credential_assessment(storage_type, value)
            selected = CredentialMetadata(
                account="enable",
                context="enable",
                method="password",
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
                    f"enable password <redacted> {marker}".rstrip(),
                    self.config_filepath,
                    line_number,
                ),),
            )
        return selected

    def get_local_credentials(self) -> list[CredentialMetadata]:
        credentials: dict[str, CredentialMetadata] = {}
        for line_number, raw_line in enumerate(self._source_lines, start=1):
            stripped = raw_line.strip()
            removal = re.fullmatch(r"no\s+username\s+(\S+)(?:\s+.*)?", stripped, re.IGNORECASE)
            if removal:
                credentials.pop(removal.group(1).casefold(), None)
                continue
            try:
                tokens = shlex.split(stripped)
            except ValueError:
                continue
            lowered = [token.casefold() for token in tokens]
            if len(tokens) < 3 or lowered[0] != "username" or "password" not in lowered[2:]:
                continue
            account = tokens[1]
            password_index = lowered.index("password", 2)
            value = ""
            if password_index + 1 < len(tokens) and lowered[password_index + 1] not in {
                "encrypted", "pbkdf2", "privilege"
            }:
                value = tokens[password_index + 1]
            marker = next(
                (token for token in lowered[password_index + 1:] if token in {"encrypted", "pbkdf2"}),
                "plaintext",
            )
            storage = self._credential_assessment(marker, value)
            credentials[account.casefold()] = CredentialMetadata(
                account=account,
                context="local_user",
                method="password",
                storage_type=marker,
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
                    f"username {account} password <redacted> {marker}",
                    self.config_filepath,
                    line_number,
                ),),
            )
        return list(credentials.values())

    def get_credential_metadata(self) -> list[CredentialMetadata]:
        enable = self.get_enable_credential()
        return [*self.get_local_credentials(), *([enable] if enable else [])]

    def get_snmp_communities(self) -> list[str]:
        return [community.name for community in self.get_snmp_configuration()[0]]

    def get_snmp_configuration(
        self,
    ) -> tuple[list[ASASNMPCommunity], list[ASASNMPHost], list[ASASNMPUser]]:
        communities, hosts, _, users = self._get_snmp_state()
        return communities, hosts, users

    def get_snmpv3_relationships(
        self,
    ) -> tuple[list[ASASNMPGroup], list[ASASNMPUser]]:
        _, _, groups, users = self._get_snmp_state()
        return groups, users

    def _get_snmp_state(
        self,
    ) -> tuple[
        list[ASASNMPCommunity],
        list[ASASNMPHost],
        list[ASASNMPGroup],
        list[ASASNMPUser],
    ]:
        communities: dict[str, ASASNMPCommunity] = {}
        hosts: dict[tuple[str, str], ASASNMPHost] = {}
        groups: dict[str, ASASNMPGroup] = {}
        raw_users: dict[
            str, tuple[str, str, str, str, str, str, ConfigEvidence]
        ] = {}
        for line_number, raw_line in enumerate(self.parser.ioscfg, start=1):
            line = raw_line.strip()
            community = re.fullmatch(
                r"(?:(no)\s+)?snmp-server community\s+(\S+)(?:\s+(ro|rw))?",
                line,
                re.IGNORECASE,
            )
            if community:
                key = community.group(2)
                if community.group(1):
                    communities.pop(key, None)
                else:
                    access = (community.group(3) or "ro").lower()
                    communities[key] = ASASNMPCommunity(
                        name=key,
                        access=access,
                        raw_line_redacted=f"snmp-server community <redacted> {access}",
                    )
                continue

            host = re.fullmatch(
                r"(?:(no)\s+)?snmp-server host\s+(\S+)\s+(\S+)(?:\s+(.+))?",
                line,
                re.IGNORECASE,
            )
            if host:
                key = (host.group(2), host.group(3))
                if host.group(1):
                    hosts.pop(key, None)
                    continue
                options = (host.group(4) or "").split()
                lowered = [token.lower() for token in options]
                version = "unknown"
                if "version" in lowered and lowered.index("version") + 1 < len(lowered):
                    version = lowered[lowered.index("version") + 1]
                elif "v3" in lowered:
                    version = "3"
                hosts[key] = ASASNMPHost(
                    interface=host.group(2),
                    address=host.group(3),
                    version=version,
                    community_configured="community" in lowered,
                    principal=(
                        options[lowered.index("version") + 2]
                        if "version" in lowered
                        and lowered.index("version") + 2 < len(options)
                        and version in {"3", "v3"}
                        and lowered[lowered.index("version") + 2] not in {"auth", "noauth", "priv"}
                        else ""
                    ),
                    raw_line_redacted=f"snmp-server host {host.group(2)} {host.group(3)} <credentials redacted>",
                )
                continue

            group = re.fullmatch(
                r"(?:(no|default)\s+)?snmp-server group\s+(\S+)\s+v3(?:\s+(auth|noauth|priv))?",
                line,
                re.IGNORECASE,
            )
            if group:
                name = group.group(2)
                if group.group(1):
                    groups.pop(name.casefold(), None)
                else:
                    level = (group.group(3) or "noauth").casefold()
                    groups[name.casefold()] = ASASNMPGroup(
                        name=name,
                        security_level=level,
                        evidence=(ConfigEvidence(
                            f"snmp-server group {name} v3 {level}",
                            self.config_filepath,
                            line_number,
                        ),),
                    )
                continue

            removed_user = re.fullmatch(
                r"(?:no|default)\s+snmp-server user\s+(\S+)(?:\s+.*)?",
                line,
                re.IGNORECASE,
            )
            if removed_user:
                raw_users.pop(removed_user.group(1).casefold(), None)
                continue
            user = re.fullmatch(r"snmp-server user\s+(\S+)\s+(\S+)\s+(.+)", line, re.IGNORECASE)
            if not user:
                continue
            name, group_name = user.group(1), user.group(2)
            tokens = user.group(3).split()
            folded = [token.casefold() for token in tokens]
            if "v3" not in folded:
                continue

            def secret_option(keyword: str) -> tuple[str, str]:
                if keyword not in folded:
                    return "", "missing"
                index = folded.index(keyword) + 1
                if index >= len(folded):
                    return "", "unknown"
                algorithm = folded[index]
                index += 1
                if algorithm in {"sha-2", "sha2"} and index < len(folded) and folded[index] in {"224", "256", "384", "512"}:
                    algorithm = f"sha-{folded[index]}"
                    index += 1
                elif algorithm == "aes" and index < len(folded) and folded[index] in {"128", "192", "256"}:
                    algorithm = f"aes-{folded[index]}"
                    index += 1
                state = "present" if index < len(folded) and folded[index] not in {"auth", "priv"} else "unknown"
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
                    f"snmp-server user {name} {group_name} v3 auth "
                    f"{authentication or 'none'} <key {auth_state}> priv "
                    f"{privacy or 'none'} <key {privacy_state}>",
                    self.config_filepath,
                    line_number,
                ),
            )

        users = []
        for name, group_name, authentication, privacy, auth_state, privacy_state, evidence in raw_users.values():
            group = groups.get(group_name.casefold())
            scopes = tuple(
                f"{host.interface}:{host.address}"
                for host in hosts.values()
                if host.version in {"3", "v3"}
                and host.principal.casefold() == name.casefold()
            )
            users.append(ASASNMPUser(
                name=name,
                group=group_name,
                authentication=authentication,
                privacy=privacy,
                authentication_key_state=auth_state,
                privacy_key_state=privacy_state,
                group_security_level=group.security_level if group else "",
                group_resolved=group is not None,
                host_scopes=scopes,
                active=bool(scopes),
                evidence=(evidence,) + (group.evidence if group else ()),
            ))
        return list(communities.values()), list(hosts.values()), list(groups.values()), users

    def get_ssh_hosts(self) -> list[dict]:
        return [
            {"ip": grant.source, "mask": grant.mask, "interface": grant.interface}
            for grant in self.get_management_grants("ssh")
        ]

    def get_management_grants(self, protocol: str) -> list[ASAManagementGrant]:
        if protocol not in {"ssh", "telnet", "http"}:
            raise ValueError("protocol must be 'ssh', 'telnet', or 'http'")
        grants: dict[tuple[str, str, str], ASAManagementGrant] = {}
        for raw_line in self.parser.ioscfg:
            line = raw_line.strip()
            ipv4 = re.fullmatch(
                rf"(?:(no)\s+)?{protocol}\s+(\d+(?:\.\d+){{3}})\s+(\d+(?:\.\d+){{3}})\s+(\S+)",
                line,
            )
            ipv6 = re.fullmatch(
                rf"(?:(no)\s+)?{protocol}\s+([0-9a-fA-F:]+/\d+)\s+(\S+)",
                line,
            )
            if ipv4:
                key = (ipv4.group(2), ipv4.group(3), ipv4.group(4))
                if ipv4.group(1):
                    grants.pop(key, None)
                else:
                    grants[key] = ASAManagementGrant(
                        protocol, ipv4.group(2), ipv4.group(3), ipv4.group(4), "ipv4", line
                    )
            elif ipv6:
                key = (ipv6.group(2), "", ipv6.group(3))
                if ipv6.group(1):
                    grants.pop(key, None)
                else:
                    grants[key] = ASAManagementGrant(
                        protocol, ipv6.group(2), "", ipv6.group(3), "ipv6", line
                    )
        return list(grants.values())

    def get_logging_enabled(self) -> bool:
        enabled = False
        for line in self.parser.ioscfg:
            if line.strip() == "logging enable":
                enabled = True
            elif line.strip() == "no logging enable":
                enabled = False
        return enabled

    def get_logging_hosts(self) -> list[str]:
        hosts: dict[tuple[str, str], str] = {}
        expression = re.compile(r"(?:(no)\s+)?logging host\s+(\S+)\s+(\S+)(?:\s+.*)?")
        for raw_line in self.parser.ioscfg:
            line = raw_line.strip()
            match = expression.fullmatch(line)
            if not match:
                continue
            key = (match.group(2), match.group(3))
            if match.group(1):
                hosts.pop(key, None)
            else:
                hosts[key] = line
        return list(hosts.values())

    def get_logging_trap_level(self) -> Optional[str]:
        level: Optional[str] = None
        for raw_line in self.parser.ioscfg:
            line = raw_line.strip()
            match = re.fullmatch(r"logging trap\s+(\S+)", line)
            if match:
                level = match.group(1).lower()
            elif line == "no logging trap":
                level = None
        return level

    def get_ssl_min_version(self) -> str:
        return self.get_ssl_service_policy().server_minimum or ""

    def get_ssl_service_policy(self) -> ASASSLServicePolicy:
        """Resolve explicit SSL policy and interface-attached WebVPN service state."""
        configured_interfaces = {
            item["nameif"].casefold(): item["nameif"] for item in self.get_interfaces()
        }
        # Some vendor examples flatten subcommands while retaining `!` block
        # delimiters, which CiscoConfParse cannot represent as children.
        in_interface = False
        for source_line in self._source_lines:
            line = source_line.strip()
            if line.startswith("!"):
                in_interface = False
            elif re.fullmatch(r"interface\s+\S+", line, re.IGNORECASE):
                in_interface = True
            elif in_interface and (match := re.fullmatch(r"nameif\s+(\S+)", line, re.IGNORECASE)):
                configured_interfaces[match.group(1).casefold()] = match.group(1)
        active: dict[str, str] = {}
        server_minimum: str | None = None
        server_minimum_valid = True
        client_minimum: str | None = None
        legacy_cipher: str | None = None
        protocol_ciphers: dict[str, str] = {}
        evidence: list[ConfigEvidence] = []
        in_webvpn = False
        valid_server_versions = {
            "any", "sslv3", "sslv3-only", "tlsv1", "tlsv1-only",
            "tlsv1.1", "tlsv1.2", "tlsv1.3",
        }

        for line_number, source_line in enumerate(self._source_lines, start=1):
            line = source_line.strip()
            if not line:
                continue
            if line.startswith("!"):
                in_webvpn = False
                continue
            if line.casefold() == "webvpn":
                in_webvpn = True
                continue
            if line.casefold() == "no webvpn":
                active.clear()
                in_webvpn = False
                continue

            if in_webvpn:
                match = re.fullmatch(r"enable\s+(\S+)(?:\s+tls-only)?", line, re.IGNORECASE)
                if match:
                    key = match.group(1).casefold()
                    if key in configured_interfaces:
                        active[key] = line
                    continue
                match = re.fullmatch(r"no enable(?:\s+(\S+))?", line, re.IGNORECASE)
                if match:
                    if match.group(1):
                        active.pop(match.group(1).casefold(), None)
                    else:
                        active.clear()
                    continue

            match = re.fullmatch(r"ssl server-version\s+(\S+)(?:\s+\S+)?", line, re.IGNORECASE)
            if match:
                server_minimum = match.group(1).casefold()
                server_minimum_valid = server_minimum in valid_server_versions
                evidence.append(ConfigEvidence(line, self.config_filepath, line_number))
                continue
            if re.fullmatch(r"no ssl server-version(?:\s+.*)?", line, re.IGNORECASE):
                server_minimum = None
                server_minimum_valid = True
                continue
            match = re.fullmatch(r"ssl client-version\s+(\S+)", line, re.IGNORECASE)
            if match:
                client_minimum = match.group(1).casefold()
                evidence.append(ConfigEvidence(line, self.config_filepath, line_number))
                continue
            if re.fullmatch(r"no ssl client-version(?:\s+.*)?", line, re.IGNORECASE):
                client_minimum = None
                continue
            if re.fullmatch(r"ssl encryption\s+.+", line, re.IGNORECASE):
                legacy_cipher = line
                evidence.append(ConfigEvidence(line, self.config_filepath, line_number))
                continue
            if re.fullmatch(r"no ssl encryption(?:\s+.*)?", line, re.IGNORECASE):
                legacy_cipher = None
                continue
            match = re.fullmatch(r"ssl cipher\s+(\S+)\s+(.+)", line, re.IGNORECASE)
            if match:
                protocol_ciphers[match.group(1).casefold()] = line
                evidence.append(ConfigEvidence(line, self.config_filepath, line_number))
                continue
            match = re.fullmatch(r"no ssl cipher\s+(\S+)(?:\s+.*)?", line, re.IGNORECASE)
            if match:
                protocol_ciphers.pop(match.group(1).casefold(), None)

        weak: list[str] = []
        unknown: list[str] = []
        weak_tokens = ("des-sha1", "3des-sha1", "rc4", "null", "md5")
        if legacy_cipher and any(token in legacy_cipher.casefold().split() for token in weak_tokens):
            weak.append(legacy_cipher)
        for protocol, command in protocol_ciphers.items():
            if protocol == "default":
                continue
            setting = command.split(maxsplit=3)[3].strip().strip('"').casefold()
            if setting in {"all", "low", "medium"}:
                weak.append(command)
            elif setting in {"fips", "high"}:
                continue
            elif setting.startswith("custom ") or command.casefold().startswith(f"ssl cipher {protocol} custom"):
                suite = setting.removeprefix("custom ").strip('"')
                if any(token in suite for token in ("null", "rc4", "md5", "des-cbc", "3des", ":all", "all:")):
                    weak.append(command)
            else:
                unknown.append(command)

        for key, command in active.items():
            evidence.append(ConfigEvidence(command, self.config_filepath, None))
        return ASASSLServicePolicy(
            active_interfaces=tuple(configured_interfaces[key] for key in active),
            server_minimum=server_minimum,
            server_minimum_valid=server_minimum_valid,
            client_minimum=client_minimum,
            weak_cipher_commands=tuple(weak),
            unknown_cipher_commands=tuple(unknown),
            evidence=tuple(evidence),
        )

    def get_interfaces(self) -> list[dict]:
        interfaces = []
        int_blocks = self.parser.find_objects("^interface")
        for block in int_blocks:
            name = block.re_match_typed(r'^interface\s+(\S+)', default='')
            nameif = ""
            sec_level = -1
            
            # Sub-commands under interface
            for child in block.children:
                if "nameif" in child.text:
                    nameif = child.re_match_typed(r'^\s*nameif\s+(\S+)', default='')
                elif "security-level" in child.text:
                    sec_level_str = child.re_match_typed(r'^\s*security-level\s+(\d+)', default='')
                    sec_level = int(sec_level_str) if sec_level_str else -1
            
            if nameif:
                interfaces.append({
                    "name": name,
                    "nameif": nameif,
                    "security_level": sec_level
                })
        return interfaces

    def get_acl_bindings(self) -> list[dict]:
        bindings = {}
        for raw_line in self.parser.ioscfg:
            match = re.fullmatch(
                r'(no\s+)?access-group\s+(\S+)\s+(in|out)\s+interface\s+(\S+)',
                raw_line.strip(),
            )
            if match:
                key = (match.group(2), match.group(3), match.group(4))
                if match.group(1):
                    bindings.pop(key, None)
                else:
                    bindings[key] = {
                        "acl_name": match.group(2),
                        "direction": match.group(3),
                        "interface": match.group(4),
                    }
        return list(bindings.values())

    def get_acl_rules(self, acl_name: str) -> list[str]:
        # Fetch lines for specified access-list
        rules = []
        acl_lines = self.parser.find_objects(f"^access-list\\s+{acl_name}\\s")
        for line in acl_lines:
            rules.append(line.text)
        return rules

    @staticmethod
    def _consume_acl_address(tokens: list[str], index: int) -> tuple[str, int]:
        if index >= len(tokens):
            return "", index
        token = tokens[index].lower()
        if token in {"any", "any4", "any6"}:
            return token, index + 1
        if token in {"host", "object", "object-group", "interface"} and index + 1 < len(tokens):
            return f"{token} {tokens[index + 1]}", index + 2
        if index + 1 < len(tokens):
            return f"{tokens[index]} {tokens[index + 1]}", index + 2
        return tokens[index], index + 1

    def get_acl_entries(self, acl_name: Optional[str] = None) -> list[ASAACLEntry]:
        entries: dict[str, ASAACLEntry] = {}
        sequence = 0
        for raw_line in self.parser.ioscfg:
            line = raw_line.strip()
            negated = line.startswith("no access-list ")
            effective_line = line[3:] if negated else line
            if not effective_line.startswith("access-list "):
                continue
            try:
                tokens = shlex.split(effective_line)
            except ValueError:
                continue
            if len(tokens) == 2:
                if negated and (not acl_name or tokens[1] == acl_name):
                    entries = {
                        key: entry
                        for key, entry in entries.items()
                        if entry.acl_name != tokens[1]
                    }
                continue
            if len(tokens) < 5 or (acl_name and tokens[1] != acl_name):
                continue
            index = 2
            configured_line = None
            if index < len(tokens) and tokens[index] == "line":
                if index + 1 >= len(tokens) or not tokens[index + 1].isdigit():
                    continue
                configured_line = int(tokens[index + 1])
                index += 2
            if index >= len(tokens) or tokens[index] != "extended":
                continue
            index += 1
            if index >= len(tokens) or tokens[index] not in {"permit", "deny"}:
                continue
            action = tokens[index]
            index += 1
            if index >= len(tokens):
                continue
            protocol = tokens[index].lower()
            index += 1
            if protocol in {"object", "object-group"} and index < len(tokens):
                protocol = f"{protocol} {tokens[index]}"
                index += 1
            source, index = self._consume_acl_address(tokens, index)
            destination, index = self._consume_acl_address(tokens, index)
            tail = tokens[index:]
            lowered_tail = [token.casefold() for token in tail]
            option_indexes = [
                lowered_tail.index(option)
                for option in ("log", "time-range", "inactive")
                if option in lowered_tail
            ]
            qualifier_end = min(option_indexes, default=len(tail))
            qualifiers = tuple(lowered_tail[:qualifier_end])
            time_range = ""
            if "time-range" in lowered_tail:
                time_index = lowered_tail.index("time-range")
                if time_index + 1 < len(tail):
                    time_range = tail[time_index + 1]
            logging = "log" in lowered_tail and not (
                lowered_tail.index("log") + 1 < len(lowered_tail)
                and lowered_tail[lowered_tail.index("log") + 1] == "disable"
            )
            behavior_signature: tuple[str, ...] = ()
            if logging:
                log_index = lowered_tail.index("log")
                log_end = min(
                    (
                        lowered_tail.index(option, log_index + 1)
                        for option in ("time-range", "inactive")
                        if option in lowered_tail[log_index + 1 :]
                    ),
                    default=len(lowered_tail),
                )
                behavior_signature = tuple(lowered_tail[log_index:log_end])
            unsupported = tuple(
                token for token in lowered_tail
                if token in {"security-group", "user-group", "object-group-network-service"}
            )
            entry = ASAACLEntry(
                acl_name=tokens[1],
                action=action,
                protocol=protocol,
                source=source.lower(),
                destination=destination.lower(),
                inactive="inactive" in [token.lower() for token in tokens],
                raw_line=effective_line,
                service_qualifiers=qualifiers,
                time_range=time_range,
                logging=logging,
                behavior_signature=behavior_signature,
                unsupported_predicates=unsupported,
                configured_line=configured_line,
                sequence=sequence,
            )
            sequence += 1
            key = " ".join(tokens)
            if negated:
                entries.pop(key, None)
            else:
                entries[key] = entry
        return sorted(
            entries.values(),
            key=lambda item: (
                item.acl_name.casefold(),
                item.configured_line is None,
                item.configured_line if item.configured_line is not None else item.sequence,
                item.sequence,
            ),
        )

    def _acl_object_state(self) -> dict[str, dict]:
        """Reconstruct effective ASA network/service object definitions in source order."""

        if self._acl_object_cache is not None:
            return self._acl_object_cache
        state: dict[str, dict] = {
            "network_objects": {},
            "network_groups": {},
            "service_objects": {},
            "service_groups": {},
            "protocol_groups": {},
        }
        lines = self._source_lines
        index = 0
        while index < len(lines):
            raw = lines[index]
            if raw[:1].isspace() or not raw.strip():
                index += 1
                continue
            header = raw.strip()
            children: list[str] = []
            cursor = index + 1
            while cursor < len(lines) and lines[cursor][:1].isspace():
                if lines[cursor].strip():
                    children.append(lines[cursor].strip())
                cursor += 1

            removed = re.fullmatch(r"(?:no|clear configure) object network\s+(\S+)", header)
            if removed:
                state["network_objects"].pop(removed.group(1).casefold(), None)
                index = cursor
                continue
            removed = re.fullmatch(r"(?:no|clear configure) object service\s+(\S+)", header)
            if removed:
                state["service_objects"].pop(removed.group(1).casefold(), None)
                index = cursor
                continue
            removed = re.fullmatch(
                r"(?:no|clear configure) object-group (network|service|protocol)\s+(\S+)(?:\s+.*)?",
                header,
            )
            if removed:
                bucket = {
                    "network": "network_groups",
                    "service": "service_groups",
                    "protocol": "protocol_groups",
                }[removed.group(1)]
                state[bucket].pop(removed.group(2).casefold(), None)
                index = cursor
                continue

            network_object = re.fullmatch(r"object network\s+(\S+)", header)
            service_object = re.fullmatch(r"object service\s+(\S+)", header)
            network_group = re.fullmatch(r"object-group network\s+(\S+)", header)
            service_group = re.fullmatch(
                r"object-group service\s+(\S+)(?:\s+(tcp|udp|tcp-udp))?", header
            )
            protocol_group = re.fullmatch(r"object-group protocol\s+(\S+)", header)
            if network_object:
                key = network_object.group(1).casefold()
                definition = state["network_objects"].get(key)
                for child in children:
                    if re.fullmatch(r"(?:no|default) (?:host|subnet|range|fqdn)(?:\s+.*)?", child):
                        definition = None
                    elif child.split(maxsplit=1)[0].casefold() in {"host", "subnet", "range", "fqdn"}:
                        definition = child
                state["network_objects"][key] = definition
            elif service_object:
                key = service_object.group(1).casefold()
                definition = state["service_objects"].get(key)
                for child in children:
                    if re.fullmatch(r"(?:no|default) service(?:\s+.*)?", child):
                        definition = None
                    elif child.startswith("service "):
                        definition = child
                state["service_objects"][key] = definition
            elif network_group:
                key = network_group.group(1).casefold()
                members = list(state["network_groups"].get(key, ()))
                for child in children:
                    if child.startswith(("network-object ", "group-object ")):
                        if child not in members:
                            members.append(child)
                    elif child.startswith(("no network-object ", "no group-object ")):
                        positive = child[3:]
                        members = [item for item in members if item.casefold() != positive.casefold()]
                state["network_groups"][key] = tuple(members)
            elif service_group:
                key = service_group.group(1).casefold()
                data = state["service_groups"].setdefault(
                    key, {"protocol": None, "members": ()}
                )
                protocol = service_group.group(2) or data["protocol"]
                members = list(data["members"])
                for child in children:
                    if child.startswith(("service-object ", "port-object ", "group-object ")):
                        if child not in members:
                            members.append(child)
                    elif child.startswith(("no service-object ", "no port-object ", "no group-object ")):
                        positive = child[3:]
                        members = [item for item in members if item.casefold() != positive.casefold()]
                state["service_groups"][key] = {
                    "protocol": protocol,
                    "members": tuple(members),
                }
            elif protocol_group:
                key = protocol_group.group(1).casefold()
                members = list(state["protocol_groups"].get(key, ()))
                for child in children:
                    if child.startswith(("protocol-object ", "group-object ")):
                        if child not in members:
                            members.append(child)
                    elif child.startswith(("no protocol-object ", "no group-object ")):
                        positive = child[3:]
                        members = [item for item in members if item.casefold() != positive.casefold()]
                state["protocol_groups"][key] = tuple(members)
            index = cursor
        self._acl_object_cache = state
        return state

    @staticmethod
    def _network_literal(tokens: list[str]) -> NetworkSemantics | None:
        if not tokens:
            return None
        folded = [token.casefold() for token in tokens]
        if folded in (["any"], ["any4"]):
            return NetworkSemantics(intervals=(AddressInterval(4, 0, (1 << 32) - 1),))
        if folded == ["any6"]:
            return NetworkSemantics(intervals=(AddressInterval(6, 0, (1 << 128) - 1),))
        if folded[0] == "subnet":
            tokens, folded = tokens[1:], folded[1:]
        try:
            if len(tokens) == 2 and folded[0] == "host":
                address = ipaddress.ip_address(tokens[1])
                return NetworkSemantics(intervals=(AddressInterval(
                    address.version, int(address), int(address)
                ),))
            if len(tokens) == 3 and folded[0] == "range":
                first, last = ipaddress.ip_address(tokens[1]), ipaddress.ip_address(tokens[2])
                if first.version != last.version or int(first) > int(last):
                    return None
                return NetworkSemantics(intervals=(AddressInterval(
                    first.version, int(first), int(last)
                ),))
            if len(tokens) == 1:
                network = ipaddress.ip_network(tokens[0], strict=False)
                return NetworkSemantics(intervals=(AddressInterval(
                    network.version, int(network.network_address), int(network.broadcast_address)
                ),))
            if len(tokens) == 2 and folded[0] not in {
                "object", "object-group", "interface", "fqdn", "eq", "range", "lt", "gt", "neq"
            }:
                network = ipaddress.ip_network((tokens[0], tokens[1]), strict=False)
                return NetworkSemantics(intervals=(AddressInterval(
                    network.version, int(network.network_address), int(network.broadcast_address)
                ),))
        except ValueError:
            return None
        return None

    @staticmethod
    def _combine_network_semantics(
        items: list[NetworkSemantics], unresolved_default: str
    ) -> NetworkSemantics:
        intervals: list[AddressInterval] = []
        unresolved: list[str] = []
        for item in items:
            intervals.extend(item.intervals)
            unresolved.extend(item.unresolved)
            if not item.complete and not item.unresolved:
                unresolved.append(unresolved_default)
        if unresolved or not intervals:
            return NetworkSemantics(
                intervals=tuple(sorted(set(intervals))),
                complete=False,
                unresolved=tuple(dict.fromkeys(unresolved or (unresolved_default,))),
            )
        return NetworkSemantics(intervals=tuple(sorted(set(intervals))))

    def _resolve_acl_network_tokens(
        self,
        tokens: list[str],
        stack: frozenset[tuple[str, str]],
        budget: list[int],
    ) -> NetworkSemantics:
        literal = self._network_literal(tokens)
        if literal is not None:
            return literal
        if len(tokens) != 2 or tokens[0].casefold() not in {"object", "object-group"}:
            return NetworkSemantics(
                complete=False, unresolved=(" ".join(tokens) or "<empty-address>",)
            )
        kind = "object" if tokens[0].casefold() == "object" else "group"
        name = tokens[1]
        key = (kind, name.casefold())
        if key in stack or budget[0] <= 0:
            return NetworkSemantics(complete=False, unresolved=(name,))
        budget[0] -= 1
        state = self._acl_object_state()
        next_stack = stack | {key}
        if kind == "object":
            definition = state["network_objects"].get(name.casefold())
            if not definition or str(definition).casefold().startswith("fqdn "):
                return NetworkSemantics(complete=False, unresolved=(name,))
            resolved = self._network_literal(str(definition).split())
            return resolved or NetworkSemantics(complete=False, unresolved=(name,))
        members = state["network_groups"].get(name.casefold())
        if not members:
            return NetworkSemantics(complete=False, unresolved=(name,))
        results = []
        for member in members:
            member_tokens = member.split()
            if member_tokens[0].casefold() == "group-object" and len(member_tokens) == 2:
                target = ["object-group", member_tokens[1]]
            elif [item.casefold() for item in member_tokens[:2]] == ["network-object", "object"] and len(member_tokens) == 3:
                target = ["object", member_tokens[2]]
            elif member_tokens[0].casefold() == "network-object":
                target = member_tokens[1:]
            else:
                target = member_tokens
            results.append(self._resolve_acl_network_tokens(target, next_stack, budget))
        return self._combine_network_semantics(results, name)

    def resolve_acl_network(self, value: str) -> NetworkSemantics:
        """Resolve literal and bounded static ASA network objects/groups."""

        return self._resolve_acl_network_tokens(
            value.split(), frozenset(), [self._MAX_ACL_OBJECT_EXPANSION]
        )

    @classmethod
    def _port_number(cls, value: str) -> int | None:
        folded = value.casefold()
        if folded.isdigit():
            number = int(folded)
            return number if 0 <= number <= 65535 else None
        return cls._ASA_PORTS.get(folded)

    @classmethod
    def _port_ranges(cls, qualifiers: list[str]) -> tuple[tuple[int, int], ...] | None:
        if not qualifiers:
            return ((0, 65535),)
        operator = qualifiers[0].casefold()
        values = [cls._port_number(value) for value in qualifiers[1:]]
        if operator == "eq" and len(values) == 1 and values[0] is not None:
            return ((values[0], values[0]),)
        if operator == "range" and len(values) == 2 and None not in values and values[0] <= values[1]:
            return ((values[0], values[1]),)
        if operator == "lt" and len(values) == 1 and values[0] is not None and values[0] > 0:
            return ((0, values[0] - 1),)
        if operator == "gt" and len(values) == 1 and values[0] is not None and values[0] < 65535:
            return ((values[0] + 1, 65535),)
        if operator == "neq" and len(values) == 1 and values[0] is not None:
            result = []
            if values[0] > 0:
                result.append((0, values[0] - 1))
            if values[0] < 65535:
                result.append((values[0] + 1, 65535))
            return tuple(result) or None
        return None

    def _service_from_tokens(
        self,
        tokens: list[str],
        stack: frozenset[tuple[str, str]],
        budget: list[int],
        default_protocol: str | None = None,
    ) -> ServiceSemantics:
        if not tokens:
            return ServiceSemantics(complete=False, unresolved=("<empty-service>",))
        folded = [token.casefold() for token in tokens]
        if folded[0] in {"service", "service-object", "protocol-object", "port-object"}:
            command = folded.pop(0)
            tokens = tokens[1:]
            if command == "port-object":
                if default_protocol is None:
                    return ServiceSemantics(complete=False, unresolved=("port-object",))
                folded.insert(0, default_protocol.casefold())
                tokens.insert(0, default_protocol)
        if len(tokens) == 2 and folded[0] == "object":
            return self._resolve_acl_service_reference(
                "object", tokens[1], stack, budget
            )
        if len(tokens) == 2 and folded[0] == "object-group":
            return self._resolve_acl_service_reference(
                "group", tokens[1], stack, budget
            )
        protocol = folded[0]
        qualifiers = folded[1:]
        if protocol in {"ip", "any", "any4", "any6"} and not qualifiers:
            return ServiceSemantics(any=True)
        protocols = ("tcp", "udp") if protocol == "tcp-udp" else (protocol,)
        if "source" in qualifiers:
            return ServiceSemantics(
                complete=False, unresolved=(" ".join(tokens),)
            )
        if qualifiers[:1] == ["destination"]:
            qualifiers = qualifiers[1:]
        if protocol in {"tcp", "udp", "tcp-udp"}:
            ranges = self._port_ranges(qualifiers)
            if ranges is None:
                return ServiceSemantics(
                    complete=False, unresolved=(" ".join(tokens),)
                )
            return ServiceSemantics(intervals=tuple(
                ServiceInterval(member_protocol, first, last)
                for member_protocol in protocols
                for first, last in ranges
            ))
        if protocol in {"icmp", "icmp6", "ipv6-icmp"}:
            canonical = "icmp6" if protocol == "ipv6-icmp" else protocol
            if not qualifiers:
                return ServiceSemantics(intervals=(ServiceInterval(canonical, 0, 65535),))
            if len(qualifiers) == 1 and qualifiers[0].isdigit() and 0 <= int(qualifiers[0]) <= 255:
                value = int(qualifiers[0])
                return ServiceSemantics(intervals=(ServiceInterval(canonical, value, value),))
            return ServiceSemantics(complete=False, unresolved=(" ".join(tokens),))
        numeric_protocol = protocol.isdigit() and 0 <= int(protocol) <= 255
        if not qualifiers and (protocol in self._ASA_PROTOCOLS or numeric_protocol):
            canonical = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmp6"}.get(
                protocol, f"ip-{protocol}" if protocol.isdigit() else protocol
            )
            return ServiceSemantics(intervals=(ServiceInterval(canonical, 0, 65535),))
        return ServiceSemantics(complete=False, unresolved=(" ".join(tokens),))

    @staticmethod
    def _combine_service_semantics(
        items: list[ServiceSemantics], unresolved_default: str
    ) -> ServiceSemantics:
        intervals: list[ServiceInterval] = []
        unresolved: list[str] = []
        for item in items:
            if item.any:
                return ServiceSemantics(any=True)
            intervals.extend(item.intervals)
            unresolved.extend(item.unresolved)
            if not item.complete and not item.unresolved:
                unresolved.append(unresolved_default)
        if unresolved or not intervals:
            return ServiceSemantics(
                intervals=tuple(sorted(set(intervals))),
                complete=False,
                unresolved=tuple(dict.fromkeys(unresolved or (unresolved_default,))),
            )
        return ServiceSemantics(intervals=tuple(sorted(set(intervals))))

    def _resolve_acl_service_reference(
        self,
        kind: str,
        name: str,
        stack: frozenset[tuple[str, str]],
        budget: list[int],
    ) -> ServiceSemantics:
        key = (kind, name.casefold())
        if key in stack or budget[0] <= 0:
            return ServiceSemantics(complete=False, unresolved=(name,))
        budget[0] -= 1
        state = self._acl_object_state()
        next_stack = stack | {key}
        if kind == "object":
            definition = state["service_objects"].get(name.casefold())
            if not definition:
                return ServiceSemantics(complete=False, unresolved=(name,))
            return self._service_from_tokens(
                str(definition).split(), next_stack, budget
            )
        data = state["service_groups"].get(name.casefold())
        if data:
            members = data["members"]
            if not members:
                return ServiceSemantics(complete=False, unresolved=(name,))
            results = []
            for member in members:
                tokens = member.split()
                folded = [item.casefold() for item in tokens]
                if folded[:1] == ["group-object"] and len(tokens) == 2:
                    results.append(self._resolve_acl_service_reference(
                        "group", tokens[1], next_stack, budget
                    ))
                elif folded[:2] == ["service-object", "object"] and len(tokens) == 3:
                    results.append(self._resolve_acl_service_reference(
                        "object", tokens[2], next_stack, budget
                    ))
                else:
                    results.append(self._service_from_tokens(
                        tokens, next_stack, budget, data["protocol"]
                    ))
            return self._combine_service_semantics(results, name)
        members = state["protocol_groups"].get(name.casefold())
        if members:
            results = []
            for member in members:
                tokens = member.split()
                if [item.casefold() for item in tokens[:1]] == ["group-object"] and len(tokens) == 2:
                    results.append(self._resolve_acl_service_reference(
                        "group", tokens[1], next_stack, budget
                    ))
                else:
                    results.append(self._service_from_tokens(tokens, next_stack, budget))
            return self._combine_service_semantics(results, name)
        return ServiceSemantics(complete=False, unresolved=(name,))

    def resolve_acl_service(self, entry: ASAACLEntry) -> ServiceSemantics:
        """Resolve bounded ASA protocols, destination ports and static service groups."""

        if entry.unsupported_predicates:
            return ServiceSemantics(
                complete=False, unresolved=entry.unsupported_predicates
            )
        protocol_tokens = entry.protocol.split()
        if len(protocol_tokens) == 2 and protocol_tokens[0].casefold() == "object-group":
            if entry.service_qualifiers:
                return ServiceSemantics(
                    complete=False, unresolved=(entry.protocol,)
                )
            return self._resolve_acl_service_reference(
                "group", protocol_tokens[1], frozenset(),
                [self._MAX_ACL_OBJECT_EXPANSION],
            )
        if len(protocol_tokens) == 2 and protocol_tokens[0].casefold() == "object":
            if entry.service_qualifiers:
                return ServiceSemantics(complete=False, unresolved=(entry.protocol,))
            return self._resolve_acl_service_reference(
                "object", protocol_tokens[1], frozenset(),
                [self._MAX_ACL_OBJECT_EXPANSION],
            )
        qualifiers = list(entry.service_qualifiers)
        if len(qualifiers) == 2 and qualifiers[0] == "object-group":
            resolved = self._resolve_acl_service_reference(
                "group", qualifiers[1], frozenset(),
                [self._MAX_ACL_OBJECT_EXPANSION],
            )
            protocol = entry.protocol.casefold()
            if resolved.complete and not resolved.any and any(
                item.protocol.casefold() != protocol for item in resolved.intervals
            ):
                return ServiceSemantics(
                    complete=False, unresolved=(" ".join(qualifiers),)
                )
            return resolved
        return self._service_from_tokens(
            [entry.protocol, *qualifiers], frozenset(),
            [self._MAX_ACL_OBJECT_EXPANSION],
        )

    def get_normalized_config(self) -> NormalizedConfig:
        """Expose only ASA state already reconstructed by native parser methods."""

        hostname = self.get_hostname()
        version = self.get_version()

        management_services: list[ManagementService] = []
        for protocol in ("telnet", "ssh"):
            for grant in self.get_management_grants(protocol):
                source = (
                    grant.source
                    if grant.address_family == "ipv6"
                    else f"{grant.source} {grant.mask}"
                )
                management_services.append(ManagementService(
                    protocol=protocol,
                    state=ConfigurationState.ENABLED,
                    interface=grant.interface,
                    permitted_sources=(source,),
                    evidence=(ConfigEvidence(
                        f"{protocol} {source} {grant.interface}", self.config_filepath
                    ),),
                ))
        if self.get_http_server_enabled():
            for grant in self.get_management_grants("http"):
                source = (
                    grant.source
                    if grant.address_family == "ipv6"
                    else f"{grant.source} {grant.mask}"
                )
                management_services.append(ManagementService(
                    protocol="https",
                    state=ConfigurationState.ENABLED,
                    interface=grant.interface,
                    permitted_sources=(source,),
                    evidence=(ConfigEvidence(
                        f"http {source} {grant.interface}", self.config_filepath
                    ),),
                ))

        users = tuple(
            LocalUser(
                username=credential.account,
                state=ConfigurationState.CONFIGURED,
                privilege=next(
                    (
                        item["privilege"] for item in self.get_users()
                        if item["username"].casefold() == credential.account.casefold()
                    ),
                    None,
                ),
                authentication=credential.method,
                evidence=credential.evidence,
            )
            for credential in self.get_local_credentials()
        )

        interfaces: list[NetworkInterface] = []
        for block in self.parser.find_objects("^interface"):
            name = block.re_match_typed(r"^interface\s+(\S+)", default="")
            if not name:
                continue
            zone = ""
            addresses: list[str] = []
            state = ConfigurationState.UNKNOWN
            evidence = [ConfigEvidence(f"interface {name}", self.config_filepath)]
            for child in block.children:
                command = child.text.strip()
                match = re.fullmatch(r"nameif\s+(\S+)", command)
                if match:
                    zone = match.group(1)
                if command == "shutdown":
                    state = ConfigurationState.DISABLED
                elif command == "no shutdown":
                    state = ConfigurationState.ENABLED
                address = re.fullmatch(r"ip address\s+(\S+)\s+(\S+)(?:\s+.*)?", command)
                if address:
                    addresses.append(f"{address.group(1)} {address.group(2)}")
                ipv6 = re.fullmatch(r"ipv6 address\s+(\S+)(?:\s+.*)?", command)
                if ipv6:
                    addresses.append(ipv6.group(1))
            if zone:
                interfaces.append(NetworkInterface(
                    name=name,
                    state=state,
                    zone=zone,
                    addresses=tuple(addresses),
                    evidence=tuple(evidence),
                ))

        bindings: dict[str, list[dict]] = {}
        for binding in self.get_acl_bindings():
            bindings.setdefault(binding["acl_name"], []).append(binding)
        policies: list[SecurityPolicy] = []
        positions: dict[str, int] = {}
        for entry in self.get_acl_entries():
            positions[entry.acl_name] = positions.get(entry.acl_name, 0) + 1
            for binding in bindings.get(entry.acl_name, []):
                policies.append(SecurityPolicy(
                    name=f"{entry.acl_name}:{positions[entry.acl_name]}",
                    state=(
                        ConfigurationState.DISABLED
                        if entry.inactive else ConfigurationState.ENABLED
                    ),
                    action=entry.action,
                    position=positions[entry.acl_name],
                    scope=f"{binding['interface']}:{binding['direction']}",
                    source_interfaces=(binding["interface"],),
                    sources=(entry.source,),
                    destinations=(entry.destination,),
                    services=(entry.protocol,),
                    evidence=(ConfigEvidence(
                        re.sub(r"\s+", " ", entry.raw_line).strip(), self.config_filepath
                    ),),
                ))

        logging_destinations: list[LoggingDestination] = []
        for line in self.get_logging_hosts():
            match = re.fullmatch(r"logging host\s+(\S+)\s+(\S+)(?:\s+.*)?", line)
            if match:
                logging_destinations.append(LoggingDestination(
                    destination_type="syslog",
                    state=ConfigurationState.ENABLED,
                    address=match.group(2),
                    severity=self.get_logging_trap_level(),
                    scope=match.group(1),
                    evidence=(ConfigEvidence(
                        f"logging host {match.group(1)} {match.group(2)}",
                        self.config_filepath,
                    ),),
                ))

        ssl_version = self.get_ssl_min_version()
        crypto = (
            (CryptoSetting(
                name="ssl-server-minimum-version",
                value=ssl_version,
                state=ConfigurationState.CONFIGURED,
                evidence=(ConfigEvidence(
                    f"ssl server-version {ssl_version}", self.config_filepath
                ),),
            ),)
            if ssl_version else ()
        )
        return NormalizedConfig(
            device_type=self.device_type,
            hostname=(
                NormalizedValue.known(hostname)
                if hostname != "?" else NormalizedValue.unknown("Hostname is absent")
            ),
            device_model=NormalizedValue.unknown(
                "ASA hardware model is not parsed from the supported configuration export"
            ),
            software_version=(
                NormalizedValue.known(version)
                if version != "?" else NormalizedValue.unknown("ASA software version is absent")
            ),
            management_services=NormalizedCollection.known(*management_services),
            users=NormalizedCollection.known(*users),
            interfaces=NormalizedCollection.known(*interfaces),
            policies=NormalizedCollection.known(*policies),
            logging_destinations=NormalizedCollection.known(*logging_destinations),
            crypto_settings=NormalizedCollection.known(*crypto),
        )
