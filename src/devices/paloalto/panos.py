"""Scope-aware parser for PAN-OS XML configuration exports."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
import xml.etree.ElementTree as ET
from xml.parsers import expat
from typing import Any, Iterable

from src.common.certificates import (
    CertificateAssessment,
    CertificateMetadata,
    assess_public_certificate,
    certificate_metadata,
    load_public_certificate,
)
from src.devices.common.policy_semantics import (
    AddressInterval,
    NetworkSemantics,
    ServiceInterval,
    ServiceSemantics,
)
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.common.input_scope import contains_unresolved_template
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


@dataclass(frozen=True)
class PanosManagementProfile:
    name: str
    scope: str
    protocols: tuple[str, ...]
    permitted_sources: tuple[str, ...]
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class PanosInterface:
    name: str
    device_scope: str
    scope: str
    zone: str
    management_profile: str
    enabled: bool
    addresses: tuple[str, ...]
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class PanosZoneProtection:
    device_scope: str
    vsys: str
    zone: str
    interfaces: tuple[str, ...]
    profile: str
    resolution_state: str
    syn_flood_state: str
    disabled_other_floods: tuple[str, ...]
    allowed_scans: tuple[str, ...]
    dos_alternative_possible: bool
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class PanosSecurityRule:
    name: str
    device_scope: str
    scope: str
    rulebase: str
    position: int
    enabled: bool
    action: str
    from_zones: tuple[str, ...]
    to_zones: tuple[str, ...]
    sources: tuple[str, ...]
    destinations: tuple[str, ...]
    applications: tuple[str, ...]
    services: tuple[str, ...]
    source_users: tuple[str, ...]
    categories: tuple[str, ...]
    schedule: str
    source_negated: bool
    destination_negated: bool
    log_start: bool
    log_end: bool
    log_setting: str
    profile_setting: tuple[str, ...]
    profile_group: str
    individual_profiles: tuple[tuple[str, str], ...]
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class PanosDefaultSecurityRule:
    name: str
    device_scope: str
    scope: str
    action: str
    resolution_state: str
    definition_scope: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class PanosAddressObject:
    name: str
    device_scope: str
    scope: str
    kind: str
    value: str
    members: tuple[str, ...]
    dynamic: bool
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class PanosServiceObject:
    name: str
    device_scope: str
    scope: str
    protocol: str
    destination_port: str
    source_port: str
    members: tuple[str, ...]
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class PanosInspectionProfile:
    """A resolved or unresolved security-profile reference used by an active rule."""

    profile_type: str
    name: str
    definition_scope: str
    resolution_state: str
    content_state: str
    actions: tuple[str, ...]
    evidence: tuple[ConfigEvidence, ...]
    threat_selectors: tuple[PanosThreatSelector, ...] = ()


@dataclass(frozen=True)
class PanosThreatSelector:
    name: str
    severities: tuple[str, ...]
    action: str
    broad_match: bool
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class PanosSecurityProfileGroup:
    name: str
    scope: str
    members: tuple[tuple[str, str], ...]
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class PanosSecurityInspection:
    rule_name: str
    rule_scope: str
    rule_position: int
    attachment_mode: str
    attachment_name: str
    resolution_state: str
    profiles: tuple[PanosInspectionProfile, ...]
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class PanosLogForwardingProfile:
    name: str
    scope: str
    syslog_servers: tuple[str, ...]
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class PanosPasswordPolicy:
    enabled: bool | None
    minimum_length: int | None
    minimum_uppercase: int | None
    minimum_lowercase: int | None
    minimum_numeric: int | None
    minimum_special: int | None
    history_count: int | None
    blocks_username: bool | None
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class PanosAdministratorPolicy:
    username: str
    role_type: str
    role: str
    role_resolution: str
    authentication_profile: str
    authentication_resolution: str
    authentication_method: str
    mfa_state: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class PanosAdministrativeSettings:
    device_scope: str
    authentication_profile: str
    authentication_resolution: str
    authentication_method: str
    mfa_state: str
    login_banner_configured: bool
    acknowledge_login_banner: bool | None
    idle_timeout_minutes: int | None
    idle_timeout_state: str
    failed_attempts: int | None
    failed_attempts_state: str
    lockout_minutes: int | None
    lockout_state: str
    max_session_count: int | None
    max_session_count_state: str
    max_session_minutes: int | None
    max_session_time_state: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class PanosSSHManagementPolicy:
    device_scope: str
    enabled: bool
    supported: bool
    selected_profile: str
    resolution_state: str
    ciphers: tuple[str, ...]
    key_exchanges: tuple[str, ...]
    macs: tuple[str, ...]
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class PanosSSLServiceProfile:
    name: str
    scope: str
    certificate: str
    minimum_version: str
    maximum_version: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class PanosManagementTLS:
    device_scope: str
    profile: str
    tls_mode: str
    certificate: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class PanosCertificateObject:
    """Public certificate-object state; private key content is never retained."""

    name: str
    scope: str
    public_material_state: str
    metadata: CertificateMetadata | None
    private_key_present: bool
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class PanosManagementCertificateBinding:
    device_scope: str
    certificate: str
    source: str
    object_scope: str | None
    resolution: str
    public_material_state: str
    assessment: CertificateAssessment | None
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class PanosUpdateSchedule:
    device_scope: str
    content_type: str
    recurrence: str
    action: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class PanosNTPAssociation:
    role: str
    address: str
    device_scope: str
    authentication: str
    key_id: str
    algorithm: str
    key_material_state: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class PanosSNMPUser:
    name: str
    device_scope: str
    authentication: str
    privacy: str
    authentication_key_state: str
    privacy_key_state: str
    evidence: tuple[ConfigEvidence, ...]


class PaloAltoPANOSParser(BaseDeviceParser):
    """Parse local firewall PAN-OS XML without inventing Panorama inheritance."""

    device_type = "PAN_OS"

    def __init__(self, config_filepath: str):
        super().__init__(config_filepath)
        self.tree, self._element_lines = self._parse_with_line_numbers(config_filepath)
        self.root = self.tree.getroot()
        for element in self.root.iter():
            element.tag = element.tag.rsplit("}", 1)[-1]
        self.template_unresolved = any(
            contains_unresolved_template(value)
            for element in self.root.iter()
            for value in (element.text or "", *element.attrib.values())
        )
        self.diagnostics: list[str] = []
        self.panorama_inheritance_unknown = bool(
            self.root.findall(".//device-group/entry")
            or self.root.findall(".//template/entry")
            or self.root.findall(".//template-stack/entry")
        )
        if self.panorama_inheritance_unknown:
            self.diagnostics.append(
                "Panorama device-group/template inheritance is present and is not resolved by an individual-file audit"
            )

    @staticmethod
    def _parse_with_line_numbers(config_filepath: str) -> tuple[ET.ElementTree, dict]:
        """Build the ElementTree and record each element's start line.

        ElementTree does not keep source positions, so expat drives a normal
        ``TreeBuilder``. Namespaced names use ElementTree's ``{uri}tag`` form;
        like ``ET.parse``, external entities are not resolved.
        """

        builder = ET.TreeBuilder()
        parser = expat.ParserCreate(namespace_separator="}")
        lines: dict = {}

        def qualified(name: str) -> str:
            return "{" + name if "}" in name else name

        def start(tag, attributes):
            element = builder.start(
                qualified(tag), {qualified(key): value for key, value in attributes.items()}
            )
            lines[element] = parser.CurrentLineNumber

        parser.StartElementHandler = start
        parser.EndElementHandler = lambda tag: builder.end(qualified(tag))
        parser.CharacterDataHandler = builder.data
        parser.buffer_text = True
        try:
            with open(config_filepath, "rb") as source:
                parser.ParseFile(source)
        except expat.ExpatError as error:
            raise ET.ParseError(str(error)) from error
        return ET.ElementTree(builder.close()), lines

    def _evidence(self, text: str, node: ET.Element | None = None) -> ConfigEvidence:
        """Evidence for ``text``, citing the start line of ``node`` when given."""

        return ConfigEvidence(
            text=text,
            source=self.config_filepath,
            line_number=self._element_lines.get(node) if node is not None else None,
        )

    @staticmethod
    def _text(node: ET.Element | None, default: str = "") -> str:
        return (node.text or "").strip() if node is not None else default

    @classmethod
    def _members(cls, parent: ET.Element, name: str) -> tuple[str, ...]:
        node = parent.find(name)
        if node is None:
            return ()
        values = tuple(filter(None, (cls._text(member) for member in node.findall("member"))))
        if values:
            return values
        text = cls._text(node)
        return (text,) if text else ()

    @classmethod
    def _yes(cls, parent: ET.Element, name: str) -> bool:
        return cls._text(parent.find(name)).casefold() == "yes"

    @staticmethod
    def _safe_int(value: str) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @classmethod
    def _element_values(cls, node: ET.Element | None) -> tuple[str, ...]:
        """Return PAN-OS list values from member nodes or enum child tags."""

        if node is None:
            return ()
        members = tuple(
            value
            for value in (cls._text(member) for member in node.findall("member"))
            if value
        )
        if members:
            return members
        children = tuple(
            child.tag
            for child in list(node)
            if child.tag not in {"member", "entry"}
        )
        if children:
            return children
        text = cls._text(node)
        return tuple(text.split()) if text else ()

    def _version_major(self) -> int | None:
        match = re.match(r"^(\d+)", self.get_version())
        return int(match.group(1)) if match else None

    def _device_entries(self) -> list[ET.Element]:
        return self.root.findall("./devices/entry") or self.root.findall(".//devices/entry")

    @staticmethod
    def _device_scope(entry: ET.Element) -> str:
        return entry.get("name") or "local-device"

    def get_hostname(self) -> str:
        for device in self._device_entries():
            value = self._text(device.find("./deviceconfig/system/hostname"))
            if value:
                return value
        return self._text(self.root.find(".//deviceconfig/system/hostname")) or "panos-device"

    def get_version(self) -> str:
        for candidate in (
            self.root.get("version", ""),
            self._text(self.root.find(".//deviceconfig/system/sw-version")),
            self._text(self.root.find(".//devices/entry/version")),
        ):
            if candidate:
                return candidate
        return "?"

    def _management_user_entries(self) -> list[ET.Element]:
        entries = list(self.root.findall("./mgt-config/users/entry"))
        entries.extend(
            self.root.findall(".//deviceconfig/system/mgt-config/users/entry")
        )
        return entries

    def _authentication_profile_entries(self) -> dict[str, list[ET.Element]]:
        profiles: dict[str, list[ET.Element]] = {}
        candidates = list(self.root.findall("./shared/authentication-profile/entry"))
        for device in self._device_entries():
            candidates.extend(device.findall("./vsys/entry/authentication-profile/entry"))
        for entry in candidates:
            name = entry.get("name") or ""
            if name:
                profiles.setdefault(name.casefold(), []).append(entry)
        return profiles

    def _authentication_sequence_entries(self) -> dict[str, list[ET.Element]]:
        sequences: dict[str, list[ET.Element]] = {}
        candidates = list(self.root.findall("./shared/authentication-sequence/entry"))
        for device in self._device_entries():
            candidates.extend(device.findall("./vsys/entry/authentication-sequence/entry"))
        for entry in candidates:
            name = entry.get("name") or ""
            if name:
                sequences.setdefault(name.casefold(), []).append(entry)
        return sequences

    @staticmethod
    def _authentication_method(entry: ET.Element) -> str:
        method = entry.find("method")
        if method is None or not list(method):
            return "unknown"
        return list(method)[0].tag.casefold()

    def _profile_mfa_state(self, entry: ET.Element, method: str) -> str:
        mfa_enabled = self._text(
            entry.find("./multi-factor-auth/mfa-enable")
        ).casefold()
        factors = self._element_values(entry.find("./multi-factor-auth/factors"))
        if mfa_enabled == "yes" and factors:
            return "configured"
        if mfa_enabled == "no":
            return "explicitly-disabled"
        if method in {"radius", "saml-idp", "cloud"}:
            return "external-unknown"
        return "not-configured"

    def _resolve_authentication_reference(
        self, name: str
    ) -> tuple[str, str, str, tuple[ConfigEvidence, ...]]:
        if not name:
            return "local", "local", "not-configured-local", ()
        profiles = self._authentication_profile_entries()
        sequences = self._authentication_sequence_entries()
        profile_matches = profiles.get(name.casefold(), [])
        sequence_matches = sequences.get(name.casefold(), [])
        if len(profile_matches) + len(sequence_matches) != 1:
            if profile_matches or sequence_matches:
                return "ambiguous", "unknown", "unknown", ()
            resolution = (
                "unknown-inherited"
                if self.panorama_inheritance_unknown
                else "unresolved"
            )
            return resolution, "unknown", "unknown", ()
        if profile_matches:
            profile = profile_matches[0]
            method = self._authentication_method(profile)
            mfa_state = self._profile_mfa_state(profile, method)
            return (
                "known",
                method,
                mfa_state,
                (self._evidence(
                    f"authentication-profile {name}; method {method}; MFA {mfa_state}"
                ),),
            )

        sequence = sequence_matches[0]
        member_names = self._element_values(
            sequence.find("authentication-profiles")
        )
        resolved_profiles = []
        for member in member_names:
            matches = profiles.get(member.casefold(), [])
            if len(matches) != 1:
                resolution = (
                    "unknown-inherited"
                    if self.panorama_inheritance_unknown
                    else "unresolved"
                )
                return resolution, "sequence", "unknown", (
                    self._evidence(
                        f"authentication-sequence {name}; unresolved member {member}"
                    ),
                )
            resolved_profiles.append(matches[0])
        if not resolved_profiles:
            return "unresolved", "sequence", "unknown", (
                self._evidence(f"authentication-sequence {name}; no profiles"),
            )
        methods = tuple(
            dict.fromkeys(self._authentication_method(item) for item in resolved_profiles)
        )
        mfa_states = tuple(
            self._profile_mfa_state(item, self._authentication_method(item))
            for item in resolved_profiles
        )
        mfa_state = (
            "configured"
            if all(state == "configured" for state in mfa_states)
            else "external-unknown"
            if any(state == "external-unknown" for state in mfa_states)
            else "not-configured"
        )
        return (
            "known",
            "sequence:" + ",".join(methods),
            mfa_state,
            (self._evidence(
                f"authentication-sequence {name}; methods {','.join(methods)}; MFA {mfa_state}"
            ),),
        )

    def get_administrator_policies(self) -> tuple[PanosAdministratorPolicy, ...]:
        """Resolve local administrator role and authentication-profile references."""

        custom_roles = {
            (entry.get("name") or "").casefold()
            for entry in self.root.findall("./mgt-config/roles/entry")
            if entry.get("name")
        }
        policies = []
        for entry in self._management_user_entries():
            username = entry.get("name") or "unnamed"
            role_node = entry.find("./permissions/role-based")
            role_type = "missing"
            role = ""
            role_resolution = "missing"
            if role_node is not None and list(role_node):
                selected = list(role_node)[0]
                if selected.tag == "custom":
                    role_type = "custom"
                    role = self._text(selected.find("profile"))
                    role_resolution = (
                        "known" if role and role.casefold() in custom_roles else "unresolved"
                    )
                else:
                    role_type = "dynamic"
                    role = selected.tag
                    role_resolution = "known"

            auth_profile = self._text(entry.find("authentication-profile"))
            (
                auth_resolution,
                auth_method,
                mfa_state,
                auth_evidence,
            ) = self._resolve_authentication_reference(auth_profile)
            evidence = [self._evidence(f"mgt-config user {username}", entry)]
            evidence.extend(auth_evidence)
            policies.append(
                PanosAdministratorPolicy(
                    username=username,
                    role_type=role_type,
                    role=role,
                    role_resolution=(
                        "unknown-inherited"
                        if role_resolution != "known" and self.panorama_inheritance_unknown
                        else role_resolution
                    ),
                    authentication_profile=auth_profile,
                    authentication_resolution=auth_resolution,
                    authentication_method=auth_method,
                    mfa_state=mfa_state,
                    evidence=tuple(evidence),
                )
            )
        return tuple(policies)

    def _local_users(self) -> list[LocalUser]:
        users = []
        for policy in self.get_administrator_policies():
            users.append(
                LocalUser(
                    username=policy.username,
                    state=ConfigurationState.ENABLED,
                    role=policy.role or None,
                    authentication=policy.authentication_profile or "local",
                    scope="management",
                    evidence=policy.evidence,
                )
            )
        return users

    def get_users(self) -> list[dict]:
        return [
            {
                "username": user.username,
                "role": user.role,
                "authentication": user.authentication,
                "scope": user.scope,
            }
            for user in self._local_users()
        ]

    def get_management_profiles(self) -> list[PanosManagementProfile]:
        profiles = []
        protocols = ("http", "https", "ssh", "telnet", "snmp", "ping")
        for device in self._device_entries():
            scope = self._device_scope(device)
            for entry in device.findall("./network/profiles/interface-management-profile/entry"):
                name = entry.get("name") or "unnamed"
                permitted = tuple(
                    filter(
                        None,
                        (
                            candidate.get("name") or self._text(candidate)
                            for candidate in entry.findall("./permitted-ip/entry")
                        ),
                    )
                )
                profiles.append(
                    PanosManagementProfile(
                        name=name,
                        scope=scope,
                        protocols=tuple(protocol for protocol in protocols if self._yes(entry, protocol)),
                        permitted_sources=permitted,
                        evidence=(self._evidence(f"{scope}: interface-management-profile {name}", entry),),
                    )
                )
        return profiles

    def _zone_map(self, device: ET.Element) -> dict[str, tuple[str, str]]:
        mapping: dict[str, tuple[str, str]] = {}
        for vsys in device.findall("./vsys/entry"):
            scope = vsys.get("name") or "vsys"
            for zone in vsys.findall("./zone/entry"):
                zone_name = zone.get("name") or ""
                for member in zone.findall("./network/*/member"):
                    interface = self._text(member)
                    if interface:
                        mapping[interface] = (scope, zone_name)
        return mapping

    def get_zone_protections(self) -> tuple[PanosZoneProtection, ...]:
        """Resolve local ingress-zone SYN flood settings without assuming defaults."""
        shared_profiles = {
            entry.get("name", ""): entry
            for entry in self.root.findall("./shared/network/profiles/zone-protection-profile/entry")
        }
        result: list[PanosZoneProtection] = []
        for device in self._device_entries():
            device_scope = self._device_scope(device)
            local_profiles = {
                entry.get("name", ""): entry
                for entry in device.findall("./network/profiles/zone-protection-profile/entry")
            }
            for vsys in device.findall("./vsys/entry"):
                vsys_name = vsys.get("name") or "vsys"
                dos_rules = vsys.findall("./rulebase/dos/rules/entry")
                dos_rules += vsys.findall("./pre-rulebase/dos/rules/entry")
                dos_rules += vsys.findall("./post-rulebase/dos/rules/entry")
                dos_alternative = any(
                    self._text(rule.find("disabled")).casefold() != "yes"
                    and (
                        rule.find("./action/protect") is not None
                        or self._text(rule.find("action")).casefold() == "protect"
                    )
                    for rule in dos_rules
                )
                for zone in vsys.findall("./zone/entry"):
                    zone_name = zone.get("name") or ""
                    if not zone_name:
                        continue
                    interfaces = tuple(dict.fromkeys(
                        self._text(member)
                        for member in zone.findall("./network/*/member")
                        if self._text(member)
                    ))
                    profile_name = self._text(zone.find("./network/zone-protection-profile"))
                    profile = local_profiles.get(profile_name)
                    if profile is None:
                        profile = shared_profiles.get(profile_name)
                    syn_state = "unknown"
                    disabled_other: tuple[str, ...] = ()
                    allowed_scans: tuple[str, ...] = ()
                    if profile is not None:
                        explicit = self._text(profile.find("./flood/tcp-syn/enable")).casefold()
                        if explicit in {"yes", "no"}:
                            syn_state = "enabled" if explicit == "yes" else "disabled"
                        disabled_other = tuple(
                            # Flood types named by the PAN-OS zone-protection profile.
                            flood_type for flood_type in ("udp", "icmp", "icmpv6", "other-ip")
                            if self._text(profile.find(
                                f"./flood/{flood_type}/enable"
                            )).casefold() == "no"
                        )
                        allowed_scans = tuple(
                            scan.get("name") or "unnamed"
                            for scan in profile.findall("./scan/entry")
                            if scan.find("./action/allow") is not None
                            or self._text(scan.find("action")).casefold() == "allow"
                        )
                    result.append(PanosZoneProtection(
                        device_scope=device_scope,
                        vsys=vsys_name,
                        zone=zone_name,
                        interfaces=interfaces,
                        profile=profile_name,
                        resolution_state="resolved" if profile is not None else (
                            "unbound" if not profile_name else "unresolved"
                        ),
                        syn_flood_state=syn_state,
                        disabled_other_floods=disabled_other,
                        allowed_scans=allowed_scans,
                        dos_alternative_possible=dos_alternative,
                        evidence=(self._evidence(
                            f"{device_scope}/{vsys_name}: zone {zone_name} interfaces "
                            f"{', '.join(interfaces) or 'unspecified'}; zone-protection-profile "
                            f"{profile_name or 'unbound'}",
                            zone,
                        ),) + ((self._evidence(
                            f"zone-protection-profile {profile_name}: flood tcp-syn enable no",
                            profile,
                        ),) if syn_state == "disabled" else ()) + tuple(
                            self._evidence(
                                f"zone-protection-profile {profile_name}: flood {flood_type} enable no",
                                profile,
                            ) for flood_type in disabled_other
                        ) + tuple(
                            self._evidence(
                                f"zone-protection-profile {profile_name}: scan {scan_name} action allow",
                                profile,
                            ) for scan_name in allowed_scans
                        ),
                    ))
        return tuple(result)

    @staticmethod
    def _interface_nodes(device: ET.Element) -> Iterable[ET.Element]:
        network = device.find("./network/interface")
        if network is None:
            return ()
        nodes: list[ET.Element] = []
        for family in list(network):
            parents = family.findall("entry")
            nodes.extend(parents)
            for parent in parents:
                nodes.extend(parent.findall("./layer3/units/entry"))
                nodes.extend(parent.findall("./layer2/units/entry"))
        return nodes

    def get_interfaces(self) -> list[PanosInterface]:
        interfaces = []
        for device in self._device_entries():
            device_scope = self._device_scope(device)
            zones = self._zone_map(device)
            for entry in self._interface_nodes(device):
                name = entry.get("name") or "unnamed"
                body = entry.find("layer3")
                if body is None:
                    body = entry.find("layer2")
                if body is None:
                    body = entry
                profile = self._text(body.find("interface-management-profile"))
                disabled = self._yes(entry, "disabled") or self._text(entry.find("link-state")).casefold() == "down"
                address_nodes = body.findall("./ip/entry") + body.findall("./ipv6/address/entry")
                addresses = tuple(
                    candidate.get("name") or self._text(candidate)
                    for candidate in address_nodes
                    if candidate.get("name") or self._text(candidate)
                )
                vsys_scope, zone = zones.get(name, (device_scope, ""))
                interfaces.append(
                    PanosInterface(
                        name=name,
                        device_scope=device_scope,
                        scope=vsys_scope,
                        zone=zone,
                        management_profile=profile,
                        enabled=not disabled,
                        addresses=addresses,
                        evidence=(self._evidence(f"{vsys_scope}: interface {name}", entry),),
                    )
                )
        return interfaces

    def get_services(self) -> dict:
        result = {"telnet": False, "ssh": False, "http": False, "https": False}
        for service in self.get_dedicated_management_services():
            if service.protocol in result:
                result[service.protocol] = True
        profiles = self.get_management_profiles()
        for interface in self.get_interfaces():
            if not interface.enabled or not interface.management_profile:
                continue
            profile = next(
                (
                    item
                    for item in profiles
                    if item.scope == interface.device_scope
                    and item.name == interface.management_profile
                ),
                None,
            )
            if profile:
                for protocol in result:
                    result[protocol] = result[protocol] or protocol in profile.protocols
        return result

    def get_policy_address_objects(self) -> tuple[PanosAddressObject, ...]:
        """Return local-vsys and shared address objects without resolving dynamics."""
        result: list[PanosAddressObject] = []

        def collect(parent: ET.Element, device_scope: str, scope: str) -> None:
            for entry in parent.findall("./address/entry"):
                name = entry.get("name") or "<unnamed-address>"
                kind = value = ""
                for candidate in ("ip-netmask", "ip-range", "ip-wildcard", "fqdn"):
                    node = entry.find(candidate)
                    if node is not None:
                        kind, value = candidate, self._text(node)
                        break
                result.append(PanosAddressObject(
                    name, device_scope, scope, kind, value, (), False,
                    (self._evidence(f"{scope}: address object {name}", entry),),
                ))
            for entry in parent.findall("./address-group/entry"):
                name = entry.get("name") or "<unnamed-address-group>"
                result.append(PanosAddressObject(
                    name, device_scope, scope, "address-group", "",
                    self._members(entry, "static"), entry.find("dynamic") is not None,
                    (self._evidence(f"{scope}: address group {name}", entry),),
                ))

        shared = self.root.find("./shared")
        if shared is not None:
            collect(shared, "shared", "shared")
        for device in self._device_entries():
            device_scope = self._device_scope(device)
            for vsys in device.findall("./vsys/entry"):
                collect(vsys, device_scope, vsys.get("name") or "vsys")
        return tuple(result)

    def get_policy_service_objects(self) -> tuple[PanosServiceObject, ...]:
        """Return static TCP/UDP services and service groups by policy scope."""
        result: list[PanosServiceObject] = []

        def collect(parent: ET.Element, device_scope: str, scope: str) -> None:
            for entry in parent.findall("./service/entry"):
                name = entry.get("name") or "<unnamed-service>"
                protocol = destination_port = source_port = ""
                protocol_parent = entry.find("protocol")
                if protocol_parent is not None:
                    for candidate in ("tcp", "udp"):
                        node = protocol_parent.find(candidate)
                        if node is not None:
                            protocol = candidate
                            destination_port = self._text(node.find("port"))
                            source_port = self._text(node.find("source-port"))
                            break
                result.append(PanosServiceObject(
                    name, device_scope, scope, protocol, destination_port,
                    source_port, (), (self._evidence(f"{scope}: service object {name}", entry),),
                ))
            for entry in parent.findall("./service-group/entry"):
                name = entry.get("name") or "<unnamed-service-group>"
                result.append(PanosServiceObject(
                    name, device_scope, scope, "", "", "",
                    self._members(entry, "members"),
                    (self._evidence(f"{scope}: service group {name}", entry),),
                ))

        shared = self.root.find("./shared")
        if shared is not None:
            collect(shared, "shared", "shared")
        for device in self._device_entries():
            device_scope = self._device_scope(device)
            for vsys in device.findall("./vsys/entry"):
                collect(vsys, device_scope, vsys.get("name") or "vsys")
        return tuple(result)

    @staticmethod
    def _address_interval(value: str) -> AddressInterval | None:
        value = value.strip()
        try:
            if "-" in value:
                first_text, last_text = (part.strip() for part in value.split("-", 1))
                first, last = ipaddress.ip_address(first_text), ipaddress.ip_address(last_text)
                if first.version != last.version or int(first) > int(last):
                    return None
                return AddressInterval(first.version, int(first), int(last))
            network = ipaddress.ip_network(value, strict=False)
            return AddressInterval(network.version, int(network.network_address), int(network.broadcast_address))
        except ValueError:
            return None

    @staticmethod
    def _policy_port_intervals(value: str) -> tuple[tuple[int, int], ...] | None:
        intervals: list[tuple[int, int]] = []
        for part in (item.strip() for item in value.split(",")):
            if not part:
                return None
            bounds = tuple(item.strip() for item in part.split("-", 1))
            first_text, last_text = (bounds[0], bounds[-1])
            if not first_text.isdigit() or not last_text.isdigit():
                return None
            first, last = int(first_text), int(last_text)
            if not 0 <= first <= last <= 65535:
                return None
            intervals.append((first, last))
        return tuple(intervals) if intervals else None

    def resolve_network_semantics(
        self, names: tuple[str, ...], *, device_scope: str, scope: str,
        expansion_limit: int = 4096,
    ) -> NetworkSemantics:
        objects = self.get_policy_address_objects()
        shared = {item.name: item for item in objects if item.scope == "shared"}
        local = {item.name: item for item in objects if item.device_scope == device_scope and item.scope == scope}
        intervals: set[AddressInterval] = set()
        unresolved: set[str] = set()
        any_match = False
        visited = 0

        def visit(name: str, ancestors: frozenset[str]) -> None:
            nonlocal any_match, visited
            key = name.strip()
            if key.casefold() == "any":
                any_match = True
                return
            if not key:
                unresolved.add("<empty-network-reference>")
                return
            visited += 1
            if visited > expansion_limit:
                unresolved.add("<network-expansion-limit>")
                return
            if key in ancestors:
                unresolved.add(key)
                return
            literal = self._address_interval(key)
            if literal is not None:
                intervals.add(literal)
                return
            record = local.get(key) or shared.get(key)
            if record is None or record.dynamic or record.kind in {"fqdn", "ip-wildcard", ""}:
                unresolved.add(key)
                return
            if record.members:
                for member in record.members:
                    visit(member, ancestors | {key})
                return
            interval = self._address_interval(record.value)
            if interval is None:
                unresolved.add(key)
            else:
                intervals.add(interval)

        if not names:
            unresolved.add("<empty-network-dimension>")
        for name in names:
            visit(name, frozenset())
        return NetworkSemantics(any_match, tuple(sorted(intervals)), not unresolved, tuple(sorted(unresolved, key=str.casefold)))

    def resolve_service_semantics(
        self, names: tuple[str, ...], *, device_scope: str, scope: str,
        expansion_limit: int = 4096,
    ) -> ServiceSemantics:
        objects = self.get_policy_service_objects()
        shared = {item.name: item for item in objects if item.scope == "shared"}
        local = {item.name: item for item in objects if item.device_scope == device_scope and item.scope == scope}
        predefined = {
            "service-http": ServiceInterval("tcp", 80, 80),
            "service-https": ServiceInterval("tcp", 443, 443),
        }
        intervals: set[ServiceInterval] = set()
        unresolved: set[str] = set()
        any_match = False
        visited = 0

        def visit(name: str, ancestors: frozenset[str]) -> None:
            nonlocal any_match, visited
            key, folded = name.strip(), name.strip().casefold()
            if folded == "any":
                any_match = True
                return
            if not key:
                unresolved.add("<empty-service-reference>")
                return
            if folded == "application-default":
                unresolved.add(key)
                return
            visited += 1
            if visited > expansion_limit:
                unresolved.add("<service-expansion-limit>")
                return
            if key in ancestors:
                unresolved.add(key)
                return
            if folded in predefined:
                intervals.add(predefined[folded])
                return
            record = local.get(key) or shared.get(key)
            if record is None:
                unresolved.add(key)
                return
            if record.members:
                for member in record.members:
                    visit(member, ancestors | {key})
                return
            if record.protocol not in {"tcp", "udp"} or (record.source_port and record.source_port.casefold() != "any"):
                unresolved.add(key)
                return
            ports = self._policy_port_intervals(record.destination_port)
            if ports is None:
                unresolved.add(key)
                return
            intervals.update(ServiceInterval(record.protocol, first, last) for first, last in ports)

        if not names:
            unresolved.add("<empty-service-dimension>")
        for name in names:
            visit(name, frozenset())
        return ServiceSemantics(any_match, tuple(sorted(intervals)), not unresolved, tuple(sorted(unresolved, key=str.casefold)))

    def has_nat_policy(self) -> bool:
        return bool(
            self.root.findall(".//rulebase/nat/rules/entry")
            or self.root.findall(".//pre-rulebase/nat/rules/entry")
            or self.root.findall(".//post-rulebase/nat/rules/entry")
        )

    def get_security_rules(self) -> list[PanosSecurityRule]:
        rules = []
        for device in self._device_entries():
            device_scope = self._device_scope(device)
            for vsys in device.findall("./vsys/entry"):
                scope = vsys.get("name") or "vsys"
                rule_nodes: list[tuple[str, ET.Element]] = []
                for rulebase_name in ("rulebase", "pre-rulebase", "post-rulebase"):
                    rule_nodes.extend(
                        (rulebase_name, entry)
                        for entry in vsys.findall(f"./{rulebase_name}/security/rules/entry")
                    )
                for position, (rulebase_name, entry) in enumerate(rule_nodes, start=1):
                    name = entry.get("name") or f"rule-{position}"
                    profiles = []
                    profile_group = ""
                    individual_profiles: list[tuple[str, str]] = []
                    profile_setting = entry.find("profile-setting")
                    if profile_setting is not None:
                        group = profile_setting.find("group")
                        if group is not None:
                            group_members = self._members(profile_setting, "group")
                            profile_group = group_members[0] if group_members else ""
                        individual = profile_setting.find("profiles")
                        if individual is not None:
                            for profile_type in list(individual):
                                for member in profile_type.findall("member"):
                                    value = self._text(member)
                                    if value:
                                        individual_profiles.append((profile_type.tag, value))
                        for leaf in profile_setting.iter():
                            if leaf is profile_setting:
                                continue
                            value = self._text(leaf)
                            if leaf.tag == "member" and value:
                                profiles.append(value)
                            elif not list(leaf) and value:
                                profiles.append(f"{leaf.tag}:{value}")
                    rules.append(
                        PanosSecurityRule(
                            name=name,
                            device_scope=device_scope,
                            scope=scope,
                            rulebase=rulebase_name,
                            position=position,
                            enabled=not self._yes(entry, "disabled"),
                            action=self._text(entry.find("action"), "deny").casefold(),
                            from_zones=self._members(entry, "from"),
                            to_zones=self._members(entry, "to"),
                            sources=self._members(entry, "source"),
                            destinations=self._members(entry, "destination"),
                            applications=self._members(entry, "application"),
                            services=self._members(entry, "service"),
                            source_users=self._members(entry, "source-user"),
                            categories=self._members(entry, "category"),
                            schedule=self._text(entry.find("schedule"), "none"),
                            source_negated=self._yes(entry, "negate-source"),
                            destination_negated=self._yes(entry, "negate-destination"),
                            log_start=self._yes(entry, "log-start"),
                            log_end=self._yes(entry, "log-end"),
                            log_setting=self._text(entry.find("log-setting")),
                            profile_setting=tuple(profiles),
                            profile_group=profile_group,
                            individual_profiles=tuple(individual_profiles),
                            evidence=(self._evidence(
                                f"{device_scope}/{scope}/{rulebase_name}: security rule {position} {name}",
                                entry,
                            ),),
                        )
                    )
        return rules

    def get_default_security_rules(self) -> list[PanosDefaultSecurityRule]:
        """Resolve explicit default-rule overrides, local before shared.

        An unmerged Panorama export cannot establish an inherited default rule.
        The platform's implicit defaults are deliberately not synthesized here.
        """
        result: list[PanosDefaultSecurityRule] = []
        shared = self.root.findall(
            "./shared/default-security-rules/rules/entry[@name='interzone-default']"
        )
        for device in self._device_entries():
            device_scope = self._device_scope(device)
            for vsys in device.findall("./vsys/entry"):
                scope = vsys.get("name") or "vsys"
                local = vsys.findall(
                    "./rulebase/default-security-rules/rules/entry[@name='interzone-default']"
                )
                entries = local if local else shared
                if not entries:
                    continue
                definition_scope = scope if local else "shared"
                values = tuple(self._text(entry.find("action")).casefold() for entry in entries)
                action = values[0] if len(values) == 1 else ""
                state = (
                    "unknown-inherited"
                    if not local and self.panorama_inheritance_unknown
                    else "known"
                    if action in {"allow", "deny", "drop", "reset-client", "reset-server", "reset-both"}
                    else "unknown"
                )
                result.append(PanosDefaultSecurityRule(
                    name="interzone-default",
                    device_scope=device_scope,
                    scope=scope,
                    action=action if state == "known" else "",
                    resolution_state=state,
                    definition_scope=definition_scope,
                    evidence=(self._evidence(
                        f"{device_scope}/{scope}: interzone-default override in {definition_scope}; "
                        f"action {action or 'unresolved'}"
                    ),),
                ))
        return result

    @staticmethod
    def _profile_actions(entry: ET.Element) -> tuple[str, ...]:
        actions: list[str] = []
        for node in entry.iter():
            if node.tag != "action":
                continue
            value = (node.text or "").strip().casefold()
            if value:
                actions.append(value)
            for child in list(node):
                child_value = (child.text or "").strip().casefold()
                actions.append(child_value or child.tag.casefold())
        return tuple(dict.fromkeys(actions))

    def _profile_threat_selectors(
        self, scope: str, profile_type: str, profile_name: str, entry: ET.Element
    ) -> tuple[PanosThreatSelector, ...]:
        if profile_type not in {"spyware", "vulnerability"}:
            return ()
        result: list[PanosThreatSelector] = []
        for rule in entry.findall("./rules/entry"):
            name = rule.get("name") or "unnamed"
            severity = rule.find("severity")
            severities = tuple(dict.fromkeys(
                value.casefold() for value in (
                    [self._text(member) for member in severity.findall("member")]
                    if severity is not None and severity.findall("member") else
                    [child.tag for child in severity] if severity is not None and len(severity) else
                    [self._text(severity)] if severity is not None else []
                ) if value
            ))
            action_node = rule.find("action")
            if action_node is None:
                action = ""
            elif self._text(action_node):
                action = self._text(action_node).casefold()
            elif len(action_node) == 1:
                action = action_node[0].tag.casefold()
            else:
                action = ""
            # Only a selector with no narrower threat/category/host predicate
            # can establish the first applicable action for an entire severity.
            match_fields = {"threat-name", "category", "host", "cve", "vendor-id"}
            broad_match = all(
                child.tag in {"severity", "action", "packet-capture"} | match_fields
                for child in rule
            ) and all(
                (node := rule.find(field)) is None
                or (not list(node) and self._text(node).casefold() in {"", "any"})
                or (len(node) == 1 and node[0].tag.casefold() == "any")
                for field in match_fields
            )
            result.append(PanosThreatSelector(
                name=name,
                severities=severities,
                action=action,
                broad_match=broad_match,
                evidence=(self._evidence(
                    f"{scope}: {profile_type} profile {profile_name} selector {name}; "
                    f"severity {', '.join(severities)}; action {action or 'unresolved'}",
                    rule,
                ),),
            ))
        return tuple(result)

    @staticmethod
    def _profile_has_content(entry: ET.Element) -> bool:
        ignored = {"description", "tag"}
        return any(node.tag not in ignored for node in list(entry))

    def _shared_nodes(self, relative_path: str) -> list[ET.Element]:
        nodes = self.root.findall(f"./shared/{relative_path}")
        seen = {id(node) for node in nodes}
        for node in self.root.findall(f".//shared/{relative_path}"):
            if id(node) not in seen:
                nodes.append(node)
                seen.add(id(node))
        return nodes

    def get_security_profile_definitions(self) -> tuple[PanosInspectionProfile, ...]:
        definitions: list[PanosInspectionProfile] = []

        def add(scope: str, profile_type: str, entry: ET.Element) -> None:
            name = entry.get("name") or "unnamed"
            actions = self._profile_actions(entry)
            selectors = self._profile_threat_selectors(scope, profile_type, name, entry)
            if not self._profile_has_content(entry):
                content_state = "empty"
            elif actions and all(
                action in {"allow", "alert", "pass", "monitor"} for action in actions
            ):
                content_state = "nonblocking"
            else:
                content_state = "configured"
            definitions.append(
                PanosInspectionProfile(
                    profile_type=profile_type,
                    name=name,
                    definition_scope=scope,
                    resolution_state="resolved",
                    content_state=content_state,
                    actions=actions,
                    evidence=(self._evidence(f"{scope}: {profile_type} profile {name}", entry),),
                    threat_selectors=selectors,
                )
            )

        for profiles in self._shared_nodes("profiles"):
            for profile_type in list(profiles):
                for entry in profile_type.findall("entry"):
                    add("shared", profile_type.tag, entry)
        for device in self._device_entries():
            for vsys in device.findall("./vsys/entry"):
                scope = vsys.get("name") or "vsys"
                profiles = vsys.find("profiles")
                if profiles is None:
                    continue
                for profile_type in list(profiles):
                    for entry in profile_type.findall("entry"):
                        add(scope, profile_type.tag, entry)
        return tuple(definitions)

    def get_security_profile_groups(self) -> tuple[PanosSecurityProfileGroup, ...]:
        groups: list[PanosSecurityProfileGroup] = []

        def add(scope: str, entry: ET.Element) -> None:
            name = entry.get("name") or "unnamed"
            members: list[tuple[str, str]] = []
            for profile_type in list(entry):
                for member in profile_type.findall("member"):
                    value = self._text(member)
                    if value:
                        members.append((profile_type.tag, value))
            groups.append(
                PanosSecurityProfileGroup(
                    name=name,
                    scope=scope,
                    members=tuple(members),
                    evidence=(self._evidence(f"{scope}: security profile group {name}", entry),),
                )
            )

        for entry in self._shared_nodes("profile-group/entry"):
            add("shared", entry)
        for device in self._device_entries():
            for vsys in device.findall("./vsys/entry"):
                scope = vsys.get("name") or "vsys"
                for entry in vsys.findall("./profile-group/entry"):
                    add(scope, entry)
        return tuple(groups)

    def get_security_inspection(self) -> tuple[PanosSecurityInspection, ...]:
        """Resolve active allow-rule attachments without inferring Panorama state."""

        definitions = self.get_security_profile_definitions()
        groups = self.get_security_profile_groups()
        builtins = {"default", "strict"}

        def profile(profile_type: str, name: str, scope: str) -> PanosInspectionProfile:
            for candidate_scope in (scope, "shared"):
                match = next(
                    (
                        item
                        for item in definitions
                        if item.definition_scope == candidate_scope
                        and item.profile_type == profile_type
                        and item.name == name
                    ),
                    None,
                )
                if match is not None:
                    return match
            if name.casefold() in builtins:
                return PanosInspectionProfile(
                    profile_type=profile_type,
                    name=name,
                    definition_scope="builtin",
                    resolution_state="builtin",
                    content_state="vendor-default",
                    actions=(),
                    evidence=(),
                )
            state = "unknown-inherited" if self.panorama_inheritance_unknown else "unresolved"
            return PanosInspectionProfile(
                profile_type=profile_type,
                name=name,
                definition_scope="",
                resolution_state=state,
                content_state="unknown",
                actions=(),
                evidence=(),
            )

        inspections: list[PanosSecurityInspection] = []
        for rule in self.get_security_rules():
            if not rule.enabled or rule.action != "allow":
                continue
            if rule.profile_group:
                group = next(
                    (
                        item
                        for candidate_scope in (rule.scope, "shared")
                        for item in groups
                        if item.scope == candidate_scope and item.name == rule.profile_group
                    ),
                    None,
                )
                if group is None:
                    state = "unknown-inherited" if self.panorama_inheritance_unknown else "unresolved"
                    profiles: tuple[PanosInspectionProfile, ...] = ()
                    group_evidence: tuple[ConfigEvidence, ...] = ()
                else:
                    state = "empty" if not group.members else "resolved"
                    profiles = tuple(
                        profile(profile_type, name, rule.scope)
                        for profile_type, name in group.members
                    )
                    group_evidence = group.evidence
                inspections.append(
                    PanosSecurityInspection(
                        rule_name=rule.name,
                        rule_scope=rule.scope,
                        rule_position=rule.position,
                        attachment_mode="group",
                        attachment_name=rule.profile_group,
                        resolution_state=state,
                        profiles=profiles,
                        evidence=rule.evidence + group_evidence,
                    )
                )
            elif rule.individual_profiles:
                inspections.append(
                    PanosSecurityInspection(
                        rule_name=rule.name,
                        rule_scope=rule.scope,
                        rule_position=rule.position,
                        attachment_mode="profiles",
                        attachment_name="individual profiles",
                        resolution_state="resolved",
                        profiles=tuple(
                            profile(profile_type, name, rule.scope)
                            for profile_type, name in rule.individual_profiles
                        ),
                        evidence=rule.evidence,
                    )
                )
        return tuple(inspections)

    def get_log_forwarding_profiles(self) -> list[PanosLogForwardingProfile]:
        profiles = []
        for device in self._device_entries():
            for vsys in device.findall("./vsys/entry"):
                scope = vsys.get("name") or "vsys"
                for entry in vsys.findall("./log-settings/profiles/entry"):
                    name = entry.get("name") or "unnamed"
                    servers = tuple(
                        self._text(member)
                        for member in entry.findall("./match-list/entry/send-syslog/member")
                        if self._text(member)
                    )
                    profiles.append(
                        PanosLogForwardingProfile(
                            name=name,
                            scope=scope,
                            syslog_servers=servers,
                            evidence=(self._evidence(f"{scope}: log-forwarding profile {name}", entry),),
                        )
                    )
        return profiles

    def get_password_policy(self) -> PanosPasswordPolicy:
        # Exported firewall configurations place local administrator policy
        # below mgt-config; older focused fixtures use deviceconfig/system.
        node = self.root.find("./mgt-config/password-complexity")
        if node is None:
            node = self.root.find(".//deviceconfig/system/password-complexity")
        if node is None:
            return PanosPasswordPolicy(None, None, None, None, None, None, None, None, ())

        def number(name: str) -> int | None:
            return self._safe_int(self._text(node.find(name)))

        def yes_no(name: str) -> bool | None:
            value = self._text(node.find(name)).casefold()
            if value == "yes":
                return True
            if value == "no":
                return False
            return None

        history_count = number("password-history-count")
        if history_count is not None and not 0 <= history_count <= 50:
            history_count = None
        return PanosPasswordPolicy(
            enabled=yes_no("enabled"),
            minimum_length=number("minimum-length"),
            minimum_uppercase=number("minimum-uppercase-letters"),
            minimum_lowercase=number("minimum-lowercase-letters"),
            minimum_numeric=number("minimum-numeric-letters"),
            minimum_special=number("minimum-special-characters"),
            history_count=history_count,
            blocks_username=yes_no("block-username-inclusion"),
            evidence=(self._evidence("mgt-config password-complexity", node),),
        )

    def get_administrative_settings(self) -> tuple[PanosAdministrativeSettings, ...]:
        """Return explicit management authentication/session settings per device."""

        settings = []

        def bounded(
            parent: ET.Element | None, path: str, minimum: int, maximum: int
        ) -> tuple[int | None, str]:
            node = parent.find(path) if parent is not None else None
            if node is None:
                return None, (
                    "unknown-inherited"
                    if self.panorama_inheritance_unknown
                    else "absent"
                )
            value = self._safe_int(self._text(node))
            if value is None or not minimum <= value <= maximum:
                return None, "invalid"
            return value, "explicit"

        for device in self._device_entries():
            scope = self._device_scope(device)
            system = device.find("./deviceconfig/system")
            management = device.find("./deviceconfig/setting/management")
            login_banner = self._text(system.find("login-banner")) if system is not None else ""
            acknowledgement_value = (
                self._text(system.find("ack-login-banner")).casefold()
                if system is not None
                else ""
            )
            acknowledgement = (
                True
                if acknowledgement_value == "yes"
                else False
                if acknowledgement_value == "no"
                else None
            )
            authentication_profile = (
                self._text(system.find("authentication-profile"))
                if system is not None
                else ""
            )
            (
                authentication_resolution,
                authentication_method,
                mfa_state,
                authentication_evidence,
            ) = self._resolve_authentication_reference(authentication_profile)
            idle_timeout, idle_state = bounded(management, "idle-timeout", 0, 1440)
            failed_attempts, attempts_state = bounded(
                management, "./admin-lockout/failed-attempts", 0, 10
            )
            lockout, lockout_state = bounded(
                management, "./admin-lockout/lockout-time", 0, 60
            )
            session_count, count_state = bounded(
                management, "./admin-session/max-session-count", 0, 4
            )
            session_time, time_state = bounded(
                management, "./admin-session/max-session-time", 0, 1499
            )
            settings.append(
                PanosAdministrativeSettings(
                    device_scope=scope,
                    authentication_profile=authentication_profile,
                    authentication_resolution=authentication_resolution,
                    authentication_method=authentication_method,
                    mfa_state=mfa_state,
                    login_banner_configured=bool(login_banner),
                    acknowledge_login_banner=acknowledgement,
                    idle_timeout_minutes=idle_timeout,
                    idle_timeout_state=idle_state,
                    failed_attempts=failed_attempts,
                    failed_attempts_state=attempts_state,
                    lockout_minutes=lockout,
                    lockout_state=lockout_state,
                    max_session_count=session_count,
                    max_session_count_state=count_state,
                    max_session_minutes=session_time,
                    max_session_time_state=time_state,
                    evidence=(
                        self._evidence(f"{scope}: administrative management settings", management),
                    ) + authentication_evidence,
                )
            )
        return tuple(settings)

    def get_ssh_management_policies(self) -> tuple[PanosSSHManagementPolicy, ...]:
        """Resolve PAN-OS 10+ management SSH profile attachment and algorithms."""

        major = self._version_major()
        supported = major is not None and major >= 10
        enabled_scopes = {
            service.scope
            for service in self.get_dedicated_management_services()
            if service.protocol == "ssh"
        }
        management_profiles = self.get_management_profiles()
        for interface in self.get_interfaces():
            if not interface.enabled or not interface.management_profile:
                continue
            if any(
                profile.scope == interface.device_scope
                and profile.name == interface.management_profile
                and "ssh" in profile.protocols
                for profile in management_profiles
            ):
                enabled_scopes.add(interface.device_scope)
        policies = []
        for device in self._device_entries():
            scope = self._device_scope(device)
            system = device.find("./deviceconfig/system")
            ssh = system.find("ssh") if system is not None else None
            selected = self._text(ssh.find("./mgmt/server-profile")) if ssh is not None else ""
            definitions = {
                (entry.get("name") or "").casefold(): entry
                for entry in (
                    ssh.findall("./profiles/mgmt-profiles/server-profiles/entry")
                    if ssh is not None
                    else ()
                )
                if entry.get("name")
            }
            profile = definitions.get(selected.casefold()) if selected else None
            if not supported:
                resolution = "unsupported"
            elif not selected:
                resolution = (
                    "unknown-inherited"
                    if self.panorama_inheritance_unknown
                    else "missing"
                )
            elif profile is None:
                resolution = (
                    "unknown-inherited"
                    if self.panorama_inheritance_unknown
                    else "unresolved"
                )
            else:
                resolution = "known"
            evidence = [self._evidence(f"{scope}: management SSH profile {selected or 'absent'}", ssh)]
            policies.append(
                PanosSSHManagementPolicy(
                    device_scope=scope,
                    enabled=scope in enabled_scopes,
                    supported=supported,
                    selected_profile=selected,
                    resolution_state=resolution,
                    ciphers=self._element_values(profile.find("ciphers")) if profile is not None else (),
                    key_exchanges=self._element_values(profile.find("kex")) if profile is not None else (),
                    macs=self._element_values(profile.find("mac")) if profile is not None else (),
                    evidence=tuple(evidence),
                )
            )
        return tuple(policies)

    def get_ssl_tls_service_profiles(self) -> list[PanosSSLServiceProfile]:
        """Return shared and vsys-local SSL/TLS profiles without merging Panorama state."""

        profiles = []
        for entry in self.root.findall("./shared/ssl-tls-service-profile/entry"):
            name = entry.get("name") or "unnamed"
            profiles.append(
                PanosSSLServiceProfile(
                    name=name,
                    scope="shared",
                    certificate=self._text(entry.find("certificate")),
                    minimum_version=self._text(entry.find("./protocol-settings/min-version")).casefold(),
                    maximum_version=self._text(entry.find("./protocol-settings/max-version")).casefold(),
                    evidence=(self._evidence(f"shared: ssl-tls-service-profile {name}", entry),),
                )
            )
        for device in self._device_entries():
            for vsys in device.findall("./vsys/entry"):
                scope = vsys.get("name") or "vsys"
                for entry in vsys.findall("./ssl-tls-service-profile/entry"):
                    name = entry.get("name") or "unnamed"
                    profiles.append(
                        PanosSSLServiceProfile(
                            name=name,
                            scope=scope,
                            certificate=self._text(entry.find("certificate")),
                            minimum_version=self._text(entry.find("./protocol-settings/min-version")).casefold(),
                            maximum_version=self._text(entry.find("./protocol-settings/max-version")).casefold(),
                            evidence=(self._evidence(f"{scope}: ssl-tls-service-profile {name}", entry),),
                        )
                    )
        return profiles

    def get_management_tls(self) -> list[PanosManagementTLS]:
        settings = []
        for device in self._device_entries():
            system = device.find("./deviceconfig/system")
            if system is None:
                continue
            scope = self._device_scope(device)
            settings.append(
                PanosManagementTLS(
                    device_scope=scope,
                    profile=self._text(system.find("ssl-tls-service-profile")),
                    tls_mode=self._text(system.find("management-tls-mode")).casefold(),
                    certificate=self._text(system.find("management-tls-certificate")),
                    evidence=(self._evidence(f"{scope}: deviceconfig system management TLS", system),),
                )
            )
        return settings

    @staticmethod
    def _certificate_material(value: str) -> tuple[str, CertificateMetadata | None]:
        if not value.strip():
            return "missing", None
        try:
            parsed = load_public_certificate(value)
        except (TypeError, UnicodeEncodeError, ValueError):
            return "malformed", None
        return "parsed", certificate_metadata(parsed)

    def _certificate_entries(self):
        for entry in self.root.findall("./shared/certificate/entry"):
            yield "shared", entry
        for device in self._device_entries():
            device_scope = self._device_scope(device)
            for entry in device.findall("./certificate/entry"):
                yield device_scope, entry
            for vsys in device.findall("./vsys/entry"):
                for entry in vsys.findall("./certificate/entry"):
                    yield vsys.get("name") or "vsys", entry

    def get_certificate_objects(self) -> list[PanosCertificateObject]:
        """Return only public-material state and private-key presence, never key content."""

        objects = []

        for scope, entry in self._certificate_entries():
            name = entry.get("name") or "unnamed"
            state, metadata = self._certificate_material(self._text(entry.find("certificate")))
            objects.append(
                PanosCertificateObject(
                    name=name,
                    scope=scope,
                    public_material_state=state,
                    metadata=metadata,
                    private_key_present=bool(self._text(entry.find("private-key"))),
                    evidence=(self._evidence(f"{scope}: certificate object {name}", entry),),
                )
            )
        return objects

    def get_management_certificate_bindings(self) -> list[PanosManagementCertificateBinding]:
        profiles = {
            (profile.scope, profile.name): profile
            for profile in self.get_ssl_tls_service_profiles()
        }
        objects = self.get_certificate_objects()
        parsed_certificates = {}
        for scope, entry in self._certificate_entries():
            value = self._text(entry.find("certificate"))
            if not value:
                continue
            try:
                parsed_certificates[(scope, entry.get("name") or "unnamed")] = (
                    load_public_certificate(value)
                )
            except (TypeError, UnicodeEncodeError, ValueError):
                continue
        all_certificates = tuple(parsed_certificates.values())
        bindings = []
        for setting in self.get_management_tls():
            reference = setting.certificate
            source = "management-tls-certificate"
            evidence = setting.evidence
            if not reference and setting.profile:
                profile = profiles.get((setting.device_scope, setting.profile)) or profiles.get(
                    ("shared", setting.profile)
                )
                if profile is None:
                    continue
                reference = profile.certificate
                source = f"ssl-tls-service-profile {profile.name}"
                evidence += profile.evidence
            if not reference:
                continue
            candidates = [
                item for item in objects
                if item.name == reference and item.scope in {"shared", setting.device_scope}
            ]
            certificate = candidates[0] if candidates else None
            parsed_certificate = (
                parsed_certificates.get((certificate.scope, certificate.name))
                if certificate else None
            )
            assessment = None
            if parsed_certificate is not None:
                assessment = assess_public_certificate(
                    parsed_certificate,
                    all_certificates,
                    self.assessment_context.trusted_certificate_sha256,
                    self.assessment_context.management_identity_for_scope(setting.device_scope),
                    self.assessment_context.assessment_datetime(),
                )
            bindings.append(
                PanosManagementCertificateBinding(
                    device_scope=setting.device_scope,
                    certificate=reference,
                    source=source,
                    object_scope=certificate.scope if certificate else None,
                    resolution="resolved" if certificate else "unresolved",
                    public_material_state=(
                        certificate.public_material_state if certificate else "unknown"
                    ),
                    assessment=assessment,
                    evidence=evidence + (certificate.evidence if certificate else ()),
                )
            )
        return bindings

    def get_update_schedules(self) -> list[PanosUpdateSchedule]:
        schedules = []
        for device in self._device_entries():
            scope = self._device_scope(device)
            root = device.find("./deviceconfig/system/update-schedule")
            if root is None:
                continue
            for content_type in ("threats", "anti-virus", "wildfire", "wf-content"):
                recurring = root.find(f"./{content_type}/recurring")
                if recurring is None:
                    continue
                recurrence = ""
                action = ""
                for child in list(recurring):
                    if child.tag == "none":
                        recurrence = "none"
                        continue
                    recurrence = child.tag
                    action = self._text(child.find("action")).casefold()
                    break
                schedules.append(
                    PanosUpdateSchedule(
                        device_scope=scope,
                        content_type=content_type,
                        recurrence=recurrence,
                        action=action,
                        evidence=(self._evidence(f"{scope}: update-schedule {content_type} {recurrence or 'unresolved'} {action or 'no-action'}", recurring),),
                    )
                )
        return schedules

    def get_system_log_forwarding_destinations(self) -> tuple[str, ...]:
        destinations = []
        profiles = {}
        for parent in (
            self.root.find("./shared/log-settings/syslog"),
            self.root.find("./shared/server-profile/syslog"),
        ):
            if parent is None:
                continue
            for entry in parent.findall("./entry"):
                name = entry.get("name")
                if not name:
                    continue
                servers = tuple(
                    self._text(server.find("server"))
                    for server in entry.findall("./server/entry")
                    if self._text(server.find("server"))
                )
                profiles[name] = servers
        match_lists = [self.root.find("./shared/log-settings/system/match-list")]
        for device in self._device_entries():
            match_lists.append(device.find("./deviceconfig/system/log-settings/system/match-list"))
            for entry in device.findall("./deviceconfig/system/server-profile/syslog/entry"):
                name = entry.get("name")
                if name:
                    profiles[name] = tuple(
                        self._text(server.find("server"))
                        for server in entry.findall("./server/entry")
                        if self._text(server.find("server"))
                    )
        for match_list in match_lists:
            if match_list is None:
                continue
            for entry in match_list.findall("./entry"):
                if self._text(entry.find("disabled")).casefold() == "yes":
                    continue
                if self._text(entry.find("disable")).casefold() == "yes":
                    continue
                if self._text(entry.find("enabled")).casefold() == "no":
                    continue
                for member in entry.findall("./send-syslog/member"):
                    destinations.extend(profiles.get(self._text(member), ()))
        return tuple(dict.fromkeys(destinations))

    def get_dedicated_management_services(self) -> list[ManagementService]:
        """Return only explicitly enabled services on the dedicated MGT port."""

        services = []
        for device in self._device_entries():
            system = device.find("./deviceconfig/system")
            if system is None:
                continue
            permitted_sources = tuple(
                candidate.get("name") or self._text(candidate)
                for candidate in system.findall("./permitted-ip/entry")
                if candidate.get("name") or self._text(candidate)
            )
            service = system.find("service")
            if service is None:
                continue
            scope = self._device_scope(device)
            for protocol in ("http", "https", "ssh", "telnet", "snmp"):
                value = self._text(service.find(f"disable-{protocol}")).casefold()
                if value != "no":
                    continue
                services.append(
                    ManagementService(
                        protocol=protocol,
                        state=ConfigurationState.ENABLED,
                        interface="MGT",
                        zone="management",
                        scope=scope,
                        permitted_sources=permitted_sources,
                        evidence=(self._evidence(f"{scope}: MGT disable-{protocol} no", service),),
                    )
                )
        return services

    @staticmethod
    def _release_tuple(version: str) -> tuple[int, int, int] | None:
        match = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", version)
        return (
            (int(match.group(1)), int(match.group(2)), int(match.group(3) or 0))
            if match
            else None
        )

    def supports_modern_ntp_algorithms(self) -> bool | None:
        release = self._release_tuple(self.get_version())
        return None if release is None else release >= (12, 1, 2)

    def get_ntp_associations(self) -> list[PanosNTPAssociation]:
        associations = []
        for device in self._device_entries():
            scope = self._device_scope(device)
            for role in ("primary", "secondary"):
                server = device.find(
                    f"./deviceconfig/system/ntp-servers/{role}-ntp-server"
                )
                if server is None:
                    continue
                address = self._text(server.find("ntp-server-address"))
                if not address:
                    continue
                authentication = "none"
                key_id = ""
                algorithm = ""
                key_material_state = "not-applicable"
                auth = server.find("authentication-type")
                if auth is not None:
                    symmetric = auth.find("symmetric-key")
                    if symmetric is not None:
                        authentication = "symmetric-key"
                        key_id = self._text(symmetric.find("key-id"))
                        algorithm_node = symmetric.find("algorithm")
                        algorithm = self._text(algorithm_node).casefold()
                        if not algorithm and algorithm_node is not None and list(algorithm_node):
                            algorithm = list(algorithm_node)[0].tag.casefold()
                        key_node = symmetric.find("authentication-key")
                        if key_node is None:
                            key_node = symmetric.find("key-value")
                        if key_node is None:
                            key_material_state = "missing"
                        elif self._text(key_node):
                            key_material_state = "present"
                        else:
                            key_material_state = "redacted-or-unexported"
                    elif auth.find("autokey") is not None:
                        authentication = "autokey"
                    elif auth.find("none") is None and list(auth):
                        authentication = "unknown"
                summary = f"{scope}: {role} NTP server {address}; authentication {authentication}"
                if authentication == "symmetric-key":
                    summary += (
                        f"; key-id {key_id or 'missing'}; algorithm {algorithm or 'missing'}; "
                        f"key material {key_material_state}"
                    )
                associations.append(PanosNTPAssociation(
                    role=role,
                    address=address,
                    device_scope=scope,
                    authentication=authentication,
                    key_id=key_id,
                    algorithm=algorithm,
                    key_material_state=key_material_state,
                    evidence=(self._evidence(summary, server),),
                ))
        return associations

    def get_ntp_servers(self) -> tuple[str, ...]:
        return tuple(item.address for item in self.get_ntp_associations())

    def get_dns_servers(self) -> tuple[str, ...]:
        servers = []
        for device in self._device_entries():
            for name in ("primary", "secondary"):
                value = self._text(
                    device.find(f"./deviceconfig/system/dns-setting/servers/{name}")
                )
                if value:
                    servers.append(value)
        return tuple(servers)

    def has_secure_snmpv3_user(self) -> bool:
        return any(
            user.authentication in {"sha", "sha-224", "sha-256", "sha-384", "sha-512"}
            and user.privacy in {"aes", "aes-192", "aes-256"}
            for user in self.get_snmpv3_users()
        )

    def get_snmpv3_users(self) -> list[PanosSNMPUser]:
        users = []
        for device in self._device_entries():
            scope = device.get("name", "local")
            for user in device.findall(
                "./deviceconfig/system/snmp-setting/access-setting/version/v3/users/entry"
            ):
                name = user.get("name", "unknown")
                authentication = self._text(user.find("authproto")).casefold()
                privacy = self._text(user.find("privproto")).casefold()

                def key_state(*names: str) -> str:
                    for field in names:
                        node = user.find(field)
                        if node is not None:
                            return "present" if self._text(node) else "redacted-or-unexported"
                    return "unknown"

                authentication_key_state = key_state("authpwd", "auth-password", "authentication-password")
                privacy_key_state = key_state("privpwd", "priv-password", "privacy-password")
                users.append(PanosSNMPUser(
                    name=name,
                    device_scope=scope,
                    authentication=authentication,
                    privacy=privacy,
                    authentication_key_state=authentication_key_state,
                    privacy_key_state=privacy_key_state,
                    evidence=(self._evidence(
                        f"{scope}: SNMPv3 user {name}; auth {authentication or 'unknown'} "
                        f"<key {authentication_key_state}>; priv {privacy or 'unknown'} "
                        f"<key {privacy_key_state}>",
                        user,
                    ),),
                ))
        return users

    def get_native_config(self) -> Any:
        return self.root

    def get_normalized_config(self) -> NormalizedConfig:
        hostname = self.get_hostname()
        version = self.get_version()
        profiles = self.get_management_profiles()
        interfaces = self.get_interfaces()
        services = self.get_dedicated_management_services()
        for interface in interfaces:
            if not interface.enabled or not interface.management_profile:
                continue
            profile = next(
                (
                    item
                    for item in profiles
                    if item.scope == interface.device_scope
                    and item.name == interface.management_profile
                ),
                None,
            )
            if profile is None:
                continue
            for protocol in profile.protocols:
                services.append(
                    ManagementService(
                        protocol=protocol,
                        state=ConfigurationState.ENABLED,
                        interface=interface.name,
                        zone=interface.zone or None,
                        scope=interface.scope,
                        permitted_sources=profile.permitted_sources,
                        evidence=profile.evidence + interface.evidence,
                    )
                )
        return NormalizedConfig(
            device_type=self.device_type,
            hostname=NormalizedValue.known(hostname, self._evidence(f"hostname {hostname}")),
            device_model=NormalizedValue.unknown("PAN-OS model metadata was not present"),
            software_version=(
                NormalizedValue.known(version, self._evidence(f"PAN-OS version {version}"))
                if version != "?"
                else NormalizedValue.unknown("PAN-OS version metadata was not present")
            ),
            management_services=NormalizedCollection.known(*services),
            users=NormalizedCollection.known(*self._local_users()),
            interfaces=NormalizedCollection.known(
                *(
                    NetworkInterface(
                        name=item.name,
                        state=ConfigurationState.ENABLED if item.enabled else ConfigurationState.DISABLED,
                        zone=item.zone or None,
                        scope=item.scope,
                        addresses=item.addresses,
                        evidence=item.evidence,
                    )
                    for item in interfaces
                )
            ),
            policies=NormalizedCollection.known(
                *(
                    SecurityPolicy(
                        name=rule.name,
                        state=ConfigurationState.ENABLED if rule.enabled else ConfigurationState.DISABLED,
                        action=rule.action,
                        position=rule.position,
                        scope=rule.scope,
                        source_interfaces=rule.from_zones,
                        destination_interfaces=rule.to_zones,
                        sources=rule.sources,
                        destinations=rule.destinations,
                        services=rule.services,
                        tracking=rule.log_setting or ("local" if rule.log_start or rule.log_end else None),
                        evidence=rule.evidence,
                    )
                    for rule in self.get_security_rules()
                )
            ),
            logging_destinations=NormalizedCollection.known(
                *(
                    LoggingDestination(
                        destination_type="syslog-profile-reference",
                        state=ConfigurationState.CONFIGURED,
                        address=server,
                        scope=profile.scope,
                        evidence=profile.evidence,
                    )
                    for profile in self.get_log_forwarding_profiles()
                    for server in profile.syslog_servers
                ),
                *(
                    LoggingDestination(
                        destination_type="system-syslog",
                        state=ConfigurationState.ENABLED,
                        address=server,
                        scope="shared",
                    )
                    for server in self.get_system_log_forwarding_destinations()
                ),
            ),
            crypto_settings=NormalizedCollection.known(
                *(
                    CryptoSetting(
                        name=f"ssl-tls-profile:{profile.name}:minimum-version",
                        value=profile.minimum_version or "unknown",
                        state=ConfigurationState.CONFIGURED,
                        scope=profile.scope,
                        evidence=profile.evidence,
                    )
                    for profile in self.get_ssl_tls_service_profiles()
                )
            ),
        )


__all__ = [
    "PaloAltoPANOSParser",
    "PanosAddressObject",
    "PanosInterface",
    "PanosLogForwardingProfile",
    "PanosManagementProfile",
    "PanosPasswordPolicy",
    "PanosSecurityRule",
    "PanosServiceObject",
    "PanosSSLServiceProfile",
    "PanosManagementTLS",
    "PanosCertificateObject",
    "PanosManagementCertificateBinding",
    "PanosNTPAssociation",
    "PanosUpdateSchedule",
]
