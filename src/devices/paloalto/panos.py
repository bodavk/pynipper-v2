"""Scope-aware parser for PAN-OS XML configuration exports."""

from __future__ import annotations

from dataclasses import dataclass
import re
import xml.etree.ElementTree as ET
from typing import Any, Iterable

from src.common.certificates import (
    CertificateAssessment,
    CertificateMetadata,
    assess_public_certificate,
    certificate_metadata,
    load_public_certificate,
)
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
class PanosSecurityRule:
    name: str
    scope: str
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
    log_start: bool
    log_end: bool
    log_setting: str
    profile_setting: tuple[str, ...]
    profile_group: str
    individual_profiles: tuple[tuple[str, str], ...]
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
        self.tree = ET.parse(config_filepath)
        self.root = self.tree.getroot()
        for element in self.root.iter():
            element.tag = element.tag.rsplit("}", 1)[-1]
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

    def _evidence(self, text: str) -> ConfigEvidence:
        return ConfigEvidence(text=text, source=self.config_filepath)

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

    def _local_users(self) -> list[LocalUser]:
        users = []
        entries = self.root.findall("./mgt-config/users/entry")
        entries += self.root.findall(".//deviceconfig/system/mgt-config/users/entry")
        for entry in entries:
            username = entry.get("name") or "unnamed"
            auth_profile = self._text(entry.find("authentication-profile"))
            role_node = entry.find("./permissions/role-based")
            role = list(role_node)[0].tag if role_node is not None and list(role_node) else ""
            users.append(
                LocalUser(
                    username=username,
                    state=ConfigurationState.ENABLED,
                    role=role or None,
                    authentication=auth_profile or "local",
                    scope="management",
                    evidence=(self._evidence(f"mgt-config user {username}"),),
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
                        evidence=(self._evidence(f"{scope}: interface-management-profile {name}"),),
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
                        evidence=(self._evidence(f"{vsys_scope}: interface {name}"),),
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

    def get_security_rules(self) -> list[PanosSecurityRule]:
        rules = []
        for device in self._device_entries():
            for vsys in device.findall("./vsys/entry"):
                scope = vsys.get("name") or "vsys"
                rule_nodes: list[ET.Element] = []
                for rulebase_name in ("rulebase", "pre-rulebase", "post-rulebase"):
                    rule_nodes.extend(vsys.findall(f"./{rulebase_name}/security/rules/entry"))
                for position, entry in enumerate(rule_nodes, start=1):
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
                            scope=scope,
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
                            log_start=self._yes(entry, "log-start"),
                            log_end=self._yes(entry, "log-end"),
                            log_setting=self._text(entry.find("log-setting")),
                            profile_setting=tuple(profiles),
                            profile_group=profile_group,
                            individual_profiles=tuple(individual_profiles),
                            evidence=(self._evidence(f"{scope}: security rule {position} {name}"),),
                        )
                    )
        return rules

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
                    evidence=(self._evidence(f"{scope}: {profile_type} profile {name}"),),
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
                    evidence=(self._evidence(f"{scope}: security profile group {name}"),),
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
                            evidence=(self._evidence(f"{scope}: log-forwarding profile {name}"),),
                        )
                    )
        return profiles

    def get_password_policy(self) -> PanosPasswordPolicy:
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
            evidence=(self._evidence("deviceconfig system password-complexity"),),
        )

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
                    evidence=(self._evidence(f"shared: ssl-tls-service-profile {name}"),),
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
                            evidence=(self._evidence(f"{scope}: ssl-tls-service-profile {name}"),),
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
                    evidence=(self._evidence(f"{scope}: deviceconfig system management TLS"),),
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
                    evidence=(self._evidence(f"{scope}: certificate object {name}"),),
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
                        evidence=(self._evidence(f"{scope}: update-schedule {content_type} {recurrence or 'unresolved'} {action or 'no-action'}"),),
                    )
                )
        return schedules

    def get_system_log_forwarding_destinations(self) -> tuple[str, ...]:
        destinations = []
        for device in self._device_entries():
            for member in device.findall(
                "./deviceconfig/system/log-settings/system/match-list/entry/send-syslog/member"
            ):
                value = self._text(member)
                if value:
                    destinations.append(value)
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
                        evidence=(self._evidence(f"{scope}: MGT disable-{protocol} no"),),
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
                    evidence=(self._evidence(summary),),
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
                        f"<key {privacy_key_state}>"
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
                )
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
    "PanosInterface",
    "PanosLogForwardingProfile",
    "PanosManagementProfile",
    "PanosPasswordPolicy",
    "PanosSecurityRule",
    "PanosSSLServiceProfile",
    "PanosManagementTLS",
    "PanosCertificateObject",
    "PanosManagementCertificateBinding",
    "PanosNTPAssociation",
    "PanosUpdateSchedule",
]
