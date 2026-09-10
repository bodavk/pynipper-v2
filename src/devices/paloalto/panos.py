"""Scope-aware parser for PAN-OS XML configuration exports."""

from __future__ import annotations

from dataclasses import dataclass
import xml.etree.ElementTree as ET
from typing import Any, Iterable

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
class PanosUpdateSchedule:
    device_scope: str
    content_type: str
    recurrence: str
    action: str
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
                    profile_setting = entry.find("profile-setting")
                    if profile_setting is not None:
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
                            evidence=(self._evidence(f"{scope}: security rule {position} {name}"),),
                        )
                    )
        return rules

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

        block_username = self._text(node.find("block-username-inclusion"))
        return PanosPasswordPolicy(
            enabled=self._text(node.find("enabled")).casefold() == "yes",
            minimum_length=number("minimum-length"),
            minimum_uppercase=number("minimum-uppercase-letters"),
            minimum_lowercase=number("minimum-lowercase-letters"),
            minimum_numeric=number("minimum-numeric-letters"),
            minimum_special=number("minimum-special-characters"),
            history_count=number("password-history-count"),
            blocks_username=(block_username.casefold() == "yes") if block_username else None,
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

    def get_ntp_servers(self) -> tuple[str, ...]:
        servers = []
        for device in self._device_entries():
            for node in device.findall(
                "./deviceconfig/system/ntp-servers/*/ntp-server-address"
            ):
                value = self._text(node)
                if value:
                    servers.append(value)
        return tuple(servers)

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
        for user in self.root.findall(
            ".//deviceconfig/system/snmp-setting/access-setting/version/v3/users/entry"
        ):
            authentication = self._text(user.find("authproto")).casefold()
            privacy = self._text(user.find("privproto")).casefold()
            if authentication in {"sha", "sha-224", "sha-256", "sha-384", "sha-512"} and privacy in {
                "aes",
                "aes-192",
                "aes-256",
            }:
                return True
        return False

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
    "PanosUpdateSchedule",
]
