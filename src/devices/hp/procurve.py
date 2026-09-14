"""Typed ArubaOS-Switch (formerly HP ProCurve) configuration parser."""

from __future__ import annotations

from dataclasses import dataclass
import re
import shlex
from typing import Any

from src.devices.common.base_parser import BaseDeviceParser
from src.devices.common.models import (
    ConfigEvidence,
    ConfigurationState,
    CryptoSetting,
    LocalUser,
    LoggingDestination,
    ManagementService,
    NormalizedCollection,
    NormalizedConfig,
    NormalizedValue,
)


@dataclass(frozen=True)
class HPCommand:
    text: str
    line_number: int


@dataclass(frozen=True)
class HPFeature:
    state: ConfigurationState
    evidence: tuple[ConfigEvidence, ...] = ()
    detail: str = ""


@dataclass(frozen=True)
class HPSnmpCommunity:
    name: str
    access: str
    restricted: bool
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class HPSnmpV3User:
    name: str
    authentication: str
    privacy: str
    authentication_key_state: str
    privacy_key_state: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class HPSNTPKey:
    key_id: str
    algorithm: str
    trusted: bool
    material_present: bool
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class HPSNTPAssociation:
    address: str
    priority: int | None
    version: int | None
    key_id: str
    authentication_state: str
    algorithm: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class HPPortProtection:
    port: str
    vlans: tuple[int, ...]
    tagged: bool
    active: bool
    role: str
    dhcp_trusted: bool
    arp_trusted: bool
    arp_protected: bool
    source_lockdown: bool
    port_security: bool
    evidence: tuple[ConfigEvidence, ...]


class HPProCurveParser(BaseDeviceParser):
    """Parse AOS-Switch running configuration, not AOS-CX syntax."""

    device_type = "HP_PROCURVE"
    _SUPPORTED_DEFAULT_RELEASE = re.compile(r"^(?:[A-Z]{2}\.)?16\.10\.", re.IGNORECASE)
    _DEFAULT_CRYPTO = {
        "cipher": {
            "aes128-cbc",
            "3des-cbc",
            "aes192-cbc",
            "aes256-cbc",
            "rijndael-cbc@lysator.liu.se",
            "aes128-ctr",
            "aes192-ctr",
            "aes256-ctr",
        },
        "kex": {
            "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384",
            "ecdh-sha2-nistp521",
            "diffie-hellman-group-exchange-sha256",
            "diffie-hellman-group14-sha1",
        },
        "mac": {
            "hmac-sha2-256",
            "hmac-md5",
            "hmac-sha1",
            "hmac-sha1-96",
            "hmac-md5-96",
        },
    }

    def __init__(self, config_filepath: str):
        super().__init__(config_filepath)
        with open(config_filepath, encoding="utf-8-sig") as config_file:
            raw_lines = tuple(config_file)
            self.raw_lines = raw_lines
            self.commands = tuple(
                HPCommand(line.strip(), number)
                for number, line in enumerate(raw_lines, start=1)
                if line.strip()
            )
        self.config = [command.text for command in self.commands]

    def _evidence(self, command: HPCommand, *, redact: bool = False) -> ConfigEvidence:
        text = command.text
        if redact:
            tokens = self._tokens(text)
            text = " ".join(tokens[:4] + ["<redacted>"]) if len(tokens) > 4 else "credential configured"
        return ConfigEvidence(text=text, source=self.config_filepath, line_number=command.line_number)

    @staticmethod
    def _tokens(line: str) -> list[str]:
        try:
            return shlex.split(line, posix=True)
        except ValueError:
            return line.split()

    def _last_fullmatch(self, pattern: str) -> tuple[HPCommand, re.Match[str]] | None:
        expression = re.compile(pattern, re.IGNORECASE)
        selected = None
        for command in self.commands:
            match = expression.fullmatch(command.text)
            if match:
                selected = (command, match)
        return selected

    def get_hostname(self) -> str:
        match = self._last_fullmatch(r'hostname\s+(?:"([^"]+)"|(\S+))')
        return (match[1].group(1) or match[1].group(2)) if match else "?"

    def get_model(self) -> str:
        for command in self.commands:
            match = re.search(r";\s*([A-Z]{1,3}\d{3,5}[A-Z]?)\s+Configuration Editor", command.text, re.IGNORECASE)
            if match:
                return match.group(1).upper()
        return "?"

    def get_version(self) -> str:
        for command in self.commands:
            match = re.search(r"Created on release\s+#([^\s;]+)", command.text, re.IGNORECASE)
            if match:
                return match.group(1)
            match = re.search(r"Software revision\s+([^\s,]+)", command.text, re.IGNORECASE)
            if match:
                return match.group(1)
        return "?"

    def has_supported_default_release(self) -> bool:
        return bool(self._SUPPORTED_DEFAULT_RELEASE.match(self.get_version()))

    def has_supported_sntp_release(self) -> bool:
        return bool(re.match(r"^(?:[A-Z]{2}\.)?16\.(?:10|11)\.", self.get_version(), re.IGNORECASE))

    def has_supported_layer2_release(self) -> bool:
        return bool(re.match(r"^(?:[A-Z]{2}\.)?16\.(?:10|11)\.", self.get_version(), re.IGNORECASE))

    @staticmethod
    def _expand_ports(value: str) -> set[str]:
        ports: set[str] = set()
        for part in re.split(r"[,\s]+", value.strip()):
            if not part:
                continue
            match = re.fullmatch(r"([A-Za-z]*)(\d+)-([A-Za-z]*)(\d+)", part)
            if match and (not match.group(3) or match.group(1).casefold() == match.group(3).casefold()):
                start, end = int(match.group(2)), int(match.group(4))
                if start <= end and end - start <= 512:
                    prefix = match.group(1) or match.group(3)
                    ports.update(f"{prefix}{number}" for number in range(start, end + 1))
            else:
                ports.add(part)
        return ports

    def get_port_protections(self) -> list[HPPortProtection]:
        """Resolve AOS-S VLAN membership and per-port Layer-2 trust controls."""

        memberships: dict[str, set[int]] = {}
        tagged: set[str] = set()
        current_vlan: int | None = None
        membership_evidence: dict[str, list[ConfigEvidence]] = {}
        for number, raw_line in enumerate(self.raw_lines, 1):
            stripped = raw_line.strip()
            vlan = re.fullmatch(r"vlan\s+(\d+)(?:\s+.*)?", stripped, re.IGNORECASE)
            if raw_line[:1].isspace() and current_vlan is not None:
                member = re.fullmatch(r"(tagged|untagged)\s+(.+)", stripped, re.IGNORECASE)
                if member:
                    for port in self._expand_ports(member.group(2)):
                        memberships.setdefault(port, set()).add(current_vlan)
                        membership_evidence.setdefault(port, []).append(ConfigEvidence(stripped, self.config_filepath, number))
                        if member.group(1).casefold() == "tagged":
                            tagged.add(port)
                    continue
            if raw_line[:1].isspace():
                continue
            current_vlan = int(vlan.group(1)) if vlan and 1 <= int(vlan.group(1)) <= 4094 else None
            if vlan:
                one_line = re.search(r"\b(tagged|untagged)\s+(.+)$", stripped, re.IGNORECASE)
                if one_line:
                    for port in self._expand_ports(one_line.group(2)):
                        memberships.setdefault(port, set()).add(current_vlan)
                        membership_evidence.setdefault(port, []).append(ConfigEvidence(stripped, self.config_filepath, number))
                        if one_line.group(1).casefold() == "tagged":
                            tagged.add(port)

        controls = {
            "dhcp_trusted": set(), "arp_trusted": set(),
            "source_lockdown": set(), "port_security": set(), "disabled": set(),
        }
        control_evidence: dict[str, list[ConfigEvidence]] = {}
        arp_vlans: set[int] = set()
        patterns = (
            ("dhcp_trusted", re.compile(r"(?P<no>no\s+)?dhcp-snooping trust\s+(?P<ports>.+)", re.I)),
            ("arp_trusted", re.compile(r"(?P<no>no\s+)?arp-protect trust\s+(?P<ports>.+)", re.I)),
            ("source_lockdown", re.compile(r"(?P<no>no\s+)?ip source-lockdown\s+(?P<ports>.+)", re.I)),
            ("port_security", re.compile(r"(?P<no>no\s+)?port-security\s+(?P<ports>\S+)(?:\s+.*)?", re.I)),
            ("disabled", re.compile(r"(?P<no>no\s+)?interface\s+(?P<ports>\S+)\s+disable", re.I)),
        )
        for command in self.commands:
            arp = re.fullmatch(r"(?P<no>no\s+)?arp-protect vlan\s+(?P<vlans>[0-9,-]+)", command.text, re.I)
            if arp:
                values = self._expand_vlan_specification(arp.group("vlans"))
                arp_vlans.difference_update(values) if arp.group("no") else arp_vlans.update(values)
                continue
            for name, expression in patterns:
                match = expression.fullmatch(command.text)
                if not match:
                    continue
                ports = self._expand_ports(match.group("ports"))
                controls[name].difference_update(ports) if match.group("no") else controls[name].update(ports)
                for port in ports:
                    control_evidence.setdefault(port, []).append(self._evidence(command))
                break

        ports = set(memberships) | {name for name, _ in self.assessment_context.interface_roles}
        return [
            HPPortProtection(
                port=port,
                vlans=tuple(sorted(memberships.get(port, set()))),
                tagged=port in tagged,
                active=port not in controls["disabled"],
                role=self.assessment_context.role_for_interface(port),
                dhcp_trusted=port in controls["dhcp_trusted"],
                arp_trusted=port in controls["arp_trusted"],
                arp_protected=bool(memberships.get(port, set()) & arp_vlans),
                source_lockdown=port in controls["source_lockdown"],
                port_security=port in controls["port_security"],
                evidence=tuple(membership_evidence.get(port, []) + control_evidence.get(port, [])),
            )
            for port in sorted(ports)
        ]

    def _feature(self, protocol: str) -> HPFeature:
        patterns = {
            "telnet": r"(?P<no>no\s+)?telnet-server",
            "ssh": r"(?P<no>no\s+)?ip\s+ssh",
            "http": r"(?P<no>no\s+)?web-management",
            "https": r"(?P<no>no\s+)?web-management\s+ssl(?:\s+port\s+\d+)?",
        }
        selected = self._last_fullmatch(patterns[protocol])
        if selected:
            command, match = selected
            return HPFeature(
                ConfigurationState.DISABLED if match.group("no") else ConfigurationState.ENABLED,
                (self._evidence(command),),
            )

        version = self.get_version()
        if self._SUPPORTED_DEFAULT_RELEASE.match(version):
            defaults = {
                "telnet": ConfigurationState.ENABLED,
                "http": ConfigurationState.ENABLED,
                "ssh": ConfigurationState.DISABLED,
                "https": ConfigurationState.DISABLED,
            }
            return HPFeature(
                defaults[protocol],
                (ConfigEvidence(f"AOS-S {version} documented default for {protocol}", self.config_filepath),),
                "AOS-S 16.10 documented default",
            )
        return HPFeature(ConfigurationState.UNKNOWN, detail="Release is absent or outside the supported AOS-S 16.10 default table")

    def get_service_states(self) -> dict[str, HPFeature]:
        return {protocol: self._feature(protocol) for protocol in ("telnet", "ssh", "http", "https")}

    def get_services(self) -> dict[str, bool | None]:
        return {
            protocol: True if feature.state == ConfigurationState.ENABLED else False if feature.state == ConfigurationState.DISABLED else None
            for protocol, feature in self.get_service_states().items()
        }

    def _local_users(self) -> list[LocalUser]:
        users = []
        expression = re.compile(
            r"password\s+(?P<role>manager|operator)(?:\s+user-name\s+(?P<name>\S+))?(?:\s+\S+.*)?",
            re.IGNORECASE,
        )
        for command in self.commands:
            match = expression.fullmatch(command.text)
            if not match:
                continue
            role = match.group("role").lower()
            users.append(
                LocalUser(
                    username=match.group("name") or role,
                    state=ConfigurationState.ENABLED,
                    role=role,
                    authentication="local-password",
                    scope="switch",
                    evidence=(self._evidence(command, redact=True),),
                )
            )
        return users

    def get_users(self) -> list[dict]:
        return [
            {"username": user.username, "role": user.role, "authentication": user.authentication}
            for user in self._local_users()
        ]

    def get_snmp_communities(self) -> list[HPSnmpCommunity]:
        communities: dict[str, HPSnmpCommunity] = {}
        expression = re.compile(r"(?P<no>no\s+)?snmp-server\s+community(?:\s+(?P<rest>.+))?", re.IGNORECASE)
        for command in self.commands:
            match = expression.fullmatch(command.text)
            if not match or not match.group("rest"):
                continue
            tokens = self._tokens(match.group("rest"))
            if not tokens:
                continue
            name = tokens[0]
            if match.group("no"):
                communities.pop(name.casefold(), None)
                continue
            lowered = {token.casefold() for token in tokens[1:]}
            access = "manager" if "manager" in lowered or "unrestricted" in lowered else "operator"
            communities[name.casefold()] = HPSnmpCommunity(
                name=name,
                access=access,
                restricted="restricted" in lowered and "unrestricted" not in lowered,
                evidence=(self._evidence(command, redact=True),),
            )
        return list(communities.values())

    def get_snmpv3_users(self) -> list[HPSnmpV3User]:
        users: dict[str, HPSnmpV3User] = {}
        expression = re.compile(r"(?P<no>no\s+)?snmpv3\s+user(?:\s+(?P<rest>.+))?", re.IGNORECASE)
        for command in self.commands:
            match = expression.fullmatch(command.text)
            if not match or not match.group("rest"):
                continue
            tokens = self._tokens(match.group("rest"))
            if not tokens:
                continue
            name = tokens[0]
            if match.group("no"):
                users.pop(name.casefold(), None)
                continue
            tail = tokens[1:]
            lowered = [token.casefold() for token in tail]

            def option(keyword: str, algorithms: set[str]) -> tuple[str, str]:
                if keyword not in lowered:
                    return "none", "missing"
                index = lowered.index(keyword) + 1
                if index >= len(lowered):
                    return "unknown", "unknown"
                if lowered[index] in algorithms:
                    algorithm = lowered[index]
                    index += 1
                else:
                    algorithm = "default-unknown"
                key_state = (
                    "present"
                    if index < len(lowered) and lowered[index] not in {"auth", "priv"}
                    else "unknown"
                )
                return algorithm, key_state

            auth, auth_state = option("auth", {"md5", "sha"})
            privacy, privacy_state = option("priv", {"des", "aes"})
            users[name.casefold()] = HPSnmpV3User(
                name=name,
                authentication=auth,
                privacy=privacy,
                authentication_key_state=auth_state,
                privacy_key_state=privacy_state,
                evidence=(ConfigEvidence(
                    f"snmpv3 user {name} auth {auth} <key {auth_state}> "
                    f"priv {privacy} <key {privacy_state}>",
                    self.config_filepath,
                    command.line_number,
                ),),
            )
        return list(users.values())

    def get_snmpv3_agent_state(self) -> bool | None:
        state = None
        for command in self.commands:
            if re.fullmatch(r"snmpv3\s+enable", command.text, re.IGNORECASE):
                state = True
            elif re.fullmatch(r"no\s+snmpv3\s+enable", command.text, re.IGNORECASE):
                state = False
        return state

    def get_ssh_algorithms(self) -> dict[str, HPFeature | tuple[str, ...]]:
        version = self.get_version()
        known_defaults = bool(self._SUPPORTED_DEFAULT_RELEASE.match(version))
        algorithms = {kind: set(values) if known_defaults else set() for kind, values in self._DEFAULT_CRYPTO.items()}
        seen = {kind: False for kind in algorithms}
        evidence: dict[str, list[ConfigEvidence]] = {kind: [] for kind in algorithms}
        expression = re.compile(r"(?P<no>no\s+)?ip\s+ssh\s+(?P<kind>cipher|kex|mac)\s+(?P<value>\S+)", re.IGNORECASE)
        for command in self.commands:
            match = expression.fullmatch(command.text)
            if not match:
                continue
            kind = match.group("kind").casefold()
            value = match.group("value").casefold()
            seen[kind] = True
            evidence[kind].append(self._evidence(command))
            if match.group("no"):
                algorithms[kind].discard(value)
            else:
                algorithms[kind].add(value)
        result: dict[str, HPFeature | tuple[str, ...]] = {}
        for kind in algorithms:
            if not known_defaults and not seen[kind]:
                result[f"{kind}_state"] = HPFeature(ConfigurationState.UNKNOWN, detail="No supported release/default or explicit algorithm command")
            else:
                result[f"{kind}_state"] = HPFeature(ConfigurationState.CONFIGURED, tuple(evidence[kind]))
            result[kind] = tuple(sorted(algorithms[kind]))
        return result

    def has_authorized_managers(self) -> bool:
        active: dict[str, bool] = {}
        expression = re.compile(r"(?P<no>no\s+)?ip\s+authorized-managers\s+(?P<source>\S+)(?:\s+.*)?", re.IGNORECASE)
        for command in self.commands:
            match = expression.fullmatch(command.text)
            if match:
                active[match.group("source")] = not bool(match.group("no"))
        return any(active.values())

    def get_remote_authentication(self) -> tuple[str, ...]:
        methods = set()
        for command in self.commands:
            match = re.fullmatch(r"aaa\s+authentication\s+(?:console|telnet|ssh|web|rest)\s+(?:login|enable)(?:\s+privilege-mode)?\s+(.+)", command.text, re.IGNORECASE)
            if match:
                tokens = {token.casefold() for token in self._tokens(match.group(1))}
                methods.update(tokens & {"radius", "tacacs"})
        return tuple(sorted(methods))

    def has_management_accounting(self) -> bool:
        active: dict[str, bool] = {}
        expression = re.compile(
            r"(?P<no>no\s+)?aaa\s+accounting\s+(?P<kind>exec|network|system|command)\s+.+\s+(?P<target>radius|syslog)",
            re.IGNORECASE,
        )
        for command in self.commands:
            match = expression.fullmatch(command.text)
            if match:
                active[match.group("kind").casefold()] = not bool(match.group("no"))
        return any(active.values())

    def get_password_configuration_control(self) -> HPFeature:
        selected = self._last_fullmatch(r"(?P<no>no\s+)?password\s+configuration-control")
        if selected:
            command, match = selected
            return HPFeature(
                ConfigurationState.DISABLED if match.group("no") else ConfigurationState.ENABLED,
                (self._evidence(command),),
            )
        if self.has_supported_default_release():
            return HPFeature(
                ConfigurationState.DISABLED,
                (ConfigEvidence("AOS-S 16.10 password configuration-control default is disabled", self.config_filepath),),
                "AOS-S 16.10 documented default",
            )
        return HPFeature(ConfigurationState.UNKNOWN, detail="Release is outside the supported AOS-S 16.10 default table")

    @staticmethod
    def _expand_vlan_specification(value: str) -> set[int]:
        vlans: set[int] = set()
        for part in value.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                start_text, end_text = part.split("-", 1)
                try:
                    start, end = int(start_text), int(end_text)
                except ValueError:
                    continue
                if 1 <= start <= end <= 4094:
                    vlans.update(range(start, end + 1))
                continue
            try:
                vlan = int(part)
            except ValueError:
                continue
            if 1 <= vlan <= 4094:
                vlans.add(vlan)
        return vlans

    def get_configured_vlans(self) -> tuple[int, ...]:
        active: set[int] = set()
        expression = re.compile(r"(?P<no>no\s+)?vlan\s+(?P<value>[0-9,-]+)(?:\s+.*)?", re.IGNORECASE)
        for command in self.commands:
            match = expression.fullmatch(command.text)
            if not match:
                continue
            values = self._expand_vlan_specification(match.group("value"))
            if match.group("no"):
                active.difference_update(values)
            else:
                active.update(values)
        return tuple(sorted(active))

    def get_dhcp_snooping_vlans(self) -> tuple[int, ...]:
        active: set[int] = set()
        expression = re.compile(r"(?P<no>no\s+)?dhcp-snooping\s+vlan\s+(?P<value>[0-9,-]+)", re.IGNORECASE)
        for command in self.commands:
            match = expression.fullmatch(command.text)
            if not match:
                continue
            values = self._expand_vlan_specification(match.group("value"))
            if match.group("no"):
                active.difference_update(values)
            else:
                active.update(values)
        return tuple(sorted(active))

    def get_logging_destinations(self) -> list[LoggingDestination]:
        destinations: dict[str, LoggingDestination] = {}
        expression = re.compile(r"(?P<no>no\s+)?logging\s+(?P<address>\S+)(?:\s+.*)?", re.IGNORECASE)
        for command in self.commands:
            match = expression.fullmatch(command.text)
            if not match or match.group("address").casefold() in {"facility", "severity", "origin-id"}:
                continue
            address = match.group("address")
            if match.group("no"):
                destinations.pop(address.casefold(), None)
            else:
                destinations[address.casefold()] = LoggingDestination(
                    destination_type="syslog",
                    state=ConfigurationState.ENABLED,
                    address=address,
                    scope="switch",
                    evidence=(self._evidence(command),),
                )
        return list(destinations.values())

    def get_sntp_keys(self) -> dict[str, HPSNTPKey]:
        keys: dict[str, HPSNTPKey] = {}
        for command in self.commands:
            removed = re.fullmatch(
                r"no\s+sntp\s+authentication\s+key-id\s+(\S+)",
                command.text,
                re.IGNORECASE,
            )
            if removed:
                keys.pop(removed.group(1), None)
                continue
            configured = re.fullmatch(
                r"sntp\s+authentication\s+key-id\s+(\S+)\s+"
                r"authentication-mode\s+(\S+)\s+(key-value|encrypted-key)\s+(\S+)"
                r"(?:\s+(trusted))?",
                command.text,
                re.IGNORECASE,
            )
            if not configured:
                continue
            key_id, algorithm, _, material, trusted = configured.groups()
            evidence = ConfigEvidence(
                f"sntp authentication key-id {key_id} authentication-mode "
                f"{algorithm.casefold()} <key redacted>{' trusted' if trusted else ''}",
                self.config_filepath,
                command.line_number,
            )
            keys[key_id] = HPSNTPKey(
                key_id=key_id,
                algorithm=algorithm.casefold(),
                trusted=bool(trusted),
                material_present=bool(material),
                evidence=(evidence,),
            )
        return keys

    def get_sntp_authentication_enabled(self) -> bool | None:
        enabled: bool | None = False if self.has_supported_sntp_release() else None
        for command in self.commands:
            if re.fullmatch(r"sntp authentication", command.text, re.IGNORECASE):
                enabled = True
            elif re.fullmatch(r"(?:no|default) sntp authentication", command.text, re.IGNORECASE):
                enabled = False
        return enabled

    @staticmethod
    def _sntp_server_parts(text: str) -> tuple[bool, int | None, str, int | None, str] | None:
        tokens = text.split()
        if tokens[:2] == ["sntp", "server"]:
            removed = False
            index = 2
        elif tokens[:3] == ["no", "sntp", "server"]:
            removed = True
            index = 3
        else:
            return None
        priority = None
        if index < len(tokens) and tokens[index].casefold() == "priority":
            if index + 1 >= len(tokens):
                return None
            try:
                priority = int(tokens[index + 1])
            except ValueError:
                return None
            index += 2
        if index >= len(tokens):
            return None
        address = tokens[index]
        tail = tokens[index + 1 :]
        version = None
        key_id = ""
        if tail and tail[0].isdigit():
            version = int(tail.pop(0))
        if "version" in [item.casefold() for item in tail]:
            value_index = [item.casefold() for item in tail].index("version") + 1
            if value_index < len(tail) and tail[value_index].isdigit():
                version = int(tail[value_index])
        if "key-id" in [item.casefold() for item in tail]:
            value_index = [item.casefold() for item in tail].index("key-id") + 1
            if value_index < len(tail):
                key_id = tail[value_index]
        return removed, priority, address, version, key_id

    def get_sntp_associations(self) -> list[HPSNTPAssociation]:
        active: dict[str, tuple[int | None, int | None, str, ConfigEvidence]] = {}
        for command in self.commands:
            parsed = self._sntp_server_parts(command.text.casefold())
            if parsed is None:
                continue
            removed, priority, address, version, key_id = parsed
            identity = address.casefold()
            if removed and key_id:
                if identity in active:
                    old_priority, old_version, _, _ = active[identity]
                    active[identity] = (
                        old_priority,
                        old_version,
                        "",
                        self._evidence(command),
                    )
            elif removed:
                active.pop(identity, None)
            else:
                active[identity] = (priority, version, key_id, self._evidence(command))
        keys = self.get_sntp_keys()
        authentication = self.get_sntp_authentication_enabled()
        associations = []
        for address, (priority, version, key_id, server_evidence) in active.items():
            key = keys.get(key_id)
            if authentication is None:
                state = "unknown"
            elif not authentication or not key_id:
                state = "unauthenticated"
            elif key is None or not key.trusted or not key.material_present:
                state = "unresolved"
            else:
                state = "authenticated"
            evidence = (server_evidence,) + (key.evidence if key else ())
            associations.append(HPSNTPAssociation(
                address=address,
                priority=priority,
                version=version,
                key_id=key_id,
                authentication_state=state,
                algorithm=key.algorithm if key else "",
                evidence=evidence,
            ))
        return associations

    def get_ntp_servers(self) -> tuple[str, ...]:
        return tuple(item.address for item in self.get_sntp_associations())

    def get_native_config(self) -> Any:
        return self.commands

    def get_normalized_config(self) -> NormalizedConfig:
        hostname = self.get_hostname()
        version = self.get_version()
        model = self.get_model()
        states = self.get_service_states()
        crypto = self.get_ssh_algorithms()
        return NormalizedConfig(
            device_type=self.device_type,
            hostname=NormalizedValue.known(hostname) if hostname != "?" else NormalizedValue.unknown("Hostname absent"),
            device_model=NormalizedValue.known(model) if model != "?" else NormalizedValue.unknown("Model metadata absent"),
            software_version=NormalizedValue.known(version) if version != "?" else NormalizedValue.unknown("Release metadata absent"),
            management_services=NormalizedCollection.known(*(
                ManagementService(protocol, feature.state, scope="switch", evidence=feature.evidence)
                for protocol, feature in states.items()
            )),
            users=NormalizedCollection.known(*self._local_users()),
            interfaces=NormalizedCollection.unsupported("AOS-S interface security is not normalized in this revision"),
            policies=NormalizedCollection.unsupported("AOS-S is not parsed as a firewall policy platform"),
            logging_destinations=NormalizedCollection.known(*self.get_logging_destinations()),
            crypto_settings=NormalizedCollection.known(*(
                CryptoSetting(
                    name=f"ssh-{kind}",
                    value=value,
                    state=ConfigurationState.CONFIGURED,
                    scope="switch",
                )
                for kind in ("cipher", "kex", "mac")
                for value in crypto[kind]
            )),
        )


__all__ = [
    "HPCommand",
    "HPFeature",
    "HPProCurveParser",
    "HPSNTPAssociation",
    "HPSNTPKey",
    "HPSnmpCommunity",
    "HPSnmpV3User",
]
