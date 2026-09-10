import re
import shlex
from dataclasses import dataclass
from typing import Optional
from ciscoconfparse import CiscoConfParse
from src.devices.common.base_parser import BaseDeviceParser


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


@dataclass(frozen=True)
class ASACredential:
    storage_type: str
    is_default: bool
    raw_line_redacted: str


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
    raw_line_redacted: str


@dataclass(frozen=True)
class ASAACLEntry:
    acl_name: str
    action: str
    protocol: str
    source: str
    destination: str
    inactive: bool
    raw_line: str

    @property
    def is_broad_permit(self) -> bool:
        any_values = {"any", "any4", "any6"}
        return (
            not self.inactive
            and self.action == "permit"
            and self.source in any_values
            and self.destination in any_values
        )


class CiscoASAParser(BaseDeviceParser):

    device_type = "ASA"

    def __init__(self, config_filepath: str):
        super().__init__(config_filepath)
        # ciscoconfparse supports 'asa' syntax
        self.parser = CiscoConfParse(config_filepath, syntax='asa')

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
                    "raw_line": text
                })
        return users

    def get_services(self) -> dict:
        return {
            "telnet": bool(self.get_management_grants("telnet")),
            "ssh": bool(self.get_management_grants("ssh")),
            "http": bool(self.parser.find_objects(r"^http server enable(?:\s|$)")),
        }

    def get_native_config(self) -> CiscoConfParse:
        return self.parser

    # Helper methods specific to ASA audit checks
    def get_enable_password(self) -> str:
        enable_line = self.parser.find_objects("^enable password")
        if len(enable_line) > 0:
            return enable_line[0].re_match_typed(r'^enable password\s+(\S+)', default='')
        return ""

    def get_enable_credential(self) -> Optional[ASACredential]:
        selected: Optional[ASACredential] = None
        for line in self.parser.ioscfg:
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
            selected = ASACredential(
                storage_type=storage_type,
                is_default=value.casefold() in {"cisco", "cisco123", "admin", "password"},
                raw_line_redacted=f"enable password <redacted> {marker}".rstrip(),
            )
        return selected

    def get_snmp_communities(self) -> list[str]:
        return [community.name for community in self.get_snmp_configuration()[0]]

    def get_snmp_configuration(
        self,
    ) -> tuple[list[ASASNMPCommunity], list[ASASNMPHost], list[str]]:
        communities: dict[str, ASASNMPCommunity] = {}
        hosts: dict[tuple[str, str], ASASNMPHost] = {}
        users: list[str] = []
        for raw_line in self.parser.ioscfg:
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
                    raw_line_redacted=f"snmp-server host {host.group(2)} {host.group(3)} <credentials redacted>",
                )
                continue

            user = re.fullmatch(r"snmp-server user\s+(\S+)\s+(.+)", line, re.IGNORECASE)
            if user:
                options = user.group(2).lower().split()
                protection = "auth+priv" if "auth" in options and "priv" in options else "incomplete"
                users.append(f"snmp-server user <redacted> {protection}")
        return list(communities.values()), list(hosts.values()), users

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
        version = ""
        for raw_line in self.parser.ioscfg:
            line = raw_line.strip()
            match = re.fullmatch(r"ssl server-version\s+(\S+)(?:\s+\S+)?", line)
            if match:
                version = match.group(1)
            elif line == "no ssl server-version":
                version = ""
        return version

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
            if index < len(tokens) and tokens[index] == "line":
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
            if protocol == "object-group" and index < len(tokens):
                protocol = f"object-group {tokens[index]}"
                index += 1
            source, index = self._consume_acl_address(tokens, index)
            destination, _ = self._consume_acl_address(tokens, index)
            entry = ASAACLEntry(
                acl_name=tokens[1],
                action=action,
                protocol=protocol,
                source=source.lower(),
                destination=destination.lower(),
                inactive="inactive" in [token.lower() for token in tokens],
                raw_line=effective_line,
            )
            key = " ".join(tokens)
            if negated:
                entries.pop(key, None)
            else:
                entries[key] = entry
        return list(entries.values())
