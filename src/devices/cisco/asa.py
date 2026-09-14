import re
import shlex
import base64
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
from src.devices.common.models import (
    ConfigEvidence,
    CredentialMetadata,
    CredentialStorageAssessment,
    DefaultCredentialAssessment,
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
        for line_number, line in enumerate(self.parser.ioscfg, start=1):
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
                evidence=(ConfigEvidence(
                    f"enable password <redacted> {marker}".rstrip(),
                    self.config_filepath,
                    line_number,
                ),),
            )
        return selected

    def get_local_credentials(self) -> list[CredentialMetadata]:
        credentials: dict[str, CredentialMetadata] = {}
        for line_number, raw_line in enumerate(self.parser.ioscfg, start=1):
            stripped = raw_line.strip()
            removal = re.fullmatch(r"no\s+username\s+(\S+)(?:\s+.*)?", stripped, re.IGNORECASE)
            if removal:
                credentials.pop(removal.group(1).casefold(), None)
                continue
            match = re.fullmatch(
                r"username\s+(\S+)\s+password(?:\s+(\S+))?(?:\s+(encrypted|pbkdf2))?(?:\s+privilege\s+\d+)?",
                stripped,
                re.IGNORECASE,
            )
            if not match:
                continue
            account = match.group(1)
            value = match.group(2) or ""
            marker = (match.group(3) or "plaintext").casefold()
            storage = self._credential_assessment(marker, value)
            credentials[account.casefold()] = CredentialMetadata(
                account=account,
                context="local_user",
                method="password",
                storage_type=marker,
                storage_assessment=storage,
                default_assessment=self._default_assessment(storage, value),
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
