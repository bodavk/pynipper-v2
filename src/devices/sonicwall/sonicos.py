"""Parser for SonicOS 7 E-CLI show-current-config text exports."""

from __future__ import annotations

from dataclasses import dataclass
import re
import shlex
from typing import Any

from src.devices.common.base_parser import BaseDeviceParser
from src.devices.common.models import (
    ConfigEvidence,
    ConfigurationState,
    LoggingDestination,
    LocalUser,
    ManagementService,
    NetworkInterface,
    NormalizedCollection,
    NormalizedConfig,
    NormalizedValue,
    SecurityPolicy,
)


class UnsupportedSonicOSFormat(ValueError):
    """Raised when input is not the supported SonicOS 7 E-CLI text dialect."""


@dataclass(frozen=True)
class SonicCommand:
    text: str
    line_number: int
    indent: int


@dataclass(frozen=True)
class SonicInterface:
    name: str
    zone: str
    management: tuple[str, ...]
    user_login: tuple[str, ...]
    enabled: bool
    address: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class SonicAccessRule:
    name: str
    position: int
    enabled: bool
    action: str
    from_zone: str
    to_zone: str
    source: str
    destination: str
    service: str
    schedule: str
    logging: bool
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class SonicVPNPolicy:
    name: str
    enabled: bool
    ike_encryption: str
    ike_authentication: str
    dh_group: str
    ipsec_encryption: str
    ipsec_authentication: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class SonicNTPServer:
    address: str
    authenticated: bool
    algorithm: str
    trusted_key_id: str
    key_id: str
    key_material_present: bool
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class SonicSNMPUser:
    name: str
    authentication: str
    privacy: str
    authentication_key_state: str
    privacy_key_state: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class SonicAdministrator:
    name: str
    roles: tuple[str, ...]
    effective_role: str
    authentication: str
    otp_enabled: bool | None
    credential_present: bool | None
    resolution_state: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class SonicAuthenticationPolicy:
    method: str | None
    permits_local_fallback: bool | None
    resolution_state: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class SonicPasswordPolicy:
    minimum_length: int | None
    complexity: str | None
    scopes: tuple[str, ...] | None
    aging_enabled: bool | None
    uniqueness: int | None
    resolution_state: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class SonicAdminSessionPolicy:
    idle_logout_minutes: int | None
    lockout_enabled: bool | None
    failures_per_minute: int | None
    lockout_duration_minutes: int | None
    max_cli_attempts: int | None
    log_without_lockout: bool | None
    resolution_state: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class SonicBannerPolicy:
    connection_enabled: bool | None
    login_enabled: bool | None
    resolution_state: str
    evidence: tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class SonicManagementTLSPolicy:
    applicable: bool
    minimum_version: str | None
    certificate_type: str | None
    resolution_state: str
    evidence: tuple[ConfigEvidence, ...]


class SonicOSParser(BaseDeviceParser):
    """Parse only SonicOS 7 plain-text E-CLI current-configuration output."""

    device_type = "SONICOS"
    format_name = "sonicos7-ecli-current-config"

    def __init__(self, config_filepath: str):
        super().__init__(config_filepath)
        with open(config_filepath, encoding="utf-8-sig") as config_file:
            self.commands = tuple(
                SonicCommand(
                    text=line.strip(),
                    line_number=number,
                    indent=len(line) - len(line.lstrip()),
                )
                for number, line in enumerate(config_file, start=1)
                if line.strip()
                and not line.strip().startswith(("#", "//"))
                and line.strip() not in {"configure", "commit", "exit"}
            )
        self.config = [command.text for command in self.commands]
        version = self._version_from_commands()
        if not re.search(r"\bSonicOS(?:X)?\b.*\b7(?:\.|\b)", version, re.IGNORECASE):
            if any(re.match(r"set\s+(?:service|admin|vpn)\b", command.text, re.IGNORECASE) for command in self.commands):
                detail = "legacy test-only 'set service/admin/vpn' syntax"
            elif any(command.text.casefold().startswith(("prefs", "preferences")) for command in self.commands):
                detail = "binary/legacy SonicOS preferences export"
            else:
                detail = "unidentified configuration dialect or missing SonicOS 7 firmware-version marker"
            raise UnsupportedSonicOSFormat(
                f"Unsupported SonicOS input: {detail}. Supply plain-text output from 'show current-config custom'."
            )

    def _evidence(self, command: SonicCommand) -> ConfigEvidence:
        text = command.text
        words = self._tokens(text)
        folded = [word.casefold() for word in words]
        secret_index = next(
            (index for index, word in enumerate(folded) if word in {"password", "shared-secret", "community"}),
            None,
        )
        if secret_index is not None:
            keep = secret_index + 1
            if (
                folded[secret_index] == "password"
                and keep < len(folded)
                and folded[keep] in {"0", "7", "encrypted", "hash", "hashed"}
            ):
                keep += 1
            text = " ".join(words[:keep] + ["<redacted>"])
        return ConfigEvidence(text, self.config_filepath, command.line_number)

    @staticmethod
    def _tokens(text: str) -> list[str]:
        try:
            return shlex.split(text)
        except ValueError:
            return text.split()

    @staticmethod
    def _after(tokens: list[str], *path: str) -> str:
        lowered = [token.casefold() for token in tokens]
        expected = [token.casefold() for token in path]
        for index in range(len(tokens) - len(expected)):
            if lowered[index : index + len(expected)] == expected:
                return tokens[index + len(expected)]
        return ""

    def _version_from_commands(self) -> str:
        for command in self.commands:
            match = re.fullmatch(r'firmware-version\s+(?:"([^"]+)"|(.+))', command.text, re.IGNORECASE)
            if match:
                return (match.group(1) or match.group(2)).strip()
        return ""

    def _release_tuple(self) -> tuple[int, int, int] | None:
        match = re.search(r"\b7\.(\d+)(?:\.(\d+))?", self._version_from_commands())
        if not match:
            return None
        return 7, int(match.group(1)), int(match.group(2) or 0)

    def has_documented_legacy_defaults(self) -> bool:
        """Return true where a custom export's omitted administrative values are unambiguous.

        SonicOS 7.3 changed new-install password and lockout defaults without
        changing upgraded appliances.  An absent custom-setting is consequently
        not a reliable value on 7.3 or later.
        """
        release = self._release_tuple()
        return release is not None and (7, 0, 0) <= release < (7, 3, 0)

    def _administration_commands(self) -> tuple[SonicCommand, ...]:
        for index, command in enumerate(self.commands):
            if command.text.casefold() == "administration":
                return self._record_commands(index)[1:]
        return ()

    @staticmethod
    def _integer(tokens: list[str], index: int) -> int | None:
        if index >= len(tokens):
            return None
        try:
            return int(tokens[index])
        except ValueError:
            return None

    @staticmethod
    def _effective_admin_role(roles: set[str]) -> str:
        for role in ("full-admin", "limited-admin", "read-only-admin", "guest-admin"):
            if role in roles:
                return role
        return ""

    def _record_commands(self, index: int) -> tuple[SonicCommand, ...]:
        parent = self.commands[index]
        children = [parent]
        for command in self.commands[index + 1 :]:
            if command.indent <= parent.indent:
                break
            children.append(command)
        return tuple(children)

    def get_hostname(self) -> str:
        for command in self.commands:
            match = re.fullmatch(r'(?:firewall-name|host-name|hostname)\s+(?:"([^"]+)"|(\S+))', command.text, re.IGNORECASE)
            if match:
                return match.group(1) or match.group(2)
        return "?"

    def get_version(self) -> str:
        version = self._version_from_commands()
        match = re.search(r"\b(7\.\S+)", version)
        return match.group(1).rstrip('"') if match else version

    def get_model(self) -> str:
        for command in self.commands:
            match = re.fullmatch(r"(?:product-name|appliance-name)\s+(.+)", command.text, re.IGNORECASE)
            if match:
                return match.group(1).strip('"')
        return "?"

    def get_interfaces(self) -> list[SonicInterface]:
        interfaces = []
        for index, command in enumerate(self.commands):
            match = re.match(r"interface\s+(X\d+(?::V\d+)?)\b", command.text, re.IGNORECASE)
            if not match:
                continue
            records = self._record_commands(index)
            tokens = self._tokens(" ".join(item.text for item in records))
            management = []
            user_login = []
            lowered = [token.casefold() for token in tokens]
            if "management" in lowered:
                start = lowered.index("management") + 1
                for token in lowered[start:]:
                    if token in {"http", "https", "ssh", "snmp", "ping"}:
                        management.append(token)
                    else:
                        break
            if "user-login" in lowered:
                start = lowered.index("user-login") + 1
                for token in lowered[start:]:
                    if token in {"http", "https"}:
                        user_login.append(token)
                    else:
                        break
            interfaces.append(
                SonicInterface(
                    name=match.group(1).upper(),
                    zone=self._after(tokens, "zone"),
                    management=tuple(dict.fromkeys(management)),
                    user_login=tuple(dict.fromkeys(user_login)),
                    enabled="shutdown" not in lowered or "no shutdown" in " ".join(lowered),
                    address=self._after(tokens, "ip-address") or self._after(tokens, "ip"),
                    evidence=tuple(self._evidence(item) for item in records),
                )
            )
        return interfaces

    def get_access_rules(self) -> list[SonicAccessRule]:
        rules = []
        for index, command in enumerate(self.commands):
            if not re.match(r"access-rule\s+(?:ipv[46]\s+)?(?:from|uuid)\b", command.text, re.IGNORECASE):
                continue
            records = self._record_commands(index)
            tokens = self._tokens(" ".join(item.text for item in records))
            lowered = [token.casefold() for token in tokens]
            enabled = "no enable" not in " ".join(lowered)
            name = self._after(tokens, "name") or self._after(tokens, "uuid") or f"rule-{len(rules) + 1}"
            rules.append(
                SonicAccessRule(
                    name=name,
                    position=len(rules) + 1,
                    enabled=enabled,
                    action=self._after(tokens, "action").casefold(),
                    from_zone=self._after(tokens, "from"),
                    to_zone=self._after(tokens, "to"),
                    source=self._after(tokens, "source", "address"),
                    destination=self._after(tokens, "destination", "address"),
                    service=self._after(tokens, "service"),
                    schedule=self._after(tokens, "schedule"),
                    logging="logging" in lowered and "no logging" not in " ".join(lowered),
                    evidence=tuple(self._evidence(item) for item in records),
                )
            )
        return rules

    def get_vpn_policies(self) -> list[SonicVPNPolicy]:
        policies = []
        for index, command in enumerate(self.commands):
            match = re.match(r'vpn\s+policy\s+(?:site-to-site\s+)?(?:"([^"]+)"|(\S+))', command.text, re.IGNORECASE)
            if not match:
                continue
            records = self._record_commands(index)
            text = " ".join(item.text for item in records)
            tokens = self._tokens(text)
            lowered = text.casefold()
            policies.append(
                SonicVPNPolicy(
                    name=match.group(1) or match.group(2),
                    enabled="enable" in [token.casefold() for token in tokens] and "no enable" not in lowered,
                    ike_encryption=self._after(tokens, "proposal", "ike", "encryption").casefold(),
                    ike_authentication=self._after(tokens, "proposal", "ike", "authentication").casefold(),
                    dh_group=self._after(tokens, "proposal", "ike", "dh-group").casefold(),
                    ipsec_encryption=self._after(tokens, "proposal", "ipsec", "encryption").casefold(),
                    ipsec_authentication=self._after(tokens, "proposal", "ipsec", "authentication").casefold(),
                    evidence=tuple(self._evidence(item) for item in records),
                )
            )
        return policies

    def get_syslog_destinations(self) -> list[LoggingDestination]:
        destinations = []
        for command in self.commands:
            match = re.search(r"(?:syslog-server|server)\s+(?:name\s+)?(?:\"([^\"]+)\"|(\S+))", command.text, re.IGNORECASE)
            if match and "syslog" in command.text.casefold() and "no enable" not in command.text.casefold():
                address = match.group(1) or match.group(2)
                destinations.append(
                    LoggingDestination(
                        destination_type="syslog",
                        state=ConfigurationState.ENABLED,
                        address=address,
                        scope="firewall",
                        evidence=(self._evidence(command),),
                    )
                )
        return destinations

    def get_ntp_server_records(self) -> list[SonicNTPServer]:
        servers: dict[str, SonicNTPServer] = {}
        for command in self.commands:
            match = re.fullmatch(r"(?P<no>no\s+)?ntp-server\s+(?P<address>\S+)(?:\s+.*)?", command.text, re.IGNORECASE)
            if match:
                address = match.group("address")
                if match.group("no"):
                    servers.pop(address.casefold(), None)
                    continue
                tokens = self._tokens(command.text)
                folded = [token.casefold() for token in tokens]
                algorithm = next(
                    (item for item in folded if item in {"md5", "sha", "sha1", "sha256"}),
                    "",
                )
                def option(name: str) -> str:
                    if name not in folded or folded.index(name) + 1 >= len(tokens):
                        return ""
                    return tokens[folded.index(name) + 1]

                trusted_key_id = option("trust-key-no")
                key_id = option("key-number")
                key_material_present = bool(option("password"))
                authenticated = bool(
                    algorithm
                    and trusted_key_id
                    and key_id
                    and trusted_key_id == key_id
                    and key_material_present
                )
                summary = (
                    f"ntp-server {address} {algorithm or 'no-auth'}; trust-key-no "
                    f"{trusted_key_id or 'missing'}; key-number {key_id or 'missing'}; "
                    f"key material {'configured' if key_material_present else 'missing'}"
                )
                servers[address.casefold()] = SonicNTPServer(
                    address=address,
                    authenticated=authenticated,
                    algorithm=algorithm,
                    trusted_key_id=trusted_key_id,
                    key_id=key_id,
                    key_material_present=key_material_present,
                    evidence=(ConfigEvidence(summary, self.config_filepath, command.line_number),),
                )
        return list(servers.values())

    def get_ntp_servers(self) -> tuple[str, ...]:
        return tuple(server.address for server in self.get_ntp_server_records())

    def get_security_services(self) -> dict[str, bool | None]:
        states: dict[str, bool | None] = {
            "gateway-anti-virus": None,
            "cloud-gateway-anti-virus": None,
            "intrusion-prevention": None,
            "anti-spyware": None,
            "capture-atp": None,
        }
        for command in self.commands:
            match = re.fullmatch(r"(?P<no>no\s+)?(?P<name>gateway-anti-virus|cloud-gateway-anti-virus|intrusion-prevention|anti-spyware|capture-atp)\s+enable", command.text, re.IGNORECASE)
            if match:
                states[match.group("name").casefold()] = not bool(match.group("no"))
        return states

    def has_secure_snmpv3_user(self) -> bool:
        return any(
            user.authentication in {"sha", "sha256", "sha384", "sha512"}
            and user.privacy in {"aes", "aes128", "aes192", "aes256", "aes_cfb128"}
            for user in self.get_snmpv3_users()
        )

    def get_snmpv3_users(self) -> list[SonicSNMPUser]:
        users: dict[str, SonicSNMPUser] = {}
        for command in self.commands:
            match = re.fullmatch(
                r"(?P<no>no\s+)?snmp(?:-server)?\s+user\s+(?P<name>\S+)(?:\s+(?P<rest>.*))?",
                command.text,
                re.IGNORECASE,
            )
            if not match:
                continue
            name = match.group("name")
            if match.group("no"):
                users.pop(name.casefold(), None)
                continue
            tokens = self._tokens(match.group("rest") or "")
            folded = [token.casefold() for token in tokens]

            def option(keyword: str) -> tuple[str, str]:
                if keyword not in folded:
                    return "none", "missing"
                index = folded.index(keyword) + 1
                if index >= len(folded):
                    return "unknown", "unknown"
                algorithm = folded[index]
                index += 1
                if index < len(folded) and folded[index] in {"0", "7", "encrypted"}:
                    index += 1
                state = "present" if index < len(folded) and folded[index] not in {"auth", "priv"} else "unknown"
                return algorithm, state

            authentication, auth_state = option("auth")
            privacy, privacy_state = option("priv")
            users[name.casefold()] = SonicSNMPUser(
                name=name,
                authentication=authentication,
                privacy=privacy,
                authentication_key_state=auth_state,
                privacy_key_state=privacy_state,
                evidence=(ConfigEvidence(
                    f"snmp user {name} auth {authentication} <key {auth_state}> "
                    f"priv {privacy} <key {privacy_state}>",
                    self.config_filepath,
                    command.line_number,
                ),),
            )
        return list(users.values())

    def get_authentication_policy(self) -> SonicAuthenticationPolicy:
        method: str | None = None
        evidence: tuple[ConfigEvidence, ...] = ()
        for index, command in enumerate(self.commands):
            if command.text.casefold() != "user authentication":
                continue
            for item in self._record_commands(index)[1:]:
                tokens = self._tokens(item.text)
                if len(tokens) >= 2 and tokens[0].casefold() == "method":
                    method = tokens[1].casefold()
                    evidence = (self._evidence(item),)
        if method is None:
            return SonicAuthenticationPolicy(None, None, "not-exported", ())
        return SonicAuthenticationPolicy(
            method=method,
            permits_local_fallback=method in {"local", "ldap+local", "radius+local"},
            resolution_state="explicit",
            evidence=evidence,
        )

    def get_password_policy(self) -> SonicPasswordPolicy:
        known_defaults = self.has_documented_legacy_defaults()
        minimum_length: int | None = 8 if known_defaults else None
        complexity: str | None = "none" if known_defaults else None
        scopes: tuple[str, ...] | None = (
            "admin", "full-admin", "limited-admin", "guest-admin", "local-users"
        ) if known_defaults else None
        aging_enabled: bool | None = False if known_defaults else None
        uniqueness: int | None = 4 if known_defaults else None
        resolution = "documented-default" if known_defaults else "unknown-release-default"
        evidence: list[ConfigEvidence] = []
        mutable_scopes = set(scopes or ())
        scopes_explicit = False

        for command in self._administration_commands():
            tokens = self._tokens(command.text)
            folded = [token.casefold() for token in tokens]
            if not folded:
                continue
            explicit = False
            if folded[:2] == ["password", "minimum-length"]:
                minimum_length = self._integer(tokens, 2)
                explicit = True
            elif folded[:2] == ["password", "complexity"]:
                offset = 3 if len(folded) > 2 and folded[2] == "type" else 2
                complexity = folded[offset] if len(folded) > offset else None
                explicit = True
            elif folded[:2] == ["no", "password"] and folded[2:3] == ["complexity"]:
                complexity = "none"
                explicit = True
            elif folded[:2] == ["password", "aging"]:
                aging_enabled = True
                explicit = True
            elif folded[:3] == ["no", "password", "aging"]:
                aging_enabled = False
                explicit = True
            elif folded[:2] == ["password", "uniqueness"]:
                uniqueness = self._integer(tokens, 2)
                explicit = True
            elif folded[:2] == ["password", "constraints-apply-to"]:
                if not scopes_explicit:
                    mutable_scopes = set()
                    scopes_explicit = True
                scope_aliases = {
                    "builtin-admin": "admin",
                    "full-admin": "full-admin",
                    "full-admins": "full-admin",
                    "limited-admin": "limited-admin",
                    "limited-admins": "limited-admin",
                    "guest-admin": "guest-admin",
                    "guest-admins": "guest-admin",
                    "local-users": "local-users",
                }
                mutable_scopes.update(scope_aliases.get(value, value) for value in folded[2:])
                scopes = tuple(sorted(mutable_scopes))
                explicit = True
            elif folded[:3] == ["no", "password", "constraints-apply-to"]:
                if not scopes_explicit:
                    mutable_scopes = set(scopes or ())
                    scopes_explicit = True
                scope_aliases = {
                    "builtin-admin": "admin",
                    "full-admin": "full-admin",
                    "full-admins": "full-admin",
                    "limited-admin": "limited-admin",
                    "limited-admins": "limited-admin",
                    "guest-admin": "guest-admin",
                    "guest-admins": "guest-admin",
                    "local-users": "local-users",
                }
                mutable_scopes.difference_update(scope_aliases.get(value, value) for value in folded[3:])
                scopes = tuple(sorted(mutable_scopes))
                explicit = True
            if explicit:
                evidence.append(self._evidence(command))
                resolution = "explicit" if all(
                    value is not None for value in (minimum_length, complexity, scopes)
                ) else "partial-explicit"

        return SonicPasswordPolicy(
            minimum_length=minimum_length,
            complexity=complexity,
            scopes=scopes,
            aging_enabled=aging_enabled,
            uniqueness=uniqueness,
            resolution_state=resolution,
            evidence=tuple(evidence),
        )

    def get_admin_session_policy(self) -> SonicAdminSessionPolicy:
        known_defaults = self.has_documented_legacy_defaults()
        idle: int | None = 5 if known_defaults else None
        lockout: bool | None = False if known_defaults else None
        failures: int | None = 5 if known_defaults else None
        duration: int | None = 5 if known_defaults else None
        cli_attempts: int | None = 5 if known_defaults else None
        log_without: bool | None = False if known_defaults else None
        resolution = "documented-default" if known_defaults else "unknown-release-default"
        evidence: list[ConfigEvidence] = []

        for command in self._administration_commands():
            tokens = self._tokens(command.text)
            folded = [token.casefold() for token in tokens]
            if not folded:
                continue
            explicit = False
            if folded[0] == "idle-logout-time":
                idle = self._integer(tokens, 1)
                explicit = True
            elif folded[0] == "user-lockout":
                lockout = True
                explicit = True
            elif folded[:2] == ["no", "user-lockout"]:
                lockout = False
                explicit = True
            elif folded[0] in {"failures-per-minute", "failed-attempts", "max-failed-attempts"}:
                failures = self._integer(tokens, 1)
                explicit = True
            elif folded[0] in {"lockout-duration", "lockout-period", "lockout-time"}:
                duration = self._integer(tokens, 1)
                explicit = True
            elif folded[0] == "max-login-attempts-cli":
                cli_attempts = self._integer(tokens, 1)
                explicit = True
            elif folded[0] == "log-without-lockout":
                log_without = True
                explicit = True
            elif folded[:2] == ["no", "log-without-lockout"]:
                log_without = False
                explicit = True
            if folded and folded[0] == "user-lockout":
                for keyword, target in (
                    ("failures-per-minute", "failures"),
                    ("failed-attempts", "failures"),
                    ("lockout-duration", "duration"),
                    ("lockout-period", "duration"),
                ):
                    if keyword in folded:
                        value = self._integer(tokens, folded.index(keyword) + 1)
                        if target == "failures":
                            failures = value
                        else:
                            duration = value
            if explicit:
                evidence.append(self._evidence(command))
                resolution = "explicit" if all(
                    value is not None for value in (idle, lockout, failures, duration, cli_attempts)
                ) else "partial-explicit"

        return SonicAdminSessionPolicy(
            idle_logout_minutes=idle,
            lockout_enabled=lockout,
            failures_per_minute=failures,
            lockout_duration_minutes=duration,
            max_cli_attempts=cli_attempts,
            log_without_lockout=log_without,
            resolution_state=resolution,
            evidence=tuple(evidence),
        )

    def get_banner_policy(self) -> SonicBannerPolicy:
        known_defaults = self.has_documented_legacy_defaults()
        connection: bool | None = False if known_defaults else None
        login: bool | None = False if known_defaults else None
        resolution = "documented-default" if known_defaults else "unknown-release-default"
        evidence: list[ConfigEvidence] = []
        for command in self.commands:
            tokens = self._tokens(command.text)
            folded = [token.casefold() for token in tokens]
            if folded[:3] == ["cli", "banner", "connection"]:
                connection = True
            elif folded[:4] == ["no", "cli", "banner", "connection"]:
                connection = False
            elif folded[:3] == ["cli", "banner", "login"]:
                login = True
            elif folded[:4] == ["no", "cli", "banner", "login"]:
                login = False
            else:
                continue
            evidence.append(self._evidence(command))
            resolution = "explicit"
        return SonicBannerPolicy(connection, login, resolution, tuple(evidence))

    def get_management_tls_policy(self) -> SonicManagementTLSPolicy:
        applicable = self.get_services()["https"]
        minimum_version: str | None = None
        certificate_type: str | None = "self-signed" if self.has_documented_legacy_defaults() else None
        resolution = "documented-certificate-default" if certificate_type else "not-exported"
        evidence: list[ConfigEvidence] = []
        for command in self._administration_commands():
            tokens = self._tokens(command.text)
            folded = [token.casefold() for token in tokens]
            if folded == ["tls-and-above"]:
                minimum_version = "tls1.1"
            elif folded == ["no", "tls-and-above"]:
                minimum_version = "tls1.0"
            elif folded[:2] == ["web-management", "certificate"]:
                value = folded[2] if len(folded) > 2 else ""
                certificate_type = "self-signed" if value in {
                    "self-signed", "selfsigned", "use-self-signed", "default"
                } else "imported"
            else:
                continue
            evidence.append(self._evidence(command))
            resolution = "explicit"
        return SonicManagementTLSPolicy(
            applicable=applicable,
            minimum_version=minimum_version,
            certificate_type=certificate_type,
            resolution_state=resolution,
            evidence=tuple(evidence),
        )

    def get_administrators(self) -> list[SonicAdministrator]:
        users: dict[str, dict[str, Any]] = {}
        memberships: dict[str, set[str]] = {}
        parent_groups: dict[str, set[str]] = {}
        role_evidence: dict[str, list[ConfigEvidence]] = {}
        group_roles = {
            "sonicwall administrators": "full-admin",
            "limited administrators": "limited-admin",
            "sonicwall read-only admins": "read-only-admin",
            "guest administrators": "guest-admin",
        }

        for root_index, root in enumerate(self.commands):
            if root.text.casefold() != "user local-users":
                continue
            records = self._record_commands(root_index)[1:]
            record_ids = {id(item) for item in records}
            for index, command in enumerate(self.commands):
                if id(command) not in record_ids:
                    continue
                tokens = self._tokens(command.text)
                folded = [token.casefold() for token in tokens]
                user_match = len(tokens) >= 2 and folded[0] == "user"
                no_user = len(tokens) >= 3 and folded[:2] == ["no", "user"]
                if user_match:
                    name = tokens[1]
                    block = self._record_commands(index)
                    credential = "password" in folded[2:] or any(
                        self._tokens(item.text)[:1]
                        and self._tokens(item.text)[0].casefold() == "password"
                        for item in block[1:]
                    )
                    otp: bool | None = None
                    for item in block[1:]:
                        item_folded = [value.casefold() for value in self._tokens(item.text)]
                        if item_folded and item_folded[0] in {"one-time-pwd-required", "one-time-password"}:
                            otp = True
                        elif item_folded[:2] in (["no", "one-time-pwd-required"], ["no", "one-time-password"]):
                            otp = False
                    users[name.casefold()] = {
                        "name": name,
                        "credential": credential,
                        "otp": otp,
                        "evidence": [self._evidence(item) for item in block],
                    }
                    membership_commands = [command, *block[1:]]
                    for item in membership_commands:
                        item_tokens = self._tokens(item.text)
                        item_folded = [value.casefold() for value in item_tokens]
                        if item_folded[:2] == ["no", "member-of"] and len(item_tokens) > 2:
                            group = item_tokens[2].casefold()
                            parent_groups.setdefault(name.casefold(), set()).discard(group)
                            role = group_roles.get(group)
                            if role:
                                memberships.setdefault(name.casefold(), set()).discard(role)
                                role_evidence.setdefault(name.casefold(), []).append(self._evidence(item))
                        elif "member-of" in item_folded:
                            member_index = item_folded.index("member-of") + 1
                            if member_index < len(item_tokens):
                                group = item_tokens[member_index].casefold()
                                parent_groups.setdefault(name.casefold(), set()).add(group)
                                role = group_roles.get(group)
                                if role:
                                    memberships.setdefault(name.casefold(), set()).add(role)
                                    role_evidence.setdefault(name.casefold(), []).append(self._evidence(item))
                elif no_user:
                    users.pop(tokens[2].casefold(), None)

            for index, command in enumerate(self.commands):
                if id(command) not in record_ids:
                    continue
                tokens = self._tokens(command.text)
                folded = [token.casefold() for token in tokens]
                if len(tokens) < 2 or folded[0] != "group":
                    continue
                group_name = tokens[1].casefold()
                role = group_roles.get(group_name)
                for item in self._record_commands(index)[1:]:
                    member_tokens = self._tokens(item.text)
                    member_folded = [value.casefold() for value in member_tokens]
                    if len(member_tokens) >= 2 and member_folded[0] == "member":
                        key = member_tokens[1].casefold()
                        parent_groups.setdefault(key, set()).add(group_name)
                        if role:
                            memberships.setdefault(key, set()).add(role)
                        role_evidence.setdefault(key, []).append(self._evidence(item))
                    elif len(member_tokens) >= 3 and member_folded[:2] == ["no", "member"]:
                        key = member_tokens[2].casefold()
                        parent_groups.setdefault(key, set()).discard(group_name)
                        if role:
                            memberships.setdefault(key, set()).discard(role)
                        role_evidence.setdefault(key, []).append(self._evidence(item))

        administrators: list[SonicAdministrator] = []
        for key, details in users.items():
            roles = set(memberships.get(key, set()))
            membership_evidence = list(role_evidence.get(key, []))
            pending = list(parent_groups.get(key, set()))
            visited: set[str] = set()
            while pending:
                group = pending.pop()
                if group in visited:
                    continue
                visited.add(group)
                membership_evidence.extend(role_evidence.get(group, []))
                role = group_roles.get(group)
                if role:
                    roles.add(role)
                pending.extend(parent_groups.get(group, set()) - visited)
            effective = self._effective_admin_role(roles)
            if not effective:
                continue
            administrators.append(SonicAdministrator(
                name=details["name"],
                roles=tuple(sorted(roles)),
                effective_role=effective,
                authentication="local",
                otp_enabled=(
                    details["otp"]
                    if details["otp"] is not None
                    else (False if self.has_documented_legacy_defaults() else None)
                ),
                credential_present=details["credential"],
                resolution_state="explicit",
                evidence=tuple(dict.fromkeys(details["evidence"] + membership_evidence)),
            ))

        admin_name = "built-in administrator"
        admin_otp: bool | None = False if self.has_documented_legacy_defaults() else None
        admin_credential: bool | None = None
        admin_evidence: list[ConfigEvidence] = []
        explicit = False
        for command in self._administration_commands():
            tokens = self._tokens(command.text)
            folded = [token.casefold() for token in tokens]
            if folded[:2] == ["admin", "name"] and len(tokens) > 2:
                admin_name = tokens[2]
            elif folded[:2] == ["admin", "password"]:
                admin_credential = True
            elif folded[:3] == ["admin", "one-time-password", "totp"]:
                admin_otp = True
            elif folded[:3] == ["no", "admin", "one-time-password"]:
                admin_otp = False
            else:
                continue
            explicit = True
            admin_evidence.append(self._evidence(command))
        administrators.insert(0, SonicAdministrator(
            name=admin_name,
            roles=("full-admin",),
            effective_role="full-admin",
            authentication="local",
            otp_enabled=admin_otp,
            credential_present=admin_credential,
            resolution_state="explicit" if explicit else (
                "documented-default" if self.has_documented_legacy_defaults() else "unknown-release-default"
            ),
            evidence=tuple(admin_evidence),
        ))
        return administrators

    def get_users(self) -> list[SonicAdministrator]:
        # Secret values are deliberately discarded; only presence metadata is retained.
        return self.get_administrators()

    def get_services(self) -> dict[str, bool]:
        interfaces = self.get_interfaces()
        return {
            protocol: any(protocol in interface.management for interface in interfaces if interface.enabled)
            for protocol in ("http", "https", "ssh", "snmp")
        }

    def get_native_config(self) -> Any:
        return self.commands

    def get_normalized_config(self) -> NormalizedConfig:
        hostname = self.get_hostname()
        version = self.get_version()
        model = self.get_model()
        interfaces = self.get_interfaces()
        return NormalizedConfig(
            device_type=self.device_type,
            hostname=NormalizedValue.known(hostname) if hostname != "?" else NormalizedValue.unknown("Hostname absent"),
            device_model=NormalizedValue.known(model) if model != "?" else NormalizedValue.unknown("Product metadata absent"),
            software_version=NormalizedValue.known(version, ConfigEvidence(self._version_from_commands(), self.config_filepath)),
            management_services=NormalizedCollection.known(*(
                ManagementService(
                    protocol=protocol,
                    state=ConfigurationState.ENABLED,
                    interface=interface.name,
                    zone=interface.zone or None,
                    scope="interface",
                    evidence=interface.evidence,
                )
                for interface in interfaces
                if interface.enabled
                for protocol in interface.management
            )),
            users=NormalizedCollection.unknown("E-CLI export cannot prove whether built-in administrator credentials are unchanged"),
            interfaces=NormalizedCollection.known(*(
                NetworkInterface(
                    name=interface.name,
                    state=ConfigurationState.ENABLED if interface.enabled else ConfigurationState.DISABLED,
                    zone=interface.zone or None,
                    scope="firewall",
                    addresses=(interface.address,) if interface.address else (),
                    evidence=interface.evidence,
                )
                for interface in interfaces
            )),
            policies=NormalizedCollection.known(*(
                SecurityPolicy(
                    name=rule.name,
                    state=ConfigurationState.ENABLED if rule.enabled else ConfigurationState.DISABLED,
                    action=rule.action,
                    position=rule.position,
                    scope="firewall",
                    source_interfaces=(rule.from_zone,),
                    destination_interfaces=(rule.to_zone,),
                    sources=(rule.source,),
                    destinations=(rule.destination,),
                    services=(rule.service,),
                    tracking="logging" if rule.logging else None,
                    evidence=rule.evidence,
                )
                for rule in self.get_access_rules()
            )),
            logging_destinations=NormalizedCollection.known(*self.get_syslog_destinations()),
            crypto_settings=NormalizedCollection.unknown("VPN proposals remain available through vendor-specific typed records"),
        )


__all__ = [
    "SonicAccessRule",
    "SonicCommand",
    "SonicInterface",
    "SonicNTPServer",
    "SonicOSParser",
    "SonicVPNPolicy",
    "UnsupportedSonicOSFormat",
]
