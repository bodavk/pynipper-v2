"""Bounded parser for saved BIG-IP TMOS tmsh/SCF object blocks.

Only selected management settings cross the parser boundary. The source may
contain passwords, keys, and certificates, but none are retained as evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import re

from src.common.unix_crypt import crypt_matches
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.common.models import ConfigEvidence, NormalizedConfig, NormalizedValue


_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|#[^\r\n]*|[{}]|[^\s{}]+')
_VERSION = re.compile(r"(?m)^\s*#\s*TMSH-VERSION:\s*([0-9][A-Za-z0-9._-]*)\s*$", re.I)
_SAFE_NAME = re.compile(r"[A-Za-z0-9_./:-]+")
_FIELDS = {
    "sys sshd": {"login", "allow", "inactivity-timeout"},
    "sys httpd": {"allow", "redirect-http-to-https", "ssl-protocol", "ssl-ciphersuite"},
    "sys global-settings": {"hostname", "console-inactivity-timeout"},
    "cli global-settings": {"audit", "idle-timeout"},
    "sys syslog": {"remote-servers"},
    "auth password-policy": {"policy-enforcement", "max-login-failures", "minimum-length", "password-memory"},
    "auth remote-user": {"default-role", "remote-console-access"},
    "auth source": {"type", "fallback"},
}


# Apache mod_ssl SSLProtocol tokens accepted by `sys httpd ssl-protocol`.
_SSL_PROTOCOL_TOKEN = re.compile(r"([+-]?)(all|SSLv2|SSLv3|TLSv1|TLSv1\.1|TLSv1\.2|TLSv1\.3)", re.I)
_ALL_TLS = ("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")
_CIPHER_LIST = re.compile(r"[A-Za-z0-9!+@:=._-]+")
_LITERAL_SUITE = re.compile(r"[A-Z0-9]+(?:-[A-Z0-9]+)+")
_WEAK_SUITE = re.compile(r"(?:^|-)(?:DES-CBC3|DES-CBC|DES|RC4|RC2|NULL|EXP|EXPORT|MD5|IDEA|SEED)(?:-|$)")
_LOOPBACK = {"127", "127.", "127.0.0.1", "127.0.0.0/8", "127.0.0.0/255.0.0.0", "::1", "::1/128"}
_ANY_ADDRESS = {"0.0.0.0/0", "0.0.0.0/0.0.0.0", "::/0", "any", "all", "0.0.0.0"}
_DEFAULT_COMMUNITIES = {"public", "private"}
# K13121: 'On installation, the BIG-IP and BIG-IQ systems create a default root user and a
# default administrative user' — root/default and admin/admin (SC-044 F5-16).
_DEFAULT_PASSWORDS = {"admin": "admin", "root": "default"}


def resolve_ssl_protocols(value: str) -> tuple[str, ...] | None:
    """Resolve an Apache ``SSLProtocol`` token list to the protocols it enables.

    ``all`` enables the TLS versions; SSLv3 is only counted when named
    explicitly, because whether ``all`` includes it depends on the TLS
    library build. A token without ``+``/``-`` replaces the set, as in
    mod_ssl. Unknown tokens return ``None``.
    """

    enabled: list[str] = []
    tokens = value.split()
    if not tokens:
        return None
    for token in tokens:
        match = _SSL_PROTOCOL_TOKEN.fullmatch(token)
        if not match:
            return None
        sign, name = match.groups()
        canonical = next(item for item in ("all", "SSLv2", "SSLv3", *_ALL_TLS) if item.casefold() == name.casefold())
        members = list(_ALL_TLS) if canonical == "all" else [canonical]
        if sign == "-":
            enabled = [item for item in enabled if item not in members]
        elif sign == "+":
            enabled += [item for item in members if item not in enabled]
        else:
            enabled = members
    return tuple(enabled)


def weak_literal_cipher_suites(value: str) -> tuple[str, ...] | None:
    """Weak suites in a cipher list made only of literal OpenSSL suite names.

    Keywords (DEFAULT, HIGH, ...), exclusions (``!``/``-``) and other
    operators change the meaning of the whole list; such lists return
    ``None`` because their effective content is not proven here.
    """

    suites = [item for item in value.split(":") if item]
    if not suites or not all(_LITERAL_SUITE.fullmatch(item) for item in suites):
        return None
    return tuple(item for item in suites if _WEAK_SUITE.search(item))


class F5ParseError(ValueError):
    """Source-free diagnostic for malformed or unsupported TMOS text."""

    def __init__(self, line_number: int):
        self.line_number = line_number
        super().__init__(f"Invalid BIG-IP tmsh object structure at line {line_number}")


@dataclass(frozen=True)
class _TokenValue:
    text: str
    line: int


@dataclass(frozen=True)
class F5Setting:
    scope: str
    name: str
    value: str | int | None
    resolution_state: str
    evidence: ConfigEvidence


@dataclass(frozen=True)
class F5UserCredential:
    name: str
    storage: str
    evidence: ConfigEvidence
    known_default: bool = False  # K13121 default (admin/admin, root/default) recognised from the hash


@dataclass(frozen=True)
class F5RemoteAuthProfile:
    provider_type: str
    name: str
    servers_state: str
    ssl_state: str
    peer_check_state: str
    evidence: ConfigEvidence


@dataclass(frozen=True)
class F5SNMPAgent:
    """Effective ``sys snmp allowed-addresses`` scope: which clients may query."""

    client_scope: str  # unrestricted | restricted | loopback-only | none | unknown
    evidence: ConfigEvidence


@dataclass(frozen=True)
class F5SNMPCommunity:
    name: str
    default_name: bool | None
    access: str  # ro | rw | unknown
    source: str  # any | restricted | unknown
    evidence: ConfigEvidence


@dataclass(frozen=True)
class F5SNMPUser:
    name: str
    security_level: str
    auth_protocol: str
    privacy_protocol: str
    access: str
    evidence: ConfigEvidence


@dataclass(frozen=True)
class F5NTPServer:
    """One NTP association. ``source`` is ``tmsh`` (the ``servers`` list) or ``include``.

    F5 K14120: tmsh/GUI server entries are for unauthenticated NTP; authentication is
    only configurable through ``include`` (``server <ip> key <n>`` plus ``trustedkey <n>``).
    Key material lives in /etc/ntp/keys, outside the export.
    """

    address: str
    source: str
    key_id: str | None
    key_trusted: bool
    evidence: ConfigEvidence


@dataclass(frozen=True)
class F5ClientSSLProfile:
    name: str
    mode_enabled: bool | None
    allow_non_ssl: bool | None
    evidence: ConfigEvidence
    ciphers: str = ""
    ciphers_evidence: ConfigEvidence | None = None
    parent: str = ""  # defaults-from
    options: tuple[str, ...] | None = None  # None when not set on this profile


@dataclass(frozen=True)
class F5Virtual:
    name: str
    enabled: bool | None
    client_profiles: tuple[str, ...]
    evidence: ConfigEvidence
    policies: tuple[str, ...] = ()
    persist: tuple[str, ...] = ()
    server_profiles: tuple[str, ...] = ()  # context serverside


@dataclass(frozen=True)
class F5VirtualEndpoint:
    virtual: F5Virtual
    port: str
    source: str
    source_explicit: bool
    protocol: str  # tcp | udp | any | unknown
    protocol_explicit: bool
    evidence: ConfigEvidence


@dataclass(frozen=True)
class F5ASMPolicy:
    """`asm policy`: tmsh reference — `[active | inactive]` (default inactive),
    `blocking-mode [enabled | disabled]` (disabled = transparent, violations only logged)."""

    name: str
    active: bool
    blocking_mode: str  # enabled | disabled | unknown
    evidence: ConfigEvidence


@dataclass(frozen=True)
class F5LTMPolicy:
    name: str
    asm_policies: tuple[str, ...]  # `asm ... enable policy <name>` actions
    evidence: ConfigEvidence


@dataclass(frozen=True)
class F5IKEPeer:
    """`net ipsec ike-peer`: tmsh reference — `mode main | aggressive`, `version` (default v1),
    `phase1-auth-method pre-shared-key | rsa-signature | ...`, `state enabled | disabled`."""

    name: str
    mode: str  # main | aggressive | unknown
    auth_method: str
    versions: tuple[str, ...]
    enabled: bool
    evidence: ConfigEvidence
    version_explicit: bool = True


@dataclass(frozen=True)
class F5SelfIP:
    """`net self`: tmsh reference — `allow-service all | default | none | { list }`, default none.
    K17333: `default` includes tcp:22 (SSH) and tcp:443 (HTTPS)."""

    name: str
    allow_service: tuple[str, ...]  # ("all",), ("default",), ("none",) or the custom list; () when absent
    vlan: str
    evidence: ConfigEvidence


def _top_level(body: list[_TokenValue]) -> dict[str, tuple[list[str], int]]:
    """Top-level `key value` / `key { values }` pairs of an object body with their line."""
    result: dict[str, tuple[list[str], int]] = {}
    index = 0
    while index < len(body):
        token = body[index]
        if token.text in {"{", "}"}:
            index += 1
            continue
        if index + 1 < len(body) and body[index + 1].text == "{":
            values = _group_values(body, index + 1) or []
            result[token.text] = (values, token.line)
            depth = 0
            index += 1
            while index < len(body):
                if body[index].text == "{":
                    depth += 1
                elif body[index].text == "}":
                    depth -= 1
                    if depth == 0:
                        break
                index += 1
            index += 1
            continue
        if index + 1 < len(body) and body[index + 1].line == token.line and body[index + 1].text not in {"{", "}"}:
            result[token.text] = ([body[index + 1].text], token.line)
            index += 2
            continue
        result[token.text] = ([], token.line)
        index += 1
    return result


def _tokens(content: str) -> list[_TokenValue]:
    result: list[_TokenValue] = []
    line = 1
    previous = 0
    for match in _TOKEN.finditer(content):
        line += content.count("\n", previous, match.start())
        previous = match.end()
        token = match.group()
        token_line = line
        line += token.count("\n")
        if token.startswith("#"):
            continue
        if token[:1] in {'"', "'"} and token[-1:] == token[:1]:
            token = token[1:-1]
        result.append(_TokenValue(token, token_line))
    return result


def _group_values(body: list[_TokenValue], start: int) -> list[str] | None:
    if start >= len(body) or body[start].text != "{":
        return None
    depth = 0
    values: list[str] = []
    for item in body[start:]:
        if item.text == "{":
            depth += 1
        elif item.text == "}":
            depth -= 1
            if depth == 0:
                return values
        elif depth == 1:
            values.append(item.text)
    return None


def _block_contents(body: list[_TokenValue], start: int) -> list[_TokenValue] | None:
    if start >= len(body) or body[start].text != "{":
        return None
    depth = 0
    for index in range(start, len(body)):
        if body[index].text == "{":
            depth += 1
        elif body[index].text == "}":
            depth -= 1
            if depth == 0:
                return body[start + 1:index]
    return None


def _object_name(raw: str, owner: str = "/Common/object") -> str | None:
    if not _SAFE_NAME.fullmatch(raw):
        return None
    if raw.startswith("/"):
        return raw
    if "/" in raw:
        return f"/{raw}"
    return f"{owner.rsplit('/', 1)[0]}/{raw}"


class F5BIGIPParser(BaseDeviceParser):
    device_type = "F5_BIGIP"

    def __init__(self, config_filepath: str):
        super().__init__(config_filepath)
        with open(config_filepath, encoding="utf-8-sig", errors="replace") as source:
            content = source.read()
        self._source_digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        version = _VERSION.search(content)
        self._version = version.group(1) if version else "?"
        self._settings: dict[tuple[str, str], F5Setting] = {}
        self._scopes_seen: set[str] = set()
        self._snmp_versions: dict[str, tuple[str, ConfigEvidence]] = {}
        self._client_ssl: dict[str, F5ClientSSLProfile] = {}
        self._server_ssl: dict[str, dict] = {}
        self._virtuals: dict[str, F5Virtual] = {}
        self._user_secret_lines: dict[str, int] = {}
        self._user_credentials: dict[str, F5UserCredential] = {}
        self._remote_auth_profiles: dict[tuple[str, str], F5RemoteAuthProfile] = {}
        self._snmp_agent: F5SNMPAgent | None = None
        self._snmp_communities: dict[str, F5SNMPCommunity] = {}
        self._snmp_users: dict[str, F5SNMPUser] = {}
        self._provision: dict[str, tuple[str, int]] = {}
        self._db: dict[str, tuple[str, int]] = {}
        self._asm_policies: dict[str, F5ASMPolicy] = {}
        self._ltm_policies: dict[str, F5LTMPolicy] = {}
        self._ntp_servers: tuple[F5NTPServer, ...] | None = None
        self._ike_peers: dict[str, F5IKEPeer] = {}
        self._user_shells: dict[str, ConfigEvidence] = {}
        self._cookie_persistence: dict[str, dict] = {}
        self._snmp_traps: list[tuple[str, str, ConfigEvidence]] = []
        self._virtual_endpoints: dict[str, dict] = {}
        self._monitor_basic_auth: list[ConfigEvidence] = []
        self._self_ips: dict[str, F5SelfIP] = {}
        self._parse(_tokens(content))
        self._native = (
            *self._settings.values(), *self._remote_auth_profiles.values(),
            *self._client_ssl.values(), *self._virtuals.values(),
            *((self._snmp_agent,) if self._snmp_agent else ()),
            *self._snmp_communities.values(), *self._snmp_users.values(),
        )

    def _parse(self, tokens: list[_TokenValue]) -> None:
        cursor = 0
        recognized = False
        while cursor < len(tokens):
            header: list[str] = []
            header_line = tokens[cursor].line
            while cursor < len(tokens) and tokens[cursor].text not in {"{", "}"}:
                header.append(tokens[cursor].text)
                cursor += 1
            if cursor == len(tokens) or tokens[cursor].text != "{" or not header:
                raise F5ParseError(header_line)
            cursor += 1
            body_start = cursor
            depth = 1
            while cursor < len(tokens) and depth:
                if tokens[cursor].text == "{":
                    depth += 1
                elif tokens[cursor].text == "}":
                    depth -= 1
                cursor += 1
            if depth:
                raise F5ParseError(header_line)
            scope = " ".join(item.lstrip("/") for item in header)
            if scope in _FIELDS:
                recognized = True
                self._scopes_seen.add(scope)
                self._read_settings(scope, tokens[body_start:cursor - 1])
            elif scope == "sys snmp":
                recognized = True
                self._read_snmp(header_line, tokens[body_start:cursor - 1])
            elif len(header) == 4 and header[:3] == ["ltm", "profile", "client-ssl"]:
                recognized = True
                self._read_client_ssl(header[3], header_line, tokens[body_start:cursor - 1])
            elif len(header) == 3 and header[:2] == ["ltm", "virtual"]:
                recognized = True
                self._read_virtual(header[2], header_line, tokens[body_start:cursor - 1])
            elif len(header) == 3 and header[:2] == ["sys", "provision"]:
                body = tokens[body_start:cursor - 1]
                level = next((body[i + 1].text for i in range(len(body) - 1) if body[i].text == "level"), "unknown")
                self._provision[header[2].casefold()] = (level.casefold(), header_line)
            elif len(header) == 3 and header[:2] == ["sys", "db"]:
                body = tokens[body_start:cursor - 1]
                value = next((body[i + 1].text for i in range(len(body) - 1) if body[i].text == "value"), "")
                self._db[header[2].casefold()] = (value, header_line)
            elif len(header) == 3 and header[:2] == ["asm", "policy"]:
                self._read_asm_policy(header[2], header_line, tokens[body_start:cursor - 1])
            elif len(header) == 3 and header[:2] == ["ltm", "policy"]:
                self._read_ltm_policy(header[2], header_line, tokens[body_start:cursor - 1])
            elif len(header) == 4 and header[:3] == ["net", "ipsec", "ike-peer"]:
                self._read_ike_peer(header[3], header_line, tokens[body_start:cursor - 1])
            elif len(header) == 4 and header[:2] == ["ltm", "monitor"] and header[2] in {"http", "https"}:
                for position, item in enumerate(tokens[body_start:cursor - 1]):
                    if item.text == "send" and position + 1 < cursor - 1 - body_start:
                        value = tokens[body_start + position + 1].text
                        if re.search(r"(?i)authorization:\s*basic\s+\S+", value):
                            self._monitor_basic_auth.append(ConfigEvidence(
                                f"ltm monitor {header[2]} {header[3]} send <Authorization: Basic redacted>",
                                self.config_filepath, item.line))
            elif len(header) == 4 and header[:3] == ["ltm", "persistence", "cookie"]:
                name = _object_name(header[3])
                if name:
                    items = _top_level(tokens[body_start:cursor - 1])
                    self._cookie_persistence[name] = {
                        "parent": _object_name((items.get("defaults-from", ([""], 0))[0] or [""])[0], name) or "",
                        "method_set": "method" in items,
                        "method": (items.get("method", (["insert"], 0))[0] or ["insert"])[0],
                        "encryption": (items.get("cookie-encryption", ([""], 0))[0] or [""])[0],
                        "evidence": ConfigEvidence(
                            f"ltm persistence cookie {name} cookie-encryption "
                            f"{(items.get('cookie-encryption', (['<absent>'], 0))[0] or ['<absent>'])[0]}",
                            self.config_filepath, items.get("cookie-encryption", ([], header_line))[1]),
                    }
            elif len(header) == 4 and header[:3] == ["ltm", "profile", "server-ssl"]:
                name = _object_name(header[3])
                if name:
                    items = _top_level(tokens[body_start:cursor - 1])
                    self._server_ssl[name] = {
                        "parent": _object_name((items.get("defaults-from", ([""], 0))[0] or [""])[0], name) or "",
                        "peer_cert_mode": (items.get("peer-cert-mode", ([""], 0))[0] or [""])[0],
                        "line": items.get("peer-cert-mode", ([], header_line))[1],
                    }
            elif len(header) == 3 and header[:2] == ["net", "self"]:
                self._read_self_ip(header[2], header_line, tokens[body_start:cursor - 1])
            elif scope == "sys ntp":
                self._read_ntp(header_line, tokens[body_start:cursor - 1])
            elif len(header) == 3 and header[:2] == ["auth", "user"]:
                recognized = True
                self._read_user_credential(header[2], tokens[body_start:cursor - 1])
            elif len(header) == 3 and header[:2] in (
                ["auth", "radius"], ["auth", "ldap"],
                ["auth", "tacacs"], ["auth", "cert-ldap"],
            ):
                recognized = True
                self._read_remote_auth_profile(
                    header[1], header[2], header_line, tokens[body_start:cursor - 1]
                )
        if not recognized:
            raise F5ParseError(1)

    def _read_user_credential(self, raw_name: str, body: list[_TokenValue]) -> None:
        name = _object_name(raw_name)
        if name is None:
            return
        depth = 0
        for index, token in enumerate(body):
            if token.text == "{":
                depth += 1
            elif token.text == "}":
                depth -= 1
            elif depth == 0 and token.text == "shell" and index + 1 < len(body):
                self._user_shells[name] = ConfigEvidence(
                    f"auth user {name} shell {body[index + 1].text}", self.config_filepath, token.line)
            elif depth == 0 and token.text in {"password", "encrypted-password"}:
                candidate = body[index + 1].text if index + 1 < len(body) else ""
                if candidate and candidate not in {"{", "}", "none", "default"}:
                    self._user_secret_lines[name] = token.line
                    masked = candidate.casefold() in {"<redacted>", "redacted", "<hidden>"} or set(candidate) == {"*"}
                    storage = "unknown" if masked else "plaintext" if token.text == "password" else "encrypted"
                    default = _DEFAULT_PASSWORDS.get(name.rsplit("/", 1)[-1])
                    known_default = bool(default) and (
                        candidate.strip('"') == default if storage == "plaintext"
                        else storage == "encrypted" and crypt_matches(default, candidate)
                    )
                    self._user_credentials[name] = F5UserCredential(
                        known_default=known_default,
                        name=name,
                        storage=storage,
                        evidence=ConfigEvidence(
                            f"auth user {name} {token.text} <redacted>",
                            self.config_filepath,
                            token.line,
                        ),
                    )

    def get_local_user_credentials(self) -> tuple[F5UserCredential, ...]:
        return tuple(self._user_credentials.values())

    def _read_remote_auth_profile(self, provider_type: str, raw_name: str,
                                  line_number: int, body: list[_TokenValue]) -> None:
        name = _object_name(raw_name)
        if name is None:
            return
        previous = self._remote_auth_profiles.get((provider_type, name))
        state = previous.servers_state if previous else "unknown"
        ssl_state = previous.ssl_state if previous else "unknown"
        peer_check_state = previous.peer_check_state if previous else "unknown"
        depth = 0
        for index, token in enumerate(body):
            if token.text == "{":
                depth += 1
            elif token.text == "}":
                depth -= 1
            elif depth == 0 and token.text == "servers":
                next_index = index + 1
                if next_index < len(body) and body[next_index].text == "replace-all-with":
                    next_index += 1
                candidate = body[next_index].text if next_index < len(body) else ""
                group = _group_values(body, next_index) if candidate == "{" else None
                state = "none" if candidate == "none" else (
                    "configured" if group else "unknown"
                )
            elif depth == 0 and token.text == "ssl" and provider_type in {"ldap", "cert-ldap"}:
                candidate = body[index + 1].text if index + 1 < len(body) else ""
                ssl_state = candidate if candidate in {"enabled", "disabled", "start-tls"} else "unknown"
            elif depth == 0 and token.text == "ssl-check-peer" and provider_type in {"ldap", "cert-ldap"}:
                candidate = body[index + 1].text if index + 1 < len(body) else ""
                peer_check_state = candidate if candidate in {"enabled", "disabled"} else "unknown"
        self._remote_auth_profiles[(provider_type, name)] = F5RemoteAuthProfile(
            provider_type, name, state, ssl_state, peer_check_state,
            ConfigEvidence(
                f"auth {provider_type} {name} servers {state} ssl {ssl_state} "
                f"ssl-check-peer {peer_check_state}",
                self.config_filepath, line_number,
            ),
        )

    def get_remote_auth_profiles(self, provider_type: str) -> tuple[F5RemoteAuthProfile, ...]:
        return tuple(
            profile for profile in self._remote_auth_profiles.values()
            if profile.provider_type == provider_type
        )

    def get_report_secret_lines(self) -> list[dict]:
        """Return user credential lines only after verifying the saved export is unchanged."""
        with open(self.config_filepath, encoding="utf-8-sig", errors="replace") as source:
            content = source.read()
        if hashlib.sha256(content.encode("utf-8")).hexdigest() != self._source_digest:
            raise ValueError("configuration changed after BIG-IP parsing; refusing secret report")
        lines = content.splitlines()
        entries = []
        for name, number in sorted(self._user_secret_lines.items(), key=lambda item: item[1]):
            if 1 <= number <= len(lines):
                raw_line = lines[number - 1].strip()
                if re.search(r"\b(?:encrypted-password|password)\s+\S+", raw_line):
                    entries.append({
                        "line-number": number,
                        "context": "local_user",
                        "source-line": raw_line,
                    })
        return entries

    def _read_settings(self, scope: str, body: list[_TokenValue]) -> None:
        depth = 0
        for index, token in enumerate(body):
            if token.text == "{":
                depth += 1
                continue
            if token.text == "}":
                depth -= 1
                continue
            if depth != 0 or token.text not in _FIELDS[scope]:
                continue
            name = token.text
            next_index = index + 1
            if next_index < len(body) and body[next_index].text == "replace-all-with":
                next_index += 1
            candidate = body[next_index].text if next_index < len(body) else ""
            group = _group_values(body, next_index) if candidate == "{" else None
            value: str | int | None = None
            if name == "hostname":
                value = (candidate if candidate not in _FIELDS[scope]
                         and re.fullmatch(r"[A-Za-z0-9._-]+", candidate) else None)
            elif name in {"login", "redirect-http-to-https", "audit", "policy-enforcement"}:
                value = candidate if candidate in {"enabled", "disabled"} else None
            elif name in {"inactivity-timeout", "console-inactivity-timeout", "idle-timeout",
                          "max-login-failures", "minimum-length", "password-memory"}:
                if candidate == "disabled" and name == "idle-timeout":
                    value = candidate
                elif re.fullmatch(r"[0-9]+", candidate):
                    value = int(candidate)
            elif name == "allow":
                entries = group if group is not None else [candidate]
                if any(item.casefold() in {"all", "0.0.0.0/0", "::/0"} for item in entries):
                    value = "unrestricted"
                elif entries == ["none"]:
                    value = "unrestricted" if scope == "sys sshd" else "none"
                elif entries and all(item and item not in {"{", "}", "add", "delete", "replace-all-with"} | _FIELDS[scope]
                                     for item in entries):
                    value = "restricted"
            elif name == "remote-servers":
                if candidate == "none":
                    value = "none"
                elif group:
                    value = "configured"
            elif name == "type" and scope == "auth source":
                if candidate in {"local", "radius", "ldap", "tacacs", "cert-ldap",
                                 "active-directory", "apm-auth"}:
                    value = candidate
            elif name == "ssl-protocol":
                value = candidate if resolve_ssl_protocols(candidate) is not None else None
            elif name == "ssl-ciphersuite":
                value = candidate if _CIPHER_LIST.fullmatch(candidate) else None
            elif name in {"default-role", "remote-console-access"} and scope == "auth remote-user":
                value = candidate if re.fullmatch(r"[a-z-]+", candidate) else None
            elif name == "fallback" and scope == "auth source":
                if candidate in {"true", "false"}:
                    value = candidate
            state = "explicit" if value is not None else "unknown"
            safe_value = str(value) if value is not None else "<unknown>"
            evidence = ConfigEvidence(
                f"{scope} {name} {safe_value}", self.config_filepath, token.line,
            )
            self._settings[(scope, name)] = F5Setting(scope, name, value, state, evidence)

    def _read_client_ssl(self, raw_name: str, line_number: int,
                         body: list[_TokenValue]) -> None:
        name = _object_name(raw_name)
        if name is None:
            return
        previous = self._client_ssl.get(name)
        mode = previous.mode_enabled if previous else None
        cleartext = previous.allow_non_ssl if previous else None
        ciphers = previous.ciphers if previous else ""
        ciphers_evidence = previous.ciphers_evidence if previous else None
        parent = previous.parent if previous else ""
        options = previous.options if previous else None
        depth = 0
        for index, token in enumerate(body):
            if token.text == "{":
                depth += 1
            elif token.text == "}":
                depth -= 1
            elif depth == 0 and token.text == "defaults-from" and index + 1 < len(body):
                parent = _object_name(body[index + 1].text, name) or ""
            elif depth == 0 and token.text == "options" and index + 1 < len(body):
                members = _block_contents(body, index + 1)
                options = (tuple(member.text for member in members if member.text not in {"{", "}"})
                           if members is not None else (body[index + 1].text,))
            elif depth == 0 and token.text == "ciphers" and index + 1 < len(body):
                ciphers = body[index + 1].text
                ciphers_evidence = ConfigEvidence(
                    f"ltm profile client-ssl {name} ciphers {ciphers}", self.config_filepath, token.line)
            elif depth == 0 and token.text in {"mode", "allow-non-ssl"}:
                candidate = body[index + 1].text if index + 1 < len(body) else ""
                value = {"enabled": True, "disabled": False}.get(candidate)
                if token.text == "mode":
                    mode = value
                else:
                    cleartext = value
        self._client_ssl[name] = F5ClientSSLProfile(
            name, mode, cleartext,
            ConfigEvidence(f"ltm profile client-ssl {name} allow-non-ssl {'enabled' if cleartext else 'disabled' if cleartext is False else '<unknown>'}",
                           self.config_filepath, line_number),
            ciphers, ciphers_evidence, parent, options,
        )

    def _read_virtual(self, raw_name: str, line_number: int,
                      body: list[_TokenValue]) -> None:
        name = _object_name(raw_name)
        if name is None:
            return
        previous = self._virtuals.get(name)
        enabled = previous.enabled if previous else None
        profiles = previous.client_profiles if previous else ()
        server_profiles = previous.server_profiles if previous else ()
        policies = previous.policies if previous else ()
        persist = previous.persist if previous else ()
        depth = 0
        for index, token in enumerate(body):
            if token.text == "{":
                depth += 1
            elif token.text == "}":
                depth -= 1
            elif depth == 0 and token.text in {"enabled", "disabled"}:
                enabled = token.text == "enabled"
            elif depth == 0 and token.text == "persist":
                next_index = index + 1
                if next_index < len(body) and body[next_index].text in {"replace-all-with", "add"}:
                    next_index += 1
                members = _block_contents(body, next_index) or []
                attached_persist, member_depth = [], 0
                for member in members:
                    if member.text == "{":
                        member_depth += 1
                    elif member.text == "}":
                        member_depth -= 1
                    elif member_depth == 0 and member.text != "none":
                        persist_name = _object_name(member.text, name)
                        if persist_name:
                            attached_persist.append(persist_name)
                persist = tuple(attached_persist)
            elif depth == 0 and token.text == "policies":
                next_index = index + 1
                if next_index < len(body) and body[next_index].text in {"replace-all-with", "add"}:
                    next_index += 1
                members = _block_contents(body, next_index) or []
                attached, member_depth = [], 0
                for member in members:
                    if member.text == "{":
                        member_depth += 1
                    elif member.text == "}":
                        member_depth -= 1
                    elif member_depth == 0 and member.text != "none":
                        policy_name = _object_name(member.text, name)
                        if policy_name:
                            attached.append(policy_name)
                policies = tuple(attached)
            elif depth == 0 and token.text == "profiles":
                next_index = index + 1
                if next_index < len(body) and body[next_index].text == "replace-all-with":
                    next_index += 1
                if next_index < len(body) and body[next_index].text in {"none", "default"}:
                    profiles = ()
                    continue
                members = _block_contents(body, next_index)
                if members is None:
                    profiles = ()
                    continue
                selected: list[str] = []
                server_selected: list[str] = []
                member_depth = 0
                for member_index, member in enumerate(members):
                    if member.text == "{":
                        member_depth += 1
                    elif member.text == "}":
                        member_depth -= 1
                    elif member_depth == 0 and member_index + 1 < len(members) and members[member_index + 1].text == "{":
                        profile_name = _object_name(member.text, name)
                        attributes = _block_contents(members, member_index + 1)
                        contexts = {
                            attributes[position + 1].text
                            for position in range(len(attributes or []) - 1)
                            if attributes[position].text == "context"
                        }
                        if profile_name and contexts & {"all", "clientside"}:
                            selected.append(profile_name)
                        if profile_name and "serverside" in contexts:
                            server_selected.append(profile_name)
                profiles = tuple(selected)
                server_profiles = tuple(server_selected)
        self._record_virtual_endpoint(name, body)
        self._virtuals[name] = F5Virtual(
            name, enabled, profiles,
            ConfigEvidence(f"ltm virtual {name} {'enabled' if enabled else 'disabled' if enabled is False else '<unknown>'}",
                           self.config_filepath, line_number),
            policies, persist, server_profiles,
        )

    def _record_virtual_endpoint(self, name: str, body: list[_TokenValue]) -> None:
        items = _top_level(body)
        # Internal virtuals do not accept client connections; reject virtuals
        # explicitly reject traffic instead of publishing the destination port.
        if "internal" in items or "reject" in items:
            return
        destination, destination_line = items.get("destination", ([], 0))
        if not destination:
            return
        target = destination[0]
        address, _, port = target.rpartition(":") if target.count(":") == 1 else target.rpartition(".")
        release = self.get_release()
        source_values = items.get("source", ([], 0))[0]
        source_explicit = "source" in items
        # F5 LTM Basics documents the unrestricted source default for v13/v14.
        # Later releases need release-specific evidence before using absence.
        source = (source_values[0] if source_values else
                  "0.0.0.0/0" if not source_explicit and release and release[0] in {13, 14}
                  else "unknown")
        protocol_values = items.get("ip-protocol", ([], 0))[0]
        protocol_explicit = "ip-protocol" in items
        raw_protocol = protocol_values[0].casefold() if protocol_values else ""
        protocol = {"6": "tcp", "17": "udp"}.get(raw_protocol, raw_protocol)
        if protocol not in {"tcp", "udp", "any"}:
            # The v13-v17 tmsh references document `any` as the default.
            # Never infer it for an export without a supported release header.
            protocol = "any" if not protocol_explicit and release and 13 <= release[0] <= 17 else "unknown"
        self._virtual_endpoints[name] = {
            "port": port, "source": source, "source_explicit": source_explicit,
            "protocol": protocol,
            "protocol_explicit": protocol_explicit,
            "evidence": ConfigEvidence(f"ltm virtual {name} destination {target} source {source} "
                                       f"ip-protocol {protocol if protocol_explicit else '<absent>'}",
                                       self.config_filepath, destination_line),
        }

    def _read_asm_policy(self, raw_name: str, line_number: int, body: list[_TokenValue]) -> None:
        name = _object_name(raw_name)
        if name is None:
            return
        texts = [token.text for token in body]
        top = []
        depth = 0
        for text in texts:
            if text == "{":
                depth += 1
            elif text == "}":
                depth -= 1
            elif depth == 0:
                top.append(text)
        active = "active" in top and "inactive" not in top
        blocking = top[top.index("blocking-mode") + 1] if "blocking-mode" in top[:-1] else "unknown"
        self._asm_policies[name] = F5ASMPolicy(name, active, blocking, ConfigEvidence(
            f"asm policy {name} {'active' if active else 'inactive'} blocking-mode {blocking}",
            self.config_filepath, line_number))

    def _read_ltm_policy(self, raw_name: str, line_number: int, body: list[_TokenValue]) -> None:
        name = _object_name(raw_name)
        if name is None:
            return
        texts = [token.text for token in body]
        referenced = []
        for index, text in enumerate(texts):
            if text == "asm":
                window = texts[index + 1:index + 6]
                if "enable" in window and "policy" in window:
                    position = window.index("policy")
                    if position + 1 < len(window):
                        target = _object_name(window[position + 1])
                        if target and target not in referenced:
                            referenced.append(target)
        self._ltm_policies[name] = F5LTMPolicy(name, tuple(referenced), ConfigEvidence(
            f"ltm policy {name} asm enable policy {', '.join(referenced) or '<none>'}",
            self.config_filepath, line_number))

    def _read_ike_peer(self, raw_name: str, line_number: int, body: list[_TokenValue]) -> None:
        name = _object_name(raw_name)
        if name is None:
            return
        items = _top_level(body)
        mode = (items.get("mode", (["unknown"], line_number))[0] or ["unknown"])[0]
        auth = (items.get("phase1-auth-method", (["unknown"], line_number))[0] or ["unknown"])[0]
        versions = tuple(items["version"][0]) if "version" in items else ("v1",)
        enabled = (items.get("state", (["enabled"], line_number))[0] or ["enabled"])[0] != "disabled"
        evidence_line = items["mode"][1] if "mode" in items else line_number
        self._ike_peers[name] = F5IKEPeer(name, mode, auth, versions, enabled, ConfigEvidence(
            f"net ipsec ike-peer {name} mode {mode} phase1-auth-method {auth} version {' '.join(versions)}",
            self.config_filepath, evidence_line), "version" in items)

    def get_ike_peers(self) -> tuple[F5IKEPeer, ...]:
        return tuple(self._ike_peers.values())

    def _read_self_ip(self, raw_name: str, line_number: int, body: list[_TokenValue]) -> None:
        items = _top_level(body)
        allow, allow_line = items.get("allow-service", ([], line_number))
        vlan = (items.get("vlan", ([""], line_number))[0] or [""])[0]
        label = " ".join(allow) if allow else "<absent: none>"
        self._self_ips[raw_name] = F5SelfIP(raw_name, tuple(allow), vlan, ConfigEvidence(
            f"net self {raw_name} allow-service {label}", self.config_filepath, allow_line))

    def get_self_ips(self) -> tuple[F5SelfIP, ...]:
        return tuple(self._self_ips.values())

    def get_asm_bindings(self) -> tuple[tuple[F5Virtual, F5LTMPolicy, F5ASMPolicy], ...]:
        """Enabled virtual servers (documented default: enabled) whose attached LTM policy enables an ASM policy."""

        result = []
        for virtual in self._virtuals.values():
            if virtual.enabled is False:
                continue
            for policy_name in virtual.policies:
                ltm = self._ltm_policies.get(policy_name)
                for asm_name in (ltm.asm_policies if ltm else ()):
                    asm = self._asm_policies.get(asm_name)
                    if asm:
                        result.append((virtual, ltm, asm))
        return tuple(result)

    def get_bound_weak_client_ciphers(self) -> tuple[tuple[F5Virtual, F5ClientSSLProfile, tuple[str, ...]], ...]:
        """Enabled virtual servers whose clientside SSL profile explicitly adds weak cipher tokens.

        Only positive tokens of the explicit ``ciphers`` string count (``!``/``-`` exclusions
        are ignored); the built-in DEFAULT string is release dependent and not assessed.
        """
        result = []
        for virtual in self._virtuals.values():
            if virtual.enabled is False:
                continue
            for profile_name in virtual.client_profiles:
                profile = self._client_ssl.get(profile_name)
                if not profile or not profile.ciphers:
                    continue
                weak = tuple(
                    token for token in re.split(r"[:, ]+", profile.ciphers)
                    if token and token[0] not in "!-" and _WEAK_SUITE.search(token.lstrip("+").upper())
                )
                if weak:
                    result.append((virtual, profile, weak))
        return tuple(result)

    def get_snmp_legacy_versions(self) -> dict[str, tuple[str, ConfigEvidence | None]]:
        """``sys snmp snmpv1``/``snmpv2c`` state; tmsh reference default is enable (SC-044 F5-19)."""
        return {name: self._snmp_versions.get(name, ("enable", None)) for name in ("snmpv1", "snmpv2c")}

    def has_db_entries(self) -> bool:
        """Whether the export contains any ``sys db`` objects (a system-level export)."""
        return bool(self._db)

    def has_object(self, scope: str) -> bool:
        """Whether the export contains the ``scope`` object, so its missing properties are at default."""
        return scope in self._scopes_seen

    def get_release(self) -> tuple[int, int, int] | None:
        """Exact ``(major, minor, patch)`` from ``#TMSH-VERSION`` (SC-044), or None."""
        numbers = [int(item) for item in re.findall(r"\d+", self._version)[:3]]
        return tuple(numbers) if len(numbers) == 3 else None

    def get_bound_default_cipher_profiles(self) -> tuple[tuple[F5Virtual, str, tuple[str, ...], ConfigEvidence], ...]:
        """Enabled virtuals whose clientside SSL profile resolves to the built-in ``DEFAULT`` ciphers (SC-044).

        The ``defaults-from`` chain is followed through exported profiles; a chain that ends
        at a built-in parent (for example ``/Common/clientssl``) or sets no ``ciphers`` uses
        ``DEFAULT``. Returns (virtual, profile, effective options, evidence); options are
        ``()`` when no profile in the chain sets them (built-in value not asserted).
        """
        result = []
        for virtual in self._virtuals.values():
            if virtual.enabled is False:
                continue
            for name in virtual.client_profiles:
                profile = self._client_ssl.get(name)
                if profile is None and name.rsplit("/", 1)[-1] != "clientssl":
                    continue  # not a client-ssl profile we can resolve
                ciphers, options, seen, current = "", None, set(), profile
                while current is not None and current.name not in seen:
                    seen.add(current.name)
                    ciphers = ciphers or current.ciphers
                    options = options if options is not None else current.options
                    current = self._client_ssl.get(current.parent) if current.parent else None
                if (ciphers or "DEFAULT").strip('"').upper() != "DEFAULT":
                    continue
                evidence = (profile.ciphers_evidence or profile.evidence) if profile else virtual.evidence
                result.append((virtual, name, options or (), evidence))
        return tuple(result)

    def get_unencrypted_cookie_persistence(self) -> tuple[tuple[F5Virtual, str, ConfigEvidence], ...]:
        """Enabled virtual servers using an insert/rewrite cookie persistence profile with
        explicit ``cookie-encryption disabled`` (K6917: the cookie encodes pool member IP and port)."""
        result = []
        for virtual in self._virtuals.values():
            if virtual.enabled is False:
                continue
            for name in virtual.persist:
                profile = self._cookie_persistence.get(name)
                if profile and profile["encryption"] == "disabled" and profile["method"] in {"insert", "rewrite"}:
                    result.append((virtual, name, profile["evidence"]))
        return tuple(result)

    def get_default_unencrypted_cookie_persistence(self) -> tuple[tuple[F5Virtual, str, str], ...]:
        """Enabled virtuals whose cookie persistence profile never sets ``cookie-encryption`` (SC-044 F5-15).

        K23254150: 'Disabled: (Default setting)'. The ``defaults-from`` chain is followed
        through exported profiles; the built-in ``cookie`` profile uses method insert.
        Returns (virtual, profile, effective method).
        """
        result = []
        for virtual in self._virtuals.values():
            if virtual.enabled is False:
                continue
            for name in virtual.persist:
                profile, method, encryption, seen = self._cookie_persistence.get(name), None, "", set()
                if profile is None and name.rsplit("/", 1)[-1] != "cookie":
                    continue
                current = profile
                while current is not None and id(current) not in seen:
                    seen.add(id(current))
                    if method is None and current["method_set"]:
                        method = current["method"]
                    encryption = encryption or current["encryption"]
                    current = self._cookie_persistence.get(current["parent"]) if current["parent"] else None
                if not encryption and (method or "insert") in {"insert", "rewrite", "passive"}:
                    result.append((virtual, name, method or "insert"))
        return tuple(result)

    def get_unverified_server_ssl(self) -> tuple[tuple[F5Virtual, str, str, ConfigEvidence], ...]:
        """Enabled virtuals whose serverside SSL profile resolves to ``peer-cert-mode ignore`` (SC-044 F5-14).

        tmsh ltm profile server-ssl: 'The default value is ignore.' Only exported
        server-ssl profiles and the built-in ``serverssl`` profile are resolved.
        Returns (virtual, profile, mode, evidence).
        """
        result = []
        for virtual in self._virtuals.values():
            if virtual.enabled is False:
                continue
            for name in virtual.server_profiles:
                profile = self._server_ssl.get(name)
                if profile is None and name.rsplit("/", 1)[-1] != "serverssl":
                    continue
                mode, line, current, seen = "", 0, profile, set()
                while current is not None and id(current) not in seen and not mode:
                    seen.add(id(current))
                    mode, line = current["peer_cert_mode"], current["line"]
                    current = self._server_ssl.get(current["parent"]) if current["parent"] else None
                if (mode or "ignore") == "ignore":
                    result.append((virtual, name, mode or "ignore", ConfigEvidence(
                        f"ltm profile server-ssl {name} peer-cert-mode {mode or '<absent: default ignore>'}",
                        self.config_filepath, line or None)))
        return tuple(result)

    def get_snmp_traps(self) -> tuple[tuple[str, str, ConfigEvidence], ...]:
        """``sys snmp traps`` targets as (name, explicit version or '', evidence)."""
        return tuple(self._snmp_traps)

    def get_monitor_basic_auth(self) -> tuple[ConfigEvidence, ...]:
        """HTTP/HTTPS monitors whose send string carries an ``Authorization: Basic`` header."""
        return tuple(self._monitor_basic_auth)

    def get_virtual_endpoints(self) -> tuple[F5VirtualEndpoint, ...]:
        """Enabled virtual servers with parser-resolved IP protocol and evidence."""
        result = []
        for name, endpoint in self._virtual_endpoints.items():
            virtual = self._virtuals.get(name)
            if virtual is None or virtual.enabled is False:
                continue
            result.append(F5VirtualEndpoint(virtual, endpoint["port"], endpoint["source"],
                                            endpoint["source_explicit"], endpoint["protocol"],
                                            endpoint["protocol_explicit"],
                                            endpoint["evidence"]))
        return tuple(result)

    def get_user_shells(self) -> dict[str, ConfigEvidence]:
        """Explicit ``auth user <name> shell`` values (bash | tmsh | none)."""
        return dict(self._user_shells)

    def get_db(self, name: str) -> tuple[str, ConfigEvidence] | None:
        """An exported ``sys db`` value with its evidence."""
        value, line = self._db.get(name.casefold(), ("", 0))
        if not value:
            return None
        return value, ConfigEvidence(f"sys db {name} value {value}", self.config_filepath, line)

    def get_firewall_default_action(self) -> tuple[str, ConfigEvidence | None]:
        """`sys db tm.fw.defaultaction`; F5 documents the default as accept (ADC mode)."""

        value, line = self._db.get("tm.fw.defaultaction", ("", 0))
        if not value:
            return "accept", None
        return value.casefold(), ConfigEvidence(
            f"sys db tm.fw.defaultaction value {value}", self.config_filepath, line)

    def get_bound_cleartext_client_ssl(self) -> tuple[tuple[F5Virtual, F5ClientSSLProfile], ...]:
        return tuple(
            (virtual, profile)
            for virtual in self._virtuals.values() if virtual.enabled is not False  # tmsh: default enabled
            for name in virtual.client_profiles
            if (profile := self._client_ssl.get(name)) is not None
            and profile.mode_enabled is True and profile.allow_non_ssl is True
        )

    @staticmethod
    def _named_blocks(body: list[_TokenValue], start: int) -> list[tuple[str, int, dict[str, str]]]:
        """``name { key value ... }`` members of a group; nested groups are skipped."""

        members = _block_contents(body, start)
        if members is None:
            return []
        result = []
        depth = 0
        for index, member in enumerate(members):
            if member.text == "{":
                depth += 1
            elif member.text == "}":
                depth -= 1
            elif depth == 0 and index + 1 < len(members) and members[index + 1].text == "{":
                attributes = _block_contents(members, index + 1) or []
                values: dict[str, str] = {}
                position = 0
                while position < len(attributes):
                    key = attributes[position].text
                    following = attributes[position + 1].text if position + 1 < len(attributes) else None
                    if following == "{":
                        nested = _block_contents(attributes, position + 1)
                        position += 2 + (len(nested) + 1 if nested is not None else 0)
                    elif following is not None and following != "}" and key not in {"{", "}"}:
                        values[key] = following
                        position += 2
                    else:
                        position += 1
                result.append((member.text, member.line, values))
        return result

    def _read_snmp(self, line_number: int, body: list[_TokenValue]) -> None:
        """Read SNMP access scope, communities and v3 users without secret values."""

        depth = 0
        for index, token in enumerate(body):
            if token.text == "{":
                depth += 1
                continue
            if token.text == "}":
                depth -= 1
                continue
            if depth != 0:
                continue
            next_index = index + 1
            if next_index < len(body) and body[next_index].text in {"replace-all-with", "add"}:
                next_index += 1
            candidate = body[next_index].text if next_index < len(body) else ""
            if token.text in {"snmpv1", "snmpv2c"} and candidate in {"enable", "disable"}:
                self._snmp_versions[token.text] = (candidate, ConfigEvidence(
                    f"sys snmp {token.text} {candidate}", self.config_filepath, token.line))
                continue
            if token.text == "allowed-addresses":
                entries = _group_values(body, next_index) if candidate == "{" else [candidate]
                if entries is None or not entries:
                    scope = "unknown"
                elif entries == ["none"]:
                    scope = "none"
                elif any(item.casefold() in _ANY_ADDRESS for item in entries):
                    scope = "unrestricted"
                elif all(item in _LOOPBACK for item in entries):
                    scope = "loopback-only"
                else:
                    scope = "restricted"
                self._snmp_agent = F5SNMPAgent(scope, ConfigEvidence(
                    f"sys snmp allowed-addresses {scope}", self.config_filepath, token.line,
                ))
            elif token.text == "communities":
                if candidate == "none":
                    self._snmp_communities = {}
                    continue
                for raw_name, member_line, values in self._named_blocks(body, next_index):
                    name = _object_name(raw_name) or "<unnamed>"
                    community = values.get("community-name")
                    default_name = None if community is None else community.casefold() in _DEFAULT_COMMUNITIES
                    access = values.get("access", "unknown")
                    access = access if access in {"ro", "rw"} else "unknown"
                    source_value = values.get("source")
                    source = ("unknown" if source_value is None
                              else "any" if source_value.casefold() in _ANY_ADDRESS | {"default"}
                              else "restricted")
                    label = ("<known default>" if default_name
                             else "<redacted>" if community is not None else "<not exported>")
                    self._snmp_communities[name] = F5SNMPCommunity(
                        name, default_name, access, source,
                        ConfigEvidence(
                            f"sys snmp communities {name} community-name {label} access {access} source {source}",
                            self.config_filepath, member_line,
                        ),
                    )
            elif token.text == "traps":
                if candidate == "none":
                    self._snmp_traps = []
                    continue
                self._snmp_traps = []
                for raw_name, member_line, values in self._named_blocks(body, next_index):
                    version = values.get("version", "")
                    self._snmp_traps.append((raw_name, version, ConfigEvidence(
                        f"sys snmp traps {raw_name} host {values.get('host', '<unknown>')} version "
                        f"{version or '<absent>'} community <redacted>", self.config_filepath, member_line)))
            elif token.text == "users":
                if candidate == "none":
                    self._snmp_users = {}
                    continue
                for raw_name, member_line, values in self._named_blocks(body, next_index):
                    name = _object_name(raw_name) or "<unnamed>"
                    fields = {
                        key: values.get(key, "unknown")
                        for key in ("security-level", "auth-protocol", "privacy-protocol", "access")
                    }
                    self._snmp_users[name] = F5SNMPUser(
                        name, fields["security-level"], fields["auth-protocol"],
                        fields["privacy-protocol"], fields["access"],
                        ConfigEvidence(
                            f"sys snmp users {name} security-level {fields['security-level']} "
                            f"auth-protocol {fields['auth-protocol']} privacy-protocol "
                            f"{fields['privacy-protocol']} access {fields['access']}",
                            self.config_filepath, member_line,
                        ),
                    )

    def _read_ntp(self, line_number: int, body: list[_TokenValue]) -> None:
        servers: list[F5NTPServer] = []
        depth = 0
        for index, token in enumerate(body):
            if token.text == "{":
                depth += 1
                continue
            if token.text == "}":
                depth -= 1
                continue
            if depth != 0:
                continue
            next_index = index + 1
            if next_index < len(body) and body[next_index].text in {"replace-all-with", "add"}:
                next_index += 1
            candidate = body[next_index].text if next_index < len(body) else ""
            if token.text == "servers":
                entries = _group_values(body, next_index) if candidate == "{" else [candidate]
                for entry in entries or ():
                    if entry and entry != "none":
                        servers.append(F5NTPServer(entry, "tmsh", None, False, ConfigEvidence(
                            f"sys ntp servers {entry}", self.config_filepath, token.line)))
            elif token.text == "include" and candidate not in {"", "none"}:
                statements = [line.strip() for line in candidate.replace("\\n", "\n").splitlines()]
                trusted = {
                    key for line in statements if line.startswith("trustedkey ")
                    for key in line.split()[1:]
                }
                for offset, line in enumerate(statements):
                    tokens = line.split()
                    if len(tokens) < 2 or tokens[0] not in {"server", "peer", "pool"}:
                        continue
                    key_id = tokens[tokens.index("key") + 1] if "key" in tokens[:-1] else None
                    servers.append(F5NTPServer(
                        tokens[1], "include", key_id, bool(key_id and key_id in trusted),
                        ConfigEvidence(
                            f"sys ntp include: {tokens[0]} {tokens[1]}"
                            + (f" key {key_id}" if key_id else ""),
                            self.config_filepath, body[next_index].line + offset,
                        ),
                    ))
        self._ntp_servers = tuple(servers)

    def get_ntp_servers(self) -> tuple[F5NTPServer, ...]:
        """NTP associations from ``sys ntp`` (empty when none are configured)."""

        return self._ntp_servers or ()

    def get_provisioned_modules(self) -> dict[str, str]:
        """``sys provision`` module levels, for example ``{"ltm": "nominal"}``."""

        return {module: level for module, (level, _) in self._provision.items()}

    def get_snmp_agent(self) -> F5SNMPAgent | None:
        return self._snmp_agent

    def get_snmp_communities(self) -> tuple[F5SNMPCommunity, ...]:
        return tuple(self._snmp_communities.values())

    def get_snmp_users(self) -> tuple[F5SNMPUser, ...]:
        return tuple(self._snmp_users.values())

    def get_setting(self, scope: str, name: str) -> F5Setting | None:
        return self._settings.get((scope, name))

    def get_hostname(self) -> str:
        setting = self.get_setting("sys global-settings", "hostname")
        return str(setting.value) if setting and setting.value is not None else "?"

    def get_version(self) -> str:
        return self._version

    def get_users(self) -> list[dict]:
        return []

    def get_services(self) -> dict[str, bool]:
        login = self.get_setting("sys sshd", "login")
        return {"ssh": login.value == "enabled"} if login and login.value is not None else {}

    def get_native_config(self) -> tuple[F5Setting | F5RemoteAuthProfile | F5ClientSSLProfile | F5Virtual, ...]:
        return self._native

    def get_normalized_config(self) -> NormalizedConfig:
        snapshot = NormalizedConfig.unknown(self.device_type)
        hostname = self.get_setting("sys global-settings", "hostname")
        return replace(
            snapshot,
            hostname=(NormalizedValue.known(str(hostname.value), hostname.evidence)
                      if hostname and hostname.value is not None else snapshot.hostname),
            software_version=(NormalizedValue.known(self._version)
                              if self._version != "?" else snapshot.software_version),
        )
