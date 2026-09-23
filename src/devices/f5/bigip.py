"""Bounded parser for saved BIG-IP TMOS tmsh/SCF object blocks.

Only selected management settings cross the parser boundary. The source may
contain passwords, keys, and certificates, but none are retained as evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import re

from src.devices.common.base_parser import BaseDeviceParser
from src.devices.common.models import ConfigEvidence, NormalizedConfig, NormalizedValue


_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|#[^\r\n]*|[{}]|[^\s{}]+')
_VERSION = re.compile(r"(?m)^\s*#\s*TMSH-VERSION:\s*([0-9][A-Za-z0-9._-]*)\s*$", re.I)
_SAFE_NAME = re.compile(r"[A-Za-z0-9_./:-]+")
_FIELDS = {
    "sys sshd": {"login", "allow", "inactivity-timeout"},
    "sys httpd": {"allow", "redirect-http-to-https"},
    "sys global-settings": {"hostname", "console-inactivity-timeout"},
    "cli global-settings": {"audit", "idle-timeout"},
    "sys syslog": {"remote-servers"},
    "auth password-policy": {"policy-enforcement", "max-login-failures", "minimum-length"},
}


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


@dataclass(frozen=True)
class F5ClientSSLProfile:
    name: str
    mode_enabled: bool | None
    allow_non_ssl: bool | None
    evidence: ConfigEvidence


@dataclass(frozen=True)
class F5Virtual:
    name: str
    enabled: bool | None
    client_profiles: tuple[str, ...]
    evidence: ConfigEvidence


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
        self._client_ssl: dict[str, F5ClientSSLProfile] = {}
        self._virtuals: dict[str, F5Virtual] = {}
        self._user_secret_lines: dict[str, int] = {}
        self._user_credentials: dict[str, F5UserCredential] = {}
        self._parse(_tokens(content))
        self._native = (*self._settings.values(), *self._client_ssl.values(), *self._virtuals.values())

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
                self._read_settings(scope, tokens[body_start:cursor - 1])
            elif len(header) == 4 and header[:3] == ["ltm", "profile", "client-ssl"]:
                recognized = True
                self._read_client_ssl(header[3], header_line, tokens[body_start:cursor - 1])
            elif len(header) == 3 and header[:2] == ["ltm", "virtual"]:
                recognized = True
                self._read_virtual(header[2], header_line, tokens[body_start:cursor - 1])
            elif len(header) == 3 and header[:2] == ["auth", "user"]:
                recognized = True
                self._read_user_credential(header[2], tokens[body_start:cursor - 1])
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
            elif depth == 0 and token.text in {"password", "encrypted-password"}:
                candidate = body[index + 1].text if index + 1 < len(body) else ""
                if candidate and candidate not in {"{", "}", "none", "default"}:
                    self._user_secret_lines[name] = token.line
                    masked = candidate.casefold() in {"<redacted>", "redacted", "<hidden>"} or set(candidate) == {"*"}
                    storage = "unknown" if masked else "plaintext" if token.text == "password" else "encrypted"
                    self._user_credentials[name] = F5UserCredential(
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
                          "max-login-failures", "minimum-length"}:
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
        depth = 0
        for index, token in enumerate(body):
            if token.text == "{":
                depth += 1
            elif token.text == "}":
                depth -= 1
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
        )

    def _read_virtual(self, raw_name: str, line_number: int,
                      body: list[_TokenValue]) -> None:
        name = _object_name(raw_name)
        if name is None:
            return
        previous = self._virtuals.get(name)
        enabled = previous.enabled if previous else None
        profiles = previous.client_profiles if previous else ()
        depth = 0
        for index, token in enumerate(body):
            if token.text == "{":
                depth += 1
            elif token.text == "}":
                depth -= 1
            elif depth == 0 and token.text in {"enabled", "disabled"}:
                enabled = token.text == "enabled"
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
                member_depth = 0
                for member_index, member in enumerate(members):
                    if member.text == "{":
                        member_depth += 1
                    elif member.text == "}":
                        member_depth -= 1
                    elif member_depth == 0 and member_index + 1 < len(members) and members[member_index + 1].text == "{":
                        profile_name = _object_name(member.text, name)
                        attributes = _block_contents(members, member_index + 1)
                        if profile_name and attributes and any(
                            attributes[position].text == "context"
                            and position + 1 < len(attributes)
                            and attributes[position + 1].text in {"all", "clientside"}
                            for position in range(len(attributes))
                        ):
                            selected.append(profile_name)
                profiles = tuple(selected)
        self._virtuals[name] = F5Virtual(
            name, enabled, profiles,
            ConfigEvidence(f"ltm virtual {name} {'enabled' if enabled else 'disabled' if enabled is False else '<unknown>'}",
                           self.config_filepath, line_number),
        )

    def get_bound_cleartext_client_ssl(self) -> tuple[tuple[F5Virtual, F5ClientSSLProfile], ...]:
        return tuple(
            (virtual, profile)
            for virtual in self._virtuals.values() if virtual.enabled is True
            for name in virtual.client_profiles
            if (profile := self._client_ssl.get(name)) is not None
            and profile.mode_enabled is True and profile.allow_non_ssl is True
        )

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

    def get_native_config(self) -> tuple[F5Setting | F5ClientSSLProfile | F5Virtual, ...]:
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
