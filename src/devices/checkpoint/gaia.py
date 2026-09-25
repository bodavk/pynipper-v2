"""Check Point Gaia OS configuration (Gaia Clish `show configuration` / `save configuration`).

SC-023. The export is a list of Gaia Clish commands that recreate the system
configuration, including many default values (Gaia Administration Guide, "Working
with System Configuration in Gaia Clish"). Later commands replace earlier ones for
the same setting. This input is separate from the FW1 policy export
(`objects.C` / `rules.C`), which carries no operating-system settings.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from src.devices.common.base_parser import BaseDeviceParser
from src.devices.common.models import ConfigEvidence


@dataclass(frozen=True)
class GaiaCommand:
    words: tuple[str, ...]
    text: str
    line_number: int


@dataclass(frozen=True)
class GaiaSetting:
    value: str
    evidence: ConfigEvidence


@dataclass(frozen=True)
class GaiaSNMPCommunity:
    name: str
    access: str  # read-only | read-write | unknown
    evidence: ConfigEvidence


@dataclass(frozen=True)
class GaiaSNMPUser:
    name: str
    security_level: str
    evidence: ConfigEvidence


@dataclass(frozen=True)
class GaiaUser:
    name: str
    uid: Optional[str]
    shell: Optional[str]
    password_hash_line: Optional[int]
    evidence: tuple[ConfigEvidence, ...]


class GaiaParseError(ValueError):
    """The input is not a Gaia Clish configuration export."""


class CheckPointGaiaParser(BaseDeviceParser):
    device_type = "CHECKPOINT_GAIA"

    def __init__(self, config_filepath: str):
        super().__init__(config_filepath)
        text = Path(config_filepath).read_text(encoding="utf-8-sig", errors="replace")
        self._source_lines = text.splitlines()
        self.diagnostics: list[str] = []
        self.commands: list[GaiaCommand] = []
        self.language_version = ""
        for number, raw in enumerate(self._source_lines, start=1):
            line = raw.strip()
            if not line:
                continue
            if line.startswith("#"):
                match = re.match(r"#\s*Language version:\s*(\S+)", line, re.IGNORECASE)
                if match:
                    self.language_version = match.group(1)
                continue
            try:
                words = tuple(shlex.split(line))
            except ValueError:
                self.diagnostics.append(f"line {number}: unbalanced quotes")
                words = tuple(line.split())
            if words and words[0] in {"set", "add", "delete"}:
                self.commands.append(GaiaCommand(words, line, number))
        self._native = tuple(self.commands)

    # --- evidence -------------------------------------------------------------------
    _SECRET_WORDS = {"password-hash", "newpass", "auth-pass-phrase", "privacy-pass-phrase",
                     "auth-pass-hash", "privacy-pass-hash", "community", "msgvalue"}

    def _evidence(self, command: GaiaCommand) -> ConfigEvidence:
        words = list(command.words)
        for index, word in enumerate(words[:-1]):
            if word in self._SECRET_WORDS and word != "msgvalue":
                words[index + 1] = "<redacted>"
            elif word == "msgvalue":
                words[index + 1] = "<banner text>"
        return ConfigEvidence(" ".join(words), self.config_filepath, command.line_number)

    def _last(self, *prefix: str) -> Optional[GaiaCommand]:
        selected = None
        for command in self.commands:
            if command.words[:len(prefix)] == prefix:
                selected = command
        return selected

    def _setting(self, *prefix: str) -> Optional[GaiaSetting]:
        command = self._last(*prefix)
        if command is None or len(command.words) <= len(prefix):
            return None
        return GaiaSetting(command.words[len(prefix)], self._evidence(command))

    # --- typed records ----------------------------------------------------------------
    def get_telnet(self) -> Optional[GaiaSetting]:
        """`set net-access telnet {on | off}`; disabled by default."""
        return self._setting("set", "net-access", "telnet")

    def get_snmp_agent(self) -> Optional[GaiaSetting]:
        return self._setting("set", "snmp", "agent")

    def get_snmp_agent_version(self) -> Optional[GaiaSetting]:
        return self._setting("set", "snmp", "agent-version")

    def get_snmp_communities(self) -> list[GaiaSNMPCommunity]:
        communities: dict[str, GaiaSNMPCommunity] = {}
        for command in self.commands:
            words = command.words
            if words[1:3] != ("snmp", "community") or len(words) < 4:
                continue
            name = words[3]
            if words[0] == "delete":
                communities.pop(name, None)
                continue
            access = words[4] if len(words) > 4 and words[4] in {"read-only", "read-write"} else "unknown"
            communities[name] = GaiaSNMPCommunity(name, access, self._evidence(command))
        return list(communities.values())

    def get_snmp_users(self) -> list[GaiaSNMPUser]:
        users: dict[str, GaiaSNMPUser] = {}
        for command in self.commands:
            words = command.words
            if words[1:4] != ("snmp", "usm", "user") or len(words) < 5:
                continue
            name = words[4]
            if words[0] == "delete":
                users.pop(name, None)
                continue
            level = words[words.index("security-level") + 1] if "security-level" in words[:-1] else "unknown"
            users[name] = GaiaSNMPUser(name, level, self._evidence(command))
        return list(users.values())

    def get_password_control(self, name: str) -> Optional[GaiaSetting]:
        """`set password-controls <name> <value>`; `deny-on-fail enable` uses two words."""
        parts = tuple(name.split())
        return self._setting("set", "password-controls", *parts)

    def get_inactivity_timeout(self) -> Optional[GaiaSetting]:
        """`set inactivity-timeout <minutes>` (Clish; default 10)."""
        return self._setting("set", "inactivity-timeout")

    def get_banner(self) -> Optional[GaiaSetting]:
        return self._setting("set", "message", "banner")

    def get_local_users(self) -> list[GaiaUser]:
        users: dict[str, dict] = {}
        for command in self.commands:
            words = command.words
            if len(words) < 3 or words[1] != "user":
                continue
            name = words[2]
            if words[0] == "delete" and len(words) == 3:
                users.pop(name, None)
                continue
            data = users.setdefault(name, {"uid": None, "shell": None, "hash": None, "evidence": []})
            if words[0] == "add" and "uid" in words[:-1]:
                data["uid"] = words[words.index("uid") + 1]
            elif words[:1] == ("set",) and words[3:4] == ("shell",) and len(words) > 4:
                data["shell"] = words[4]
            elif words[:1] == ("set",) and words[3:4] == ("password-hash",) and len(words) > 4:
                data["hash"] = command.line_number
            else:
                continue
            data["evidence"].append(self._evidence(command))
        return [GaiaUser(name, data["uid"], data["shell"], data["hash"], tuple(data["evidence"]))
                for name, data in users.items()]

    def get_report_secret_lines(self) -> list[dict]:
        """Current password hashes, SNMP communities and SNMPv3 user lines (`--show-secrets`)."""
        wanted: dict[int, str] = {}
        for user in self.get_local_users():
            if user.password_hash_line:
                wanted[user.password_hash_line] = "local_user"
        for community in self.get_snmp_communities():
            wanted[community.evidence.line_number] = "snmp_community"
        for user in self.get_snmp_users():
            wanted[user.evidence.line_number] = "snmpv3_user_key"
        return [
            {"line-number": number, "context": context, "source-line": self._source_lines[number - 1].strip()}
            for number, context in sorted(wanted.items())
        ]

    # --- BaseDeviceParser -------------------------------------------------------------
    def get_hostname(self) -> str:
        setting = self._setting("set", "hostname")
        return setting.value if setting else "?"

    def get_version(self) -> str:
        # `show configuration` states the Clish language version, not the Gaia release.
        return "?"

    def get_users(self) -> list[dict]:
        return [{"username": user.name, "uid": user.uid, "shell": user.shell} for user in self.get_local_users()]

    def get_services(self) -> dict:
        telnet = self.get_telnet()
        snmp = self.get_snmp_agent()
        return {
            "telnet": bool(telnet and telnet.value == "on"),
            "snmp": bool(snmp and snmp.value == "on"),
        }

    def get_native_config(self) -> tuple[GaiaCommand, ...]:
        return self._native


__all__ = ["CheckPointGaiaParser", "GaiaParseError"]
