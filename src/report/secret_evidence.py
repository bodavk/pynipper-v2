"""Explicitly opted-in raw credential lines for a separate report appendix.

Finding and normalized records remain secret-free. This adapter only reads the
parser's original in-memory source snapshot for effective credential metadata
whose sanitized evidence points to a line in that same input file.
"""

from __future__ import annotations

from pathlib import Path

from src.devices.common.base_parser import BaseDeviceParser


SUPPORTED_SECRET_REPORT_DEVICES = frozenset({
    "IOS_SWITCH", "IOS_ROUTER", "IOS_CATALYST", "IOS_XE",
    "ASA", "PIX", "JUNOS", "SCREENOS", "ARISTA_EOS", "FORTIOS",
    "HP_PROCURVE", "F5_BIGIP", "SONICOS", "PAN_OS", "CHECKPOINT_GAIA",
})


def _original_lines(parser: BaseDeviceParser) -> tuple[str, ...]:
    for attribute in ("_source_lines", "raw_lines"):
        source = getattr(parser, attribute, None)
        if isinstance(source, (list, tuple)) and all(isinstance(item, str) for item in source):
            return tuple(source)
    if parser.device_type == "ARISTA_EOS":
        commands = getattr(parser, "commands", ())
        count = max((command.line_number for command in commands), default=0)
        lines = [""] * count
        for command in commands:
            lines[command.line_number - 1] = command.text
        return tuple(lines)
    return ()


def collect_secret_evidence(parser: BaseDeviceParser) -> dict:
    """Return only effective parser-qualified credential lines, never all input."""
    if parser.device_type not in SUPPORTED_SECRET_REPORT_DEVICES:
        raise ValueError("unmasked credential evidence is not supported for this device family")
    if parser.device_type == "F5_BIGIP":
        return {
            "status": "unmasked-credential-lines",
            "scope-note": (
                "Only explicit auth user password/encrypted-password source lines in the saved "
                "TMOS export are shown. Other credentials and hidden values are not included. "
                "These excerpts are sensitive and should be handled as credentials."
            ),
            "entries": parser.get_report_secret_lines(),
        }
    if parser.device_type == "CHECKPOINT_GAIA":
        return {
            "status": "unmasked-credential-lines",
            "scope-note": (
                "Only Gaia Clish user password-hash, SNMP community and SNMPv3 USM user lines in the "
                "saved 'show configuration' output are shown. Security-policy secrets (objects, VPN "
                "keys) are not part of Gaia OS configuration and are not included. These excerpts "
                "are sensitive and should be handled as credentials."
            ),
            "entries": parser.get_report_secret_lines(),
        }
    if parser.device_type == "FORTIOS":
        return {
            "status": "unmasked-credential-lines",
            "scope-note": (
                "Current configured FortiOS secret-field directives are shown where their original "
                "source line can be verified. Appended values and hidden/unexported values may be "
                "incomplete. These excerpts are sensitive and should be handled as credentials."
            ),
            "entries": parser.get_report_secret_lines(),
        }
    if parser.device_type == "PAN_OS":
        return {
            "status": "unmasked-credential-lines",
            "scope-note": (
                "PAN-OS secret elements (local administrator hashes, SNMP communities and v3 "
                "keys, NTP keys, RADIUS/TACACS+/LDAP server secrets and IKE pre-shared keys) "
                "are shown as the element only, with its starting line. Values are usually "
                "device-encrypted but remain sensitive; other secrets may not be included."
            ),
            "entries": parser.get_report_secret_lines(),
        }
    if parser.device_type == "SONICOS":
        return {
            "status": "unmasked-credential-lines",
            "scope-note": (
                "Password lines for the built-in administrator and currently resolved local "
                "administrators, plus RADIUS/TACACS+/LDAP secrets, SNMP communities and VPN "
                "shared secrets in SonicOS 7 E-CLI exports, are shown. Ordinary local users "
                "and hidden values are not included. "
                "These excerpts are sensitive and should be handled as credentials."
            ),
            "entries": parser.get_report_secret_lines(),
        }
    lines = _original_lines(parser)

    if parser.device_type == "HP_PROCURVE":
        records = list(parser.get_local_administrator_credentials())
    else:
        records = list(parser.get_credential_metadata())
        additional = getattr(parser, "get_additional_credential_metadata", None)
        if callable(additional):
            records.extend(additional())
    source_path = Path(parser.config_filepath).resolve()
    entries: dict[int, dict] = {}
    for record in records:
        for evidence in record.evidence:
            number = evidence.line_number
            if (
                number is None or number < 1 or number > len(lines)
                or Path(evidence.source).resolve() != source_path
                or "redacted" not in evidence.text.casefold()
            ):
                continue
            original = lines[number - 1].strip()
            if original:
                entries[number] = {
                    "line-number": number,
                    "context": getattr(record, "context", getattr(record, "role", "local_credential")),
                    "source-line": original,
                }
    # Other effective secret directives (SNMP communities and v3 keys, NTP keys,
    # routing authentication) resolved by the parser's typed records.
    extra = getattr(parser, "get_report_secret_evidence", None)
    if callable(extra):
        for context, evidence in extra():
            number = evidence.line_number
            if (
                number is None or number < 1 or number > len(lines)
                or Path(evidence.source).resolve() != source_path
                or number in entries
            ):
                continue
            original = lines[number - 1].strip()
            if original:
                entries[number] = {
                    "line-number": number,
                    "context": context,
                    "source-line": original,
                }
    return {
        "status": "unmasked-credential-lines",
        "scope-note": (
            "Only effective secret directives with parser-qualified source lines are shown: "
            "credentials and, where the parser resolves them, SNMP communities/keys, NTP keys "
            "and bound routing-authentication keys. Other secrets and hidden/unexported values "
            "may remain unavailable or masked. These excerpts are sensitive and should be "
            "handled as credentials."
        ),
        "entries": [entries[number] for number in sorted(entries)],
    }
