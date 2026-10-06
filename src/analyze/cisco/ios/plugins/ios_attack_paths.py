"""SC-063 attack-path producers for IOS and IOS-XE.

Both producers consume parser-owned records only. They join predicates that
apply to one listener (a VTY range or the SNMP agent for one community) and
record a bounded not-assessed reason whenever a predicate depends on a value
the export does not settle (an unqualified release default, an unresolved or
unsupported access list, overlapping VTY ranges or an unparsed command).
"""

from __future__ import annotations

import re

from src.analyze.common.attack_paths import (
    FactState, PathFact, PathResult, evidence_locations, linked_findings, mark_evaluated,
    record_path, record_path_not_assessed,
)
from src.devices.cisco.ios import CiscoIOSParser

_CLEARTEXT = "cleartext-admin-unrestricted"
_SNMP = "writable-default-snmp"


def _vty_key(header: str) -> str:
    match = re.fullmatch(r"line vty\s+(\d+)(?:\s+(\d+))?", header.strip())
    if not match:
        return "system/vty/ipv4"
    first, last = match.group(1), match.group(2) or match.group(1)
    return f"system/vty:{first}-{last}/ipv4" if first != last else f"system/vty:{first}/ipv4"


def _source_admission(ios: CiscoIOSParser, acl_name: str, *, allow_extended: bool, listener: str):
    """(state, predicate, evidence): 'any' and 'permit-all' are known; 'restrictive' ends the path."""
    if not acl_name:
        return "known", f"No IPv4 access list restricts {listener}, so every IPv4 source is admitted.", ()
    acl = ios.get_management_ipv4_acl(acl_name, allow_extended=allow_extended)
    if acl.state == "permit-all":
        return ("known", f"IPv4 access list '{acl.name}' on {listener} permits every source before any deny.",
                acl.evidence)
    if acl.state == "restrictive":
        return "restrictive", "", ()
    return ("unknown",
            f"IPv4 access list '{acl.name}' on {listener} is {acl.state}; its source restriction was not proven.",
            acl.evidence)


def _vty_password_login(ios: CiscoIOSParser, line, aaa_enabled: bool, password_blocks: frozenset[str]):
    """(state, predicate): known password-based login, 'none' (no authentication) or unknown."""
    if aaa_enabled:
        name = line.login_list or "default"
        lists = {item.name: item for item in ios.get_aaa_method_lists() if item.service == "login_authentication"}
        method = lists.get(name)
        if method is None:
            return "unknown", f"AAA login list '{name}' is not defined in the export; the login method was not resolved."
        if not method.methods or method.methods[0] == "none":
            return "none", ""
        return "known", (f"Logins use AAA login list '{name}' ({' '.join(method.methods)}), which prompts for a "
                         "username and password.")
    header = re.sub(r"\s+", " ", line.line.strip())
    if line.login_kind == "local":
        has_users = any(item.context == "local_user" for item in ios.get_credential_metadata())
        if not has_users:
            return "unknown", "'login local' is set but no local username exists; the login cannot be resolved."
        return "known", "Logins use 'login local' (local usernames and passwords)."
    if line.login_kind == "line_password":
        if header not in password_blocks:
            return "unknown", "'login' is set but no line password is exported for this range."
        return "known", "Logins use 'login' with the line password."
    if line.login_kind == "none":
        return "none", ""
    return "unknown", "No login command is exported for this range; the release default was not qualified."


def produce_cleartext_admin(plugin, ios: CiscoIOSParser, *, aaa_enabled: bool, legacy_vty_default: bool) -> None:
    parser = ios
    mark_evaluated(parser, _CLEARTEXT)
    lines = ios.get_disjoint_vty_lines()
    if lines is None:
        record_path_not_assessed(parser, _CLEARTEXT, "VTY ranges overlap or could not be parsed; the effective "
                                 "per-line transport and access-class were not resolved.")
        return
    findings = plugin.get_issues()
    password_blocks = ios.get_vty_blocks_with_line_password()
    for line in lines:
        key = _vty_key(line.line)
        if line.exec_enabled is False:
            continue
        line_evidence = tuple(line.evidence)
        if line.transports is None:
            if not legacy_vty_default:
                record_path_not_assessed(parser, _CLEARTEXT, f"{key}: 'transport input' is not exported and the "
                                         "release default was not qualified for this train.")
                continue
            transport_text = (f"{line.line} exports no 'transport input'; on this train the documented default "
                              "is 'transport input all', which accepts Telnet.")
            transport_evidence = line_evidence + (f"version {ios.get_version()}",)
        elif any(token in line.transports for token in ("telnet", "all")):
            transport_text = f"{line.line} accepts Telnet ('transport input {' '.join(line.transports)}')."
            transport_evidence = line_evidence
        else:
            continue
        source_state, source_text, source_evidence = _source_admission(
            ios, line.ipv4_access_class, allow_extended=True, listener=line.line)
        if source_state == "restrictive":
            continue
        login_state, login_text = _vty_password_login(ios, line, aaa_enabled, password_blocks)
        if login_state == "none":
            continue
        link = linked_findings(findings, ("cisco.ios.vty.telnet",), line_evidence)
        steps = (
            PathFact("telnet-listener", key, "system", "ipv4", FactState.KNOWN, transport_text,
                     evidence_locations(transport_evidence), link),
            PathFact("unrestricted-source", key, "system", "ipv4",
                     FactState.KNOWN if source_state == "known" else FactState.UNKNOWN, source_text,
                     evidence_locations(line_evidence + tuple(source_evidence))),
            PathFact("password-login", key, "system", "ipv4",
                     FactState.KNOWN if login_state == "known" else FactState.UNKNOWN,
                     login_text + " The password crosses the network in clear text over Telnet.",
                     evidence_locations(line_evidence)),
        )
        if source_state != "known" or login_state != "known":
            record_path_not_assessed(parser, _CLEARTEXT, f"{key}: {source_text if source_state != 'known' else login_text}")
            continue
        record_path(parser, PathResult(_CLEARTEXT, key, "system", "ipv4", steps))


def produce_writable_default_snmp(plugin, ios: CiscoIOSParser) -> None:
    parser = ios
    mark_evaluated(parser, _SNMP)
    findings = plugin.get_issues()
    for community in ios.get_snmp_community_admissions():
        if not community.exact_default:
            continue
        key = f"system/snmp-community:line-{community.evidence.line_number}/ipv4"
        if not community.parsed:
            record_path_not_assessed(parser, _SNMP, f"{key}: the community command could not be fully parsed.")
            continue
        if community.access != "rw":
            continue
        if community.view:
            record_path_not_assessed(parser, _SNMP, f"{key}: view '{community.view}' limits the writable objects; "
                                     "MIB views are not evaluated.")
            continue
        source_state, source_text, source_evidence = _source_admission(
            ios, community.ipv4_acl, allow_extended=False, listener="this community")
        if source_state == "restrictive":
            continue
        if source_state != "known":
            record_path_not_assessed(parser, _SNMP, f"{key}: {source_text}")
            continue
        link = linked_findings(findings, ("cisco.ios.snmp.default_community", "cisco.ios.snmp.legacy_community"),
                               (community.evidence,))
        steps = (
            PathFact("default-rw-community", key, "system", "ipv4", FactState.KNOWN,
                     ("An SNMPv1/v2c community whose value matches the exact default list (value redacted) "
                      "grants read-write access with no MIB view."),
                     evidence_locations((community.evidence,)), link),
            PathFact("unrestricted-manager", key, "system", "ipv4", FactState.KNOWN, source_text,
                     evidence_locations((community.evidence,) + tuple(source_evidence))),
        )
        record_path(parser, PathResult(_SNMP, key, "system", "ipv4", steps))
