"""Qualified IOS/XE and ASA text rewrites; unknown commands block publication."""
from __future__ import annotations

import ipaddress
import re

from src.devices.common.anonymization import (
    AnonymizationError, RewritePlan, SourceToken, enum_values, numeric,
    require, statements,
)
from src.anonymize.engine import address, network


PORTS = "ftp ftp-data ssh telnet smtp domain dns bootps bootpc tftp www http https pop3 ntp netbios-ns netbios-dgm netbios-ssn imap snmp snmptrap bgp ldap ldaps isakmp non500-isakmp syslog radius radius-acct tacacs"
PROTOCOLS = "ip ipv6 tcp udp icmp icmp6 esp ah gre ospf eigrp igmp sctp"
PHYSICAL = re.compile(r"(?:GigabitEthernet|FastEthernet|TenGigabitEthernet|TwentyFiveGigE|FortyGigabitEthernet|HundredGigE|Ethernet|Vlan|Loopback|Tunnel|Port-channel|Serial|Management|BVI|Dot11Radio|Dialer)[0-9./:-]+", re.I)
EXACT = {
    "end", "exit", "aaa new-model", "aaa session-id common", "ip cef", "ip subnet-zero",
    "ip classless", "ip routing", "ipv6 unicast-routing", "shutdown", "cdp run", "cdp enable",
    "ip source-route", "ip redirects", "ip proxy-arp", "ip directed-broadcast", "mop enabled",
    "ip http server", "ip http secure-server", "ip domain lookup", "ip bootp server",
    "service password-encryption", "service password-recovery", "service pad",
    "service tcp-keepalives-in", "service tcp-keepalives-out", "service config",
    "boot-start-marker", "boot-end-marker", "logging enable", "logging timestamp",
    "ntp authenticate", "http server enable", "sysopt connection permit-vpn",
    "login", "login local", "exec", "password", "ip address", "ipv6 enable",
    "archive", "log config", "hidekeys", "notify syslog", "control-plane",
    "threat-detection basic-threat", "ip nat inside", "ip nat outside", "switchport",
}
SEVERITIES = "emergencies alerts critical errors warnings notifications informational debugging"


def build_plan(source: str, *, asa: bool = False) -> RewritePlan:
    plan = RewritePlan()
    # Consume IOS banner bodies BEFORE tokenization so quoted prose or command-
    # looking secrets cannot become parsed statements. Mask with spaces, retaining
    # absolute offsets. The closing delimiter and command prefix stay structural.
    masked = list(source)
    banners = 0
    if not asa:
        pattern = re.compile(r"(?m)^[ \t]*banner (?:motd|login|exec|incoming|slip-ppp)[ \t]+(?P<delimiter>\^C|[^\s])")
        position = 0
        while (match := pattern.search(source, position)) is not None:
            delimiter = match.group("delimiter")
            start = match.end()
            end = source.find(delimiter, start)
            line = source.count("\n", 0, match.start()) + 1
            require(end >= 0, "unterminated Cisco banner", line)
            token = SourceToken(start, end, line, source[start:end])
            # A constant delimiter may itself look like customer text: limit
            # accepted delimiters to conventional exported punctuation/control.
            require(delimiter == "^C" or (not delimiter.isalnum() and delimiter not in "\"'\\"),
                    "unsupported Cisco banner delimiter", line)
            body = re.sub(r"[^\r\n]+", "[sample]", token.value) if token.value.strip() else token.value
            require(delimiter not in body, "banner delimiter collision", line)
            plan.add(token, "literal", body)
            banners += 1
            for index in range(match.start(), end + len(delimiter)):
                if source[index] not in "\r\n":
                    masked[index] = " "
            position = end + len(delimiter)
    rows = statements("".join(masked), comments=("!", ":"))
    context = ""
    context_name = ""
    count = banners

    def ref(token, namespace):
        require(bool(token.value), "empty object identity or reference", token.line)
        if namespace == "acl" and token.value.isdigit():
            numeric(token)
            plan.constants.add("numbered Cisco ACL identifiers")
        elif namespace == "method" and token.value == "default":
            plan.constants.add("Cisco default method list")
        elif namespace == "iface" and PHYSICAL.fullmatch(token.value):
            plan.constants.add("native Cisco interface identifiers")
        else:
            plan.add(token, "name", namespace)

    def ip(token):
        address(token.value, token.line)
        plan.add(token, "ip")

    def masked_ip(first, mask, *, wildcard=False):
        if wildcard:
            try:
                parsed = ipaddress.IPv4Address(mask.value)
                inverse = str(ipaddress.IPv4Address(int(parsed) ^ 0xffffffff))
            except ValueError:
                raise AnonymizationError("malformed Cisco wildcard", mask.line) from None
            prefix = network(first.value, inverse, first.line)
        else:
            prefix = network(first.value, mask.value, first.line)
            inverse = mask.value
        require(prefix.version == 4, "IPv4 address family mismatch", first.line)
        plan.networks.append((first.value, inverse, first.line))
        ip(first)

    def credential(args):
        if not args:
            return
        representation = "0"
        if args[0].value in {"0", "4", "5", "6", "7", "8", "9"}:
            representation = args[0].value
            args = args[1:]
        require(len(args) == 1, "unsupported Cisco credential syntax", args[0].line if args else 1)
        if representation == "7":
            require(bool(re.fullmatch(r"(?:0[0-9]|1[0-5])[0-9A-Fa-f]+", args[0].value)),
                    "malformed type-7 credential requires a synthetic fixture", args[0].line)
        plan.add(args[0], "secret", representation)
        plan.limitations.add("Cisco credential substitutions preserve parser syntax, not cryptographic validity or exact default matches.")

    def asa_credential(args):
        if args and args[-1].value in {"encrypted", "pbkdf2"}:
            credential(args[:-1])
        else:
            credential(args)

    def selector(tokens, index):
        require(index < len(tokens), "missing ACL address selector", tokens[0].line)
        value = tokens[index].value
        if value in {"any", "any4", "any6"}:
            plan.constants.add("unrestricted Cisco address selectors")
            return index + 1
        if value == "host":
            require(index + 1 < len(tokens), "missing ACL host", tokens[0].line)
            ip(tokens[index + 1])
            return index + 2
        if value in {"object", "object-group"} and asa:
            require(index + 1 < len(tokens), "missing ACL object reference", tokens[0].line)
            ref(tokens[index + 1], "net" if value == "object" else "netgrp")
            return index + 2
        if "/" in value:
            require(address(value.split("/")[0], tokens[index].line).version == 6,
                    "unsupported ACL prefix form", tokens[index].line)
            plan.add(tokens[index], "prefix")
            return index + 1
        require(index + 1 < len(tokens), "missing ACL mask", tokens[0].line)
        masked_ip(tokens[index], tokens[index + 1], wildcard=not asa)
        return index + 2

    def ports(tokens, index):
        if index < len(tokens) and tokens[index].value in {"eq", "neq", "gt", "lt", "range"}:
            size = 2 if tokens[index].value == "range" else 1
            require(index + size < len(tokens), "missing ACL port operand", tokens[0].line)
            for token in tokens[index + 1:index + size + 1]:
                if token.value.isdigit():
                    numeric(token)
                else:
                    enum_values((token,), PORTS)
            return index + size + 1
        return index

    def acl(tokens, standard=False):
        require(len(tokens) >= 2 and tokens[0].value in {"permit", "deny"}, "unsupported ACL action", tokens[0].line)
        index = 1
        if not standard:
            if tokens[index].value.isdigit():
                numeric(tokens[index])
            else:
                enum_values((tokens[index],), PROTOCOLS)
            index += 1
        index = selector(tokens, index)
        if not standard:
            index = ports(tokens, index)
            index = selector(tokens, index)
            index = ports(tokens, index)
        while index < len(tokens):
            value = tokens[index].value
            if value in {"log", "log-input", "established", "inactive", "echo", "echo-reply", "unreachable"}:
                index += 1
            elif value == "time-range" and index + 1 < len(tokens):
                ref(tokens[index + 1], "time")
                index += 2
            else:
                raise AnonymizationError("unsupported ACL predicate", tokens[index].line)

    for row in rows:
        tokens = list(row.tokens)
        if not tokens:
            continue
        values = [token.value for token in tokens]
        if values[0].startswith(("!", ":")):
            plan.text(row, source, "! anonymized")
            context = ""
            continue
        count += 1
        if source[row.start:tokens[0].start] == "":
            context = ""
        removed = values[0] in {"no", "default"}
        if removed:
            tokens, values = tokens[1:], values[1:]
            require(bool(tokens), "missing command after removal", row.line)
        words = " ".join(values)
        if words in EXACT:
            require(words not in {"password", "ip address"} or removed, "missing command value", row.line)
            if words == "archive":
                context = "archive"
            continue
        if re.fullmatch(r"(?:version|ASA Version) [0-9]+(?:\.[0-9]+){1,3}(?:\([0-9]+[a-z]?\))?(?:[A-Z][0-9]+[a-z]?|[a-z]|[0-9]+)?", words):
            continue
        if values[0] == "hostname" and len(tokens) == 2:
            plan.add(tokens[1], "domain" if "." in values[1] else "name", "host")
        elif values[:2] in (["domain-name", values[-1]], ["ip", "domain-name"]) or values[:3] == ["ip", "domain", "name"]:
            require(len(tokens) in {2, 3, 4} and values[-1] not in {"domain-name", "name"}, "malformed domain command", row.line)
            plan.add(tokens[-1], "domain")
        elif values[0] in {"description", "remark"} or (asa and values[0] == "banner"):
            if asa and values[0] == "banner":
                require(len(tokens) >= 3, "malformed ASA banner", row.line)
                enum_values((tokens[1],), "asdm exec login motd")
                start = 2
            else:
                start = 1
            require(start < len(tokens), "missing free-text value", row.line)
            if all(not token.value.strip() for token in tokens[start:]):
                continue  # an empty message/description must not become protection
            plan.add(SourceToken(tokens[start].start, tokens[-1].end, row.line,
                                 source[tokens[start].start:tokens[-1].end]), "literal", "anonymized")
        elif values[0] == "interface" and len(tokens) == 2:
            require(bool(PHYSICAL.fullmatch(values[1])), "unsupported native interface syntax", row.line)
            ref(tokens[1], "iface")
            context = "interface"
        elif values[0] == "nameif" and asa and len(tokens) == 2:
            ref(tokens[1], "iface")
        elif (values[:2] == ["ip", "vrf"] or values[:2] == ["vrf", "definition"]) and len(tokens) == 3 and not asa:
            ref(tokens[2], "vrf")
            context = "vrf"
        elif values[:3] == ["ip", "vrf", "forwarding"] and len(tokens) == 4 and not asa:
            ref(tokens[3], "vrf")
        elif values[:2] == ["vrf", "forwarding"] and len(tokens) == 3 and not asa:
            ref(tokens[2], "vrf")
        elif values[0] == "vlan" and len(tokens) == 2 and not asa:
            numeric(tokens[1], lists=True)
            context = "vlan"
        elif values[0] == "name" and context == "vlan" and len(tokens) == 2:
            ref(tokens[1], "segment")
        elif values[0] == "rd" and context == "vrf" and len(tokens) == 2:
            require(bool(re.fullmatch(r"[0-9]+:[0-9]+", values[1])), "unsupported RD identity", row.line)
        elif values[0] == "route-target" and context == "vrf" and len(tokens) == 3:
            enum_values((tokens[1],), "import export both")
            require(bool(re.fullmatch(r"[0-9]+:[0-9]+", values[2])), "unsupported route-target identity", row.line)
        elif values[:2] == ["ip", "address"] and len(tokens) in {4, 5}:
            if len(tokens) == 5:
                enum_values((tokens[-1],), "secondary")
            masked_ip(tokens[2], tokens[3])
        elif values[:2] == ["ipv6", "address"] and len(tokens) in {3, 4}:
            require("/" in values[2], "unsupported IPv6 interface address", row.line)
            plan.add(tokens[2], "prefix")
            if len(tokens) == 4:
                enum_values((tokens[3],), "eui-64 link-local")
                require(values[3] != "eui-64", "embedded MAC/IPv6 identity requires qualification", row.line)
        elif values[0] == "line" and len(tokens) in {3, 4}:
            enum_values((tokens[1],), "con console aux vty")
            for token in tokens[2:]:
                numeric(token)
            context = "line"
        elif values[0] == "username":
            require(len(tokens) >= 2, "missing username", row.line)
            ref(tokens[1], "user")
            index = 2
            while index < len(tokens):
                if values[index] == "privilege" and index + 1 < len(tokens):
                    numeric(tokens[index + 1])
                    index += 2
                elif values[index] == "algorithm-type" and index + 1 < len(tokens):
                    enum_values((tokens[index + 1],), "md5 sha256 scrypt")
                    index += 2
                elif values[index] in {"password", "secret"}:
                    args = tokens[index + 1:]
                    # ASA trailers carry storage/privilege rather than secrets.
                    if asa:
                        ending = next((i for i, token in enumerate(args) if token.value in {"encrypted", "pbkdf2", "privilege"}), len(args))
                        credential(args[:ending])
                        tail = args[ending:]
                        while tail:
                            if tail[0].value in {"encrypted", "pbkdf2"}:
                                tail = tail[1:]
                            elif len(tail) >= 2 and tail[0].value == "privilege":
                                numeric(tail[1])
                                tail = tail[2:]
                            else:
                                raise AnonymizationError("unsupported ASA credential trailer", row.line)
                    else:
                        credential(args)
                    index = len(tokens)
                else:
                    raise AnonymizationError("unsupported account property", row.line)
        elif values[0] in {"password", "secret"}:
            credential(tokens[1:])
        elif values[0] == "enable" and len(tokens) >= 2:
            index = 1
            if values[index] == "algorithm-type" and len(tokens) >= 4:
                enum_values((tokens[index + 1],), "md5 sha256 scrypt")
                index += 2
            require(values[index] in {"secret", "password"}, "unsupported enable setting", row.line)
            if asa:
                asa_credential(tokens[index + 1:])
            else:
                credential(tokens[index + 1:])
        elif values[0] == "access-list":
            require(len(tokens) >= 3, "malformed ACL command", row.line)
            ref(tokens[1], "acl")
            tail = tokens[2:]
            if tail[0].value == "remark":
                require(len(tail) > 1, "missing ACL remark", row.line)
                plan.add(SourceToken(tail[1].start, tail[-1].end, row.line,
                                     source[tail[1].start:tail[-1].end]), "literal", "anonymized")
            else:
                standard = values[1].isdigit() and (1 <= int(values[1]) <= 99 or 1300 <= int(values[1]) <= 1999)
                if asa:
                    require(tail[0].value in {"standard", "extended"}, "unsupported ASA ACL form", row.line)
                    standard = tail[0].value == "standard"
                    tail = tail[1:]
                acl(tail, standard)
        elif values[:2] == ["ip", "access-list"] and len(tokens) == 4:
            enum_values((tokens[2],), "standard extended")
            ref(tokens[3], "acl")
            context = f"acl-{values[2]}"
        elif values[:2] == ["ipv6", "access-list"] and len(tokens) == 3:
            ref(tokens[2], "acl6")
            context = "acl-extended"
        elif context.startswith("acl-"):
            tail = tokens
            if tail[0].value.isdigit():
                numeric(tail[0])
                tail = tail[1:]
            require(bool(tail), "empty numbered ACL entry", row.line)
            acl(tail, context == "acl-standard")
        elif values[0] in {"access-class", "ipv6"} and ((values[0] == "access-class" and len(tokens) == 3)
                or (values[:2] == ["ipv6", "access-class"] and len(tokens) == 4)):
            ref(tokens[-2], "acl6" if values[0] == "ipv6" else "acl")
            enum_values((tokens[-1],), "in out")
        elif values[:2] == ["ip", "access-group"] and len(tokens) == 4:
            ref(tokens[2], "acl")
            enum_values((tokens[3],), "in out")
        elif values[0] == "access-group" and asa and len(tokens) == 5 and values[3] == "interface":
            ref(tokens[1], "acl")
            enum_values((tokens[2],), "in out")
            ref(tokens[4], "iface")
        elif values[0] == "transport" and len(tokens) >= 3:
            enum_values((tokens[1],), "input output preferred")
            enum_values(tokens[2:], "ssh telnet none all")
        elif values[:2] == ["login", "authentication"] and len(tokens) == 3:
            ref(tokens[2], "method")
        elif values[0] in {"exec-timeout", "absolute-timeout", "security-level", "timeout"}:
            for token in tokens[1:]:
                numeric(token)
        elif values[0] == "aaa" and len(tokens) >= 4 and values[1] in {"authentication", "authorization", "accounting"} and not asa:
            enum_values((tokens[2],), "login enable exec commands network system")
            index = 3
            if values[2] == "commands":
                numeric(tokens[index])
                index += 1
            require(index < len(tokens), "missing AAA method list", row.line)
            ref(tokens[index], "method")
            index += 1
            while index < len(tokens):
                if values[index] == "group" and index + 1 < len(tokens):
                    if values[index + 1] not in {"radius", "tacacs+"}:
                        ref(tokens[index + 1], "aaagroup")
                    index += 2
                else:
                    enum_values((tokens[index],), "local local-case enable none if-authenticated start-stop stop-only broadcast")
                    index += 1
        elif values[:3] == ["aaa", "group", "server"] and len(tokens) == 5:
            enum_values((tokens[3],), "radius tacacs+")
            ref(tokens[4], "aaagroup")
            context = "aaagroup"
        elif values[0] == "server-private" and context == "aaagroup":
            require(len(tokens) >= 2, "missing AAA endpoint", row.line)
            ip(tokens[1])
            index = 2
            while index < len(tokens):
                if values[index] in {"auth-port", "acct-port"} and index + 1 < len(tokens):
                    numeric(tokens[index + 1])
                    index += 2
                elif values[index] == "key":
                    credential(tokens[index + 1:])
                    break
                else:
                    raise AnonymizationError("unsupported AAA server property", row.line)
        elif values[:2] in (["radius", "server"], ["tacacs", "server"]) and len(tokens) == 3:
            ref(tokens[2], "server")
            context = "server"
        elif values[0] == "key" and context == "server":
            credential(tokens[1:])
        elif values[:2] == ["address", "ipv4"] and context == "server":
            require(len(tokens) >= 3, "missing AAA address", row.line)
            ip(tokens[2])
            require(len(tokens[3:]) % 2 == 0, "malformed AAA ports", row.line)
            for index in range(3, len(tokens), 2):
                enum_values((tokens[index],), "auth-port acct-port")
                numeric(tokens[index + 1])
        elif values[0] == "logging":
            require(len(tokens) >= 2, "missing logging setting", row.line)
            if values[1] in {"trap", "console", "monitor", "buffered", "history"}:
                for token in tokens[2:]:
                    numeric(token) if token.value.isdigit() else enum_values((token,), SEVERITIES)
            elif values[1] == "source-interface" and len(tokens) == 3:
                ref(tokens[2], "iface")
            elif values[1] == "host" and len(tokens) in ({3} if not asa else {4}):
                if asa:
                    ref(tokens[2], "iface")
                plan.add(tokens[-1], "endpoint")
            else:
                raise AnonymizationError("unsupported logging syntax", row.line)
        elif values[:2] == ["ntp", "server"] and len(tokens) >= 3:
            plan.add(tokens[2], "endpoint")
            index = 3
            while index < len(tokens):
                if values[index] in {"key", "version"} and index + 1 < len(tokens):
                    numeric(tokens[index + 1])
                    index += 2
                elif values[index] == "source" and index + 1 < len(tokens):
                    ref(tokens[index + 1], "iface")
                    index += 2
                elif values[index] in {"prefer", "iburst"}:
                    index += 1
                else:
                    raise AnonymizationError("unsupported NTP association property", row.line)
        elif values[:2] == ["ntp", "authentication-key"] and len(tokens) >= 5:
            numeric(tokens[2])
            enum_values((tokens[3],), "md5 sha1 sha256")
            credential(tokens[4:])
        elif values[:2] == ["ntp", "trusted-key"]:
            for token in tokens[2:]:
                numeric(token)
        elif values[:2] == ["snmp-server", "community"] and len(tokens) in {3, 4, 5}:
            plan.add(tokens[2], "secret", "0")
            if len(tokens) >= 4:
                enum_values((tokens[3],), "RO RW ro rw")
            if len(tokens) == 5:
                ref(tokens[4], "acl")
        elif values[:2] == ["ip", "route"] and len(tokens) in {5, 6}:
            masked_ip(tokens[2], tokens[3])
            ip(tokens[4])
            if len(tokens) == 6:
                numeric(tokens[5])
        elif values[:2] == ["ip", "ssh"] and len(tokens) == 4:
            enum_values((tokens[2],), "version time-out authentication-retries")
            numeric(tokens[3])
        elif values[0] in {"ssh", "http"} and asa and len(tokens) == 4:
            masked_ip(tokens[1], tokens[2])
            ref(tokens[3], "iface")
        elif values[:2] == ["object", "network"] and asa and len(tokens) == 3:
            ref(tokens[2], "net")
            context = "net"
        elif values[:2] == ["object-group", "network"] and asa and len(tokens) == 3:
            ref(tokens[2], "netgrp")
            context = "netgrp"
        elif values[0] == "host" and context == "net" and len(tokens) == 2:
            ip(tokens[1])
        elif values[0] == "subnet" and context == "net" and len(tokens) == 3:
            masked_ip(tokens[1], tokens[2])
        elif values[0] == "range" and context == "net" and len(tokens) == 3:
            plan.ranges.append((values[1], values[2], row.line))
            ip(tokens[1])
            ip(tokens[2])
        elif values[:2] == ["fqdn", "v4"] and context == "net" and len(tokens) == 3:
            plan.add(tokens[2], "domain")
        elif values[0] == "group-object" and context == "netgrp" and len(tokens) == 2:
            ref(tokens[1], "netgrp")
        elif values[0] == "network-object" and context == "netgrp" and len(tokens) == 3:
            if values[1] == "host":
                ip(tokens[2])
            elif values[1] == "object":
                ref(tokens[2], "net")
            else:
                masked_ip(tokens[1], tokens[2])
        else:
            raise AnonymizationError("unsupported Cisco command or context", row.line)
    require(count > 0, "empty Cisco export", 1)
    return plan
