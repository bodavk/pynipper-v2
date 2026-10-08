"""Explicit, fail-closed FortiOS native-export rewrite grammar.

Only registered sections/fields are handled. This is not a generic 'set value'
scrubber; an unknown field can contain a credential, script or reference.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re

from src.devices.common.anonymization import (
    AnonymizationError, RewritePlan, SourceToken, enum_values, numeric,
    require, statements,
)
from src.anonymize.engine import address, network


TABLES = {
    "system admin": "user", "system api-user": "apiuser",
    "system accprofile": "role", "system interface": "iface",
    "system zone": "zone", "system snmp community": "number",
    "system snmp user": "snmpuser", "user local": "user",
    "user radius": "radius", "user tacacs+": "tacacs", "user ldap": "ldap",
    "user group": "group", "firewall address": "addr",
    "firewall address6": "addr6", "firewall addrgrp": "addr",
    "firewall addrgrp6": "addr6", "firewall service custom": "service",
    "firewall service group": "service", "firewall policy": "number",
    "firewall policy6": "number", "firewall local-in-policy": "number",
    "firewall local-in-policy6": "number", "firewall vip": "vip",
    "firewall ippool": "pool", "firewall schedule recurring": "schedule",
    "firewall schedule onetime": "schedule", "vpn ipsec phase1-interface": "vpn",
    "vpn ipsec phase2-interface": "phase2", "ips sensor": "ips",
    "antivirus profile": "av", "webfilter profile": "web",
    "dnsfilter profile": "dns", "application list": "app",
    "firewall ssl-ssh-profile": "tls", "firewall profile-group": "profiles",
    "router static": "number", "router static6": "number",
}
SINGLETONS = {
    "system global", "system password-policy", "system ntp", "system ha",
    "system dns", "system auto-install", "system fortiguard",
    "system autoupdate schedule", "vpn ssl settings",
    *(f"log syslogd{suffix} {kind}" for suffix in ("", "2", "3", "4")
      for kind in ("setting", "filter")),
}
NESTED = {"ipv6", "trusthost", "authentication-rule", "ntpserver", "hosts", "query-v1-port", "entries"}
NESTED_PARENTS = {
    "ipv6": {"system interface"}, "trusthost": {"system api-user"},
    "authentication-rule": {"vpn ssl settings"}, "ntpserver": {"system ntp"},
    "hosts": {"system snmp community"}, "entries": {"ips sensor"},
}
ENUMS = {
    "status": "up down enable disable", "action": "accept deny block pass monitor",
    "strong-crypto": "enable disable", "ssl-static-key-ciphers": "enable disable",
    "admin-ssh-v1": "enable disable", "ssh-cbc-cipher": "enable disable",
    "pre-login-banner": "enable disable", "post-login-banner": "enable disable",
    "log-single-cpu-high": "enable disable", "admin-restrict-local": "enable disable",
    "cli-audit-log": "enable disable", "private-data-encryption": "enable disable",
    "remote-auth": "enable disable", "peer-auth": "enable disable",
    "two-factor": "disable fortitoken email sms fortitoken-cloud",
    "server-identity-check": "enable disable", "require-message-authenticator": "enable disable",
    "transport-protocol": "udp tcp tls", "role": "wan lan dmz undefined",
    "allowaccess": "ping https ssh snmp http telnet fgfm radius-acct probe-response fabric ftm capwap",
    "ip6-allowaccess": "ping https ssh snmp http telnet fgfm fabric capwap",
    "reuse-password": "enable disable", "ntpsync": "enable disable",
    "syncinterval": "1 5 10 60", "logtraffic": "all utm disable",
    "utm-status": "enable disable", "profile-type": "single group",
    "inspection-mode": "flow proxy", "nat": "enable disable",
    "logtraffic-start": "enable disable", "srcaddr-negate": "enable disable",
    "dstaddr-negate": "enable disable", "service-negate": "enable disable",
    "mode": "a-p a-a standalone main aggressive udp reliable legacy-reliable",
    "authmethod": "psk signature", "ike-version": "1 2", "nattraversal": "enable disable forced",
    "authentication": "enable disable", "encryption": "enable disable",
    "ha-mgmt-status": "enable disable", "auto-install-config": "enable disable",
    "auto-install-image": "enable disable", "auto-firmware-upgrade": "enable disable",
    "frequency": "automatic every daily weekly", "enc-algorithm": "disable low high",
    "anomaly": "enable disable", "forward-traffic": "enable disable",
    "local-traffic": "enable disable", "system": "enable disable", "user": "enable disable",
    "security-level": "no-auth-no-priv auth-no-priv auth-priv",
    "auth-proto": "md5 sha sha256 sha384 sha512", "priv-proto": "des aes aes128 aes192 aes256",
    "apply-to": "admin-password ipsec-preshared-key",
    "sysgrp": "none read read-write", "netgrp": "none read read-write",
    "fwgrp": "none read read-write", "vpngrp": "none read read-write",
    "loggrp": "none read read-write", "secfabgrp": "none read read-write",
    "wifi": "none read read-write", "scope": "vdom global",
    "ssl-min-proto-version": "SSLv3 TLSv1 TLSv1-1 TLSv1-2 TLSv1-3",
    "tls-min-proto-version": "SSLv3 TLSv1 TLSv1-1 TLSv1-2 TLSv1-3",
    "ssl-min-proto-ver": "ssl3 tls1-0 tls1-1 tls1-2 tls1-3",
    "ssl-max-proto-ver": "ssl3 tls1-0 tls1-1 tls1-2 tls1-3",
    "admin-https-ssl-versions": "tlsv1-0 tlsv1-1 tlsv1-2 tlsv1-3",
    "protocol": "TCP/UDP/SCTP ICMP ICMP6 IP", "type": "ipmask iprange fqdn geography dynamic ipv4-trusthost ipv6-trusthost custom fortiguard",
    "service": "enable disable", "dst-check": "enable disable",
}
NUMBERS = set("dh-params admin-lockout-threshold admin-lockout-duration admintimeout admin-sport admin-port admin-ssh-port minimum-length min-lower-case-letter min-upper-case-letter min-non-alphanumeric min-number login-attempt-limit login-block-time auth-timeout idle-timeout group-id priority hb-interval hb-lost-threshold vrf vrf-select distance metric mtu vlanid port protocol-number icmptype icmpcode timeout keylife keylifeseconds replay seq-num".split())
NUM_LISTS = {"dhgrp", "tcp-portrange", "udp-portrange", "sctp-portrange"}
TEXT = {"alias", "description", "comment", "comments", "group-name", "name", "contact-info", "location"}
SECRETS = {"password", "passwd", "passphrase", "secret", "psksecret", "api-key", "auth-pwd", "priv-pwd", "auth-password", "priv-password", "key"}
REFS = {
    "accprofile": "role", "remote-group": "group", "groups": "group",
    "srcintf": "iface", "dstintf": "iface", "interface": "iface",
    "source-interface": "iface", "source-ip-interface": "iface", "monitor": "iface",
    "srcaddr": "addr", "dstaddr": "addr", "srcaddr6": "addr6", "dstaddr6": "addr6",
    "source-address": "addr", "source-address6": "addr6",
    "service": "service", "schedule": "schedule", "vdom": "tenant",
    "phase1name": "vpn", "ips-sensor": "ips", "av-profile": "av",
    "webfilter-profile": "web", "dnsfilter-profile": "dns", "application-list": "app",
    "ssl-ssh-profile": "tls", "profile-group": "profiles", "servercert": "cert",
    "admin-server-cert": "cert", "ca-cert": "cert", "client-cert": "cert",
    "default-portal": "portal", "portal": "portal", "peergrp": "peergrp",
}
BUILTINS = {
    "role": {"super_admin", "read_only", "prof_admin"}, "tenant": {"root"},
    "iface": {"any"}, "addr": {"all"}, "addr6": {"all"},
    "service": {"ALL", "ALL_TCP", "ALL_UDP", "DNS", "HTTP", "HTTPS", "SSH", "FTP", "PING", "TELNET"},
    "schedule": {"always"}, "ips": {"default"}, "av": {"default"},
    "tls": {"certificate-inspection", "deep-inspection", "no-inspection"},
    "cert": {"Fortinet_Factory", "Fortinet_SSL", "Fortinet_CA_SSL", "Fortinet_CA_Untrusted"},
    "portal": {"full-access", "tunnel-access", "web-access"},
}
ALGORITHMS = set("aes128-cbc aes192-cbc aes256-cbc aes128-ctr aes192-ctr aes256-ctr aes128-gcm@openssh.com aes256-gcm@openssh.com chacha20-poly1305@openssh.com curve25519-sha256 curve25519-sha256@libssh.org diffie-hellman-group1-sha1 diffie-hellman-group14-sha1 diffie-hellman-group14-sha256 diffie-hellman-group16-sha512 diffie-hellman-group18-sha512 hmac-sha1 hmac-sha2-256 hmac-sha2-512 hmac-md5 3des-sha1 aes128-sha1 aes256-sha1 aes128-sha256 aes256-sha256 des-md5 des-sha1 null-sha1 aes128gcm aes256gcm".split())


@dataclass
class Frame:
    section: str
    scope: str = field(repr=False)
    entry: str | None = field(default=None, repr=False)


def build_plan(source: str) -> RewritePlan:
    rows = statements(source, comments=("#",))
    plan = RewritePlan()
    stack: list[Frame] = []
    definitions = set()
    pending = []
    range_fields = {}

    def ref(token, namespace, scope, *, definition=False):
        require(bool(token.value), "empty object identity or reference", token.line)
        pending.append((token, namespace, scope, definition))
        if definition:
            definitions.add((namespace, scope, token.value))

    for row in rows:
        tokens = row.tokens
        if not tokens:
            continue
        values = [token.value for token in tokens]
        command = values[0]
        if command.startswith("#"):
            if command.startswith("#config-version="):
                match = re.match(r"#config-version=(FGT[0-9]{2,4}[A-Z]{0,3}|FGVM[A-Z0-9]{0,6})-(\d+\.\d+(?:\.\d+)?)", command)
                require(match is not None, "unsupported FortiOS release header", row.line)
                controls = "".join(f":{key}={match_value.group(1)}" for key in ("opmode", "vdom")
                                   if (match_value := re.search(rf":{key}=([0-9]+)(?::|$)", command)))
                plan.text(row, source, f"#config-version={match.group(1)}-{match.group(2)}{controls}")
            else:
                plan.text(row, source, "# anonymized")
            continue
        if command == "config":
            section = " ".join(values[1:])
            require(len(stack) < 32, "scope nesting budget exceeded", row.line)
            parent = stack[-1] if stack else None
            require(section in TABLES or section in SINGLETONS or section in NESTED or section in {"global", "vdom"},
                    "unsupported FortiOS section", row.line)
            if section in NESTED:
                require(parent is not None and parent.section in NESTED_PARENTS.get(section, set()),
                        "unsupported nested section binding", row.line)
            elif section in {"global", "vdom"}:
                require(parent is None, "unexpected outer scope nesting", row.line)
            elif parent:
                require(parent.section in {"global", "vdom"}, "unsupported nested section", row.line)
            scope = parent.scope if parent else "root"
            if parent and parent.section == "vdom":
                require(parent.entry is not None, "VDOM section without active entry", row.line)
                scope = parent.entry
            if section == "global":
                scope = "global"
            stack.append(Frame(section, scope))
            continue
        require(bool(stack), "command outside a FortiOS section", row.line)
        frame = stack[-1]
        if command == "end":
            require(len(tokens) == 1, "malformed section terminator", row.line)
            stack.pop()
            continue
        if command == "next":
            require(len(tokens) == 1 and frame.entry is not None, "unexpected entry terminator", row.line)
            frame.entry = None
            continue
        if command in {"edit", "delete", "purge", "rename", "clone", "move"}:
            namespace = "tenant" if frame.section == "vdom" else TABLES.get(frame.section)
            if frame.section in NESTED:
                namespace = "number"
            require(namespace is not None, "unsupported object operation", row.line)
            require(command != "purge" and len(tokens) >= 2, "unsupported object operation", row.line)
            if command in {"edit", "delete"}:
                require(len(tokens) == 2, "malformed object operation", row.line)
            else:
                require(len(tokens) == 4 and values[2] in ({"to"} if command in {"rename", "clone"} else {"before", "after"}),
                        "malformed object ordering operation", row.line)
            operands = (tokens[1],) if len(tokens) == 2 else (tokens[1], tokens[3])
            for token in operands:
                if namespace == "number":
                    numeric(token)
                else:
                    ref(token, namespace, frame.scope, definition=command in {"edit", "rename", "clone"})
            if command == "edit":
                require(frame.entry is None, "entry replaced before terminator", row.line)
                frame.entry = values[1]
            continue
        require(command in {"set", "unset", "append", "unselect"} and len(tokens) >= 2,
                "unsupported FortiOS command", row.line)
        field = values[1]
        args = tokens[2:]
        require(frame.section not in TABLES or frame.entry is not None, "setting outside an edited object", row.line)
        known = (field in REFS or field in ENUMS or field in NUMBERS or field in NUM_LISTS or field in TEXT
                 or field in SECRETS or field in {"uuid", "member", "hostname", "fqdn", "server", "secondary", "primary", "remote-gw", "gateway", "source-ip", "ip", "subnet", "src-subnet", "dst-subnet", "ipv4-trusthost", "ipv6-trusthost", "subnet6", "ip6-address", "ip6-prefix", "extip", "mappedip", "start-ip", "end-ip", "dst", "proposal", "ssh-enc-algo", "ssh-kex-algo", "ssh-mac-algo"}
                 or re.fullmatch(r"(?:ip6-)?trusthost[0-9]+", field))
        require(bool(known), "unsupported FortiOS field", row.line)
        if command == "unset":
            require(not args, "malformed unset", row.line)
            continue
        require(bool(args), "missing setting value", row.line)
        scope = frame.scope
        if field == "uuid":
            require(len(args) == 1, "malformed UUID field", row.line)
            plan.add(args[0], "uuid")
        elif field in TEXT:
            for token in args:
                if field == "name" and frame.section == "system snmp community":
                    plan.add(token, "secret", "0")
                else:
                    plan.add(token, "literal", token.value if not token.value.strip()
                             else "anonymized" if token.quoted else "anonymous")
        elif field == "hostname":
            require(len(args) == 1, "malformed hostname", row.line)
            plan.add(args[0], "domain" if "." in args[0].value else "name", "host")
        elif field in SECRETS:
            require(len(args) in {1, 2} and (len(args) == 1 or args[0].value == "ENC"),
                    "unsupported credential representation", row.line)
            plan.add(args[-1], "secret", "fortios-enc" if len(args) == 2 else "0")
            plan.limitations.add("FortiOS ENC substitutes retain parser storage syntax, not usable vendor ciphertext.")
        elif field == "member":
            namespace = TABLES.get(frame.section)
            if frame.section == "user group":
                namespace = "authmember"
            require(namespace in {"addr", "addr6", "service", "authmember"}, "unsupported group membership", row.line)
            for token in args:
                ref(token, namespace, scope)
        elif field in REFS:
            namespace = REFS[field]
            if field == "service" and frame.section == "system ntp":
                enum_values(args, "enable disable")
            else:
                if frame.section.endswith("6") and namespace == "addr":
                    namespace = "addr6"
                for token in args:
                    ref(token, namespace, scope)
        elif field in ENUMS:
            enum_values(args, ENUMS[field])
        elif field in NUMBERS or field in NUM_LISTS:
            for token in args:
                numeric(token, lists=field in NUM_LISTS)
        elif field in {"proposal", "ssh-enc-algo", "ssh-kex-algo", "ssh-mac-algo"}:
            enum_values(args, " ".join(ALGORITHMS))
        elif field in {"fqdn", "server", "primary", "secondary"}:
            require(len(args) == 1, "unsupported endpoint list", row.line)
            plan.add(args[0], "domain" if field == "fqdn" else "endpoint")
        elif field in {"ip", "subnet", "src-subnet", "dst-subnet", "ipv4-trusthost", "dst"} or re.fullmatch(r"trusthost[0-9]+", field):
            require(len(args) == 2, "unsupported IPv4 address/mask syntax", row.line)
            prefix = network(args[0].value, args[1].value, row.line)
            require(prefix.version == 4, "address family mismatch", row.line)
            plan.networks.append((args[0].value, args[1].value, row.line))
            plan.add(args[0], "ip")
        elif field in {"subnet6", "ip6-address", "ip6-prefix", "ipv6-trusthost"} or re.fullmatch(r"ip6-trusthost[0-9]+", field):
            require(len(args) == 1 and "/" in args[0].value, "unsupported IPv6 prefix syntax", row.line)
            require(address(args[0].value.split("/")[0], row.line).version == 6, "address family mismatch", row.line)
            plan.add(args[0], "prefix")
        else:
            require(len(args) == 1, "unsupported address setting", row.line)
            address(args[0].value, row.line)
            plan.add(args[0], "ip")
            if field in {"start-ip", "end-ip"}:
                entry = range_fields.setdefault((scope, frame.section, frame.entry), {"start-ip": [], "end-ip": []})
                entry[field].append((args[0].value, row.line))
    require(not stack, "unterminated FortiOS section", rows[-1].line if rows else 1)
    require(bool(rows) and any(row.tokens and row.tokens[0].value == "config" for row in rows),
            "not a native FortiOS export", 1)
    for entry in range_fields.values():
        require(len(entry["start-ip"]) * len(entry["end-ip"]) <= 256,
                "ordered range proof budget exceeded", 1)
        for first, line in entry["start-ip"]:
            for last, _ in entry["end-ip"]:
                plan.ranges.append((first, last, line))
    folded_definitions = {(ns, sc, name.casefold()) for ns, sc, name in definitions}
    for token, namespace, scope, definition in pending:
        if namespace == "tenant" and token.value == "root":
            plan.constants.add("FortiOS reserved root VDOM")
            continue
        if namespace == "authmember":
            member_namespaces = {"radius", "tacacs", "ldap", "user"}
            member_scopes = set((scope, "global", "root"))
            require(not any((ns, sc, token.value.casefold()) in folded_definitions
                            and (ns, sc, token.value) not in definitions
                            for ns in member_namespaces for sc in member_scopes),
                    "case-variant authentication reference requires qualification", token.line)
            matches = [(ns, sc) for ns in member_namespaces for sc in member_scopes
                       if (ns, sc, token.value) in definitions]
            local = [item for item in matches if item[1] == scope]
            matches = local or matches
            require(len(matches) <= 1, "ambiguous authentication member namespace", token.line)
            if matches:
                namespace, scope = matches[0]
        elif not definition:
            candidates = {namespace}
            if namespace == "iface":
                candidates.add("zone")
            elif namespace == "addr":
                candidates.add("vip")
            for fallback in dict.fromkeys((scope, "global", "root")):
                require(not any((ns, fallback, token.value.casefold()) in folded_definitions
                                and (ns, fallback, token.value) not in definitions for ns in candidates),
                        "case-variant object reference requires qualification", token.line)
                matches = [ns for ns in candidates if (ns, fallback, token.value) in definitions]
                require(len(matches) <= 1, "ambiguous reference namespace", token.line)
                if matches:
                    namespace, scope = matches[0], fallback
                    break
        # Public native identities can be exported as explicit editable objects
        # (notably the factory "all" address). Preserve their identity in its
        # qualified namespace, including definitions; do not repair/rename them.
        # An address named HTTP is NOT the built-in service named HTTP.
        if namespace == "iface" and re.fullmatch(r"(?:port|wan|mgmt)[0-9]+|lan[0-9]*", token.value):
            plan.constants.add("native FortiOS port identifiers")
        elif namespace != "tenant" and token.value.casefold() in {value.casefold() for value in BUILTINS.get(namespace, set())}:
            plan.constants.add(f"FortiOS built-in {namespace}")
        else:
            plan.add(token, "name", namespace, "" if namespace == "tenant" else scope)
    return plan
