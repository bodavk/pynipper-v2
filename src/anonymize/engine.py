"""Bounded, private mappings and source-span rewriting. No network imports."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import ipaddress
import secrets
import string
import uuid

from src.devices.common.anonymization import AnonymizationError, RewritePlan


MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_REWRITES = 100_000
MAX_NETWORKS = 4096


def address(value: str, line: int):
    try:
        if "%" in value:
            raise ValueError
        return ipaddress.ip_address(value)
    except ValueError:
        raise AnonymizationError("unsupported or malformed address", line) from None


def network(value: str, mask: str, line: int):
    try:
        if "%" in value:
            raise ValueError
        return ipaddress.ip_network(f"{value}/{mask}", strict=False)
    except ValueError:
        raise AnonymizationError("unsupported or malformed network mask", line) from None


def special(ip) -> bool:
    return ip.is_unspecified or str(ip) in {"127.0.0.1", "::1", "255.255.255.255"}


def pools(ip) -> tuple:
    """Explicit allocation pools; no inference of interface/boundary roles."""
    if ip.version == 4:
        if ip.is_loopback:
            return (ipaddress.ip_network("127.0.0.0/8"),)
        if ip.is_link_local:
            return (ipaddress.ip_network("169.254.0.0/16"),)
        for prefix in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"):
            if ip in ipaddress.ip_network(prefix):
                return tuple(map(ipaddress.ip_network,
                                 ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")))
        for prefix in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
            if ip in ipaddress.ip_network(prefix):
                return tuple(map(ipaddress.ip_network,
                                 ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")))
        if ip.is_global and not ip.is_multicast:
            # Synthetic public values can be real allocated space: offline only.
            return tuple(map(ipaddress.ip_network,
                             ("8.0.0.0/8", "11.0.0.0/8", "12.0.0.0/8", "23.0.0.0/8",
                              "44.0.0.0/8", "45.0.0.0/8", "66.0.0.0/8", "77.0.0.0/8")))
    else:
        if ip.is_link_local:
            return (ipaddress.ip_network("fe80::/10"),)
        if ip in ipaddress.ip_network("2001:db8::/32"):
            return (ipaddress.ip_network("2001:db8::/32"),)
        if ip in ipaddress.ip_network("fc00::/7"):
            return (ipaddress.ip_network("fd00::/8"),)
        if ip.is_global and not ip.is_multicast:
            return (ipaddress.ip_network("2000::/3"),)
    raise AnonymizationError("unsupported special address class")


class AddressMap:
    """Translate disjoint enclosing blocks; hosts retain relative offsets.

    Both networks and ranges participate BEFORE allocation. No independent
    random host substitutions and no prefix permutation of range endpoints.
    """

    def __init__(self, plan: RewritePlan):
        roots = []
        hosts = []
        retained = []
        for rewrite in plan.rewrites:
            if rewrite.kind in {"ip", "prefix", "endpoint"}:
                value = rewrite.token.value
                if rewrite.kind == "endpoint":
                    try:
                        ip = ipaddress.ip_address(value)
                    except ValueError:
                        continue
                else:
                    ip = address(value.split("/")[0], rewrite.token.line)
                if not special(ip):
                    hosts.append(ip)
                else:
                    retained.append(ip)
                if rewrite.kind == "prefix":
                    try:
                        prefix = ipaddress.ip_network(value, strict=False)
                    except ValueError:
                        raise AnonymizationError("malformed address prefix", rewrite.token.line) from None
                    if prefix.prefixlen and not (special(prefix.network_address) and prefix.prefixlen == prefix.max_prefixlen):
                        roots.append(prefix)
        for value, mask, line in plan.networks:
            prefix = network(value, mask, line)
            if prefix.prefixlen and not special(prefix.network_address):
                roots.append(prefix)
        for first, last, line in plan.ranges:
            low, high = address(first, line), address(last, line)
            if low.version != high.version or int(low) > int(high) or special(low) or special(high):
                raise AnonymizationError("unsupported address range", line)
            bits = low.max_prefixlen - (int(low) ^ int(high)).bit_length()
            roots.append(ipaddress.ip_network(f"{low}/{bits}", strict=False))
        roots = list(set(roots))
        hosts = list(set(hosts))
        if len(roots) + len(hosts) > MAX_NETWORKS:
            raise AnonymizationError("address proof budget exceeded")
        # Longest containing source network is irrelevant: enclosing roots
        # preserve all their nested prefixes and all participating endpoints.
        for ip in hosts:
            if not any(ip.version == root.version and ip in root for root in roots):
                roots.append(ipaddress.ip_network(f"{ip}/{24 if ip.version == 4 else 64}", strict=False))
        ordered = sorted(set(roots), key=lambda item: (item.version, item.prefixlen, int(item.network_address)))
        self.blocks = []
        documentation_pools = tuple(map(ipaddress.ip_network,
            ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")))
        documentation_rotation = secrets.choice((1, 2))
        for root in ordered:
            if any(root.version == other.version and root.subnet_of(other) for other, _ in self.blocks):
                continue
            if any(ip.version == root.version and ip in root for ip in retained):
                raise AnonymizationError("a translated block contains a retained special address")
            candidates = pools(root.network_address)
            if not any(root.subnet_of(pool) for pool in candidates):
                raise AnonymizationError("network crosses supported address classes")
            allocated = None
            for _ in range(1024):
                pool = secrets.choice(candidates)
                if pool.prefixlen > root.prefixlen:
                    continue
                count = 1 << (root.prefixlen - pool.prefixlen)
                base = int(pool.network_address) + secrets.randbelow(count) * root.num_addresses
                target = ipaddress.ip_network((base, root.prefixlen)) if root.version == 4 else ipaddress.IPv6Network((base, root.prefixlen))
                # Do not collide with ANY source block or already assigned output.
                documentation = root.version == 4 and candidates == documentation_pools
                if documentation:
                    source_pool = next(pool for pool in candidates if root.subnet_of(pool))
                    target_pool = candidates[(candidates.index(source_pool) + documentation_rotation) % 3]
                    base = int(target_pool.network_address) + int(root.network_address) - int(source_pool.network_address)
                    target = ipaddress.ip_network((base, root.prefixlen))
                if target == root or (not documentation and any(
                        target.version == item.version and target.overlaps(item) for item in ordered)):
                    continue
                if any(target.version == item.version and target.overlaps(item) for _, item in self.blocks):
                    continue
                try:
                    if pools(target.network_address) != candidates or pools(target.broadcast_address) != candidates:
                        continue
                except AnonymizationError:
                    continue
                allocated = target
                break
            if allocated is None:
                raise AnonymizationError("no collision-free equivalent address block available")
            self.blocks.append((root, allocated))

    def ip(self, value: str, line: int) -> str:
        ip = address(value, line)
        if special(ip):
            return str(ip)
        for original, replacement in self.blocks:
            if original.version == ip.version and ip in original:
                cls = ipaddress.IPv4Address if ip.version == 4 else ipaddress.IPv6Address
                return str(cls(int(replacement.network_address) + int(ip) - int(original.network_address)))
        raise AnonymizationError("address is outside the qualified mapping", line)


@dataclass
class Mapping:
    addresses: AddressMap = field(repr=False)
    names: dict = field(default_factory=dict, repr=False)
    domains: dict = field(default_factory=dict, repr=False)
    credentials: dict = field(default_factory=dict, repr=False)
    uuids: dict = field(default_factory=dict, repr=False)
    allocated_uuids: set[str] = field(default_factory=set, repr=False)
    salt: str = field(default_factory=lambda: secrets.token_hex(3), repr=False)
    reserved_names: set[str] = field(default_factory=set, repr=False)

    def name(self, value: str, namespace: str, scope: str) -> str:
        if not value:
            return ""  # do not turn omitted/empty metadata into a configured identity
        key = (namespace, scope, value)
        if key not in self.names:
            nonce = self.salt
            for _ in range(32):
                separator = "-" if namespace == "host" else "_"
                candidate = f"{namespace}{separator}{nonce}{separator}{len(self.names) + 1:04d}"
                if candidate not in self.reserved_names:
                    self.names[key] = candidate
                    break
                nonce = secrets.token_hex(3)
            else:
                raise AnonymizationError("identifier allocation budget exceeded")
        return self.names[key]

    def domain(self, value: str) -> str:
        wildcard = value.startswith("*.")
        trailing = value.endswith(".")
        parts = value.removeprefix("*.").rstrip(".").lower().split(".")
        if (len(value) > 253 or len(parts) > 32 or not all(part and len(part) <= 63 and
                part[0] != "-" and part[-1] != "-" and
                all(char in string.ascii_lowercase + string.digits + "-" for char in part) for part in parts)):
            raise AnonymizationError("unsupported domain syntax")
        output = []
        for index in range(len(parts)):
            suffix = tuple(parts[index:])
            if suffix not in self.domains:
                if len(self.domains) >= MAX_REWRITES:
                    raise AnonymizationError("domain allocation budget exceeded")
                self.domains[suffix] = f"d{len(self.domains) + 1:x}"
            output.append(self.domains[suffix])
        result = ("*." if wildcard else "") + ".".join(output) + f".p{self.salt}.invalid" + ("." if trailing else "")
        if len(result.rstrip(".")) > 253:
            raise AnonymizationError("synthetic domain exceeds supported length")
        return result

    def secret(self, value: str, representation: str) -> str:
        key = (representation, value)
        if key in self.credentials:
            return self.credentials[key]
        if not value:
            replacement = ""
        elif value in {"*****", "<redacted>"}:
            replacement = value  # native masking markers, not exported material
        else:
            # Retain storage grammar, not password/default-match semantics.
            prefix = ""
            body = value
            if value.startswith("$"):
                pieces = value.split("$", 2)
                if len(pieces) == 3 and pieces[1] in {"1", "4", "5", "6", "8", "9"}:
                    prefix, body = f"${pieces[1]}$", pieces[2]
            if representation == "7" and len(body) >= 4 and all(c in string.hexdigits for c in body):
                replacement = "00" + "".join(secrets.choice("0123456789ABCDEF") for _ in body[2:])
            else:
                def substitute(char):
                    if char in string.ascii_uppercase:
                        return secrets.choice(string.ascii_uppercase.replace(char, ""))
                    if char in string.ascii_lowercase:
                        return secrets.choice(string.ascii_lowercase.replace(char, ""))
                    if char in string.digits:
                        return secrets.choice(string.digits.replace(char, ""))
                    if char in "/+=.$":
                        return char  # encoded/hash grammar separators
                    return "_"
                replacement = prefix + "".join(substitute(c) for c in body)
            if representation == "0" and replacement.casefold() in {"admin", "cisco", "cisco123", "password"}:
                replacement = ("X" if replacement[0].isupper() else "x") + replacement[1:]
            if replacement == value:
                raise AnonymizationError("secret cannot be replaced without losing its representation")
        self.credentials[key] = replacement
        return replacement

    def identifier(self, value: str, line: int) -> str:
        try:
            original = uuid.UUID(value)
        except ValueError:
            raise AnonymizationError("malformed UUID", line) from None
        if original.int == 0:
            return str(original)
        if original.version not in {1, 2, 3, 4, 5}:
            raise AnonymizationError("unsupported UUID version", line)
        if original not in self.uuids:
            replacement = uuid.UUID(bytes=secrets.token_bytes(16), version=original.version)
            if replacement == original or str(replacement) in self.allocated_uuids:
                raise AnonymizationError("UUID allocation collision", line)
            self.uuids[original] = str(replacement)
            self.allocated_uuids.add(str(replacement))
        return self.uuids[original]


def render(source: str, plan: RewritePlan) -> tuple[str, dict]:
    if len(plan.rewrites) > MAX_REWRITES:
        raise AnonymizationError("rewrite budget exceeded")
    spellings = {}
    for item in plan.rewrites:
        if item.kind == "name":
            key = (item.namespace, item.scope, item.token.value.casefold())
            previous = spellings.setdefault(key, item.token.value)
            if previous != item.token.value:
                raise AnonymizationError("case-variant identifier relationships require qualification", item.token.line)
    mapping = Mapping(AddressMap(plan), reserved_names={item.token.value for item in plan.rewrites if item.kind == "name"})
    pieces = []
    counts = Counter()
    position = 0
    for rewrite in sorted(plan.rewrites, key=lambda item: item.token.start):
        token = rewrite.token
        if token.start < position or token.end > len(source):
            raise AnonymizationError("overlapping or invalid source spans", token.line)
        if rewrite.kind == "literal":
            value = rewrite.namespace
        elif rewrite.kind == "name":
            value = mapping.name(token.value, rewrite.namespace, rewrite.scope)
        elif rewrite.kind == "domain":
            value = mapping.domain(token.value)
        elif rewrite.kind == "endpoint":
            try:
                ipaddress.ip_address(token.value)
            except ValueError:
                # An IP-looking malformed endpoint cannot become a domain.
                if ":" in token.value or all(c in string.digits + "." for c in token.value):
                    raise AnonymizationError("malformed endpoint address", token.line) from None
                value = mapping.domain(token.value)
            else:
                value = mapping.addresses.ip(token.value, token.line)
        elif rewrite.kind == "ip":
            value = mapping.addresses.ip(token.value, token.line)
        elif rewrite.kind == "prefix":
            ip, separator, length = token.value.partition("/")
            if not separator:
                raise AnonymizationError("missing address prefix length", token.line)
            prefix = network(ip, length, token.line)
            if prefix.prefixlen == 0 and address(ip, token.line).is_unspecified:
                value = str(prefix)
            else:
                value = f"{mapping.addresses.ip(ip, token.line)}/{prefix.prefixlen}"
        elif rewrite.kind == "secret":
            value = mapping.secret(token.value, rewrite.namespace)
        elif rewrite.kind == "uuid":
            value = mapping.identifier(token.value, token.line)
        else:
            raise AnonymizationError("unregistered transformation", token.line)
        if rewrite.kind != "literal" or token.quoted:
            if token.quoted or any(c.isspace() for c in value):
                value = '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
        # Maintain physical locations even when replacing multiline text.
        missing_lines = source[token.start:token.end].count("\n") - value.count("\n")
        if missing_lines > 0:
            if token.quoted and value.endswith('"'):
                value = value[:-1] + "\n" * missing_lines + '"'
            else:
                value += "\n" * missing_lines
        pieces.extend((source[position:token.start], value))
        position = token.end
        counts[rewrite.kind] += 1
    pieces.append(source[position:])
    return "".join(pieces), {
        "schema-version": 1,
        "status": "privacy-checked-within-supported-scope",
        "transformations": dict(sorted(counts.items())),
        "retained-structural-constants": sorted(plan.constants | {
            "native empty/masked credential markers and standard unspecified/loopback selectors"
        }),
        "test-equivalence": "not-certified",
        "limitations": sorted(plan.limitations | {
            "Pseudonymization is not guaranteed anonymity; topology and release metadata remain.",
            "Relative host offsets are retained within translated address blocks.",
            "Synthetic data must never be installed on production devices.",
            "Credential/default/blocklist equivalence and observed exploitability are not certified.",
        }),
    }
