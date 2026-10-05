"""Conservative, platform-neutral policy containment primitives.

These helpers prove bounded set containment and effective permission. They do not turn
unresolved objects, empty dimensions, or dynamic predicates into ``Any``.
Platform adapters remain responsible for deciding whether rule scope, order,
action, and non-network predicates are comparable.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable
from itertools import product
import ipaddress


class ProofState(str, Enum):
    PROVEN = "proven"
    DISPROVEN = "disproven"
    UNKNOWN = "unknown"


@dataclass(frozen=True, order=True)
class AddressInterval:
    family: int
    first: int
    last: int

    def __post_init__(self) -> None:
        if self.family not in {4, 6}:
            raise ValueError("address family must be 4 or 6")
        maximum = (1 << (32 if self.family == 4 else 128)) - 1
        if not 0 <= self.first <= self.last <= maximum:
            raise ValueError("invalid address interval")


@dataclass(frozen=True, order=True)
class ServiceInterval:
    protocol: str
    first_port: int
    last_port: int

    def __post_init__(self) -> None:
        if not self.protocol.strip():
            raise ValueError("service protocol must not be empty")
        if not 0 <= self.first_port <= self.last_port <= 65535:
            raise ValueError("invalid service port interval")


@dataclass(frozen=True)
class NetworkSemantics:
    any: bool = False
    intervals: tuple[AddressInterval, ...] = ()
    complete: bool = True
    unresolved: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.unresolved and self.complete:
            raise ValueError("unresolved networks cannot be complete")


@dataclass(frozen=True)
class ServiceSemantics:
    any: bool = False
    intervals: tuple[ServiceInterval, ...] = ()
    complete: bool = True
    unresolved: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.unresolved and self.complete:
            raise ValueError("unresolved services cannot be complete")


def _ranges_cover(
    prior: Iterable[tuple[int, int]], current: Iterable[tuple[int, int]]
) -> bool:
    prior_ranges = tuple(prior)
    current_ranges = tuple(current)
    if not prior_ranges or not current_ranges:
        return False
    merged: list[tuple[int, int]] = []
    for first, last in sorted(prior_ranges):
        if not merged or first > merged[-1][1] + 1:
            merged.append((first, last))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], last))
    return all(
        any(start <= first and end >= last for start, end in merged)
        for first, last in current_ranges
    )


def network_covers(prior: NetworkSemantics, current: NetworkSemantics) -> ProofState:
    if not prior.complete or not current.complete:
        return ProofState.UNKNOWN
    if prior.any:
        return ProofState.PROVEN
    if current.any:
        return ProofState.DISPROVEN
    families = {interval.family for interval in current.intervals}
    if not families:
        return ProofState.UNKNOWN
    covered = all(
        _ranges_cover(
            ((item.first, item.last) for item in prior.intervals if item.family == family),
            ((item.first, item.last) for item in current.intervals if item.family == family),
        )
        for family in families
    )
    return ProofState.PROVEN if covered else ProofState.DISPROVEN


def service_covers(prior: ServiceSemantics, current: ServiceSemantics) -> ProofState:
    if not prior.complete or not current.complete:
        return ProofState.UNKNOWN
    if prior.any:
        return ProofState.PROVEN
    if current.any:
        return ProofState.DISPROVEN
    protocols = {interval.protocol.casefold() for interval in current.intervals}
    if not protocols:
        return ProofState.UNKNOWN
    covered = all(
        _ranges_cover(
            ((item.first_port, item.last_port) for item in prior.intervals if item.protocol.casefold() == protocol),
            ((item.first_port, item.last_port) for item in current.intervals if item.protocol.casefold() == protocol),
        )
        for protocol in protocols
    )
    return ProofState.PROVEN if covered else ProofState.DISPROVEN


def static_values_cover(
    prior: tuple[str, ...], current: tuple[str, ...], *, any_value: str = "any"
) -> ProofState:
    """Compare a static OR-list while preserving empty input as unknown."""
    if not prior or not current:
        return ProofState.UNKNOWN
    prior_values = {value.casefold() for value in prior}
    current_values = {value.casefold() for value in current}
    if any_value.casefold() in prior_values:
        return ProofState.PROVEN
    if any_value.casefold() in current_values:
        return ProofState.DISPROVEN
    return ProofState.PROVEN if current_values.issubset(prior_values) else ProofState.DISPROVEN


def network_disjoint(first: NetworkSemantics, second: NetworkSemantics) -> ProofState:
    """Prove two complete static address sets cannot match the same address."""
    if not first.complete or not second.complete or not (
        first.any or first.intervals
    ) or not (second.any or second.intervals):
        return ProofState.UNKNOWN
    if first.any or second.any:
        return ProofState.DISPROVEN
    overlaps = any(
        left.family == right.family
        and left.first <= right.last and right.first <= left.last
        for left in first.intervals for right in second.intervals
    )
    return ProofState.DISPROVEN if overlaps else ProofState.PROVEN


def service_disjoint(first: ServiceSemantics, second: ServiceSemantics) -> ProofState:
    """Prove complete protocol/port sets do not overlap."""
    if not first.complete or not second.complete or not (
        first.any or first.intervals
    ) or not (second.any or second.intervals):
        return ProofState.UNKNOWN
    if first.any or second.any:
        return ProofState.DISPROVEN
    overlaps = any(
        left.protocol.casefold() == right.protocol.casefold()
        and left.first_port <= right.last_port and right.first_port <= left.last_port
        for left in first.intervals for right in second.intervals
    )
    return ProofState.DISPROVEN if overlaps else ProofState.PROVEN


@dataclass(frozen=True)
class TrafficMatch:
    sources: NetworkSemantics
    destinations: NetworkSemantics
    services: ServiceSemantics
    qualified: bool = True
    reason: str = ""


@dataclass(frozen=True)
class EffectivePermissionProof:
    """PROVEN means nonempty, DISPROVEN empty, UNKNOWN insufficient proof."""
    state: ProofState
    reason: str
    witness: str = ""


def effective_permission(candidate: TrafficMatch, prior: tuple[TrafficMatch, ...], *,
                         target: TrafficMatch | None = None, families: tuple[int, ...] = (4, 6),
                         fragment_limit: int = 2048, work_limit: int = 100000) -> EffectivePermissionProof:
    """Bounded exact address/protocol/destination-port subtraction.

    Vendor parsers qualify non-geometric predicates, scope and terminal order.
    All earlier terminal actions remove traffic from this candidate's *own*
    permission. The finite IP protocol universe keeps ALL exact without
    equating it to TCP/UDP. No witness is returned on an incomplete proof.
    """
    def known(match):
        return match.qualified and all(item.complete for item in (match.sources, match.destinations, match.services))

    if not known(candidate) or (target is not None and not known(target)):
        return EffectivePermissionProof(ProofState.UNKNOWN, "Candidate or target selectors/predicates are unresolved.")
    if len(prior) > 64:
        return EffectivePermissionProof(ProofState.UNKNOWN, "Earlier-rule proof budget exceeded (64 rules).")
    names = {"icmp": 1, "igmp": 2, "tcp": 6, "udp": 17, "gre": 47, "esp": 50,
             "ah": 51, "icmp6": 58, "ipv6-icmp": 58, "eigrp": 88, "ospf": 89,
             "pim": 103, "vrrp": 112, "sctp": 132, "udp-lite": 136, "udplite": 136}
    def protocol_number(value):
        value = value.casefold()
        if value in names:
            return names[value]
        number = value.removeprefix("ip-")
        return int(number) if number.isdigit() and 0 <= int(number) <= 255 else None
    if any(protocol_number(item.protocol) is None for match in (candidate, *prior, *((target,) if target else ()))
           for item in match.services.intervals):
        return EffectivePermissionProof(ProofState.UNKNOWN, "An IP protocol identity is unsupported by the remainder proof.")
    def selector_maximum(proto):
        return 65535 if proto in {6, 17, 132, 136} else 255 if proto in {1, 58} else 0

    def boxes(match):
        result = []
        for family in families:
            maximum = (1 << (32 if family == 4 else 128)) - 1
            src = ((0, maximum),) if match.sources.any else tuple((x.first, x.last) for x in match.sources.intervals if x.family == family)
            dst = ((0, maximum),) if match.destinations.any else tuple((x.first, x.last) for x in match.destinations.intervals if x.family == family)
            svc = tuple((p, 0, selector_maximum(p)) for p in range(256)) if match.services.any else tuple(
                (protocol_number(x.protocol), x.first_port, min(x.last_port, selector_maximum(protocol_number(x.protocol))))
                for x in match.services.intervals if x.first_port <= selector_maximum(protocol_number(x.protocol)))
            if len(result) + len(src) * len(dst) * len(svc) > fragment_limit:
                return None
            result.extend((family, proto, s0, s1, d0, d1, p0, p1)
                          for (s0, s1), (d0, d1), (proto, p0, p1) in product(src, dst, svc))
        return result

    def intersection(a, b):
        if a[:2] != b[:2]:
            return None
        ranges = [(max(a[i], b[i]), min(a[i+1], b[i+1])) for i in (2, 4, 6)]
        if any(lo > hi for lo, hi in ranges):
            return None
        return a[:2] + tuple(v for pair in ranges for v in pair)

    def subtract(a, b):
        overlap = intersection(a, b)
        if overlap is None:
            return [a]
        pieces = []
        core = list(a)
        for i in (2, 4, 6):
            if core[i] < overlap[i]:
                piece = core.copy()
                piece[i+1] = overlap[i] - 1
                pieces.append(tuple(piece))
            if overlap[i+1] < core[i+1]:
                piece = core.copy()
                piece[i] = overlap[i+1] + 1
                pieces.append(tuple(piece))
            core[i:i+2] = overlap[i:i+2]
        return pieces

    remaining = boxes(candidate)
    if remaining is None or not remaining:
        return EffectivePermissionProof(ProofState.UNKNOWN, "Empty selectors or fragment proof budget exceeded.")
    work = 0
    if target:
        target_boxes = boxes(target)
        if target_boxes is None or not target_boxes or len(remaining) * len(target_boxes) > work_limit:
            return EffectivePermissionProof(ProofState.UNKNOWN, "Target intersection proof budget exceeded or empty selectors.")
        remaining = [overlap for a in remaining for b in target_boxes if (overlap := intersection(a, b))]
        if len(remaining) > fragment_limit:
            return EffectivePermissionProof(ProofState.UNKNOWN, "Target intersection fragment budget exceeded.")
    for earlier in prior:
        if not remaining:
            break
        if not known(earlier):
            return EffectivePermissionProof(ProofState.UNKNOWN, earlier.reason or "Earlier rule has unsupported or unresolved predicates.")
        if any(state == ProofState.PROVEN for state in (
            network_disjoint(earlier.sources, candidate.sources),
            network_disjoint(earlier.destinations, candidate.destinations))):
            continue
        earlier_boxes = boxes(earlier)
        if earlier_boxes is None or not earlier_boxes:
            return EffectivePermissionProof(ProofState.UNKNOWN, "Earlier-rule selectors are empty or exceed fragment budget.")
        # Bucket by family/protocol so ALL does not repeatedly scan hundreds
        # of distinct protocol boxes. Budget actual geometric subtraction.
        grouped = {}
        for item in remaining:
            grouped.setdefault(item[:2], []).append(item)
        fragment_count = len(remaining)
        for box in earlier_boxes:
            next_remaining = []
            current = grouped.get(box[:2], ())
            for item in current:
                work += 1
                if work > work_limit:
                    return EffectivePermissionProof(ProofState.UNKNOWN, "Ordered subtraction work budget exceeded.")
                next_remaining.extend(subtract(item, box))
                if fragment_count - len(current) + len(next_remaining) > fragment_limit:
                    return EffectivePermissionProof(ProofState.UNKNOWN, "Ordered subtraction fragment budget exceeded.")
            fragment_count += len(next_remaining) - len(current)
            grouped[box[:2]] = next_remaining
        remaining = [item for group in grouped.values() for item in group]
    if not remaining:
        return EffectivePermissionProof(ProofState.DISPROVEN, "Earlier terminal rules leave no effective candidate permission intersecting the target.")
    family, proto, s0, s1, d0, d1, p0, p1 = remaining[0]
    address_type = ipaddress.IPv4Address if family == 4 else ipaddress.IPv6Address
    witness = (f"IPv{family} source {address_type(s0)}–{address_type(s1)}, "
               f"destination {address_type(d0)}–{address_type(d1)}, "
               f"IP protocol {proto}" + (f", destination ports {p0}–{p1}" if proto in {6, 17, 132, 136}
                                          else f", ICMP types {p0}–{p1}" if proto in {1, 58} else ""))
    return EffectivePermissionProof(ProofState.PROVEN,
                                    "A nonempty effective remainder is proven after preceding terminal rules; not every matched flow is necessarily permitted.", witness)




__all__ = [
    "AddressInterval", "NetworkSemantics", "ProofState", "ServiceInterval",
    "ServiceSemantics", "network_covers", "service_covers", "static_values_cover",
    "TrafficMatch", "EffectivePermissionProof", "effective_permission",
]
