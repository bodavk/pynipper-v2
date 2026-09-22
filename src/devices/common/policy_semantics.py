"""Conservative, platform-neutral policy containment primitives.

These helpers prove only set containment. They deliberately do not turn
unresolved objects, empty dimensions, or dynamic predicates into ``Any``.
Platform adapters remain responsible for deciding whether rule scope, order,
action, and non-network predicates are comparable.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable


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


__all__ = [
    "AddressInterval", "NetworkSemantics", "ProofState", "ServiceInterval",
    "ServiceSemantics", "network_covers", "service_covers", "static_values_cover",
]
