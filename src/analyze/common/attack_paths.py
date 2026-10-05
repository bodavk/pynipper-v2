"""Configuration-supported attack paths (SC-063).

A path links a small number of *necessary* configuration predicates that apply
to the same entity (account, listener, VPN scope or ordered policy pair). It is
a reviewer aid, not a finding: it never changes finding counts or severities
and never claims that a path was reachable, attempted or exploited.

Producers are vendor adapters over parser-owned typed records. They must not
join on finding text or rule IDs; rule IDs only *link* to findings that the
plugin already emitted for the same evidence. Every step of an emitted path
must be ``KNOWN``. Anything else is recorded as a bounded not-assessed reason.
The ledger is kept per parser, like the SC-049 control ledger.
"""

from __future__ import annotations

import weakref
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

from src.analyze.common.issue import EvidenceLocation, Severity
from src.devices.common.models import ConfigEvidence

ATTACK_PATH_SCHEMA_VERSION = 1
CATALOGUE_VERSION = 1
MAX_PATTERNS = 12
MAX_DISPLAYED_RESULTS = 12
_MAX_REASONS = 5
_MAX_EVIDENCE_PER_STEP = 6
_MAX_LINKS_PER_STEP = 3


class FactState(str, Enum):
    KNOWN = "known"
    UNKNOWN = "unknown"
    UNSUPPORTED = "unsupported"
    PARSE_ERROR = "parse-error"
    INACTIVE = "inactive"
    EXCLUDED = "excluded"


class PatternStatus(str, Enum):
    PATH_FOUND = "path-found"
    NO_PATH_FOUND = "evaluated-no-path"
    NOT_ASSESSED = "not-assessed"
    EXCLUDED = "excluded"
    GATED = "gated"
    NOT_IMPLEMENTED = "not-implemented-for-device"
    NOT_RECORDED = "not-recorded"


@dataclass(frozen=True)
class PathPattern:
    pattern_id: str
    version: int
    title: str
    priority: Severity
    device_types: frozenset[str]
    component_rule_ids: tuple[str, ...]
    summary: str
    assumptions: tuple[str, ...]
    breakpoints: tuple[str, ...]
    gate: str = ""

    @property
    def gated(self) -> bool:
        return bool(self.gate)


@dataclass(frozen=True)
class PathFact:
    """One sanitized, typed predicate about a single entity."""

    kind: str
    entity: str
    scope: str
    family: str
    state: FactState
    predicate: str
    evidence: tuple[EvidenceLocation, ...] = ()
    linked_findings: tuple[tuple[str, str], ...] = ()

    def to_dict(self, order: int) -> dict:
        return {
            "order": order,
            "kind": self.kind,
            "entity": self.entity,
            "scope": self.scope,
            "family": self.family,
            "state": self.state.value,
            "predicate": self.predicate,
            "evidence": [item.to_dict() for item in self.evidence[:_MAX_EVIDENCE_PER_STEP]],
            "linked-findings": [
                {"rule-id": rule_id, "title": title}
                for rule_id, title in self.linked_findings[:_MAX_LINKS_PER_STEP]
            ],
        }


@dataclass(frozen=True)
class PathResult:
    pattern_id: str
    instance_key: str
    scope: str
    family: str
    steps: tuple[PathFact, ...]


_FORTIOS = frozenset({"FORTIOS"})
_IOS_ASA = frozenset({"IOS_ROUTER", "IOS_SWITCH", "IOS_CATALYST", "IOS_XE", "ASA"})

_NOT_TESTED = (
    "Upstream and Internet reachability of the listener was not tested.",
    "No password was known, guessed or tested; no login was attempted.",
)

PATTERNS: dict[str, PathPattern] = {
    pattern.pattern_id: pattern
    for pattern in (
        PathPattern(
            "default-credential-admin-entry", 1, "Default credential on an externally admitted admin listener",
            Severity.CRITICAL, frozenset({"ASA", "PAN_OS"}), (),
            "An exact documented default credential on an account admitted by an external management listener.",
            _NOT_TESTED, ("Change the default credential.",),
            gate="Requires exact default-credential qualification bound to the selecting authentication path; not in this release.",
        ),
        PathPattern(
            "privileged-admin-guessing", 1, "Online password guessing against a privileged administrator",
            Severity.HIGH, _FORTIOS,
            ("fortinet.fortios.admin.trusted_hosts", "fortinet.fortios.admin.mfa", "fortinet.fortios.admin.lockout"),
            ("An externally classified interface offers HTTPS or SSH administration, and the same enabled, "
             "privileged, locally authenticated administrator accepts any source address, has no second factor "
             "and is protected only by a weakened lockout."),
            _NOT_TESTED + ("Upstream filtering, VIPs or a management VRF may still block the listener.",),
            ("Restrict the administrator's trusthost entries to management networks.",
             "Enable a second factor for the administrator.",
             "Remove HTTPS/SSH from allowaccess on external interfaces.",
             "Restore lockout to at most 3 attempts and at least 60 seconds."),
        ),
        PathPattern(
            "sslvpn-password-guessing", 1, "Online password guessing into SSL-VPN",
            Severity.HIGH, _FORTIOS,
            ("fortinet.fortios.sslvpn.unrestricted_sources", "fortinet.fortios.sslvpn.unlimited_login_attempts",
             "fortinet.fortios.sslvpn.password_only_local_user"),
            ("An active SSL-VPN listener on an external interface admits every IPv4 source, sets no failed-login "
             "limit, and maps an enabled local user that authenticates with a password only."),
            _NOT_TESTED + ("Successful authentication would not by itself prove access to internal resources; "
                           "firewall policies for SSL-VPN traffic were not evaluated for this path.",),
            ("Set a small login-attempt-limit with a login-block-time.",
             "Require a second factor or client certificate for the user.",
             "Restrict SSL-VPN source-address to approved networks."),
        ),
        PathPattern(
            "unauthenticated-management-api", 1, "Unauthenticated management API admitted from outside",
            Severity.CRITICAL, frozenset({"JUNOS"}), (),
            "A gRPC listener with skip-authentication proven admitted from an external source.",
            _NOT_TESTED, ("Remove skip-authentication and require mutual TLS.",),
            gate="Requires listener, interface, filter and routing-instance admission proof; not in this release.",
        ),
        PathPattern(
            "writable-default-snmp", 1, "Writable default SNMP community",
            Severity.HIGH, frozenset({"ASA"}), (),
            "A read-write exact-default community bound to a broadly permitted manager source.",
            _NOT_TESTED, ("Remove the default read-write community.",),
            gate="Requires in-parser community identity matching without exposing the value; not in this release.",
        ),
        PathPattern(
            "risky-ingress-without-inspection", 1, "Risky inbound service without effective inspection",
            Severity.HIGH, _FORTIOS, (),
            "An external-to-internal first-match accept for a risky service with no effective blocking profile.",
            _NOT_TESTED, ("Restrict or inspect the service.",),
            gate="Requires inbound policy-to-profile, NAT/VIP and ISDB resolution; not in this release.",
        ),
        PathPattern(
            "protective-deny-defeated", 1, "Protective deny defeated by an earlier allow",
            Severity.HIGH, _FORTIOS, ("fortinet.fortios.policy.shadowed_rule",),
            ("Earlier enabled accept policies statically cover every source, destination and service of a later "
             "deny policy in the same scope, address family and interface pair, so the deny is never reached."),
            ("Traffic matching the deny was not observed; the intended effect of the deny is inferred from its order.",
             "Schedules, identity, ISDB and NAT objects were not involved in the proof (they are excluded from it)."),
            ("Move the deny above the covering accept policies, or narrow the accept policies.",
             "Remove the deny if its intent is obsolete, so policy review is not misled."),
        ),
        PathPattern(
            "cleartext-admin-unrestricted", 1, "Unrestricted clear-text administration",
            Severity.HIGH, _IOS_ASA, (),
            "A VTY or ASA management service with broad source admission, Telnet/HTTP and password authentication.",
            _NOT_TESTED, ("Disable Telnet/HTTP and restrict management sources.",),
            gate="Requires service-specific ACL and binding proof; not in this release.",
        ),
        PathPattern(
            "weak-dialup-vpn", 1, "Weak dial-up VPN entry",
            Severity.HIGH, _FORTIOS, (),
            "An enabled dial-up gateway binding aggressive IKEv1, PSK-only authentication and a weak proposal.",
            _NOT_TESTED, ("Use IKEv2 with certificates and strong proposals.",),
            gate="Requires proof that the three settings negotiate on one bound tunnel; not in this release.",
        ),
        PathPattern(
            "exposed-vulnerable-feature", 1, "Exposed vulnerable feature",
            Severity.CRITICAL, frozenset(), (),
            "A locally supplied advisory naming a feature that is enabled and admitted from an untrusted source.",
            _NOT_TESTED, ("Upgrade or disable the affected feature.",),
            gate="Requires authoritative feature applicability and local advisory provenance; version matches never qualify.",
        ),
    )
}
assert len(PATTERNS) <= MAX_PATTERNS

_PRIORITY_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1}


@dataclass
class _Ledger:
    results: dict[str, dict[str, PathResult]] = field(default_factory=dict)
    not_assessed: dict[str, list[str]] = field(default_factory=dict)
    evaluated: set[str] = field(default_factory=set)


_LEDGERS: "weakref.WeakKeyDictionary[object, _Ledger]" = weakref.WeakKeyDictionary()


def _ledger(parser) -> _Ledger:
    ledger = _LEDGERS.get(parser)
    if ledger is None:
        ledger = _Ledger()
        _LEDGERS[parser] = ledger
    return ledger


def _pattern(pattern_id: str) -> PathPattern:
    if pattern_id not in PATTERNS:
        raise KeyError(f"Unregistered attack-path pattern '{pattern_id}'")
    pattern = PATTERNS[pattern_id]
    if pattern.gated:
        raise ValueError(f"Attack-path pattern '{pattern_id}' is gated: {pattern.gate}")
    return pattern


def evidence_locations(items: Iterable) -> tuple[EvidenceLocation, ...]:
    """Sanitized parser evidence or fixed explanatory strings, deduplicated in order."""
    seen, result = set(), []
    for item in items:
        if not isinstance(item, (str, ConfigEvidence)):
            continue
        location = EvidenceLocation.from_item(item)
        key = (location.text, location.line_number)
        if location.text.strip() and key not in seen:
            seen.add(key)
            result.append(location)
    return tuple(result)


def linked_findings(findings: Iterable, rule_ids: Iterable[str], evidence: Iterable) -> tuple[tuple[str, str], ...]:
    """Already-emitted findings for the same entity: same rule and a shared located evidence line.

    This links a path step to an existing finding for navigation; it is never the join itself.
    """
    wanted = set(rule_ids)
    lines = {
        (location.text, location.line_number)
        for location in evidence_locations(evidence) if location.line_number is not None
    }
    result = []
    for finding in findings:
        if finding.rule_id not in wanted:
            continue
        shared = {(item.text, item.line_number) for item in getattr(finding, "evidence_locations", ())}
        link = (finding.rule_id, finding.title)
        if lines & shared and link not in result:
            result.append(link)
    return tuple(result)


def mark_evaluated(parser, pattern_id: str) -> None:
    _pattern(pattern_id)
    _ledger(parser).evaluated.add(pattern_id)


def record_path_not_assessed(parser, pattern_id: str, reason: str) -> None:
    _pattern(pattern_id)
    reasons = _ledger(parser).not_assessed.setdefault(pattern_id, [])
    reason = reason[:300]
    if reason not in reasons and len(reasons) < _MAX_REASONS:
        reasons.append(reason)


def record_path(parser, result: PathResult) -> bool:
    """Record a path only when every step is KNOWN and scope/family are compatible."""
    _pattern(result.pattern_id)
    blocking = [step for step in result.steps if step.state != FactState.KNOWN]
    if not result.steps or blocking:
        record_path_not_assessed(
            parser, result.pattern_id,
            f"{result.instance_key}: step(s) {', '.join(step.kind for step in blocking) or 'missing'} "
            "not known; the path was not emitted.",
        )
        return False
    for step in result.steps:
        if step.scope.casefold() != result.scope.casefold() or step.family not in {result.family, "any"}:
            raise ValueError(f"Path step '{step.kind}' is outside the path scope or address family")
    ledger = _ledger(parser)
    ledger.evaluated.add(result.pattern_id)
    ledger.results.setdefault(result.pattern_id, {}).setdefault(result.instance_key, result)
    return True


def _result_dict(pattern: PathPattern, result: PathResult) -> dict:
    links: list[dict] = []
    for step in result.steps:
        for rule_id, title in step.linked_findings[:_MAX_LINKS_PER_STEP]:
            entry = {"rule-id": rule_id, "title": title}
            if entry not in links:
                links.append(entry)
    return {
        "pattern-id": pattern.pattern_id,
        "pattern-version": pattern.version,
        "instance-key": result.instance_key,
        "title": pattern.title,
        "priority": pattern.priority.value,
        "scope": result.scope,
        "family": result.family,
        "summary": pattern.summary,
        "steps": [step.to_dict(order) for order, step in enumerate(result.steps, start=1)],
        "linked-findings": links,
        "assumptions": list(pattern.assumptions),
        "breakpoints": list(pattern.breakpoints),
    }


_SCOPE_NOTE = (
    "Each path joins configuration predicates that apply to the same account, listener, VPN scope or ordered "
    "policy pair. It is a remediation-priority aid, not an additional finding, and it does not change finding "
    "severities. Public reachability, password knowledge, successful login, exploitability and attacker "
    "activity were not tested. An empty list is not a security pass: see the pattern status table for "
    "patterns that were gated, not implemented for this device or not assessable."
)


def empty_attack_path_section(device_type: str, reason: str) -> dict:
    """Section for callers that ran no analysis (for example a parse error)."""
    return {
        "schema-version": ATTACK_PATH_SCHEMA_VERSION,
        "catalogue-version": CATALOGUE_VERSION,
        "results": [],
        "omitted-result-count": 0,
        "patterns": [
            _pattern_status(pattern, device_type, PatternStatus.NOT_ASSESSED, [reason], 0)
            if device_type in pattern.device_types and not pattern.gated
            else _static_status(pattern, device_type)
            for pattern in PATTERNS.values()
        ],
        "scope-note": _SCOPE_NOTE,
    }


def _pattern_status(pattern: PathPattern, device_type: str, status: PatternStatus, reasons, count: int) -> dict:
    return {
        "pattern-id": pattern.pattern_id,
        "pattern-version": pattern.version,
        "title": pattern.title,
        "priority": pattern.priority.value,
        "status": status.value,
        "instance-count": count,
        "reasons": list(reasons)[:_MAX_REASONS],
    }


def _static_status(pattern: PathPattern, device_type: str) -> dict:
    if pattern.gated and (device_type in pattern.device_types or not pattern.device_types):
        return _pattern_status(pattern, device_type, PatternStatus.GATED, [pattern.gate], 0)
    return _pattern_status(
        pattern, device_type, PatternStatus.NOT_IMPLEMENTED,
        ["No producer exists for this device family in this release; the pattern was not assessed."], 0,
    )


def attack_path_section(parser, *, template_unresolved: bool = False) -> dict:
    """Versioned, bounded, deterministic ``attack-paths`` report section."""
    ledger = _LEDGERS.get(parser) or _Ledger()
    device_type = getattr(parser, "device_type", "")
    context = parser.assessment_context
    statuses, emitted = [], []
    for pattern in PATTERNS.values():
        if pattern.gated or device_type not in pattern.device_types:
            statuses.append(_static_status(pattern, device_type))
            continue
        found = ledger.results.get(pattern.pattern_id, {})
        reasons = ledger.not_assessed.get(pattern.pattern_id, [])
        if not all(context.permits_rule(rule) for rule in pattern.component_rule_ids):
            statuses.append(_pattern_status(
                pattern, device_type, PatternStatus.EXCLUDED, ["A component category is excluded by the assessment policy."], 0,
            ))
            continue
        if template_unresolved:
            statuses.append(_pattern_status(
                pattern, device_type, PatternStatus.NOT_ASSESSED,
                ["Unrendered template; omitted settings and defaults cannot be joined into a path."], 0,
            ))
            continue
        if found:
            status = PatternStatus.PATH_FOUND
        elif reasons:
            status = PatternStatus.NOT_ASSESSED
        elif pattern.pattern_id in ledger.evaluated:
            status = PatternStatus.NO_PATH_FOUND
        else:
            status = PatternStatus.NOT_RECORDED
            reasons = ["The producer did not record an outcome for this input."]
        statuses.append(_pattern_status(pattern, device_type, status, reasons, len(found)))
        emitted.extend((pattern, found[key]) for key in sorted(found))
    emitted.sort(key=lambda item: (_PRIORITY_ORDER.get(item[0].priority, 9),
                                   list(PATTERNS).index(item[0].pattern_id), item[1].instance_key))
    return {
        "schema-version": ATTACK_PATH_SCHEMA_VERSION,
        "catalogue-version": CATALOGUE_VERSION,
        "results": [_result_dict(pattern, result) for pattern, result in emitted[:MAX_DISPLAYED_RESULTS]],
        "omitted-result-count": max(0, len(emitted) - MAX_DISPLAYED_RESULTS),
        "patterns": statuses,
        "scope-note": _SCOPE_NOTE,
    }


__all__: Iterable[str] = [
    "ATTACK_PATH_SCHEMA_VERSION", "PATTERNS", "FactState", "PathFact", "PathPattern", "PathResult",
    "PatternStatus", "attack_path_section", "empty_attack_path_section", "evidence_locations",
    "linked_findings", "mark_evaluated", "record_path", "record_path_not_assessed",
]
