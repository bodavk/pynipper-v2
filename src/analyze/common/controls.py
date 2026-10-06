"""Per-control assessment outcomes and manual-review coverage (SC-049).

Controls are metadata kept separate from findings. A plugin records an explicit
outcome for each migrated control it evaluates; the report never derives a pass
from the mere absence of a finding. Controls that are applicable to the device
type but were not recorded are shown as ``not-recorded``; checks without control
metadata are not listed and therefore make no assurance claim.
"""

from __future__ import annotations

import weakref
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

from src.analyze.common.cis_references import cis_references_for_rules

CONTROL_SCHEMA_VERSION = 1

_IOS_FAMILY = frozenset({"IOS_ROUTER", "IOS_SWITCH", "IOS_CATALYST", "IOS_XE"})


class ControlOutcome(str, Enum):
    FINDING = "finding"
    NO_FINDING = "evaluated-no-finding"
    UNKNOWN = "unknown"
    UNSUPPORTED = "unsupported"
    NOT_APPLICABLE = "not-applicable"
    EXCLUDED = "excluded"
    NOT_RECORDED = "not-recorded"


# Higher wins when one control records several outcomes (for example per instance).
_PRECEDENCE = {
    ControlOutcome.FINDING: 5,
    ControlOutcome.UNKNOWN: 4,
    ControlOutcome.UNSUPPORTED: 3,
    ControlOutcome.NO_FINDING: 2,
    ControlOutcome.NOT_APPLICABLE: 1,
}


@dataclass(frozen=True)
class ControlDefinition:
    control_id: str
    title: str
    version: int
    device_types: frozenset[str]
    rule_ids: tuple[str, ...]
    references: tuple[str, ...] = ()


@dataclass
class _Ledger:
    results: dict[str, tuple[ControlOutcome, list[str]]] = field(default_factory=dict)
    manual_review: list[tuple[str, str]] = field(default_factory=list)
    instances: dict[str, dict[str, tuple[ControlOutcome, list[str]]]] = field(default_factory=dict)
    unassessed: dict[str, dict[str, list[str]]] = field(default_factory=dict)


CONTROLS: dict[str, ControlDefinition] = {
    definition.control_id: definition
    for definition in (
        ControlDefinition("paloalto.panos.threat-updates", "Explicit recurring threat-content installation", 1, frozenset({"PAN_OS"}),
                          ("paloalto.panos.updates.threat_content",)),
        ControlDefinition("paloalto.panos.administrator-policy", "Administrator role and authentication binding knowledge", 1, frozenset({"PAN_OS"}),
                          ("paloalto.panos.admin.role_assignment", "paloalto.panos.admin.authentication_profile_unresolved")),
        ControlDefinition("paloalto.panos.policy-inspection", "Exported attached security-profile actions", 1, frozenset({"PAN_OS"}),
                          ("paloalto.panos.policy.security_profiles", "paloalto.panos.policy.security_profile_unresolved", "paloalto.panos.policy.security_profile_ineffective", "paloalto.panos.policy.threat_selector_nonblocking")),
        ControlDefinition("paloalto.panos.management-ssh", "Explicit applied management SSH algorithms", 1, frozenset({"PAN_OS"}),
                          ("paloalto.panos.admin.ssh_profile_missing", "paloalto.panos.admin.ssh_profile_unresolved", "paloalto.panos.admin.ssh_profile_algorithms")),
        ControlDefinition("paloalto.panos.management-tls", "Explicit management TLS policy", 1, frozenset({"PAN_OS"}),
                          ("paloalto.panos.management.tls_profile_missing", "paloalto.panos.management.tls_profile_unresolved", "paloalto.panos.management.tls_minimum_version")),
        ControlDefinition("fortinet.fortios.policy-order", "Bounded transit-policy effectiveness", 1, frozenset({"FORTIOS"}),
                          ("fortinet.fortios.policy.shadowed_rule", "fortinet.fortios.policy.redundant_rule")),
        ControlDefinition("cisco.asa.policy-order", "Bounded bound-ACL effectiveness", 1, frozenset({"ASA"}),
                          ("cisco.asa.acl.shadowed_rule", "cisco.asa.acl.redundant_rule")),
        ControlDefinition("paloalto.panos.policy-order", "Bounded security-rule effectiveness and NAT relevance", 1, frozenset({"PAN_OS"}),
                          ("paloalto.panos.policy.shadowed_rule", "paloalto.panos.policy.redundant_rule")),
        ControlDefinition("fortinet.fortios.policy-logging", "Effective boundary-policy logging", 1,
                          frozenset({"FORTIOS"}), ("fortinet.fortios.policy.logging",)),
        ControlDefinition("fortinet.fortios.policy-inspection", "Effective boundary-policy inspection", 1,
                          frozenset({"FORTIOS"}), ("fortinet.fortios.policy.security_profiles", "fortinet.fortios.policy.security_profile_ineffective", "fortinet.fortios.policy.security_profile_unresolved")),
        ControlDefinition("paloalto.panos.password-complexity", "Explicit administrator password complexity", 1,
                          frozenset({"PAN_OS"}), ("paloalto.panos.credentials.password_complexity",)),
        ControlDefinition("cisco.asa.management-authentication", "Management AAA authentication binding", 1,
                          frozenset({"ASA"}), ("cisco.asa.aaa.management_authentication",)),
        ControlDefinition("cisco.asa.management-accounting", "Management session accounting binding", 1,
                          frozenset({"ASA"}), ("cisco.asa.aaa.management_accounting",)),
        ControlDefinition(
            "cisco.ios.smart-install", "Smart Install (vstack) disabled", 1, _IOS_FAMILY,
            ("cisco.ios.services.smart_install",),
            ("https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-20180409-smi.html",),
        ),
        ControlDefinition(
            "cisco.ios.pptp-dialin", "No PPTP dial-in VPDN group", 1, _IOS_FAMILY,
            ("cisco.ios.vpn.pptp_gateway",),
        ),
        ControlDefinition(
            "cisco.ios.ldap-transport", "AAA LDAP servers use TLS", 1, _IOS_FAMILY,
            ("cisco.ios.aaa.ldap_cleartext",),
        ),
        ControlDefinition(
            "fortinet.fortios.forticloud-sso", "FortiCloud SSO admin login not exposed to FG-IR-26-060", 1,
            frozenset({"FORTIOS"}), ("fortinet.fortios.admin.forticloud_sso_login",),
        ),
        ControlDefinition(
            "fortinet.fortios.admin-restrict-local", "Local admins restricted while remote auth works", 1,
            frozenset({"FORTIOS"}), ("fortinet.fortios.admin.local_login_unrestricted",),
        ),
        ControlDefinition(
            "fortinet.fortios.cli-audit-log", "CLI command audit logging enabled", 1,
            frozenset({"FORTIOS"}), ("fortinet.fortios.cli.audit_disabled",),
        ),
        ControlDefinition(
            "juniper.junos.isis-authentication", "IS-IS adjacencies authenticated", 1,
            frozenset({"JUNOS"}),
            ("juniper.junos.routing.isis.authentication", "juniper.junos.routing.isis.cleartext_authentication",
             "juniper.junos.routing.isis.send_only"),
        ),
        ControlDefinition(
            "arista.eos.ospf-authentication", "OSPFv2 interfaces authenticated with message digest", 1,
            frozenset({"ARISTA_EOS"}),
            ("arista.eos.routing.ospf.authentication", "arista.eos.routing.ospf.weak_authentication"),
        ),
        # SC-049 second batch (2026-10-06): core management-plane controls.
        ControlDefinition("cisco.ios.vty-transport", "VTY lines accept only encrypted transport", 1, _IOS_FAMILY,
                          ("cisco.ios.vty.telnet",)),
        ControlDefinition("cisco.ios.ssh-protocol", "SSH server uses protocol version 2 only", 1, _IOS_FAMILY,
                          ("cisco.ios.ssh.protocol_version",)),
        ControlDefinition("cisco.ios.snmp-community", "No SNMPv1/v2c community is configured", 1, _IOS_FAMILY,
                          ("cisco.ios.snmp.legacy_community", "cisco.ios.snmp.default_community")),
        ControlDefinition("cisco.ios.ntp-authentication", "NTP associations are authenticated", 1, _IOS_FAMILY,
                          ("cisco.ios.ntp.authentication",)),
        ControlDefinition("cisco.ios.remote-logging", "A remote syslog destination is configured", 1, _IOS_FAMILY,
                          ("cisco.ios.logging.remote_destination",)),
        ControlDefinition("cisco.asa.snmp-community", "No default or writable SNMP community", 1, frozenset({"ASA"}),
                          ("cisco.asa.snmp.default_community", "cisco.asa.snmp.write_community")),
        ControlDefinition("cisco.asa.ntp-authentication", "NTP servers are authenticated", 1, frozenset({"ASA"}),
                          ("cisco.asa.ntp.authentication",)),
        ControlDefinition("cisco.asa.remote-logging", "Logging to a remote host is configured", 1, frozenset({"ASA"}),
                          ("cisco.asa.logging.missing",)),
        ControlDefinition("fortinet.fortios.admin-trusted-hosts", "Privileged administrators are source restricted", 1,
                          frozenset({"FORTIOS"}), ("fortinet.fortios.admin.trusted_hosts",)),
        ControlDefinition("fortinet.fortios.admin-mfa", "Privileged local administrators use a second factor", 1,
                          frozenset({"FORTIOS"}), ("fortinet.fortios.admin.mfa",)),
        ControlDefinition("fortinet.fortios.remote-logging", "A remote log destination is configured", 1,
                          frozenset({"FORTIOS"}), ("fortinet.fortios.logging.missing",)),
        ControlDefinition("juniper.junos.ssh-root-login", "SSH root login is denied", 1, frozenset({"JUNOS"}),
                          ("juniper.junos.ssh.root_login",)),
        ControlDefinition("juniper.junos.snmp-community", "No SNMPv1/v2c community is configured", 1, frozenset({"JUNOS"}),
                          ("juniper.junos.snmp.legacy_community",)),
        ControlDefinition("juniper.junos.remote-logging", "A remote syslog destination is configured", 1, frozenset({"JUNOS"}),
                          ("juniper.junos.logging.remote_destination",)),
        ControlDefinition("arista.eos.remote-logging", "A remote syslog destination is configured", 1, frozenset({"ARISTA_EOS"}),
                          ("arista.eos.logging.remote_destination",)),
        ControlDefinition("arista.eos.ssh-source-restriction", "SSH management is source restricted", 1, frozenset({"ARISTA_EOS"}),
                          ("arista.eos.ssh.source_restriction",)),
        # SC-049 third batch (2026-10-06).
        ControlDefinition("cisco.ios.http-server", "HTTP management is disabled or restricted", 1, _IOS_FAMILY,
                          ("cisco.ios.http.cleartext_service", "cisco.ios.http.access_restriction")),
        ControlDefinition("cisco.asa.management-telnet", "Telnet management is not enabled", 1, frozenset({"ASA"}),
                          ("cisco.asa.management.telnet",)),
        ControlDefinition("cisco.asa.ssh-source-restriction", "SSH management is source restricted", 1, frozenset({"ASA"}),
                          ("cisco.asa.management.unrestricted_ssh",)),
        ControlDefinition("fortinet.fortios.admin-lockout", "Administrator lockout is not weakened", 1, frozenset({"FORTIOS"}),
                          ("fortinet.fortios.admin.lockout",)),
        ControlDefinition("fortinet.fortios.password-policy", "Administrator password policy is enabled and strong", 1,
                          frozenset({"FORTIOS"}), ("fortinet.fortios.password_policy.disabled", "fortinet.fortios.password_policy.weak")),
        ControlDefinition("juniper.junos.ntp-authentication", "NTP servers are authenticated", 1, frozenset({"JUNOS"}),
                          ("juniper.junos.ntp.authentication",)),
        ControlDefinition("juniper.junos.login-lockout", "Login retry and lockout limits are configured", 1, frozenset({"JUNOS"}),
                          ("juniper.junos.authentication.lockout", "juniper.junos.authentication.login_attempts")),
        ControlDefinition("arista.eos.ntp-authentication", "NTP servers are authenticated", 1, frozenset({"ARISTA_EOS"}),
                          ("arista.eos.ntp.authentication",)),
        ControlDefinition("paloalto.panos.cleartext-management", "HTTP and Telnet management are disabled", 1, frozenset({"PAN_OS"}),
                          ("paloalto.panos.management.http", "paloalto.panos.management.telnet")),
        # SC-049 fourth batch (2026-10-06).
        ControlDefinition("fortinet.fortios.admin-session-timeout", "Administrative idle session timeout is bounded", 1,
                          frozenset({"FORTIOS"}), ("fortinet.fortios.admin.session_timeout",)),
        ControlDefinition("fortinet.fortios.login-banner", "Pre-login administrator banner is enabled", 1,
                          frozenset({"FORTIOS"}), ("fortinet.fortios.banner.login_disabled",)),
        ControlDefinition("fortinet.fortios.snmp-community", "No reachable SNMPv1/v2c community is enabled", 1,
                          frozenset({"FORTIOS"}), ("fortinet.fortios.snmp.legacy_community",)),
        ControlDefinition("fortinet.fortios.ntp-authentication", "Custom NTP servers are authenticated", 1,
                          frozenset({"FORTIOS"}), ("fortinet.fortios.ntp.authentication",)),
        ControlDefinition("juniper.junos.login-banner", "A pre-authentication login message is configured", 1,
                          frozenset({"JUNOS"}), ("juniper.junos.authentication.login_banner",)),
        ControlDefinition("juniper.junos.idle-timeout", "Login classes in use enforce an idle timeout", 1,
                          frozenset({"JUNOS"}), ("juniper.junos.authentication.idle_timeout",)),
        ControlDefinition("arista.eos.login-lockout", "Remote login lockout is enabled with strong thresholds", 1,
                          frozenset({"ARISTA_EOS"}),
                          ("arista.eos.authentication.lockout_disabled", "arista.eos.authentication.lockout_policy")),
        ControlDefinition("arista.eos.idle-timeout", "Interactive management sessions have a bounded idle timeout", 1,
                          frozenset({"ARISTA_EOS"}), ("arista.eos.admin.idle_timeout",)),
        ControlDefinition("arista.eos.login-banner", "A pre-login banner is configured", 1,
                          frozenset({"ARISTA_EOS"}), ("arista.eos.admin.login_banner",)),
        ControlDefinition("arista.eos.snmp-default-community", "No default SNMP community is configured", 1,
                          frozenset({"ARISTA_EOS"}), ("arista.eos.snmp.default_community",)),
        ControlDefinition("paloalto.panos.login-banner", "Administrative login banner is configured", 1,
                          frozenset({"PAN_OS"}), ("paloalto.panos.admin.login_banner",)),
        ControlDefinition("paloalto.panos.ntp-authentication", "NTP servers are authenticated", 1,
                          frozenset({"PAN_OS"}), ("paloalto.panos.ntp.authentication",)),
        ControlDefinition("paloalto.panos.policy-logging", "Allow rules log at session end and forward to syslog", 1,
                          frozenset({"PAN_OS"}), ("paloalto.panos.policy.log_forwarding", "paloalto.panos.policy.session_logging")),
        # SC-049 fifth batch (2026-10-06): first F5 BIG-IP and Check Point Gaia controls.
        ControlDefinition("f5.bigip.self-ip-port-lockdown", "Self IPs do not allow SSH or HTTPS management", 1,
                          frozenset({"F5_BIGIP"}), ("f5.bigip.management.self_ip_port_lockdown",)),
        ControlDefinition("f5.bigip.root-login", "Direct root login is disabled", 1, frozenset({"F5_BIGIP"}),
                          ("f5.bigip.auth.root_login_enabled",)),
        ControlDefinition("f5.bigip.ssh-source-restriction", "SSH management is source restricted", 1,
                          frozenset({"F5_BIGIP"}), ("f5.bigip.ssh.unrestricted_sources",)),
        ControlDefinition("f5.bigip.httpd-source-restriction", "Configuration utility is source restricted", 1,
                          frozenset({"F5_BIGIP"}), ("f5.bigip.http.unrestricted_sources",)),
        ControlDefinition("f5.bigip.password-policy-enforcement", "Local password policy is enforced", 1,
                          frozenset({"F5_BIGIP"}), ("f5.bigip.password_policy.enforcement_disabled",)),
        ControlDefinition("f5.bigip.snmp-community", "No default, writable or unrestricted SNMP community", 1,
                          frozenset({"F5_BIGIP"}),
                          ("f5.bigip.snmp.community_access", "f5.bigip.snmp.default_community", "f5.bigip.snmp.write_community")),
        ControlDefinition("f5.bigip.remote-user-defaults", "Remote users get no default admin role or console access", 1,
                          frozenset({"F5_BIGIP"}), ("f5.bigip.auth.remote_default_admin", "f5.bigip.auth.remote_console_access")),
        ControlDefinition("checkpoint.gaia.login-lockout", "Failed-login lockout is enabled with strong thresholds", 1,
                          frozenset({"CHECKPOINT_GAIA"}),
                          ("checkpoint.gaia.password_policy.lockout_disabled", "checkpoint.gaia.password_policy.lockout_threshold")),
        ControlDefinition("checkpoint.gaia.password-length", "Minimum password length is at least eight", 1,
                          frozenset({"CHECKPOINT_GAIA"}), ("checkpoint.gaia.password_policy.minimum_length",)),
        ControlDefinition("checkpoint.gaia.web-session-timeout", "Gaia Portal session timeout is at most ten minutes", 1,
                          frozenset({"CHECKPOINT_GAIA"}), ("checkpoint.gaia.web.session_timeout_excessive",)),
        ControlDefinition("checkpoint.gaia.cli-idle-timeout", "Clish idle timeout is at most ten minutes", 1,
                          frozenset({"CHECKPOINT_GAIA"}), ("checkpoint.gaia.cli.idle_timeout_excessive",)),
        ControlDefinition("checkpoint.gaia.login-banner", "Pre-login banner is enabled", 1,
                          frozenset({"CHECKPOINT_GAIA"}), ("checkpoint.gaia.banner.login_disabled",)),
        ControlDefinition("checkpoint.gaia.management-telnet", "Telnet management is not enabled", 1,
                          frozenset({"CHECKPOINT_GAIA"}), ("checkpoint.gaia.management.telnet",)),
        ControlDefinition("checkpoint.gaia.snmp-community", "No default or writable SNMP community", 1,
                          frozenset({"CHECKPOINT_GAIA"}),
                          ("checkpoint.gaia.snmp.default_community", "checkpoint.gaia.snmp.write_community")),
        ControlDefinition("checkpoint.gaia.ssh-root-login", "SSH root login is denied", 1,
                          frozenset({"CHECKPOINT_GAIA"}), ("checkpoint.gaia.ssh.root_login_permitted",)),
    )
}

_LEDGERS: "weakref.WeakKeyDictionary[object, _Ledger]" = weakref.WeakKeyDictionary()


def _ledger(parser) -> _Ledger:
    ledger = _LEDGERS.get(parser)
    if ledger is None:
        ledger = _Ledger()
        _LEDGERS[parser] = ledger
    return ledger


def record_control(parser, control_id: str, outcome: ControlOutcome, reason: str, *, instance: str = "device") -> None:
    """Record a check's outcome for a registered control; unknown IDs are a programming error."""
    if control_id not in CONTROLS:
        raise KeyError(f"Unregistered control '{control_id}'")
    ledger = _ledger(parser)
    if outcome in {ControlOutcome.UNKNOWN, ControlOutcome.UNSUPPORTED}:
        details = ledger.unassessed.setdefault(control_id, {}).setdefault(instance, [])
        if reason not in details and len(details) < 3:
            details.append(reason)
    scoped = ledger.instances.setdefault(control_id, {})
    previous = scoped.get(instance)
    if previous is None or _PRECEDENCE[outcome] > _PRECEDENCE[previous[0]]:
        scoped[instance] = (outcome, [reason])
    elif outcome == previous[0] and reason not in previous[1] and len(previous[1]) < 3:
        previous[1].append(reason)
    current = ledger.results.get(control_id)
    if current is None or _PRECEDENCE[outcome] > _PRECEDENCE[current[0]]:
        ledger.results[control_id] = (outcome, [reason])
    elif outcome == current[0] and reason not in current[1] and len(current[1]) < 3:
        current[1].append(reason)


def record_manual_review(parser, feature: str, reason: str) -> None:
    """A recognized security construct whose semantics the tool does not evaluate."""
    ledger = _ledger(parser)
    entry = (feature[:120], reason[:300])
    if entry not in ledger.manual_review:
        ledger.manual_review.append(entry)


def control_coverage(parser, *, template_unresolved: bool = False) -> dict:
    """Additive, sanitized control-outcome section for the coverage report."""
    ledger = _LEDGERS.get(parser) or _Ledger()
    device_type = getattr(parser, "device_type", "")
    context = parser.assessment_context
    results = []
    for definition in CONTROLS.values():
        if device_type not in definition.device_types:
            continue
        outcome, reasons = ledger.results.get(
            definition.control_id,
            (ControlOutcome.NOT_RECORDED, ["The check did not record an outcome for this input."]),
        )
        if not all(context.permits_rule(rule) for rule in definition.rule_ids):
            outcome, reasons = ControlOutcome.EXCLUDED, ["Excluded by the assessment policy."]
        elif template_unresolved and outcome == ControlOutcome.NO_FINDING:
            outcome, reasons = ControlOutcome.UNKNOWN, ["Unrendered template; omitted settings cannot be judged."]
        unassessed = {key: list(details) for key, details in ledger.unassessed.get(definition.control_id, {}).items()}
        if template_unresolved:
            for key, (state, _) in ledger.instances.get(definition.control_id, {}).items():
                if state == ControlOutcome.NO_FINDING:
                    unassessed.setdefault(key, []).append("Unrendered template; omitted settings cannot be judged.")
        results.append({
            "control-id": definition.control_id,
            "title": definition.title,
            "control-version": definition.version,
            "outcome": outcome.value,
            "reasons": list(reasons),
            "rule-ids": list(definition.rule_ids),
            "references": list(definition.references),
            "cis-references": cis_references_for_rules(definition.rule_ids),
            "instances": [
                {"instance-key": key, "outcome": (
                    ControlOutcome.EXCLUDED.value if outcome == ControlOutcome.EXCLUDED else
                    ControlOutcome.UNKNOWN.value if template_unresolved and state == ControlOutcome.NO_FINDING else state.value),
                 "reasons": (["Excluded by the assessment policy."] if outcome == ControlOutcome.EXCLUDED else
                             ["Unrendered template; omitted settings cannot be judged."] if template_unresolved and state == ControlOutcome.NO_FINDING else list(details))}
                for key, (state, details) in sorted(ledger.instances.get(definition.control_id, {}).items())
            ],
            "unassessed-instances": ([] if outcome == ControlOutcome.EXCLUDED else [
                {"instance-key": key, "reasons": list(details)}
                for key, details in sorted(unassessed.items())]),
            "unassessed-instance-count": (0 if outcome == ControlOutcome.EXCLUDED else len(unassessed)),
        })
    return {
        "schema-version": CONTROL_SCHEMA_VERSION,
        "results": results,
        "manual-review": [{"feature": feature, "reason": reason} for feature, reason in ledger.manual_review],
        "scope-note": (
            "Only the listed controls record explicit outcomes. 'evaluated-no-finding' means the check ran on "
            "the parsed configuration and found no issue; it is not benchmark certification. Other checks report "
            "findings only, so the absence of their findings is not a verified pass."
        ),
    }


def outcome_counts(controls: dict) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in controls.get("results", ()):
        counts[item["outcome"]] = counts.get(item["outcome"], 0) + 1
    return counts


__all__: Iterable[str] = [
    "CONTROLS", "ControlOutcome", "ControlDefinition", "record_control",
    "record_manual_review", "control_coverage", "outcome_counts",
]
