"""FortiOS producers for SC-063 configuration-supported attack paths.

Each producer re-reads parser-owned typed records and joins them on the same
account, listener, SSL-VPN scope or ordered policy pair. Findings are only
linked for navigation. Absent settings are treated as documented defaults only
where the release qualification below holds; otherwise the step is UNKNOWN and
the instance is reported as not assessed.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.analyze.common.attack_paths import (
    FactState, PathFact, PathResult, evidence_locations, linked_findings,
    mark_evaluated, record_path, record_path_not_assessed,
)
from src.devices.fortinet.fortios import FortiFirewallPolicy, FortiOSParser

ADMIN = "privileged-admin-guessing"
SSLVPN = "sslvpn-password-guessing"
DENY = "protective-deny-defeated"

# 7.4.1 CLI reference (config system admin): two-factor disable, trusthost1
# 0.0.0.0 0.0.0.0 and the other IPv4 trusthosts unset. Absent values are only
# interpreted on 7.4.1 or later; explicit values are used on any release.
_ADMIN_DEFAULTS_FROM = (7, 4, 1)
_UNRESTRICTED = {"0.0.0.0 0.0.0.0", "0.0.0.0/0", "0.0.0.0 0"}
_MFA_METHODS = {"email", "fortitoken", "fortitoken-cloud", "sms"}
_LOCAL_RESTRICTED = {"enable", "all", "non-console-only"}


@dataclass(frozen=True)
class DenyShadow:
    """A later enabled deny covered by earlier enabled accept policies (from check_policy_effectiveness)."""

    deny: FortiFirewallPolicy
    covering: tuple[FortiFirewallPolicy, ...]
    finding: object


def _text(value: object) -> str:
    if isinstance(value, list):
        return " ".join(str(item) for item in value)
    return "" if value is None else str(value)


def _values(settings: dict, key: str) -> set[str]:
    value = settings.get(key)
    items = value if isinstance(value, list) else ([] if value is None else [value])
    return {str(item).casefold() for item in items}


def _external_role_known(fortios: FortiOSParser) -> bool:
    return any(role == "external" for _, role in fortios.assessment_context.interface_roles)


def _local_in_on(fortios: FortiOSParser, scope_names: set[str] | None, interfaces: set[str]) -> list[str]:
    """Enabled IPv4 local-in policies that may filter the listener; their effect is not evaluated here.

    ``scope_names`` None means any VDOM: global interfaces are bound to VDOMs whose local-in
    policies may apply, so every scope is considered.
    """
    names = []
    for policy in fortios.get_local_in_policies():
        if policy.family != "ipv4" or not policy.enabled:
            continue
        if scope_names is not None and policy.scope.casefold() not in scope_names:
            continue
        if policy.interface.casefold() in interfaces or policy.interface.casefold() == "any":
            names.append(policy.name)
    return names


def _admin_listeners(fortios: FortiOSParser, scope: str, ssh_password: bool):
    """Enabled external interfaces in the admin scope offering password-capable HTTPS/SSH administration."""
    listeners = []
    for if_scope, name, settings, path in fortios.iter_interfaces():
        if if_scope.casefold() != scope.casefold():
            continue
        if _text(settings.get("status")).casefold() == "down":
            continue
        services = _values(settings, "allowaccess") & ({"https", "ssh"} if ssh_password else {"https"})
        if not services or fortios.assessment_context.role_for_interface(name) != "external":
            continue
        listeners.append((name, tuple(sorted(services)), fortios.field_evidence(path + ("allowaccess",))))
    return listeners


def produce_admin_paths(plugin, fortios: FortiOSParser, release) -> None:
    mark_evaluated(fortios, ADMIN)
    defaults_known = release is not None and release >= _ADMIN_DEFAULTS_FROM
    roles = {(role.scope, role.administrator): role for role in fortios.get_administrator_roles()}
    globals_ = {scope.casefold(): (settings, path) for scope, settings, path in fortios.iter_scoped_sections("system global")}
    remote_admins = any(
        _text(settings.get("status")).casefold() != "disable"
        and _text(settings.get("remote-auth")).casefold() == "enable"
        for _, _, settings, _ in fortios.iter_administrators()
    )
    findings = plugin.get_issues()
    for scope, username, settings, path in fortios.iter_administrators():
        if _text(settings.get("status")).casefold() == "disable":
            continue
        key = f"{scope}/admin:{username}"
        if _text(settings.get("remote-auth")).casefold() == "enable" or _text(settings.get("peer-auth")).casefold() == "enable":
            continue  # not a locally verified password account
        role = roles.get((scope, username))
        if role is None or role.resolution_state != "known":
            record_path_not_assessed(fortios, ADMIN, f"{key}: access profile privilege could not be resolved.")
            continue
        if role.privileged_state != "privileged":
            continue
        account_evidence = tuple(fortios.field_evidence(path)) + tuple(role.evidence)

        trusts = [
            (field, " ".join(_text(value).split()).casefold())
            for field, value in settings.items()
            if str(field).casefold().startswith("trusthost")
        ]
        if trusts:
            broad = [field for field, value in trusts if value in _UNRESTRICTED]
            if not broad:
                continue
            trust_state, trust_text = FactState.KNOWN, f"explicit {', '.join(broad)} admits every IPv4 source"
            trust_evidence = tuple(item for field in broad for item in fortios.field_evidence(path + (field,)))
        elif defaults_known:
            trust_state, trust_text = FactState.KNOWN, "no IPv4 trusthost is set; the documented 7.4.1+ default admits every IPv4 source"
            trust_evidence = ("trusthost absent: documented default 0.0.0.0 0.0.0.0",)
        else:
            record_path_not_assessed(fortios, ADMIN, f"{key}: trusthost is absent and the release default is not qualified.")
            continue

        mfa = _text(settings.get("two-factor")).casefold()
        if mfa in _MFA_METHODS:
            continue
        if mfa == "disable":
            mfa_text, mfa_evidence = "two-factor is explicitly disabled", tuple(fortios.field_evidence(path + ("two-factor",)))
        elif not mfa and defaults_known:
            mfa_text, mfa_evidence = "two-factor is absent; the documented 7.4.1+ default is disable", ("two-factor absent: documented default disable",)
        else:
            record_path_not_assessed(fortios, ADMIN, f"{key}: the second-factor state is not established.")
            continue

        global_settings, global_path = globals_.get(scope.casefold(), ({}, ("system global",)))
        threshold = _text(global_settings.get("admin-lockout-threshold"))
        duration = _text(global_settings.get("admin-lockout-duration"))
        weak = []
        if threshold.isdigit() and (int(threshold) == 0 or int(threshold) > 3):
            weak.append(f"threshold {threshold}")
        if duration.isdigit() and int(duration) < 60:
            weak.append(f"duration {duration} seconds")
        if not weak:
            continue  # explicit or documented default lockout (3 attempts, 60 seconds) is in place
        lockout_evidence = tuple(
            item for field in ("admin-lockout-threshold", "admin-lockout-duration")
            for item in fortios.field_evidence(global_path + (field,))
        )

        if remote_admins and _text(global_settings.get("admin-restrict-local")).casefold() in _LOCAL_RESTRICTED:
            record_path_not_assessed(
                fortios, ADMIN,
                f"{key}: admin-restrict-local limits local login to remote-server outages, which the export cannot show.",
            )
            continue
        ssh_password = _text(global_settings.get("admin-ssh-password")).casefold() != "disable"
        if not _external_role_known(fortios):
            record_path_not_assessed(
                fortios, ADMIN, f"{key}: no interface is classified external by the assessment policy.",
            )
            continue
        listeners = _admin_listeners(fortios, scope, ssh_password)
        if not listeners:
            continue
        names = {name.casefold() for name, _, _ in listeners}
        local_in = _local_in_on(fortios, None, names)
        if local_in:
            record_path_not_assessed(
                fortios, ADMIN,
                f"{key}: local-in policy {', '.join(sorted(local_in)[:3])} may filter administrative access; its effect is not evaluated.",
            )
            continue

        listener_evidence = tuple(item for _, _, ev in listeners for item in ev) + tuple(
            f"assessment policy: {name} role external" for name, _, _ in listeners
        )
        steps = (
            PathFact(
                "management-listener", f"{scope}/interface:{','.join(name for name, _, _ in listeners)}", scope, "ipv4",
                FactState.KNOWN,
                "Enabled external interface(s) "
                + "; ".join(f"{name} ({'/'.join(services).upper()})" for name, services, _ in listeners)
                + " accept password-capable administrative logins.",
                evidence_locations(listener_evidence),
            ),
            PathFact(
                "admin-source-restriction", key, scope, "ipv4", trust_state,
                f"Administrator '{username}': {trust_text}.", evidence_locations(trust_evidence),
                linked_findings(findings, ("fortinet.fortios.admin.trusted_hosts",), account_evidence),
            ),
            PathFact(
                "privileged-local-account", key, scope, "any", FactState.KNOWN,
                f"Administrator '{username}' is enabled, uses local password authentication and has privileged profile '{role.profile}'.",
                evidence_locations(account_evidence),
            ),
            PathFact(
                "second-factor", key, scope, "any", FactState.KNOWN,
                f"Administrator '{username}': {mfa_text}.", evidence_locations(mfa_evidence),
                linked_findings(findings, ("fortinet.fortios.admin.mfa",), account_evidence),
            ),
            PathFact(
                "lockout", f"{scope}/system-global", scope, "any", FactState.KNOWN,
                f"Administrative lockout is explicitly weakened ({', '.join(weak)}); the documented default is 3 attempts and 60 seconds.",
                evidence_locations(lockout_evidence),
                linked_findings(findings, ("fortinet.fortios.admin.lockout",),
                                lockout_evidence + tuple(fortios.field_evidence(global_path))),
            ),
        )
        record_path(fortios, PathResult(ADMIN, key, scope, "ipv4", steps))


def produce_sslvpn_paths(plugin, fortios: FortiOSParser) -> None:
    mark_evaluated(fortios, SSLVPN)
    findings = plugin.get_issues()
    users = list(fortios.get_sslvpn_password_only_users())
    for vpn in fortios.get_sslvpn_settings():
        scope = vpn["scope"]
        if not vpn["active"]:
            continue
        scope_users = [user for user in users if user.scope.casefold() == scope.casefold()]
        if not scope_users or vpn["values"]["login-attempt-limit"] != "0":
            continue  # absent limit is the documented default (2 attempts)
        if not vpn["source_addresses"]:
            record_path_not_assessed(
                fortios, SSLVPN, f"{scope}/sslvpn: source-address is not set; the release default is not qualified.",
            )
            continue
        if not (vpn["source_unrestricted"] and vpn["source_address_negated"] == "disable"):
            continue
        if not _external_role_known(fortios):
            record_path_not_assessed(fortios, SSLVPN, f"{scope}/sslvpn: no interface is classified external by the assessment policy.")
            continue
        down = {name.casefold() for name in vpn["configured_down_interfaces"]}
        external = sorted(
            name for name in vpn["interfaces"]
            if name.casefold() not in down and fortios.assessment_context.role_for_interface(name) == "external"
        )
        if not external:
            continue
        local_in = _local_in_on(fortios, {scope.casefold()}, {name.casefold() for name in external})
        if local_in:
            record_path_not_assessed(
                fortios, SSLVPN,
                f"{scope}/sslvpn: local-in policy {', '.join(sorted(local_in)[:3])} may filter the listener; its effect is not evaluated.",
            )
            continue
        listener_evidence = tuple(vpn["interface_evidence"]) + tuple(vpn["source_evidence"])
        limit_evidence = tuple(vpn["evidence"]["login-attempt-limit"])
        listener = PathFact(
            "sslvpn-listener", f"{scope}/sslvpn:{','.join(external)}", scope, "ipv4", FactState.KNOWN,
            f"Active SSL-VPN listens on external interface(s) {', '.join(external)} and its source-address covers every IPv4 address (negate disabled).",
            evidence_locations(listener_evidence + tuple(f"assessment policy: {name} role external" for name in external)),
            linked_findings(findings, ("fortinet.fortios.sslvpn.unrestricted_sources",), listener_evidence),
        )
        limit = PathFact(
            "sslvpn-login-limit", f"{scope}/sslvpn", scope, "any", FactState.KNOWN,
            "login-attempt-limit is explicitly 0, so failed logins are not limited.",
            evidence_locations(limit_evidence),
            linked_findings(findings, ("fortinet.fortios.sslvpn.unlimited_login_attempts",), limit_evidence),
        )
        for user in sorted(scope_users, key=lambda item: (item.username, item.auth_rule)):
            key = f"{scope}/sslvpn-user:{user.username}"
            binding = f"group '{user.group}'" if user.group else "a direct user mapping"
            account = PathFact(
                "password-only-user", key, scope, "any", FactState.KNOWN,
                (f"Authentication rule '{user.auth_rule}' maps enabled local user '{user.username}' through {binding}; "
                 "the user's second factor and client-certificate requirements are explicitly disabled."),
                evidence_locations(user.evidence),
                linked_findings(findings, ("fortinet.fortios.sslvpn.password_only_local_user",), user.evidence),
            )
            record_path(fortios, PathResult(SSLVPN, key, scope, "ipv4", (listener, limit, account)))


def produce_deny_shadow_paths(fortios: FortiOSParser, candidates) -> None:
    mark_evaluated(fortios, DENY)
    for candidate in candidates:
        deny, covering = candidate.deny, candidate.covering
        key = f"{deny.scope}/{deny.family}/policy:{deny.name}"
        link = ((candidate.finding.rule_id, candidate.finding.title),)
        allow = PathFact(
            "earlier-allow", f"{deny.scope}/{deny.family}/policy:{','.join(item.name for item in covering)}",
            deny.scope, deny.family, FactState.KNOWN,
            "Earlier enabled accept policy "
            + ", ".join(f"'{item.name}' (position {item.position})" for item in covering)
            + " statically covers the deny's interfaces, sources, destinations and services.",
            evidence_locations(item for policy in covering for item in policy.evidence),
            link,
        )
        later = PathFact(
            "defeated-deny", key, deny.scope, deny.family, FactState.KNOWN,
            f"Enabled deny policy '{deny.name}' at position {deny.position} is never reached under first-match evaluation.",
            evidence_locations(deny.evidence), link,
        )
        record_path(fortios, PathResult(DENY, key, deny.scope, deny.family, (allow, later)))


def produce_attack_paths(plugin, fortios: FortiOSParser, release, deny_shadows) -> None:
    produce_admin_paths(plugin, fortios, release)
    produce_sslvpn_paths(plugin, fortios)
    produce_deny_shadow_paths(fortios, deny_shadows)
