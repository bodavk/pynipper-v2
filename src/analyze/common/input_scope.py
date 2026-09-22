"""Conservative finding selection for unresolved deployment templates.

Only rules whose risky state is directly expressed by the template can remain
in a report. New rules are intentionally omitted until their evidence contract
is reviewed for incomplete input.
"""

_EXPLICIT_RULES = {
    "PAN_OS": frozenset({
        "paloalto.panos.management.telnet",
        "paloalto.panos.management.http",
        "paloalto.panos.policy.broad_allow",
        "paloalto.panos.policy.broad_service",
        "paloalto.panos.policy.disabled_permissive_rule",
        "paloalto.panos.ntp.authentication",
        "paloalto.panos.ntp.weak_algorithm",
        "paloalto.panos.credentials.password_history_disabled",
        "paloalto.panos.credentials.username_inclusion_allowed",
    }),
    "FORTIOS": frozenset({
        "fortinet.fortios.management.insecure_protocol",
        "fortinet.fortios.policy.broad_accept",
        "fortinet.fortios.tls.minimum_version",
        "fortinet.fortios.ntp.authentication",
        "fortinet.fortios.vpn.weak_proposal",
    }),
}


def select_template_findings(parser, findings):
    if not getattr(parser, "template_unresolved", False):
        return list(findings)
    allowed = _EXPLICIT_RULES.get(parser.device_type, frozenset())
    selected = []
    for finding in findings:
        explicit_update = (
            finding.rule_id == "paloalto.panos.updates.threat_content"
            and any("update-schedule threats" in evidence.text
                    for schedule in parser.get_update_schedules() if schedule.content_type == "threats"
                    for evidence in schedule.evidence)
        )
        if finding.rule_id in allowed or explicit_update:
            selected.append(finding)
        else:
            parser.template_suppressed_findings = getattr(parser, "template_suppressed_findings", 0) + 1
    return selected
