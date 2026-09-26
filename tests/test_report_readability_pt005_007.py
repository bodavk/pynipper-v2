"""PT-005/006/007: readable report layout, layered explanations, related areas."""

import json
import re
from pathlib import Path

import pytest

from src.analyze.common.guidance import AREAS, guidance_for
from src.analyze.common.issue import Finding, Severity
from src.devices.common.models import ConfigEvidence
from src.main import main
from src.report.explanations import (
    NO_RELATED_FINDING, build_finding_views, json_security_audit, severity_tiles,
)
from src.report.report import _generate_html_report


ANALYZE_ROOT = Path(__file__).resolve().parents[1] / "src" / "analyze"
CORPUS = Path(__file__).parent / "test_data" / "regression"
RULE_LITERAL = re.compile(
    r'"((?:cisco|fortinet|juniper|checkpoint|paloalto|hp|arista|sonicwall|f5)\.[a-z0-9_.]+)"'
)
# Rule IDs assembled with f-strings in plugins, expanded to their known forms.
DYNAMIC_RULE_IDS = (
    "cisco.ios.console.session_timeout",
    "cisco.ios.tty.session_timeout",
    "cisco.ios.credentials.enable_storage",
    "cisco.ios.credentials.local_user_storage",
    "cisco.ios.routing.bgp.missing_prefix_list",
    "cisco.ios.routing.bgp.permit_all_route_map",
    "cisco.ios.routing.bgp.inbound_policy",
    "cisco.ios.discovery.cdp.external",
    "cisco.ios.layer2.access_edge.dot1x_open_access",
    "fortinet.fortios.crypto.strong_crypto",
    "fortinet.fortios.crypto.ssh_cbc_cipher",
    "fortinet.fortios.ssh.weak_enc_algo",
    "hp.procurve.layer2.access_edge.trunk",
    "arista.eos.routing.bgp.authentication",
    "arista.eos.routing.bgp.missing_route_map",
    "arista.eos.routing.bgp.permit_all_route_map",
    "arista.eos.routing.bgp.inbound_policy",
    "arista.eos.routing.bgp.outbound_policy",
    "arista.eos.routing.bgp.prefix_limit_disabled",
    "cisco.ios.credentials.tacacs_key_storage",
    "cisco.ios.credentials.isakmp_pre_shared_key_storage",
    "cisco.ios.credentials.keyring_pre_shared_key_storage",
    "cisco.asa.credentials.tunnel_group_pre_shared_key_storage",
    "cisco.asa.credentials.aaa_server_key_storage",
    "checkpoint.gaia.management.telnet",
    "checkpoint.gaia.snmp.default_community",
    "checkpoint.gaia.snmp.write_community",
    "checkpoint.gaia.snmp.legacy_version",
    "checkpoint.gaia.snmp.v3_security",
    "checkpoint.gaia.password_policy.lockout_disabled",
    "checkpoint.gaia.password_policy.history_disabled",
    "checkpoint.gaia.password_policy.complexity",
    "checkpoint.gaia.password_policy.minimum_length",
    "checkpoint.gaia.cli.idle_timeout_excessive",
    "checkpoint.gaia.banner.login_disabled",
    "juniper.junos.routing.bgp.inbound_policy",
    "juniper.junos.screen.syn_flood_inactive",
    "juniper.junos.screen.udp_flood_alarm_only",
    "juniper.junos.ssh.weak_ciphers",
    "paloalto.panos.management.http",
    "paloalto.panos.management.telnet",
)
F_STRING_RULE = re.compile(
    r'f"((?:cisco|fortinet|juniper|checkpoint|paloalto|hp|arista|sonicwall|f5)\.[^"]*)"'
)


def _source_rule_ids():
    ids = set(DYNAMIC_RULE_IDS)
    for path in ANALYZE_ROOT.rglob("*.py"):
        ids.update(RULE_LITERAL.findall(path.read_text(encoding="utf-8")))
    return ids


def test_every_f_string_rule_template_has_a_listed_expansion():
    for path in ANALYZE_ROOT.rglob("*.py"):
        for template in F_STRING_RULE.findall(path.read_text(encoding="utf-8")):
            placeholder = "PLACEHOLDER"
            pattern = re.escape(re.sub(r"\{[^}]*\}", placeholder, template))
            pattern = pattern.replace(placeholder, "[a-z0-9_.]+")
            assert any(re.fullmatch(pattern, rule) for rule in DYNAMIC_RULE_IDS), (path.name, template)


def test_every_rule_id_has_layered_guidance():
    missing = sorted(rule for rule in _source_rule_ids() if guidance_for(rule) is None)
    assert missing == []


def test_guidance_entries_and_areas_are_complete():
    for rule in _source_rule_ids():
        entry = guidance_for(rule)
        assert entry.area in AREAS
        for text in (entry.summary, entry.example, entry.technical, entry.verify):
            assert len(text.split()) >= 5, (rule, entry.key)
    for area in AREAS.values():
        assert area.related and area.key not in area.related
        assert set(area.related) <= set(AREAS)


@pytest.mark.parametrize(
    "rule_id,key",
    [
        ("fortinet.fortios.policy.broad_accept", "policy-broad"),
        ("checkpoint.fw1.policy.shadowed_rule", "policy-hygiene"),
        ("cisco.ios.vty.telnet", "management-cleartext"),
        ("cisco.ios.ssh.authentication_retries", "lockout"),
        ("cisco.ios.vty.session_timeout", "session-timeout"),
        ("juniper.junos.ssh.root_login", "authentication-missing"),
        ("hp.procurve.snmp.default_community", "snmp-community"),
        ("paloalto.panos.updates.threat_content", "threat-inspection"),
        ("juniper.junos.routing.bgp.prefix_limit", "bgp-policy"),
        ("fortinet.fortios.dos.logging", "logging"),
        ("cisco.ios.credentials.known_default_value", "credentials-default"),
        ("f5.bigip.password_policy.login_lockout_disabled", "lockout"),
    ],
)
def test_representative_rules_map_to_the_intended_explanation(rule_id, key):
    assert guidance_for(rule_id).key == key


def _finding(rule_id, severity, title, line=None):
    evidence = (ConfigEvidence(f"evidence for {title}", "/tmp/device.conf", line),) if line else (
        f"evidence for {title}",
    )
    return Finding(
        rule_id=rule_id,
        device="FORTIOS",
        title=title,
        observation=f"Observation <b>{title}</b>",
        impact="Impact",
        recommendation="Recommendation",
        severity=severity,
        exploitability="Exploitability",
        evidence=evidence,
        references=("https://example.com/guide",),
    )


def _issues():
    return {
        "2.0.0. Logging": _finding("fortinet.fortios.logging.missing", Severity.MEDIUM, "No remote logging"),
        "2.0.1. Broad": _finding("fortinet.fortios.policy.broad_accept", Severity.CRITICAL, "Broad policy", 12),
        "2.0.2. Banner": _finding("fortinet.fortios.admin.login_banner", Severity.LOW, "No banner"),
        "2.0.3. Telnet": _finding("fortinet.fortios.management.insecure_protocol", Severity.HIGH, "Telnet on"),
    }


def test_views_are_severity_ordered_with_related_findings_and_explicit_gaps():
    views = build_finding_views(_issues())
    assert [view["finding"].title for view in views] == [
        "Broad policy", "Telnet on", "No remote logging", "No banner",
    ]
    assert [view["anchor"] for view in views] == [f"finding-{n}" for n in range(1, 5)]
    broad = views[0]
    related = {item["area"]: item for item in broad["related"]}
    assert set(related) == set(AREAS["traffic-policy"].related)
    assert [other["title"] for other in related["logging-audit"]["findings"]] == ["No remote logging"]
    assert related["logging-audit"]["note"] is None
    assert related["threat-inspection"]["findings"] == []
    assert related["threat-inspection"]["note"] == NO_RELATED_FINDING
    for view in views:
        for item in view["related"]:
            assert all(other["key"] != view["key"] for other in item["findings"])


def test_severity_tiles_include_zero_counts_in_order():
    tiles = severity_tiles(_issues())
    assert [(tile["name"], tile["count"]) for tile in tiles] == [
        ("critical", 1), ("high", 1), ("medium", 1), ("low", 1), ("informational", 0),
    ]


def test_json_adds_guidance_and_related_areas_without_changing_finding_fields():
    issues = _issues()
    audit = json_security_audit(issues)
    assert list(audit) == list(issues)
    for key, finding in issues.items():
        record = audit[key]
        base = finding.to_dict()
        assert {name: record[name] for name in base} == base
        assert record["guidance"]["summary"]
        assert record["guidance"]["area-title"] == AREAS[record["guidance"]["area"]].title
        assert record["related-areas"]


def _data():
    return {"device-type": "FORTIOS", "hostname": "edge"}


def test_html_layout_orders_by_severity_and_explains_each_finding(tmp_path):
    output = tmp_path / "report.html"
    _generate_html_report(str(output), _issues(), [], _data())
    html = output.read_text(encoding="utf-8")
    positions = [html.index(f'id="finding-{n}"') for n in range(1, 5)]
    assert positions == sorted(positions)
    card = html[positions[0]:positions[1]]
    for heading in ("What was found", "Why it matters", "How it could be abused", "How to fix",
                    "Evidence in the configuration", "Also check", "Technical background"):
        assert heading in card
    assert "In plain terms:" in card and "Example:" in card
    assert '<td class="line">Line 12</td>' in card
    assert 'href="#finding-3"' in card  # related logging finding
    assert NO_RELATED_FINDING.split(":")[0] in card
    assert "Observation &lt;b&gt;Broad policy&lt;/b&gt;" in card
    assert "<b>Broad policy</b>" not in html
    # Filter buttons only for severities present; tiles for all levels.
    assert 'data-filter="critical">Critical (1)' in html
    assert 'data-filter="informational">' not in html.split('class="filters"')[1].split("</div>")[0]
    # The first priority action links to the first (most severe) finding.
    fix_first = html.split("Fix first")[1].split("</ol>")[0]
    assert 'href="#finding-1">Broad policy</a>' in fix_first


def test_html_without_findings_keeps_the_scope_warning(tmp_path):
    output = tmp_path / "empty.html"
    _generate_html_report(str(output), {}, [], _data())
    html = output.read_text(encoding="utf-8")
    assert "does not mean every control passed" in html
    assert 'id="finding-1"' not in html


def test_public_cli_json_and_html_include_explanations(tmp_path):
    source = CORPUS / "fortios" / "vulnerable.conf"
    html, payload = tmp_path / "r.html", tmp_path / "r.json"
    assert main(["-d", "fortios", "-i", str(source), "-o", "HTML", "-f", str(html), "-x"]) == 0
    assert main(["-d", "fortios", "-i", str(source), "-o", "JSON", "-f", str(payload), "-x"]) == 0
    audit = json.loads(payload.read_text(encoding="utf-8"))["security-audit"]
    assert all(item["guidance"] for item in audit.values())
    rendered = html.read_text(encoding="utf-8")
    assert rendered.count('class="finding sev-') == len(audit)
    assert "regression-secret" not in rendered


def test_parse_error_report_shows_a_prominent_warning(tmp_path):
    source = tmp_path / "broken.conf"
    source.write_text('config system global\nset hostname "open\n', encoding="utf-8")
    output = tmp_path / "broken.html"
    assert main(["-d", "fortios", "-i", str(source), "-o", "HTML", "-f", str(output), "-x"]) == 2
    html = output.read_text(encoding="utf-8")
    assert "could not be parsed completely" in html
    assert "does not mean every control passed" in html
