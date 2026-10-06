"""Baseline trusthost syntax shares parser validation, not path eligibility."""
import json
import socket

import pytest

from src.analyze.common.controls import control_coverage
from src.analyze.common.issue import FindingBasis
from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.devices.fortinet.fortios import FortiOSParser
from src.main import main
from src.common.assessment import AssessmentContext

CONTROL = "fortinet.fortios.admin-trusted-hosts"
RULE = "fortinet.fortios.admin.trusted_hosts"
HEADER = "#config-version=FGT100F-7.4.4-FW-build0001-240101:opmode=0:vdom=0:user=admin\n"


def account(name="admin", selectors="", role="super_admin", extra=""):
    return f'edit "{name}"\nset accprofile "{role}"\n{selectors}\n{extra}\nnext\n'


def analyze(tmp_path, body):
    source = tmp_path / "synthetic.conf"
    source.write_text(HEADER + body, encoding="utf-8")
    parser = FortiOSParser(str(source))
    findings = list(process_fortios_conf(parser).values())
    result = next(r for r in control_coverage(parser)["results"] if r["control-id"] == CONTROL)
    return parser, findings, result


@pytest.mark.parametrize("selectors,outcome,finding", [
    ("set ip6-trusthost1 2001:db8:::1/64", "unknown", False),
    ("set trusthost1 not-an-ip 255.255.255.0", "unknown", False),
    ("set trusthost1 192.0.2.1 255.0.255.0", "unknown", False),
    ("set trusthost1 192.0.2.1 0.0.0.255", "unknown", False),
    ("set trusthost1 192.0.2.1/0.0.0.255", "unknown", False),
    ("set trusthost1 192.0.2.1/33", "unknown", False),
    ("set ip6-trusthost1 2001:db8::/129", "unknown", False),
    ("set ip6-trusthost1 192.0.2.0/24", "unknown", False),
    ("set trusthost1 2001:db8::/64", "unknown", False),
    ("set ip6-trusthost11 2001:db8::/64", "unknown", False),
    ("set trusthost0 192.0.2.0 255.255.255.0", "unknown", False),
    ("set trusthost1 192.0.2.0 255.255.255.0", "evaluated-no-finding", False),
    ("set ip6-trusthost1 2001:db8::/64", "evaluated-no-finding", False),
    ("set trusthost1 0.0.0.0 0.0.0.0", "finding", True),
    ("set ip6-trusthost1 ::/0", "finding", True),
    ("", "finding", True),
    ("set trusthost1 192.0.2.0 255.255.255.0\nset ip6-trusthost1 bad", "unknown", False),
    ("set trusthost1 0.0.0.0 0.0.0.0\nset ip6-trusthost1 bad", "finding", True),
    ("set ip6-trusthost1 bad\nset ip6-trusthost1 2001:db8::/64", "evaluated-no-finding", False),
    ("set ip6-trusthost1 2001:db8::/64\nunset ip6-trusthost1", "finding", True),
])
def test_selector_syntax_and_effective_mutations(tmp_path, selectors, outcome, finding):
    parser, findings, result = analyze(tmp_path, "config system admin\n" + account(selectors=selectors) + "end\n")
    assert result["outcome"] == outcome
    matches = [f for f in findings if f.rule_id == RULE]
    assert bool(matches) == finding
    if outcome == "unknown" or ("bad" in selectors and finding):
        assert result["unassessed-instance-count"] == 1
    if finding:
        assert matches[0].basis == (FindingBasis.EXPLICIT_VALUE if "set " in selectors and "unset " not in selectors else FindingBasis.REQUIRED_SETTING_MISSING)
    if outcome == "evaluated-no-finding":
        reason = " ".join(result["reasons"])
        assert ("IPv6" if "ip6-trusthost" in selectors else "IPv4") in reason


@pytest.mark.parametrize("role,extra,outcome", [
    ("read_only", "", "not-applicable"),
    ("missing", "", "unknown"),
    ("super_admin", "set status disable", "not-applicable"),
    ("super_admin", "set remote-auth enable\nset remote-group ADMINS", "unknown"),
])
def test_privilege_and_remote_gates_unchanged(tmp_path, role, extra, outcome):
    _, findings, result = analyze(tmp_path, "config system admin\n" + account(selectors="set ip6-trusthost1 bad", role=role, extra=extra) + "end\n")
    assert result["outcome"] == outcome
    assert not any(f.rule_id == RULE for f in findings)


def test_account_and_vdom_isolation_retains_mixed_unknown(tmp_path):
    body = ""
    for scope, selectors in (("tenant-a", "set ip6-trusthost1 bad"), ("tenant-b", "")):
        body += f'config vdom\nedit {scope}\nconfig system admin\n' + account(selectors=selectors) + "end\nnext\nend\n"
    _, findings, result = analyze(tmp_path, body)
    assert result["outcome"] == "finding" and result["unassessed-instance-count"] == 1
    assert result["unassessed-instances"][0]["instance-key"] == "tenant-a/admin"
    assert len([f for f in findings if f.rule_id == RULE]) == 1


def test_exclusions_and_typed_parser_origins_do_not_change_other_checks(tmp_path):
    parser, findings, _ = analyze(tmp_path, "config system admin\n" + account(selectors="set ip6-trusthost1 bad") + "end\n")
    scope, name, settings, path = next(parser.iter_administrators())
    record = parser.get_admin_trusted_hosts(scope, name, settings, path)
    assert (record.scope, record.administrator) == ("root", "admin")
    assert record.selectors[0].origin == "malformed" and record.selectors[0].family == "ipv6"
    assert record.selectors[0].evidence[0].line_number > 0
    assert any(f.rule_id == "fortinet.fortios.admin.mfa" for f in findings)
    parser.set_assessment_context(AssessmentContext.from_mapping({"excluded_categories": ["admin"]}))
    assert next(r for r in control_coverage(parser)["results"] if r["control-id"] == CONTROL)["outcome"] == "excluded"


@pytest.mark.parametrize("format", ["JSON", "HTML"])
def test_public_malformed_value_unknown_offline_redacted(tmp_path, monkeypatch, format):
    def forbidden(*args, **kwargs):
        raise AssertionError("Network access during an offline audit")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    source, output = tmp_path / "f.conf", tmp_path / f"report.{format.lower()}"
    source.write_text(HEADER + "config system admin\n" + account(selectors="set ip6-trusthost1 2001:db8:::1/64", extra="set password HiddenAdminSecret") + "end\n", encoding="utf-8")
    assert main(["-d", "FORTIOS", "-i", str(source), "-o", format, "-f", str(output)]) == 0
    report = output.read_text(encoding="utf-8")
    assert "HiddenAdminSecret" not in report
    assert "Malformed" in report
    if format == "JSON":
        data = json.loads(report)
        assert not any(f["rule_id"] == RULE for f in data["security-audit"].values())
        assert next(r for r in data["coverage"]["controls"]["results"] if r["control-id"] == CONTROL)["outcome"] == "unknown"


# --- omitted trusted-host family (maintainer rule: omitted setting, documented 7.4.1+ default) ---

def interface(ipv4_access="https ssh", ipv6_access="", status=""):
    v6 = (f'config ipv6\nset ip6-address 2001:db8::1/64\nset ip6-allowaccess {ipv6_access}\nend\n'
          if ipv6_access else "")
    return ('config system interface\nedit "port1"\nset ip 192.0.2.1 255.255.255.0\n'
            f'set allowaccess {ipv4_access}\n{status}\n{v6}next\nend\n')


def run(tmp_path, selectors, iface, header=HEADER):
    source = tmp_path / "omitted.conf"
    source.write_text(header + iface + "config system admin\n" + account(selectors=selectors) + "end\n",
                      encoding="utf-8")
    parser = FortiOSParser(str(source))
    findings = [f for f in process_fortios_conf(parser).values() if f.rule_id == RULE]
    result = next(r for r in control_coverage(parser)["results"] if r["control-id"] == CONTROL)
    return findings, result


def test_ipv4_only_restriction_with_ipv6_admin_access_is_a_documented_default_finding(tmp_path):
    findings, result = run(tmp_path, "set trusthost1 192.0.2.0 255.255.255.0", interface(ipv6_access="https ssh"))
    [finding] = findings
    assert finding.basis == FindingBasis.DOCUMENTED_DEFAULT
    assert "no ip6-trusthost is configured" in finding.observation and "::/0" in finding.observation
    assert "port1" in finding.observation
    assert result["outcome"] == "finding"


def test_ipv6_only_restriction_with_ipv4_admin_access_is_a_finding(tmp_path):
    findings, result = run(tmp_path, "set ip6-trusthost1 2001:db8::/64", interface(ipv6_access="https"))
    [finding] = findings
    assert "no trusthost is configured" in finding.observation and "0.0.0.0 0.0.0.0" in finding.observation


def test_ipv4_only_restriction_without_ipv6_admin_access_has_no_finding(tmp_path):
    findings, result = run(tmp_path, "set trusthost1 192.0.2.0 255.255.255.0", interface(ipv6_access="ping"))
    assert findings == []
    assert result["outcome"] == "evaluated-no-finding"
    assert "no interface allows administration in an omitted family" in " ".join(result["reasons"])


def test_down_interface_is_not_an_omitted_family_listener(tmp_path):
    findings, result = run(tmp_path, "set trusthost1 192.0.2.0 255.255.255.0",
                           interface(ipv6_access="https", status="set status down"))
    assert findings == [] and result["outcome"] == "evaluated-no-finding"


def test_omitted_family_default_before_741_is_unknown(tmp_path):
    old = "#config-version=FGT100F-7.2.8-FW-build0001-240101:opmode=0:vdom=0:user=admin\n"
    findings, result = run(tmp_path, "set trusthost1 192.0.2.0 255.255.255.0", interface(ipv6_access="https"), header=old)
    assert findings == []
    assert result["outcome"] == "unknown"
    assert "7.4.1" in " ".join(result["reasons"])


def test_both_families_restricted_has_no_finding(tmp_path):
    findings, result = run(tmp_path, "set trusthost1 192.0.2.0 255.255.255.0\nset ip6-trusthost1 2001:db8::/64",
                           interface(ipv6_access="https ssh"))
    assert findings == [] and result["outcome"] == "evaluated-no-finding"
