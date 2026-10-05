"""SC-049: per-control outcomes and manual-review coverage."""

import contextlib
import io
import json

import pytest

from src.analyze.arista.core.process_arista_conf import process_arista_conf
from src.analyze.cisco.ios.core.process_cisco_ios_conf import process_cisco_ios_conf
from src.analyze.common.controls import CONTROLS, ControlOutcome, control_coverage, record_control
from src.common.assessment import AssessmentContext
from src.devices import get_parser
from src.devices.arista.eos import AristaEOSParser
from src.main import main
from src.report.coverage import build_report_context

IOS_HEADER = "version 15.4\nhostname r1\n!\n"


def _ios(tmp_path, body, excluded=()):
    path = tmp_path / "r1.conf"
    path.write_text(IOS_HEADER + body + "end\n", encoding="utf-8")
    parser = get_parser("IOS_ROUTER", str(path))
    if excluded:
        parser.set_assessment_context(AssessmentContext.from_mapping({"excluded_categories": list(excluded)}))
    with contextlib.redirect_stdout(io.StringIO()):
        process_cisco_ios_conf(parser)
    return {item["control-id"]: item for item in build_report_context(parser)["coverage"]["controls"]["results"]}


@pytest.mark.parametrize("body,outcome", [
    ("vstack\n", "finding"),
    ("no vstack\n", "evaluated-no-finding"),
    ("", "unknown"),
])
def test_smart_install_outcomes(tmp_path, body, outcome):
    assert _ios(tmp_path, body)["cisco.ios.smart-install"]["outcome"] == outcome


def test_not_applicable_and_excluded(tmp_path):
    controls = _ios(tmp_path, "no vstack\n")
    assert controls["cisco.ios.ldap-transport"]["outcome"] == "not-applicable"
    excluded = _ios(tmp_path, "vstack\n", excluded=("services",))
    assert excluded["cisco.ios.smart-install"]["outcome"] == "excluded"


def test_only_applicable_controls_listed(tmp_path):
    controls = _ios(tmp_path, "no vstack\n")
    assert all(control_id.startswith("cisco.ios.") for control_id in controls)


def test_unsupported_with_manual_review_and_not_recorded(tmp_path):
    path = tmp_path / "eos.conf"
    path.write_text("! device: leaf (DCS-7050SX3-48YC8, EOS-4.29.2F)\nhostname leaf\n"
                    "interface Ethernet1\n   ip ospf area 0.0.0.0\nrouter ospf 1\n"
                    "   area 0.0.0.0 authentication message-digest\n", encoding="utf-8")
    parser = AristaEOSParser(str(path))
    with contextlib.redirect_stdout(io.StringIO()):
        process_arista_conf(parser)
    section = build_report_context(parser)["coverage"]["controls"]
    outcome = {item["control-id"]: item["outcome"] for item in section["results"]}
    assert outcome["arista.eos.ospf-authentication"] == "unsupported"
    assert section["manual-review"] and section["manual-review"][0]["feature"] == "OSPF area authentication"
    # A fresh parser that was never analysed reports controls as not recorded, never as passed.
    fresh = AristaEOSParser(str(path))
    assert {item["outcome"] for item in control_coverage(fresh)["results"]} == {"not-recorded"}


def test_precedence_and_registration(tmp_path):
    path = tmp_path / "r.conf"
    path.write_text(IOS_HEADER, encoding="utf-8")
    parser = get_parser("IOS_ROUTER", str(path))
    record_control(parser, "cisco.ios.pptp-dialin", ControlOutcome.NO_FINDING, "a")
    record_control(parser, "cisco.ios.pptp-dialin", ControlOutcome.FINDING, "b")
    record_control(parser, "cisco.ios.pptp-dialin", ControlOutcome.NO_FINDING, "c")
    result = {i["control-id"]: i for i in control_coverage(parser)["results"]}["cisco.ios.pptp-dialin"]
    assert result["outcome"] == "finding" and result["reasons"] == ["b"]
    with pytest.raises(KeyError):
        record_control(parser, "cisco.ios.unregistered", ControlOutcome.FINDING, "x")
    assert all(definition.rule_ids and definition.version >= 1 for definition in CONTROLS.values())


def test_public_pipeline_json_and_html(tmp_path):
    config = tmp_path / "r1.conf"
    config.write_text(IOS_HEADER + "vstack\nldap server DC1\n ipv4 192.0.2.30\n transport port 636\n"
                      " bind authenticate root-dn cn=svc password 0 BindPw1\n!\naaa new-model\n"
                      "aaa authentication login default group ldap local\nend\n", encoding="utf-8")
    report = tmp_path / "report.json"
    assert main(["-d", "IOS_ROUTER", "-i", str(config), "-o", "JSON", "-f", str(report), "-x"]) == 0
    data = json.loads(report.read_text(encoding="utf-8"))
    controls = data["coverage"]["controls"]
    assert controls["schema-version"] == 1
    assert {item["control-id"]: item["outcome"] for item in controls["results"]}["cisco.ios.ldap-transport"] == "unknown"
    assert "BindPw1" not in report.read_text(encoding="utf-8")
    html = tmp_path / "report.html"
    assert main(["-d", "IOS_ROUTER", "-i", str(config), "-o", "HTML", "-f", str(html), "-x"]) == 0
    text = html.read_text(encoding="utf-8")
    assert "Control outcomes" in text and "Configured features requiring manual review" in text
    assert "BindPw1" not in text
