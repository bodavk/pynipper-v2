"""PT-004: findings cite the configuration line behind their evidence."""

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from scripts.run_full_regression import CORPUS_ROOT, MANIFEST_PATH, PROCESSORS
from src.analyze.common.evidence_lines import attach_source_lines
from src.analyze.common.issue import EvidenceLocation, Finding
from src.common.assessment import AssessmentContext
from src.devices import get_parser
from src.devices.common.models import ConfigEvidence
from src.main import main


def _finding(*evidence):
    return Finding(
        rule_id="test.rule.condition",
        device="IOS_ROUTER",
        title="Title",
        observation="Observation",
        impact="Impact",
        recommendation="Recommendation",
        evidence=evidence,
    )


def test_config_evidence_keeps_parser_line_and_file_name():
    finding = _finding(ConfigEvidence("ip http server", "/tmp/dir/router.conf", 12), "absent")
    assert finding.evidence == ("ip http server", "absent")
    assert finding.evidence_locations == (
        EvidenceLocation("ip http server", 12, "router.conf", "parser"),
        EvidenceLocation("absent"),
    )
    assert finding.to_dict()["evidence_locations"] == [
        {"text": "ip http server", "line": 12, "source": "router.conf", "line_origin": "parser"},
        {"text": "absent", "line": None, "source": None, "line_origin": None},
    ]


@pytest.mark.parametrize("bad", ["", "   ", None, 3])
def test_invalid_evidence_is_rejected(bad):
    with pytest.raises(ValueError):
        _finding(bad)


def test_source_match_requires_exactly_one_identical_line(tmp_path):
    source = tmp_path / "router.conf"
    source.write_text(
        "hostname r1\nip http server\n line vty 0 4\nline vty 0 4\n"
        "snmp-server community <redacted> RO\n",
        encoding="utf-8",
    )
    parser = get_parser("IOS_ROUTER", str(source))
    findings = attach_source_lines(parser, [_finding(
        "ip http server",                       # unique -> located
        "line vty 0 4",                         # repeated -> not located
        "snmp-server community <redacted> RO",  # present verbatim -> located
        "ip ssh version 1",                     # absent -> not located
        ConfigEvidence("hostname r1", str(source), 1),
    )])
    lines = [(item.line_number, item.origin) for item in findings[0].evidence_locations]
    assert lines == [(2, "source-match"), (None, None), (5, "source-match"),
                     (None, None), (1, "parser")]


def test_multi_file_input_is_not_text_matched(tmp_path):
    parser = get_parser("CHECKPOINT_FW1", str(CORPUS_ROOT / "checkpoint_fw1" / "vulnerable"))
    assert parser.locate_source_line("anything") is None


def _corpus_findings():
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    for case in manifest["cases"]:
        parser = get_parser(case["device"], str(CORPUS_ROOT / case["input"]))
        if case.get("assessment_policy"):
            parser.set_assessment_context(AssessmentContext.from_mapping(case["assessment_policy"]))
        with redirect_stdout(io.StringIO()):
            findings = PROCESSORS[case["device"]](parser)
        yield case, Path(parser.config_filepath), list(findings.values())


def test_corpus_line_numbers_point_at_the_cited_configuration():
    located = total = 0
    for case, source, findings in _corpus_findings():
        for finding in findings:
            for location in finding.evidence_locations:
                total += 1
                if location.line_number is None:
                    continue
                located += 1
                path = source / location.source if source.is_dir() else source
                assert path.name == location.source, (case["name"], location)
                physical = path.read_text(encoding="utf-8-sig").split("\n")
                assert 1 <= location.line_number <= len(physical), (case["name"], location)
                line = physical[location.line_number - 1].strip()
                assert line, (case["name"], location)
                if location.origin == "source-match":
                    assert line == location.text
    # Most evidence is locatable. The rest is absence/derived statements.
    assert located / total > 0.75, (located, total)


@pytest.mark.parametrize(
    "case_name,rule_id,file_name",
    [
        ("checkpoint-fw1-vulnerable", "checkpoint.fw1.policy.broad_accept", "rules.C"),
        ("panos-vulnerable", "paloalto.panos.policy.broad_allow", "vulnerable.xml"),
        ("cisco-ios-vulnerable", "cisco.ios.http.cleartext_service", "vulnerable.conf"),
    ],
)
def test_structured_and_line_formats_are_located(case_name, rule_id, file_name):
    for case, _, findings in _corpus_findings():
        if case["name"] != case_name:
            continue
        locations = [
            location
            for finding in findings if finding.rule_id == rule_id
            for location in finding.evidence_locations
        ]
        assert locations and all(item.line_number for item in locations)
        assert {item.source for item in locations} == {file_name}
        return
    pytest.fail(f"corpus case {case_name} not found")


def test_reports_show_line_numbers(tmp_path):
    source = CORPUS_ROOT / "cisco_ios" / "vulnerable.conf"
    number = next(
        index for index, line in enumerate(source.read_text(encoding="utf-8").split("\n"), 1)
        if line.strip() == "ip http server"
    )
    html = tmp_path / "report.html"
    payload = tmp_path / "report.json"
    assert main(["-d", "cisco-ios", "-i", str(source), "-o", "HTML", "-f", str(html), "-x"]) == 0
    assert main(["-d", "cisco-ios", "-i", str(source), "-o", "JSON", "-f", str(payload), "-x"]) == 0
    assert f"Line {number} (vulnerable.conf):</strong> <code>ip http server</code>" in (
        html.read_text(encoding="utf-8")
    )
    issues = json.loads(payload.read_text(encoding="utf-8"))["security-audit"]
    http = next(item for item in issues.values() if item["rule_id"] == "cisco.ios.http.cleartext_service")
    assert http["evidence_locations"][0]["line"] == number
