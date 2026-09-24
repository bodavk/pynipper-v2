"""SC-006 CNS stage: unencrypted CNS configuration retrieval on commissioned IOS devices."""

import json

import pytest

from src.analyze.cisco.ios.plugins.baseline_plugin import PluginIOSBaseline
from src.common.assessment import AssessmentContext
from src.devices.cisco.ios import CiscoIOSParser
from src.main import main

RULE = "cisco.ios.services.cns_config_cleartext"


def _scan(tmp_path, config, lifecycle="commissioned"):
    path = tmp_path / "router.conf"
    path.write_text("version 17.9\nhostname r1\n" + config, encoding="utf-8")
    parser = CiscoIOSParser(str(path))
    parser.set_assessment_context(AssessmentContext.from_mapping({"device_lifecycle": lifecycle}))
    plugin = PluginIOSBaseline()
    plugin.check_boot_config_retrieval(parser)
    return parser, [item for item in plugin.get_issues() if item.rule_id == RULE]


@pytest.mark.parametrize(
    "command,kind",
    [
        ("cns config initial cns.example.invalid 80 no-persist", "cns initial"),
        ("cns config partial 192.0.2.50", "cns partial"),
    ],
)
def test_unencrypted_cns_agent_is_reported_without_endpoint(tmp_path, command, kind):
    parser, findings = _scan(tmp_path, command + "\n")
    finding, = findings
    assert kind in finding.observation
    rendered = " ".join(finding.evidence)
    assert "cns.example.invalid" not in rendered and "192.0.2.50" not in rendered
    assert finding.evidence_locations[0].line_number == 3
    assert parser.get_cns_config_retrievals()[0].protocol == "http"


@pytest.mark.parametrize(
    "config",
    [
        "cns config partial 192.0.2.50 encrypt 443\n",
        "cns config initial 192.0.2.50\nno cns config initial\n",
        "cns event 192.0.2.50\n",  # unrelated CNS token
        "",
    ],
)
def test_encrypted_removed_or_unrelated_cns_is_not_reported(tmp_path, config):
    assert _scan(tmp_path, config)[1] == []


@pytest.mark.parametrize("lifecycle", ["unknown", "provisioning"])
def test_provisioning_or_unknown_lifecycle_is_not_graded(tmp_path, lifecycle):
    assert _scan(tmp_path, "cns config partial 192.0.2.50\n", lifecycle)[1] == []


def test_public_cli_reports_cns_on_commissioned_device(tmp_path):
    source = tmp_path / "router.conf"
    source.write_text("version 17.9\nhostname r1\ncns config partial 192.0.2.50\n", encoding="utf-8")
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"device_lifecycle": "commissioned"}), encoding="utf-8")
    report = tmp_path / "report.json"
    assert main(["-d", "cisco-ios", "-i", str(source), "-o", "JSON", "-f", str(report), "-x",
                 "--assessment-policy", str(policy)]) == 0
    text = report.read_text(encoding="utf-8")
    assert RULE in {item["rule_id"] for item in json.loads(text)["security-audit"].values()}
    assert "192.0.2.50" not in text
