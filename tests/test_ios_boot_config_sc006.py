"""SC-006: explicit TFTP boot configuration on commissioned IOS devices."""

import json
import subprocess
import sys

import pytest

from src.analyze.cisco.ios.plugins.baseline_plugin import PluginIOSBaseline
from src.common.assessment import AssessmentContext
from src.devices.cisco.ios import CiscoIOSParser


RULE = "cisco.ios.services.tftp_boot_config"


def _scan(tmp_path, config, lifecycle="commissioned"):
    path = tmp_path / "router.conf"
    path.write_text(config, encoding="utf-8")
    parser = CiscoIOSParser(str(path))
    parser.set_assessment_context(AssessmentContext.from_mapping({
        "device_lifecycle": lifecycle,
    }))
    plugin = PluginIOSBaseline()
    plugin.check_boot_config_retrieval(parser)
    return parser, [item for item in plugin.get_issues() if item.rule_id == RULE]


def test_explicit_tftp_boot_config_on_commissioned_device(tmp_path):
    parser, findings = _scan(
        tmp_path, "version 17.9\nboot network tftp://example.invalid/private/syntheticsecret.cfg\n"
        "no service config\n",
    )
    retrieval = parser.get_explicit_boot_config_retrievals()[0]
    assert (retrieval.kind, retrieval.protocol) == ("network", "tftp")
    assert [item.rule_id for item in findings] == [RULE]
    assert "syntheticsecret" not in " ".join(item.text for item in retrieval.evidence)
    assert "syntheticsecret" not in " ".join(findings[0].evidence)


@pytest.mark.parametrize("config,lifecycle", [
    ("version 17.9\nboot network tftp:config.cfg\n", "unknown"),
    ("version 17.9\nboot network tftp:config.cfg\n", "provisioning"),
    ("version 17.9\nboot network tftp:config.cfg\nno boot network\n", "commissioned"),
    ("version 17.9\nboot network ftp://user:syntheticsecret@example.invalid/config.cfg\n", "commissioned"),
    ("version 12.2\nboot network tftp:config.cfg\n", "commissioned"),
    ("boot network tftp:config.cfg\n", "commissioned"),
    ("version 17.9\ncns config partial\n", "commissioned"),
])
def test_unqualified_cases_do_not_generate_findings(tmp_path, config, lifecycle):
    _, findings = _scan(tmp_path, config, lifecycle)
    assert findings == []


def test_ordered_target_removal_preserves_other_boot_source(tmp_path):
    parser, findings = _scan(
        tmp_path, "version 17.9\nboot host tftp:removed.cfg\nboot network tftp:active.cfg\n"
        "no boot host tftp:removed.cfg\n",
    )
    assert [(item.kind, item.protocol) for item in parser.get_explicit_boot_config_retrievals()] == [
        ("network", "tftp"),
    ]
    assert len(findings) == 1


def test_policy_lifecycle_validation_and_serialization():
    context = AssessmentContext.from_mapping({"device_lifecycle": "commissioned"})
    assert context.to_dict()["device-lifecycle"] == "commissioned"
    with pytest.raises(ValueError, match="device_lifecycle"):
        AssessmentContext.from_mapping({"device_lifecycle": "unsupported"})


def test_public_cli_uses_lifecycle_and_redacts_endpoint(tmp_path):
    config = tmp_path / "router.conf"
    config.write_text(
        "version 17.9\nhostname edge\nboot network tftp://example.invalid/syntheticsecret.cfg\n",
        encoding="utf-8",
    )
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"device_lifecycle": "commissioned"}), encoding="utf-8")
    report = tmp_path / "report.json"
    completed = subprocess.run(
        [sys.executable, "-m", "src.main", "-d", "IOS_XE", "-i", str(config),
         "-o", "JSON", "-f", str(report), "-x", "--assessment-policy", str(policy)],
        capture_output=True, text=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    rendered = report.read_text(encoding="utf-8")
    assert any(item["rule_id"] == RULE for item in json.loads(rendered)["security-audit"].values())
    assert "syntheticsecret" not in rendered + completed.stdout + completed.stderr
