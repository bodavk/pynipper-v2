"""SC-024 bounded stages: BIG-IP AFM default action and ASM enforcement on bound policies."""

import pytest

from src.analyze.common.issue import FindingBasis
from src.analyze.f5.core.process_bigip_conf import process_bigip_conf
from src.devices.f5.bigip import F5BIGIPParser

BASE = "#TMSH-VERSION: 16.1.5\nsys global-settings {\n    hostname bigip1\n}\n"
AFM = "sys provision afm {\n    level nominal\n}\n"
ASM = "sys provision asm {\n    level nominal\n}\n"
APP = (
    "ltm policy /Common/asm_auto_l7_policy__vs_web {\n    controls { asm }\n    requires { http }\n"
    "    rules {\n        default {\n            actions {\n                0 {\n"
    "                    asm\n                    request\n                    enable\n                    policy /Common/web_waf\n"
    "                }\n            }\n            ordinal 1\n        }\n    }\n    strategy /Common/first-match\n}\n"
    "ltm virtual /Common/vs_web {\n    destination /Common/192.0.2.10:443\n"
    "    policies {\n        /Common/asm_auto_l7_policy__vs_web { }\n    }\n}\n"
)


def _run(tmp_path, body):
    path = tmp_path / "bigip.scf"
    path.write_text(BASE + body, encoding="utf-8")
    parser = F5BIGIPParser(str(path))
    return {f.rule_id: f for f in process_bigip_conf(parser).values()
            if f.rule_id.startswith(("f5.bigip.afm", "f5.bigip.asm"))}


def test_afm_in_adc_mode_by_default(tmp_path):
    finding = _run(tmp_path, AFM)["f5.bigip.afm.default_accept"]
    assert finding.basis is FindingBasis.DOCUMENTED_DEFAULT


@pytest.mark.parametrize("value,expected", [("accept", True), ("drop", False), ("reject", False)])
def test_afm_explicit_default_action(tmp_path, value, expected):
    findings = _run(tmp_path, AFM + f'sys db tm.fw.defaultaction {{\n    value "{value}"\n}}\n')
    assert ("f5.bigip.afm.default_accept" in findings) is expected


def test_afm_not_provisioned_is_not_assessed(tmp_path):
    assert _run(tmp_path, "sys provision afm {\n    level none\n}\n") == {}


@pytest.mark.parametrize("policy,expected", [
    ("asm policy /Common/web_waf {\n    active\n    blocking-mode disabled\n}\n", "f5.bigip.asm.transparent_policy"),
    ("asm policy /Common/web_waf {\n    blocking-mode enabled\n}\n", "f5.bigip.asm.inactive_policy"),
    ("asm policy /Common/web_waf {\n    active\n    blocking-mode enabled\n}\n", None),
])
def test_asm_policy_bound_to_a_virtual(tmp_path, policy, expected):
    findings = _run(tmp_path, ASM + policy + APP)
    assert list(findings) == ([expected] if expected else [])


def test_asm_on_disabled_virtual_or_unattached_policy_is_not_assessed(tmp_path):
    policy = "asm policy /Common/web_waf {\n    active\n    blocking-mode disabled\n}\n"
    disabled = APP.replace("    destination /Common/192.0.2.10:443\n", "    destination /Common/192.0.2.10:443\n    disabled\n")
    assert _run(tmp_path, ASM + policy + disabled) == {}
    unattached = APP.split("ltm virtual")[0]
    assert _run(tmp_path, ASM + policy + unattached) == {}


def test_virtual_without_explicit_state_is_enabled_by_default(tmp_path):
    body = ("ltm profile client-ssl /Common/unsafe_ssl {\n    mode enabled\n    allow-non-ssl enabled\n}\n"
            "ltm virtual /Common/application {\n    destination /Common/192.0.2.100:443\n"
            "    profiles { /Common/unsafe_ssl { context clientside } }\n}\n")
    path = tmp_path / "bigip.scf"
    path.write_text(BASE + body, encoding="utf-8")
    rules = [f.rule_id for f in process_bigip_conf(F5BIGIPParser(str(path))).values()]
    assert "f5.bigip.ltm.clientssl_cleartext_enabled" in rules
