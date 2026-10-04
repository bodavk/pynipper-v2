"""SC-037 FortiOS SNMPv1/v2c trap targets (documented defaults per the 7.4.1 CLI reference)."""

import contextlib
import io

import pytest

from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis, Severity
from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.devices import get_parser

RULE = "fortinet.fortios.snmp.legacy_version"


def _community(host="set ip 10.0.0.5 255.255.255.255", extra="", host_extra=""):
    return (
        "config system snmp sysinfo\n    set status enable\nend\n"
        "config system snmp community\n    edit 1\n        set name \"trapcomm\"\n"
        f"        config hosts\n            edit 1\n                {host}\n{host_extra}"
        "            next\n        end\n"
        f"{extra}    next\nend\n"
    )


def _run(tmp_path, body, interface=""):
    path = tmp_path / "fgt.conf"
    path.write_text(
        "#config-version=FGT60F-7.4.4-FW-build1517-230606:opmode=0:vdom=0:user=admin\n"
        "config system global\n    set hostname fw\nend\n" + interface + body,
        encoding="utf-8",
    )
    with contextlib.redirect_stdout(io.StringIO()):
        findings = process_fortios_conf(get_parser("FORTIOS", str(path))).values()
    return [finding for finding in findings if finding.rule_id == RULE]


def test_default_trap_target_is_documented_default(tmp_path):
    findings = _run(tmp_path, _community())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.MEDIUM
    assert finding.basis is FindingBasis.DOCUMENTED_DEFAULT
    assert "v1/v2c" in finding.observation
    assert guidance_for(RULE)
    assert "trapcomm" not in repr(finding)


def test_explicit_trap_status(tmp_path):
    extra = "        set trap-v1-status disable\n        set trap-v2c-status enable\n"
    findings = _run(tmp_path, _community(extra=extra))
    assert findings[0].basis is FindingBasis.EXPLICIT_VALUE
    assert "v2c traps" in findings[0].observation


@pytest.mark.parametrize("extra,host,host_extra", [
    ("        set trap-v1-status disable\n        set trap-v2c-status disable\n",
     "set ip 10.0.0.5 255.255.255.255", ""),
    ("", "set ip 10.0.0.0 255.255.255.0", ""),
    ("", "set ip 10.0.0.5 255.255.255.255", "                set host-type query\n"),
    ("        set status disable\n", "set ip 10.0.0.5 255.255.255.255", ""),
])
def test_no_trap_finding(tmp_path, extra, host, host_extra):
    assert not _run(tmp_path, _community(host=host, extra=extra, host_extra=host_extra))


def test_agent_disabled_suppresses(tmp_path):
    body = _community().replace("set status enable\nend", "set status disable\nend", 1)
    assert not _run(tmp_path, body)


def test_polled_scope_left_to_legacy_community(tmp_path):
    interface = ("config system interface\n    edit \"port1\"\n        set ip 192.0.2.1 255.255.255.0\n"
                 "        set allowaccess ping snmp\n    next\nend\n")
    assert not _run(tmp_path, _community(), interface)
