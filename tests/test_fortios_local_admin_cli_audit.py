"""FortiOS admin-restrict-local and cli-audit-log (CLI reference 6.4.14-7.6.0 default disable)."""

import contextlib
import io

import pytest

from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis, Severity
from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.devices import get_parser

RESTRICT = "fortinet.fortios.admin.local_login_unrestricted"
AUDIT = "fortinet.fortios.cli.audit_disabled"
REMOTE_ADMIN = "    edit \"radius-admins\"\n        set remote-auth enable\n        set remote-group \"FortiAdmins\"\n        set wildcard enable\n    next\n"
LOCAL_ADMIN = "    edit \"breakglass\"\n        set accprofile \"super_admin\"\n        set password ENC SH2redacted\n    next\n"


def _run(tmp_path, global_settings="", admins=REMOTE_ADMIN + LOCAL_ADMIN, body="", version="7.4.4"):
    path = tmp_path / "fgt.conf"
    path.write_text(
        f"#config-version=FGT60F-{version}-FW-build1517-230606:opmode=0:vdom=0:user=admin\n"
        f"config system global\n    set hostname fw\n{global_settings}end\n"
        f"config system admin\n{admins}end\n{body}",
        encoding="utf-8",
    )
    with contextlib.redirect_stdout(io.StringIO()):
        return list(process_fortios_conf(get_parser("FORTIOS", str(path))).values())


def _rules(findings, rule):
    return [finding for finding in findings if finding.rule_id == rule]


def test_restrict_local_default(tmp_path):
    findings = _rules(_run(tmp_path), RESTRICT)
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].basis is FindingBasis.DOCUMENTED_DEFAULT
    assert "breakglass" in findings[0].observation
    assert guidance_for(RESTRICT)


def test_restrict_local_explicit_disable(tmp_path):
    findings = _rules(_run(tmp_path, "    set admin-restrict-local disable\n"), RESTRICT)
    assert findings[0].basis is FindingBasis.EXPLICIT_VALUE


@pytest.mark.parametrize("value", ["enable", "all", "non-console-only"])
def test_restrict_local_enabled(tmp_path, value):
    assert not _rules(_run(tmp_path, f"    set admin-restrict-local {value}\n"), RESTRICT)


@pytest.mark.parametrize("admins", [REMOTE_ADMIN, LOCAL_ADMIN])
def test_restrict_local_needs_both_kinds(tmp_path, admins):
    assert not _rules(_run(tmp_path, admins=admins), RESTRICT)


def test_restrict_local_old_release_absent_not_graded(tmp_path):
    assert not _rules(_run(tmp_path, version="6.4.13"), RESTRICT)


def test_cli_audit_default_without_remote_logging(tmp_path):
    findings = _rules(_run(tmp_path), AUDIT)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.MEDIUM
    assert finding.basis is FindingBasis.DOCUMENTED_DEFAULT
    assert "No enabled remote log destination" in finding.observation
    assert guidance_for(AUDIT)


def test_cli_audit_context_with_forwarding(tmp_path):
    body = (
        "config log syslogd setting\n    set status enable\n    set server 192.0.2.5\nend\n"
        "config log fortianalyzer setting\n    set status enable\nend\n"
        "config log fortianalyzer filter\n    set severity warning\nend\n"
    )
    finding = _rules(_run(tmp_path, "    set cli-audit-log disable\n", body=body), AUDIT)[0]
    assert finding.basis is FindingBasis.EXPLICIT_VALUE
    assert "forwards them to: syslogd" in finding.observation
    assert "fortianalyzer (filter severity warning)" in finding.observation


def test_cli_audit_context_eventfilter_disabled(tmp_path):
    body = "config log eventfilter\n    set system disable\nend\n"
    finding = _rules(_run(tmp_path, body=body), AUDIT)[0]
    assert "also not logged" in finding.observation


def test_cli_audit_enabled(tmp_path):
    assert not _rules(_run(tmp_path, "    set cli-audit-log enable\n"), AUDIT)
