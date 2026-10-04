"""FortiOS explicit SHA-1 SSH host-key signature algorithm (7.4.1 config system global)."""

import contextlib
import io

from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import Severity
from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.devices import get_parser

RULE = "fortinet.fortios.ssh.weak_hostkey_algo"


def _run(tmp_path, line):
    path = tmp_path / "fgt.conf"
    path.write_text(
        "#config-version=FGT60F-7.4.4-FW-build1517-230606:opmode=0:vdom=0:user=admin\n"
        f"config system global\n    set hostname fw\n{line}end\n",
        encoding="utf-8",
    )
    with contextlib.redirect_stdout(io.StringIO()):
        findings = process_fortios_conf(get_parser("FORTIOS", str(path))).values()
    return [finding for finding in findings if finding.rule_id == RULE]


def test_explicit_ssh_rsa_hostkey(tmp_path):
    findings = _run(tmp_path, "    set ssh-hostkey-algo ssh-rsa rsa-sha2-512\n")
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert "ssh-rsa" in findings[0].observation
    assert guidance_for(RULE)


def test_default_and_modern_hostkeys_not_reported(tmp_path):
    assert not _run(tmp_path, "")
    assert not _run(tmp_path, "    set ssh-hostkey-algo rsa-sha2-512 ssh-ed25519\n")
