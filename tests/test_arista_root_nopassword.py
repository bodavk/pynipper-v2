"""SC-030 EOS root account and password-less remote login (EOS User Security guide)."""

import contextlib
import io

import pytest

from src.analyze.arista.core.process_arista_conf import process_arista_conf
from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis, Severity
from src.devices.arista.eos import AristaEOSParser


def _run(tmp_path, body):
    path = tmp_path / "eos.conf"
    path.write_text("! device: leaf (DCS-7050SX3-48YC8, EOS-4.29.2F)\nhostname leaf\n" + body, encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        return list(process_arista_conf(AristaEOSParser(str(path))).values())


def _rules(findings, rule):
    return [finding for finding in findings if finding.rule_id == rule]


ROOT = "arista.eos.auth.root_login_enabled"
REMOTE = "arista.eos.auth.nopassword_remote_login"


def test_root_secret_redacted(tmp_path):
    findings = _rules(_run(tmp_path, "aaa root secret sha512 $6$abc$RootHash\n"), ROOT)
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert "RootHash" not in repr(findings[0])
    assert guidance_for(ROOT)


def test_root_nopassword_console(tmp_path):
    finding = _rules(_run(tmp_path, "aaa root nopassword\n"), ROOT)[0]
    assert "console" in finding.observation


@pytest.mark.parametrize("body", ["aaa root secret x\nno aaa root\n", ""])
def test_root_disabled(tmp_path, body):
    assert not _rules(_run(tmp_path, body), ROOT)


def test_nopassword_remote_login(tmp_path):
    body = "username ops nopassword\naaa authentication policy local allow-nopassword-remote-login\n"
    findings = _rules(_run(tmp_path, body), REMOTE)
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].basis is FindingBasis.EXPLICIT_VALUE
    assert "'ops'" in findings[0].observation
    assert guidance_for(REMOTE)


def test_nopassword_remote_login_needs_users(tmp_path):
    body = "username ops secret sha512 $6$a$b\naaa authentication policy local allow-nopassword-remote-login\n"
    assert not _rules(_run(tmp_path, body), REMOTE)
