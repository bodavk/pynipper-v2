"""SC-036 ASA URL credentials and Auto Update Server verification (ASA command reference)."""

import contextlib
import io

import pytest

from src.analyze.cisco.asa.core.process_asa_conf import process_asa_conf
from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis, Severity
from src.devices import get_parser


def _run(tmp_path, body, version="9.16(4)"):
    path = tmp_path / "asa.conf"
    path.write_text(f"ASA Version {version}\nhostname fw\n{body}", encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        return list(process_asa_conf(get_parser("ASA", str(path))).values())


def _rules(findings, rule):
    return [finding for finding in findings if finding.rule_id == rule]


def test_url_credentials_redacted(tmp_path):
    body = "auto-update server https://upd:S3cret@192.0.2.5/aus verify-certificate\n"
    findings = _run(tmp_path, body)
    urls = _rules(findings, "cisco.asa.credentials.url_storage")
    assert len(urls) == 1 and "S3cret" not in repr(urls[0])
    assert not _rules(findings, "cisco.asa.update.server_unverified")
    assert guidance_for("cisco.asa.credentials.url_storage")


@pytest.mark.parametrize("line,version,basis", [
    ("auto-update server http://192.0.2.5/aus\n", "9.16(4)", FindingBasis.EXPLICIT_VALUE),
    ("auto-update server https://192.0.2.5/aus no-verification\n", "9.16(4)", FindingBasis.EXPLICIT_VALUE),
    ("auto-update server https://192.0.2.5/aus\n", "9.1(7)", FindingBasis.DOCUMENTED_DEFAULT),
])
def test_unverified_update_server(tmp_path, line, version, basis):
    findings = _rules(_run(tmp_path, line, version), "cisco.asa.update.server_unverified")
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH and findings[0].basis is basis
    assert guidance_for("cisco.asa.update.server_unverified")


def test_default_verification_on_modern_release(tmp_path):
    assert not _rules(_run(tmp_path, "auto-update server https://192.0.2.5/aus\n"), "cisco.asa.update.server_unverified")
