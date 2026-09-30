"""SC-031: obsolete TLS minimum on bound FortiOS LDAP authentication."""

import json
import subprocess
import sys

import pytest

from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis
from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.devices.fortinet.fortios import FortiOSParser


RULE = "fortinet.fortios.aaa.ldap_weak_tls"


def _scan(tmp_path, *, secure="ldaps", minimum="TLSv1", bound=True):
    path = tmp_path / "fortios.conf"
    config = (
        "config user ldap\nedit corp\nset server 192.0.2.60\n"
        "set password private-example\n"
        + (f"set secure {secure}\n" if secure else "")
        + (f"set ssl-min-proto-version {minimum}\n" if minimum else "")
        + "next\nend\n"
        + ("config user group\nedit staff\nset member corp\nnext\nend\n" if bound else "")
    )
    path.write_text(config, encoding="utf-8")
    parser = FortiOSParser(str(path))
    findings = [item for item in process_fortios_conf(parser).values() if item.rule_id == RULE]
    return findings


@pytest.mark.parametrize("secure,minimum,bound,expected", [
    ("ldaps", "SSLv3", True, True),
    ("starttls", "TLSv1", True, True),
    ("ldaps", "TLSv1-1", True, True),
    ("ldaps", "TLSv1-2", True, False),
    ("ldaps", "TLSv1-3", True, False),
    ("ldaps", "default", True, False),
    ("ldaps", None, True, False),
    ("disable", "TLSv1", True, False),
    (None, "TLSv1", True, False),
    ("ldaps", "TLSv1", False, False),
])
def test_obsolete_tls_requires_bound_encrypted_ldap(
    tmp_path, secure, minimum, bound, expected
):
    findings = _scan(tmp_path, secure=secure, minimum=minimum, bound=bound)
    assert bool(findings) is expected
    if expected:
        assert findings[0].basis is FindingBasis.EXPLICIT_VALUE
        assert guidance_for(RULE) is not None
        assert "private-example" not in " ".join(findings[0].evidence)


@pytest.mark.parametrize("output_type", ["JSON", "HTML"])
def test_public_report_shows_weak_ldap_tls_without_secret(tmp_path, output_type):
    source = tmp_path / "fortios.conf"
    source.write_text(
        "config user ldap\nedit corp\nset server 192.0.2.60\n"
        "set password private-example\nset secure ldaps\n"
        "set ssl-min-proto-version TLSv1-1\nnext\nend\n"
        "config user group\nedit staff\nset member corp\nnext\nend\n",
        encoding="utf-8",
    )
    report = tmp_path / f"report.{output_type.lower()}"
    completed = subprocess.run(
        [sys.executable, "-m", "src.main", "-d", "FORTIOS", "-i", str(source),
         "-o", output_type, "-f", str(report), "-x"],
        capture_output=True, text=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    rendered = report.read_text(encoding="utf-8")
    assert "LDAP authentication permits an obsolete TLS version" in rendered
    assert "private-example" not in rendered + completed.stdout + completed.stderr
    if output_type == "JSON":
        payload = json.loads(rendered)
        assert any(item["rule_id"] == RULE for item in payload["security-audit"].values())
