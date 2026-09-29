"""SC-044: secondary-family defaults (Junos). Row IDs: docs/agent_notes/INSECURE_DEFAULTS_BY_RELEASE.md."""

import contextlib
import io

import pytest

from src.analyze.common.issue import FindingBasis
from src.analyze.juniper.junos.core.process_junos_conf import process_junos_conf
from src.devices import get_parser

BASE = "set version 21.4R3\nset system host-name r1\n"
KEY = 'set system root-authentication ssh-ed25519 "ssh-ed25519 AAAAC3NzaSecretKey root@admin"\n'


def _findings(tmp_path, text):
    path = tmp_path / "junos.conf"
    path.write_text(text, encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        return [f for f in process_junos_conf(get_parser("JUNOS", str(path))).values()
                if f.rule_id == "juniper.junos.ssh.root_login"]


@pytest.mark.parametrize("body,basis", [
    ("set system services ssh\n" + KEY, FindingBasis.DOCUMENTED_DEFAULT),
    ("set system services ssh\n", None),  # no root key: deny-password blocks root
    (KEY, None),  # SSH service off
    ("set system services ssh root-login deny\n" + KEY, None),
    ("set system services ssh root-login allow\n", FindingBasis.EXPLICIT_VALUE),
])
def test_junos_root_login_default(tmp_path, body, basis):  # JUN-01
    findings = _findings(tmp_path, BASE + body)
    assert (findings[0].basis if findings else None) is basis
    assert all("AAAAC3" not in " ".join(map(str, f.evidence)) for f in findings)


from src.analyze.paloalto.core.process_panos_conf import process_panos_conf  # noqa: E402


def _panos(tmp_path, phash):
    path = tmp_path / "panos.xml"
    path.write_text(
        '<config version="10.2.0"><mgt-config><users><entry name="admin">'
        f'<phash>{phash}</phash><permissions><role-based><superuser>yes</superuser></role-based>'
        '</permissions></entry></users></mgt-config></config>\n', encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        return [f for f in process_panos_conf(get_parser("PAN_OS", str(path))).values()
                if f.rule_id == "paloalto.panos.credentials.known_default_value"]


@pytest.mark.parametrize("phash,expected", [
    ("$1$pqrstuvw$/TZXoDOcsfgEmk0r6UsSQ/", True),  # crypt(3) MD5 of 'admin'
    ("$5$Zx9Yw8Vu7Ts6Rq5P$5CqTuRG3lTMKZo6yj5cBmslJDFAe5cAfy6bOvord5dC", True),
    ("$1$pqrstuvw$AAAAAAAAAAAAAAAAAAAAAA", False),
])
def test_panos_factory_admin_password(tmp_path, phash, expected):  # PAN-02
    findings = _panos(tmp_path, phash)
    assert bool(findings) is expected
    assert all(phash not in " ".join(map(str, f.evidence)) for f in findings)


from src.analyze.hp.core.process_hp_conf import process_hp_conf  # noqa: E402


@pytest.mark.parametrize("release,body,expected", [
    ("WC.16.04.0012", "", {"hp.procurve.management.telnet", "hp.procurve.management.http"}),
    ("WC.16.04.0012", "no telnet-server\nno web-management\n", set()),
    ("WC.16.03.0005", "", set()),  # no documented default for other trains
])
def test_aos_1604_service_defaults(tmp_path, release, body, expected):  # AOS-01
    path = tmp_path / "aos.conf"
    path.write_text(f"; J9772A Configuration Editor; Created on release #{release}\nhostname edge\n{body}", encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        found = {f.rule_id for f in process_hp_conf(get_parser("HP_PROCURVE", str(path))).values()
                 if f.rule_id in {"hp.procurve.management.telnet", "hp.procurve.management.http"}}
    assert found == expected
