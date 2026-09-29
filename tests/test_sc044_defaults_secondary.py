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
