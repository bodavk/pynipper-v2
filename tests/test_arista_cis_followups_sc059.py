"""SC-059: CIS Arista EOS follow-ups."""

import contextlib
import io

from src.analyze.arista.core.process_arista_conf import process_arista_conf
from src.analyze.common.guidance import guidance_for
from src.devices.arista.eos import AristaEOSParser


def _rules(tmp_path, body):
    path = tmp_path / "eos.conf"
    path.write_text("! device: leaf (DCS-7050SX3-48YC8, EOS-4.29.2F)\nhostname leaf\n" + body, encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        return {f.rule_id: f for f in process_arista_conf(AristaEOSParser(str(path))).values()}


def test_syslog_tls_and_telnet(tmp_path):
    rules = _rules(tmp_path, "logging host 192.0.2.20\nmanagement telnet\n   no shutdown\n")
    assert "arista.eos.logging.remote_cleartext" in rules
    assert "arista.eos.management.insecure_protocol" in rules
    assert guidance_for("arista.eos.logging.remote_cleartext") and guidance_for("arista.eos.management.insecure_protocol")
    tls = _rules(tmp_path, "logging vrf MGMT host 192.0.2.20 protocol tls ssl-profile S\nmanagement telnet\n   shutdown\n")
    assert not {"arista.eos.logging.remote_cleartext", "arista.eos.management.insecure_protocol"} & set(tls)


def test_hygiene(tmp_path):
    rules = _rules(tmp_path, "")
    assert "CIS 1.2" in rules["arista.eos.hardening.cis_hygiene"].observation
    assert guidance_for("arista.eos.hardening.cis_hygiene")
    clean = _rules(tmp_path, "vrf instance MGMT\nip name-server vrf MGMT 192.0.2.53\nenable password sha512 $6$a$b\n"
                             "management security\n   password encryption reversible aes-256-gcm\n")
    assert "arista.eos.hardening.cis_hygiene" not in clean
