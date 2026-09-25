"""--show-secrets: additional secret types (IOS/EOS family, ASA) and PAN-OS support."""

import json
from pathlib import Path

import pytest

from src.devices import get_parser
from src.main import main
from src.report.secret_evidence import collect_secret_evidence

IOS = """version 17.9
hostname r1
snmp-server community PublicSecret RO
snmp-server community RemovedSecret RW
no snmp-server community RemovedSecret
snmp-server group G v3 priv
snmp-server user U1 G v3 auth sha AuthSecret1 priv aes 128 PrivSecret1
ntp authentication-key 1 md5 NtpSecret1
ntp trusted-key 1
ntp authenticate
ntp server 192.0.2.1 key 1
ntp authentication-key 9 md5 UnusedNtpSecret
interface GigabitEthernet0/0
 ip address 192.0.2.10 255.255.255.0
 ip ospf message-digest-key 1 md5 OspfSecret1
 ip ospf authentication message-digest
 ip ospf 1 area 0
router ospf 1
router bgp 65001
 neighbor 198.51.100.1 remote-as 65002
 neighbor 198.51.100.1 password BgpSecret1
"""

ASA = """ASA Version 9.18(4)
hostname edge
ntp authentication-key 1 md5 NtpSecret1
ntp trusted-key 1
ntp authenticate
ntp server 192.0.2.1 key 1 source inside
snmp-server group G v3 priv
snmp-server user U1 G v3 auth sha AuthSecret1 priv aes 128 PrivSecret1
snmp-server host inside 192.0.2.9 community CommSecret1 version 2c
snmp-server community CommSecret2
snmp-server community RemovedSecret
no snmp-server community RemovedSecret
"""

PAN = """<config version="11.1">
<mgt-config><users><entry name="admin">
<phash>$5$synthetic$PanHashSecret</phash>
</entry></users></mgt-config>
<devices><entry name="localhost.localdomain"><deviceconfig><system>
<hostname>pa</hostname>
<snmp-setting><access-setting><version><v2c>
<snmp-community-string>PanCommunitySecret</snmp-community-string>
</v2c></version></access-setting></snmp-setting>
<ntp-servers><primary-ntp-server><ntp-server-address>192.0.2.1</ntp-server-address>
<authentication-type><symmetric-key><algorithm><sha1>
<authentication-key>PanNtpSecret</authentication-key>
</sha1></algorithm></symmetric-key></authentication-type></primary-ntp-server></ntp-servers>
</system></deviceconfig>
<network><ike><gateway><entry name="gw1"><authentication><pre-shared-key>
<key>PanPskSecret</key>
</pre-shared-key></authentication></entry></gateway></ike></network>
</entry></devices></config>
"""


def _entries(tmp_path, device, text, name="device.conf"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return collect_secret_evidence(get_parser(device, str(path)))["entries"]


def test_ios_includes_effective_snmp_ntp_and_routing_secrets(tmp_path):
    entries = {item["line-number"]: item for item in _entries(tmp_path, "IOS_ROUTER", IOS)}
    assert {number: item["context"] for number, item in entries.items()} == {
        3: "snmp_community", 7: "snmpv3_user_key", 8: "ntp_key",
        15: "ospf_key", 21: "bgp_password",
    }
    rendered = json.dumps(list(entries.values()))
    assert "RemovedSecret" not in rendered and "UnusedNtpSecret" not in rendered
    assert "BgpSecret1" in entries[21]["source-line"]


def test_asa_includes_snmp_and_ntp_secrets(tmp_path):
    entries = _entries(tmp_path, "ASA", ASA)
    assert [(item["line-number"], item["context"]) for item in entries] == [
        (3, "ntp_key"), (8, "snmpv3_user_key"), (9, "snmp_host_community"), (10, "snmp_community"),
    ]
    assert "RemovedSecret" not in json.dumps(entries)


def test_panos_secret_elements_are_shown_as_elements_only(tmp_path):
    entries = _entries(tmp_path, "PAN_OS", PAN, "pa.xml")
    assert [(item["context"], item["line-number"]) for item in entries] == [
        ("local_user", 3), ("snmp_community", 8), ("ntp_key", 12), ("ike_pre_shared_key", 16),
    ]
    assert entries[0]["source-line"] == "<phash>$5$synthetic$PanHashSecret</phash>"
    assert all("<hostname>" not in item["source-line"] for item in entries)


def test_panos_cli_supports_show_secrets_and_default_stays_masked(tmp_path):
    source = tmp_path / "pa.xml"
    source.write_text(PAN, encoding="utf-8")
    sensitive, masked = tmp_path / "sensitive.json", tmp_path / "masked.json"
    assert main(["-d", "pan-os", "-i", str(source), "-o", "JSON", "-f", str(sensitive), "-x",
                 "--show-secrets"]) == 0
    payload = json.loads(sensitive.read_text(encoding="utf-8"))
    assert "PanPskSecret" in json.dumps(payload["secret-evidence"])
    assert "PanPskSecret" not in json.dumps(payload["security-audit"])
    assert main(["-d", "pan-os", "-i", str(source), "-o", "JSON", "-f", str(masked), "-x"]) == 0
    assert "PanPskSecret" not in masked.read_text(encoding="utf-8")


def test_checkpoint_policy_export_remains_unsupported(tmp_path, capsys):
    # Policy-only exports carry no device credentials; the option is refused explicitly.
    corpus = Path(__file__).parent / "test_data" / "regression" / "checkpoint_fw1" / "vulnerable"
    with pytest.raises(SystemExit) as error:
        main(["-d", "checkpoint-fw1", "-i", str(corpus), "-o", "JSON",
              "-f", str(tmp_path / "x.json"), "-x", "--show-secrets"])
    assert error.value.code == 2
    assert "not supported for this family" in capsys.readouterr().err


def test_windows_sensitive_report_restricts_acl_before_writing(tmp_path, monkeypatch):
    from src.report import report as report_module

    calls = []
    monkeypatch.setattr(report_module, "_IS_WINDOWS", True)
    monkeypatch.setenv("USERNAME", "auditor")
    monkeypatch.setenv("USERDOMAIN", "LAB")

    def fake_run(command, **kwargs):
        calls.append(command)
        assert Path(command[1]).read_text(encoding="utf-8") == ""  # nothing written yet
        return type("Result", (), {"returncode": 0})()

    monkeypatch.setattr(report_module.subprocess, "run", fake_run)
    target = tmp_path / "sensitive.json"
    report_module._write_report_file(str(target), "SECRET", sensitive=True)
    assert calls == [["icacls", str(target), "/inheritance:r", "/grant:r", "LAB\\auditor:F"]]
    assert target.read_text(encoding="utf-8") == "SECRET"


def test_windows_acl_failure_fails_closed(tmp_path, monkeypatch):
    from src.report import report as report_module

    monkeypatch.setattr(report_module, "_IS_WINDOWS", True)
    monkeypatch.setenv("USERNAME", "auditor")
    monkeypatch.setattr(report_module.subprocess, "run",
                        lambda command, **kwargs: type("Result", (), {"returncode": 5})())
    target = tmp_path / "sensitive.json"
    with pytest.raises(PermissionError):
        report_module._write_report_file(str(target), "SECRET", sensitive=True)
    assert not target.exists()


IOS_KEYS = """version 17.9
hostname r1
tacacs-server key 7 TacSecret0
tacacs server TAC1
 address ipv4 192.0.2.40
 key TacSecret1
tacacs server TAC2
 key RemovedTac
no tacacs server TAC2
crypto isakmp key IsakmpSecret1 address 203.0.113.1
crypto isakmp key RemovedIsakmp address 203.0.113.2
no crypto isakmp key RemovedIsakmp address 203.0.113.2
crypto keyring KR
 pre-shared-key address 203.0.113.5 key RingSecret1
"""

ASA_KEYS = """ASA Version 9.18(4)
hostname edge
tunnel-group 203.0.113.1 type ipsec-l2l
tunnel-group 203.0.113.1 ipsec-attributes
 ikev1 pre-shared-key PskSecret1
 ikev2 remote-authentication pre-shared-key RemovedPsk2
 no ikev2 remote-authentication pre-shared-key RemovedPsk2
tunnel-group 203.0.113.9 ipsec-attributes
 ikev1 pre-shared-key RemovedGroupPsk
clear configure tunnel-group 203.0.113.9
aaa-server TAC protocol tacacs+
aaa-server TAC (inside) host 192.0.2.40
 key AaaSecret1
"""


def test_ios_tacacs_and_ike_keys_follow_removal(tmp_path):
    entries = _entries(tmp_path, "IOS_ROUTER", IOS_KEYS)
    assert [(item["line-number"], item["context"]) for item in entries] == [
        (3, "tacacs_key"), (6, "tacacs_key"), (10, "isakmp_pre_shared_key"),
        (14, "keyring_pre_shared_key"),
    ]
    assert "Removed" not in json.dumps(entries)


def test_asa_tunnel_group_and_aaa_keys_follow_removal(tmp_path):
    entries = _entries(tmp_path, "ASA", ASA_KEYS)
    assert [(item["line-number"], item["context"]) for item in entries] == [
        (5, "tunnel_group_pre_shared_key"), (13, "aaa_server_key"),
    ]
    assert "Removed" not in json.dumps(entries)


JUNOS = """## Model: SRX345
set version 22.4R1.10
set system host-name j1
set system radius-server 192.0.2.5 secret "$9$RadiusSecret"
set system ntp authentication-key 1 type sha256 value "$9$NtpSecret"
set snmp community CommSecret authorization read-only
set snmp community RemovedCommunity authorization read-only
delete snmp community RemovedCommunity
set security ike policy P pre-shared-key ascii-text "$9$PskSecret"
set protocols bgp group G neighbor 198.51.100.1 authentication-key "$9$BgpSecret"
set protocols ospf area 0 interface ge-0/0/0.0 authentication md5 1 key "$9$OspfSecret"
set system tacplus-server 192.0.2.6 secret "$9$InactiveSecret"
deactivate system tacplus-server 192.0.2.6
"""


def test_junos_active_secret_statements(tmp_path):
    entries = _entries(tmp_path, "JUNOS", JUNOS)
    assert [(item["line-number"], item["context"]) for item in entries] == [
        (4, "radius_secret"), (5, "ntp_key"), (6, "snmp_community"),
        (9, "ike_pre_shared_key"), (10, "routing_key"), (11, "routing_key"),
    ]
    rendered = json.dumps(entries)
    assert "RemovedCommunity" not in rendered and "InactiveSecret" not in rendered


def test_junos_hierarchical_secret_statement(tmp_path):
    entries = _entries(tmp_path, "JUNOS", """## Model: SRX345
version 22.4R1.10;
system {
    host-name j1;
    radius-server {
        192.0.2.5 secret "$9$HierSecret";
    }
}
""")
    assert [(item["line-number"], item["context"]) for item in entries] == [(6, "radius_secret")]
