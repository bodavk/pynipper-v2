"""Wave 4 (SC-025, SC-035): Smart Install and recoverable stored secrets."""

import contextlib
import io

import pytest

from src.analyze.cisco.asa.core.process_asa_conf import process_asa_conf
from src.analyze.cisco.ios.core.process_cisco_ios_conf import process_cisco_ios_conf
from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis
from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.devices import get_parser


def _run(tmp_path, device, text, processor):
    path = tmp_path / "device.conf"
    path.write_text(text, encoding="utf-8")
    parser = get_parser(device, str(path))
    with contextlib.redirect_stdout(io.StringIO()):
        return [finding for finding in processor(parser).values()]


def _ids(findings, prefix):
    return sorted(finding.rule_id for finding in findings if finding.rule_id.startswith(prefix))


IOS_HEAD = "version 15.2\nhostname sw1\n"


# --- SC-025 Smart Install -------------------------------------------------------------

@pytest.mark.parametrize("body,expected", [
    ("vstack\n", True),
    ("vstack director 192.0.2.1\n", True),
    ("vstack\nno vstack\n", False),
    ("no vstack\n", False),
    ("", False),  # older releases never showed vstack: unknown, not a finding
])
def test_smart_install_follows_effective_state(tmp_path, body, expected):
    findings = _run(tmp_path, "IOS_SWITCH", IOS_HEAD + body + "end\n", process_cisco_ios_conf)
    found = [f for f in findings if f.rule_id == "cisco.ios.services.smart_install"]
    assert bool(found) is expected
    if found:
        assert found[0].basis is FindingBasis.EXPLICIT_VALUE
        assert guidance_for(found[0].rule_id) is not None


def test_smart_install_on_ios_xe(tmp_path):
    findings = _run(tmp_path, "IOS_XE", "version 17.9\nhostname sw2\nvstack\nend\n", process_cisco_ios_conf)
    assert "cisco.ios.services.smart_install" in _ids(findings, "cisco.ios.services")


# --- SC-035 IOS TACACS+ and IKE keys ----------------------------------------------------

IOS_KEYS = IOS_HEAD + """tacacs-server host 192.0.2.5 key 7 0822455D0A16
tacacs-server key Cleartext1
tacacs server T1
 address ipv4 192.0.2.6
 key 6 ABCDEFGHIJ
crypto isakmp key Secret1 address 198.51.100.1
crypto isakmp key 6 XYZXYZ address 198.51.100.2
crypto keyring KR
 pre-shared-key address 203.0.113.1 key PlainKey
end
"""


def test_ios_service_keys_storage(tmp_path):
    findings = [f for f in _run(tmp_path, "IOS_ROUTER", IOS_KEYS, process_cisco_ios_conf)
                if f.rule_id.endswith("_key_storage")]
    assert sorted(f.rule_id for f in findings) == [
        "cisco.ios.credentials.isakmp_pre_shared_key_storage",
        "cisco.ios.credentials.keyring_pre_shared_key_storage",
        "cisco.ios.credentials.tacacs_key_storage",
        "cisco.ios.credentials.tacacs_key_storage",
    ]
    text = " ".join(" ".join(f.evidence) for f in findings)
    for secret in ("Cleartext1", "Secret1", "PlainKey", "0822455D0A16"):
        assert secret not in text
    assert all(f.basis is FindingBasis.EXPLICIT_VALUE for f in findings)


def test_ios_removed_keys_are_not_reported(tmp_path):
    text = IOS_HEAD + ("tacacs-server key Cleartext1\nno tacacs-server key\n"
                       "crypto isakmp key Secret1 address 198.51.100.1\n"
                       "no crypto isakmp key Secret1 address 198.51.100.1\n"
                       "crypto keyring KR\n pre-shared-key address 203.0.113.1 key PlainKey\n"
                       "no crypto keyring KR\nend\n")
    findings = _run(tmp_path, "IOS_ROUTER", text, process_cisco_ios_conf)
    assert not [f for f in findings if f.rule_id.endswith("_key_storage")]


# --- SC-035 ASA master passphrase -------------------------------------------------------

ASA_HEAD = "ASA Version 9.16(4)\nhostname asa1\n"


@pytest.mark.parametrize("value,expected", [
    ("Cleartext1", True),
    ("*****", False),
    ("8 Q1dZWnBhc3N3b3Jk", False),
])
def test_asa_tunnel_group_key_storage(tmp_path, value, expected):
    text = ASA_HEAD + ("tunnel-group 198.51.100.1 type ipsec-l2l\n"
                       "tunnel-group 198.51.100.1 ipsec-attributes\n"
                       f" ikev1 pre-shared-key {value}\n")
    findings = _run(tmp_path, "ASA", text, process_asa_conf)
    found = [f for f in findings if f.rule_id == "cisco.asa.credentials.tunnel_group_pre_shared_key_storage"]
    assert bool(found) is expected
    if found:
        assert "Cleartext1" not in " ".join(found[0].evidence)


def test_asa_aaa_server_key_storage(tmp_path):
    text = ASA_HEAD + ("aaa-server TAC protocol tacacs+\n"
                       "aaa-server TAC (inside) host 192.0.2.10\n"
                       " key Cleartext2\n")
    findings = _run(tmp_path, "ASA", text, process_asa_conf)
    assert "cisco.asa.credentials.aaa_server_key_storage" in _ids(findings, "cisco.asa.credentials")


# --- SC-035 FortiOS private-data-encryption ---------------------------------------------

FORTI_HEAD = "#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0:user=admin\n"
FORTI_SECRETS = """config system admin
    edit "admin"
        set password ENC SH2abcdefabcdef
    next
end
config vpn ipsec phase1-interface
    edit "to-branch"
        set interface "wan1"
        set psksecret ENC Zm9vYmFyYmF6
        set remote-gw 198.51.100.1
    next
end
"""


@pytest.mark.parametrize("global_block,expected,basis", [
    ("", True, FindingBasis.DOCUMENTED_DEFAULT),
    ("config system global\n    set private-data-encryption disable\nend\n", True, FindingBasis.EXPLICIT_VALUE),
    ("config system global\n    set private-data-encryption enable\nend\n", False, None),
])
def test_fortios_private_data_encryption(tmp_path, global_block, expected, basis):
    findings = _run(tmp_path, "FORTIOS", FORTI_HEAD + global_block + FORTI_SECRETS, process_fortios_conf)
    found = [f for f in findings if f.rule_id == "fortinet.fortios.credentials.private_data_storage"]
    assert bool(found) is expected
    if found:
        assert found[0].basis is basis
        assert "Zm9vYmFy" not in " ".join(found[0].evidence)


def test_fortios_admin_hashes_alone_do_not_trigger(tmp_path):
    body = "config system admin\n    edit \"admin\"\n        set password ENC SH2abcdef\n    next\nend\n"
    findings = _run(tmp_path, "FORTIOS", FORTI_HEAD + body, process_fortios_conf)
    assert "fortinet.fortios.credentials.private_data_storage" not in _ids(findings, "fortinet")
