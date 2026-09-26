"""Wave 4 follow-ups: F5 monitors/traps/virtual services, FortiOS admin hashes,
IOS legacy-release defaults (SC-044) and Junos VRRP authentication."""

import contextlib
import io

import pytest

from src.analyze.cisco.ios.core.process_cisco_ios_conf import process_cisco_ios_conf
from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis
from src.analyze.f5.core.process_bigip_conf import process_bigip_conf
from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.analyze.juniper.junos.core.process_junos_conf import process_junos_conf
from src.devices import get_parser


def _run(tmp_path, device, text, processor):
    path = tmp_path / "device.conf"
    path.write_text(text, encoding="utf-8")
    parser = get_parser(device, str(path))
    with contextlib.redirect_stdout(io.StringIO()):
        return list(processor(parser).values())


def _rules(findings, rule):
    return [finding for finding in findings if finding.rule_id == rule]


F5 = "#TMSH-VERSION: 16.1.5\nsys global-settings {\n    hostname bigip1\n}\n"


def test_f5_monitor_basic_auth_is_redacted(tmp_path):
    text = F5 + ('ltm monitor http /Common/app_mon {\n    defaults-from /Common/http\n'
                 '    send "GET / HTTP/1.1\\r\\nAuthorization: Basic dXNlcjpwYXNz\\r\\n\\r\\n"\n}\n')
    findings = _rules(_run(tmp_path, "F5_BIGIP", text, process_bigip_conf), "f5.bigip.credentials.monitor_storage")
    assert len(findings) == 1
    assert "dXNlcjpwYXNz" not in " ".join(findings[0].evidence)
    plain = text.replace("Authorization: Basic dXNlcjpwYXNz\\r\\n", "")
    assert not _rules(_run(tmp_path, "F5_BIGIP", plain, process_bigip_conf), "f5.bigip.credentials.monitor_storage")


@pytest.mark.parametrize("version,expected", [("2c", True), ("1", True), ("3", False)])
def test_f5_snmp_trap_version(tmp_path, version, expected):
    text = F5 + ("sys snmp {\n    traps {\n        /Common/nms {\n            community secret1\n"
                 f"            host 192.0.2.30\n            version {version}\n        }}\n    }}\n}}\n")
    findings = _rules(_run(tmp_path, "F5_BIGIP", text, process_bigip_conf), "f5.bigip.snmp.legacy_version")
    assert bool(findings) is expected
    if findings:
        assert "secret1" not in " ".join(findings[0].evidence)


@pytest.mark.parametrize("destination,source,expected", [
    ("192.0.2.20:21", "0.0.0.0/0", True),
    ("192.0.2.20:telnet", "0.0.0.0/0", True),
    ("192.0.2.20:443", "0.0.0.0/0", False),
    ("192.0.2.20:21", "198.51.100.0/24", False),
])
def test_f5_virtual_risky_service(tmp_path, destination, source, expected):
    text = F5 + f"ltm virtual /Common/vs {{\n    destination /Common/{destination}\n    source {source}\n}}\n"
    findings = _rules(_run(tmp_path, "F5_BIGIP", text, process_bigip_conf), "f5.bigip.ltm.risky_service_exposure")
    assert bool(findings) is expected
    if findings:
        assert guidance_for(findings[0].rule_id) is not None


@pytest.mark.parametrize("version,hash_value,expected", [
    ("7.6.2", "SH2abcdef", True),
    ("7.6.2", "PB2abcdef", False),
    ("7.4.4", "SH2abcdef", False),
])
def test_fortios_admin_hash(tmp_path, version, hash_value, expected):
    text = (f"#config-version=FGT60F-{version}-FW-build1517-230606:opmode=0:vdom=0:user=admin\n"
            f'config system admin\n    edit "admin"\n        set password ENC {hash_value}\n    next\nend\n')
    findings = _rules(_run(tmp_path, "FORTIOS", text, process_fortios_conf), "fortinet.fortios.credentials.admin_hash_storage")
    assert bool(findings) is expected


@pytest.mark.parametrize("version,body,expected", [
    ("12.0", "", {"finger"}),
    ("11.3", "", {"finger", "tcp-small-servers", "udp-small-servers"}),
    ("11.3", "no service finger\nno service tcp-small-servers\nno service udp-small-servers\n", set()),
    ("12.4", "", set()),
])
def test_ios_legacy_release_defaults(tmp_path, version, body, expected):
    findings = _rules(_run(tmp_path, "IOS_ROUTER", f"version {version}\nhostname r1\n{body}end\n",
                           process_cisco_ios_conf), "cisco.ios.services.legacy_default")
    found = set()
    for finding in findings:
        assert finding.basis is FindingBasis.DOCUMENTED_DEFAULT
        found.update(name for name in ("finger", "tcp-small-servers", "udp-small-servers") if name in finding.observation)
    assert found == expected


JUNOS = "set version 21.4R3\nset system host-name r1\n"


@pytest.mark.parametrize("lines,expected,basis", [
    ("set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.2/24 vrrp-group 1 virtual-address 10.0.0.1\n",
     True, FindingBasis.DOCUMENTED_DEFAULT),
    ("set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.2/24 vrrp-group 1 virtual-address 10.0.0.1\n"
     "set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.2/24 vrrp-group 1 authentication-type simple\n",
     True, FindingBasis.EXPLICIT_VALUE),
    ("set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.2/24 vrrp-group 1 virtual-address 10.0.0.1\n"
     "set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.2/24 vrrp-group 1 authentication-type md5\n",
     False, None),
    ("set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.2/24 vrrp-group 1 virtual-address 10.0.0.1\n"
     "set protocols vrrp version-3\n", False, None),
    ("set interfaces ge-0/0/1 disable\n"
     "set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.2/24 vrrp-group 1 virtual-address 10.0.0.1\n",
     False, None),
])
def test_junos_vrrp_authentication(tmp_path, lines, expected, basis):
    findings = _rules(_run(tmp_path, "JUNOS", JUNOS + lines, process_junos_conf), "juniper.junos.fhrp.authentication")
    assert bool(findings) is expected
    if findings:
        assert findings[0].basis is basis
