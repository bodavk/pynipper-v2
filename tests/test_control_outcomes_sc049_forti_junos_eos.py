"""SC-049: control outcomes for FortiOS, Junos and Arista EOS controls."""

import contextlib
import io

import pytest

from src.analyze.arista.core.process_arista_conf import process_arista_conf
from src.analyze.common.controls import control_coverage
from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.analyze.juniper.junos.core.process_junos_conf import process_junos_conf
from src.devices.arista.eos import AristaEOSParser
from src.devices.fortinet.fortios import FortiOSParser
from src.devices.juniper.junos import JunOSParser


def _outcomes(tmp_path, parser_class, processor, text):
    path = tmp_path / "device.conf"
    path.write_text(text, encoding="utf-8")
    parser = parser_class(str(path))
    with contextlib.redirect_stdout(io.StringIO()):
        processor(parser)
    return {item["control-id"]: item["outcome"] for item in control_coverage(parser)["results"]}


FORTI_HEADER = "#config-version=FGT100F-7.4.6-FW-build0001-240101:opmode=0:vdom=0:user=admin\n"


def _forti_admin(body):
    return FORTI_HEADER + "config system admin\n" + body + "end\n"


GOOD_ADMIN = ('edit "admin"\nset accprofile "super_admin"\nset trusthost1 10.0.0.0 255.255.255.0\n'
              'set two-factor fortitoken\nnext\n')
OPEN_ADMIN = 'edit "admin"\nset accprofile "super_admin"\nnext\n'
READONLY_ADMIN = 'edit "viewer"\nset accprofile "read_only"\nnext\n'
REMOTE_ADMIN = ('edit "radius"\nset accprofile "super_admin"\nset remote-auth enable\nset remote-group "ADMINS"\n'
                'set trusthost1 10.0.0.0 255.255.255.0\nnext\n')
UNRESOLVED_ADMIN = 'edit "ops"\nset accprofile "custom_missing"\nnext\n'
SYSLOG = 'config log syslogd setting\nset status enable\nset server "192.0.2.10"\nend\n'


def _forti(tmp_path, text):
    return _outcomes(tmp_path, FortiOSParser, process_fortios_conf, text)


@pytest.mark.parametrize("body,trusted,mfa", [
    (OPEN_ADMIN, "finding", "finding"),
    (GOOD_ADMIN, "evaluated-no-finding", "evaluated-no-finding"),
    (READONLY_ADMIN, "not-applicable", "not-applicable"),
    (UNRESOLVED_ADMIN, "unknown", "unknown"),
    (REMOTE_ADMIN, "evaluated-no-finding", "not-applicable"),
])
def test_fortios_admin_controls(tmp_path, body, trusted, mfa):
    outcomes = _forti(tmp_path, _forti_admin(body))
    assert outcomes["fortinet.fortios.admin-trusted-hosts"] == trusted
    assert outcomes["fortinet.fortios.admin-mfa"] == mfa


def test_fortios_admin_controls_without_exported_admins_are_unknown(tmp_path):
    outcomes = _forti(tmp_path, FORTI_HEADER + SYSLOG)
    assert outcomes["fortinet.fortios.admin-trusted-hosts"] == "unknown"
    assert outcomes["fortinet.fortios.admin-mfa"] == "unknown"


@pytest.mark.parametrize("extra,outcome", [("", "finding"), (SYSLOG, "evaluated-no-finding")])
def test_fortios_remote_logging(tmp_path, extra, outcome):
    assert _forti(tmp_path, _forti_admin(GOOD_ADMIN) + extra)["fortinet.fortios.remote-logging"] == outcome


JUNOS_HEADER = "set version 24.4R2\nset system host-name r1\n"


def _junos(tmp_path, body):
    return _outcomes(tmp_path, JunOSParser, process_junos_conf, JUNOS_HEADER + body)


@pytest.mark.parametrize("body,outcome", [
    ("set system services ssh root-login allow\n", "finding"),
    ("set system services ssh root-login deny\n", "evaluated-no-finding"),
    ("set system services ssh\nset system root-authentication ssh-ed25519 \"ssh-ed25519 AAAA key\"\n", "finding"),
    ("set system services ssh\n", "evaluated-no-finding"),
    ("set system services netconf ssh\nset system login message hi\n", "not-applicable"),
    ("set apply-groups GLOBAL\nset groups GLOBAL system services ssh\n", "unknown"),
])
def test_junos_ssh_root_login(tmp_path, body, outcome):
    assert _junos(tmp_path, body)["juniper.junos.ssh-root-login"] == outcome


@pytest.mark.parametrize("body,outcome", [
    ("set snmp community s3cret authorization read-only\n", "finding"),
    ("set snmp v3 usm local-engine user nms authentication-sha256 authentication-key x\n", "evaluated-no-finding"),
    ("set apply-groups GLOBAL\nset groups GLOBAL snmp location lab\n", "unknown"),
])
def test_junos_snmp_community(tmp_path, body, outcome):
    assert _junos(tmp_path, body)["juniper.junos.snmp-community"] == outcome


@pytest.mark.parametrize("body,outcome", [
    ("set system syslog file messages any notice\n", "finding"),
    ("set system syslog host 192.0.2.10 any info\n", "evaluated-no-finding"),
])
def test_junos_remote_logging(tmp_path, body, outcome):
    assert _junos(tmp_path, body)["juniper.junos.remote-logging"] == outcome


EOS_HEADER = "! device: leaf (DCS-7050SX3-48YC8, EOS-4.29.2F)\nhostname leaf\n"


def _eos(tmp_path, body):
    return _outcomes(tmp_path, AristaEOSParser, process_arista_conf, EOS_HEADER + body)


@pytest.mark.parametrize("body,outcome", [
    ("logging buffered 10000\n", "finding"),
    ("logging host 192.0.2.10\n", "evaluated-no-finding"),
])
def test_eos_remote_logging(tmp_path, body, outcome):
    assert _eos(tmp_path, body)["arista.eos.remote-logging"] == outcome


SSH_ACL = "ip access-list standard MGMT\n   10 permit 10.0.0.0/24\n"
ANY_ACL = "ip access-list standard MGMT\n   10 permit any\n"


@pytest.mark.parametrize("body,outcome", [
    ("management ssh\n   idle-timeout 10\n", "finding"),
    (ANY_ACL + "management ssh\n   ip access-group MGMT in\n", "finding"),
    (SSH_ACL + "management ssh\n   ip access-group MGMT in\n", "evaluated-no-finding"),
    ("management ssh\n   ip access-group MISSING in\n", "unknown"),
    ("management ssh\n   shutdown\n", "not-applicable"),
    ("", "unknown"),
])
def test_eos_ssh_source_restriction(tmp_path, body, outcome):
    assert _eos(tmp_path, body)["arista.eos.ssh-source-restriction"] == outcome


# --- SC-049 third batch -------------------------------------------------------

FORTI_OLD_HEADER = "#config-version=FGT100F-6.2.0-FW-build0001-190101:opmode=0:vdom=0:user=admin\n"
STRONG_POLICY = ("config system password-policy\nset status enable\nset apply-to admin-password\n"
                 "set minimum-length 14\nset min-lower-case-letter 1\nset min-upper-case-letter 1\n"
                 "set min-non-alphanumeric 1\nset min-number 1\nset reuse-password disable\nend\n")


@pytest.mark.parametrize("header,body,outcome", [
    (FORTI_HEADER, "", "finding"),
    (FORTI_HEADER, "config system password-policy\nset status disable\nend\n", "finding"),
    (FORTI_HEADER, "config system password-policy\nset status enable\nset minimum-length 8\nend\n", "finding"),
    (FORTI_HEADER, STRONG_POLICY, "evaluated-no-finding"),
    (FORTI_OLD_HEADER, "", "unknown"),
    (FORTI_OLD_HEADER, "config system password-policy\nset status enable\nend\n", "unknown"),
])
def test_fortios_password_policy(tmp_path, header, body, outcome):
    assert _forti(tmp_path, header + body)["fortinet.fortios.password-policy"] == outcome


@pytest.mark.parametrize("header,body,outcome", [
    (FORTI_HEADER, "config system global\nset admin-lockout-threshold 10\nend\n", "finding"),
    (FORTI_HEADER, "config system global\nset admin-lockout-duration 30\nend\n", "finding"),
    (FORTI_HEADER, "config system global\nset admin-lockout-threshold 3\nset admin-lockout-duration 300\nend\n",
     "evaluated-no-finding"),
    (FORTI_HEADER, "config system global\nset hostname fw\nend\n", "evaluated-no-finding"),
    (FORTI_OLD_HEADER, "config system global\nset hostname fw\nend\n", "unknown"),
])
def test_fortios_admin_lockout(tmp_path, header, body, outcome):
    assert _forti(tmp_path, header + body)["fortinet.fortios.admin-lockout"] == outcome


JUNOS_NTP_KEY = ("set system ntp authentication-key 1 type sha256 value \"$9$abc\"\n"
                 "set system ntp trusted-key 1\n")


@pytest.mark.parametrize("body,outcome", [
    ("set system ntp server 192.0.2.1\n", "finding"),
    (JUNOS_NTP_KEY + "set system ntp server 192.0.2.1 key 1\n", "evaluated-no-finding"),
    ("set system login message hi\n", "not-applicable"),
    ("set apply-groups GLOBAL\nset groups GLOBAL system ntp server 192.0.2.1\n", "unknown"),
])
def test_junos_ntp_authentication(tmp_path, body, outcome):
    assert _junos(tmp_path, body)["juniper.junos.ntp-authentication"] == outcome


@pytest.mark.parametrize("body,outcome", [
    ("set system login retry-options tries-before-disconnect 3\n", "finding"),
    ("set system login retry-options tries-before-disconnect 10\n"
     "set system login retry-options lockout-period 10\n", "finding"),
    ("set system login retry-options tries-before-disconnect 3\n"
     "set system login retry-options lockout-period 10\n", "evaluated-no-finding"),
    ("set system login retry-options lockout-period 10\n", "evaluated-no-finding"),
    ("set apply-groups GLOBAL\nset groups GLOBAL system login message hi\n"
     "set system login retry-options lockout-period 10\n", "unknown"),
])
def test_junos_login_lockout(tmp_path, body, outcome):
    assert _junos(tmp_path, body)["juniper.junos.login-lockout"] == outcome


@pytest.mark.parametrize("body,outcome", [
    ("ntp server 192.0.2.1\n", "finding"),
    ("ntp authentication-key 1 sha1 TOPSECRET\nntp trusted-key 1\nntp authenticate\n"
     "ntp server 192.0.2.1 key 1\n", "evaluated-no-finding"),
    ("hostname leaf\n", "not-applicable"),
    ("ntp authenticate\nntp server 192.0.2.1 key 9\n", "unknown"),
])
def test_eos_ntp_authentication(tmp_path, body, outcome):
    assert _eos(tmp_path, body)["arista.eos.ntp-authentication"] == outcome


def _panos_xml(profile, extra=""):
    return f"""<config version="11.1.0">
<mgt-config><users><entry name="admin"><permissions><role-based><superuser>yes</superuser></role-based></permissions></entry></users></mgt-config>
<devices><entry name="localhost.localdomain">
<deviceconfig><system><hostname>fw</hostname></system></deviceconfig>
<network><profiles><interface-management-profile><entry name="MGMT">{profile}</entry></interface-management-profile></profiles>
<interface><ethernet><entry name="ethernet1/1"><layer3><interface-management-profile>MGMT</interface-management-profile></layer3></entry></ethernet></interface></network>
</entry></devices>{extra}
</config>"""


def _panos(tmp_path, text):
    from src.analyze.paloalto.core.process_panos_conf import process_panos_conf
    from src.devices.paloalto.panos import PaloAltoPANOSParser
    return _outcomes(tmp_path, PaloAltoPANOSParser, process_panos_conf, text)


@pytest.mark.parametrize("text,outcome", [
    (_panos_xml("<http>yes</http>"), "finding"),
    (_panos_xml("<telnet>yes</telnet><ssh>yes</ssh>"), "finding"),
    (_panos_xml("<https>yes</https><ssh>yes</ssh>"), "evaluated-no-finding"),
    (_panos_xml("<https>yes</https>",
                "<template><entry name=\"T1\"><config/></entry></template>"), "unknown"),
])
def test_panos_cleartext_management(tmp_path, text, outcome):
    assert _panos(tmp_path, text)["paloalto.panos.cleartext-management"] == outcome
