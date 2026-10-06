"""SC-049 batch 4: control outcomes for FortiOS, Junos, Arista EOS and PAN-OS."""

import contextlib
import io

import pytest

from src.analyze.arista.core.process_arista_conf import process_arista_conf
from src.analyze.common.controls import CONTROLS, control_coverage
from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.analyze.juniper.junos.core.process_junos_conf import process_junos_conf
from src.analyze.paloalto.core.process_panos_conf import process_panos_conf
from src.devices.arista.eos import AristaEOSParser
from src.devices.fortinet.fortios import FortiOSParser
from src.devices.juniper.junos import JunOSParser
from src.devices.paloalto.panos import PaloAltoPANOSParser


BATCH4 = (
    "fortinet.fortios.admin-session-timeout", "fortinet.fortios.login-banner", "fortinet.fortios.snmp-community",
    "fortinet.fortios.ntp-authentication", "juniper.junos.login-banner", "juniper.junos.idle-timeout",
    "arista.eos.login-lockout", "arista.eos.idle-timeout", "arista.eos.login-banner",
    "arista.eos.snmp-default-community", "paloalto.panos.login-banner", "paloalto.panos.ntp-authentication",
    "paloalto.panos.policy-logging",
)


def _run(tmp_path, parser_class, processor, text):
    path = tmp_path / "device.conf"
    path.write_text(text, encoding="utf-8")
    parser = parser_class(str(path))
    with contextlib.redirect_stdout(io.StringIO()):
        findings = processor(parser)
    rules = {issue.rule_id for issue in (findings.values() if isinstance(findings, dict) else findings or [])}
    outcomes = {item["control-id"]: item["outcome"] for item in control_coverage(parser)["results"]}
    for control in BATCH4:
        if control in outcomes:
            # A recorded finding must coincide with a mapped rule firing, and vice versa.
            assert (outcomes[control] == "finding") == bool(set(CONTROLS[control].rule_ids) & rules), control
    return outcomes, rules


def test_batch4_controls_are_registered():
    assert all(control in CONTROLS for control in BATCH4)


# --- FortiOS -----------------------------------------------------------------

FORTI = "#config-version=FGT100F-7.4.6-FW-build0001-240101:opmode=0:vdom=0:user=admin\n"
FORTI_OLD = "#config-version=FGT100F-6.2.0-FW-build0001-190101:opmode=0:vdom=0:user=admin\n"


def _forti(tmp_path, text):
    return _run(tmp_path, FortiOSParser, process_fortios_conf, text)[0]


@pytest.mark.parametrize("header,body,outcome", [
    (FORTI, "config system global\nset admintimeout 480\nend\n", "finding"),
    (FORTI, "config system global\nset admintimeout 0\nend\n", "finding"),
    (FORTI, "config system global\nset admintimeout 5\nend\n", "evaluated-no-finding"),
    (FORTI, "config system global\nset hostname fw\nend\n", "evaluated-no-finding"),
    (FORTI, "config system global\nset admintimeout abc\nend\n", "unknown"),
    (FORTI_OLD, "config system global\nset hostname fw\nend\n", "unknown"),
])
def test_fortios_admin_session_timeout(tmp_path, header, body, outcome):
    assert _forti(tmp_path, header + body)["fortinet.fortios.admin-session-timeout"] == outcome


@pytest.mark.parametrize("header,body,outcome", [
    (FORTI, "config system global\nset hostname fw\nend\n", "finding"),
    (FORTI, "config system global\nset pre-login-banner disable\nend\n", "finding"),
    (FORTI, "config system global\nset pre-login-banner enable\nend\n", "evaluated-no-finding"),
    (FORTI, "config system interface\nedit \"port1\"\nset ip 192.0.2.1 255.255.255.0\nnext\nend\n", "unknown"),
    (FORTI_OLD, "config system global\nset pre-login-banner enable\nend\n", "unknown"),
])
def test_fortios_login_banner(tmp_path, header, body, outcome):
    assert _forti(tmp_path, header + body)["fortinet.fortios.login-banner"] == outcome


SNMP_PORT = 'config system interface\nedit "port1"\nset allowaccess ping snmp\nnext\nend\n'
COMMUNITY = 'config system snmp community\nedit 1\nset name "s3cret"\nnext\nend\n'


@pytest.mark.parametrize("body,outcome", [
    (SNMP_PORT + COMMUNITY, "finding"),
    (SNMP_PORT, "evaluated-no-finding"),
    (SNMP_PORT + 'config system snmp community\nedit 1\nset name "x"\nset status disable\nnext\nend\n',
     "evaluated-no-finding"),
    (COMMUNITY, "not-applicable"),
    ("config system snmp sysinfo\nset status disable\nend\n" + SNMP_PORT + COMMUNITY, "not-applicable"),
])
def test_fortios_snmp_community(tmp_path, body, outcome):
    assert _forti(tmp_path, FORTI + body)["fortinet.fortios.snmp-community"] == outcome


NTP_CUSTOM = "config system ntp\nset ntpsync enable\nset type custom\nconfig ntpserver\nedit 1\n{server}next\nend\nend\n"


@pytest.mark.parametrize("header,body,outcome", [
    (FORTI, NTP_CUSTOM.format(server='set server "192.0.2.1"\n'), "finding"),
    (FORTI, NTP_CUSTOM.format(server='set server "192.0.2.1"\nset authentication enable\nset key-id 1\nset key ENC x\n'),
     "evaluated-no-finding"),
    (FORTI, "config system ntp\nset ntpsync enable\nset type fortiguard\nend\n", "not-applicable"),
    (FORTI, "config system ntp\nset ntpsync disable\nend\n", "not-applicable"),
    (FORTI, "config system global\nset hostname fw\nend\n", "not-applicable"),
    (FORTI_OLD, "config system global\nset hostname fw\nend\n", "unknown"),
])
def test_fortios_ntp_authentication(tmp_path, header, body, outcome):
    assert _forti(tmp_path, header + body)["fortinet.fortios.ntp-authentication"] == outcome


# --- Junos -------------------------------------------------------------------

JUNOS = "set version 24.4R2\nset system host-name r1\n"
INHERIT = "set apply-groups GLOBAL\nset groups GLOBAL system services ssh\n"


def _junos(tmp_path, body):
    return _run(tmp_path, JunOSParser, process_junos_conf, JUNOS + body)[0]


@pytest.mark.parametrize("body,outcome", [
    ("set system services ssh\n", "finding"),
    ("set system login message \"Authorized use only\"\n", "evaluated-no-finding"),
    (INHERIT, "unknown"),
])
def test_junos_login_banner(tmp_path, body, outcome):
    assert _junos(tmp_path, body)["juniper.junos.login-banner"] == outcome


@pytest.mark.parametrize("body,outcome", [
    ("set system login user ops class super-user\n", "finding"),
    ("set system login class ADM idle-timeout 0\nset system login class ADM permissions all\n"
     "set system login user ops class ADM\n", "finding"),
    ("set system login class ADM idle-timeout 10\nset system login class ADM permissions all\n"
     "set system login user ops class ADM\n", "evaluated-no-finding"),
    ("set system login idle-timeout 10\nset system login user ops class super-user\n", "evaluated-no-finding"),
    ("set system login user ops class MISSING\n", "unknown"),
    (INHERIT + "set system login user ops class super-user\n", "unknown"),
    ("set system services ssh\n", "not-applicable"),
])
def test_junos_idle_timeout(tmp_path, body, outcome):
    assert _junos(tmp_path, body)["juniper.junos.idle-timeout"] == outcome


# --- Arista EOS --------------------------------------------------------------

EOS = "! device: leaf (DCS-7050SX3-48YC8, EOS-4.29.2F)\nhostname leaf\n"
EOS_UNKNOWN_RELEASE = "hostname leaf\n"
SSH = "management ssh\n   idle-timeout 10\n"


def _eos(tmp_path, body, header=EOS):
    return _run(tmp_path, AristaEOSParser, process_arista_conf, header + body)[0]


@pytest.mark.parametrize("body,outcome", [
    (SSH, "finding"),
    (SSH + "aaa authentication policy lockout failure 10 duration 600\n", "finding"),
    (SSH + "aaa authentication policy lockout failure 3 duration 60\n", "finding"),
    (SSH + "aaa authentication policy lockout failure 5 duration 900\n", "evaluated-no-finding"),
    (SSH + "aaa authentication policy lockout failure x duration 900\n", "unknown"),
    ("management ssh\n   shutdown\n", "not-applicable"),
    ("", "unknown"),
])
def test_eos_login_lockout(tmp_path, body, outcome):
    assert _eos(tmp_path, body)["arista.eos.login-lockout"] == outcome


@pytest.mark.parametrize("body,header,outcome", [
    ("management ssh\n   idle-timeout 60\n", EOS, "finding"),
    ("management ssh\n", EOS, "finding"),
    (SSH, EOS, "evaluated-no-finding"),
    ("management ssh\n", EOS_UNKNOWN_RELEASE, "unknown"),
    ("management ssh\n   shutdown\n", EOS, "not-applicable"),
    ("", EOS, "unknown"),
])
def test_eos_idle_timeout(tmp_path, body, header, outcome):
    assert _eos(tmp_path, body, header)["arista.eos.idle-timeout"] == outcome


@pytest.mark.parametrize("body,header,outcome", [
    (SSH, EOS, "finding"),
    (SSH + "banner login\nAuthorized use only\nEOF\n", EOS, "evaluated-no-finding"),
    (SSH, EOS_UNKNOWN_RELEASE, "unknown"),
    ("management ssh\n   shutdown\n", EOS, "not-applicable"),
])
def test_eos_login_banner(tmp_path, body, header, outcome):
    assert _eos(tmp_path, body, header)["arista.eos.login-banner"] == outcome


@pytest.mark.parametrize("body,outcome", [
    ("snmp-server community public ro\n", "finding"),
    ("snmp-server community Xy7-secret ro\n", "evaluated-no-finding"),
    ("hostname leaf\n", "evaluated-no-finding"),
    ("no snmp-server vrf default\nsnmp-server community public ro\n", "unknown"),
])
def test_eos_snmp_default_community(tmp_path, body, outcome):
    assert _eos(tmp_path, body)["arista.eos.snmp-default-community"] == outcome


# --- PAN-OS ------------------------------------------------------------------

def _panos_xml(system="", rules="", extra="", shared=""):
    return f"""<config version="11.1.0">
<mgt-config><users><entry name="admin"><permissions><role-based><superuser>yes</superuser></role-based></permissions></entry></users></mgt-config>
<shared>{shared}</shared>
<devices><entry name="localhost.localdomain">
<deviceconfig><system><hostname>fw</hostname>{system}</system></deviceconfig>
<vsys><entry name="vsys1"><rulebase><security><rules>{rules}</rules></security></rulebase></entry></vsys>
</entry></devices>{extra}
</config>"""


TEMPLATE = "<template><entry name=\"T1\"><config/></entry></template>"


def _panos(tmp_path, text):
    return _run(tmp_path, PaloAltoPANOSParser, process_panos_conf, text)[0]


@pytest.mark.parametrize("text,outcome", [
    (_panos_xml(), "finding"),
    (_panos_xml("<login-banner>Authorized use only</login-banner>"), "evaluated-no-finding"),
    (_panos_xml(extra=TEMPLATE), "unknown"),
])
def test_panos_login_banner(tmp_path, text, outcome):
    assert _panos(tmp_path, text)["paloalto.panos.login-banner"] == outcome


NTP_PLAIN = ("<ntp-servers><primary-ntp-server><ntp-server-address>192.0.2.1</ntp-server-address>"
             "<authentication-type><none/></authentication-type></primary-ntp-server></ntp-servers>")
NTP_KEYED = ("<ntp-servers><primary-ntp-server><ntp-server-address>192.0.2.1</ntp-server-address>"
             "<authentication-type><symmetric-key><key-id>1</key-id><algorithm><sha1/></algorithm>"
             "<authentication-key>-AQ==abc</authentication-key></symmetric-key>"
             "</authentication-type></primary-ntp-server></ntp-servers>")
NTP_ODD = ("<ntp-servers><primary-ntp-server><ntp-server-address>192.0.2.1</ntp-server-address>"
           "<authentication-type><future-mode/></authentication-type></primary-ntp-server></ntp-servers>")


@pytest.mark.parametrize("text,outcome", [
    (_panos_xml(NTP_PLAIN), "finding"),
    (_panos_xml(NTP_KEYED), "evaluated-no-finding"),
    (_panos_xml(), "not-applicable"),
    (_panos_xml(NTP_PLAIN, extra=TEMPLATE), "unknown"),
    (_panos_xml(NTP_ODD), "unknown"),
])
def test_panos_ntp_authentication(tmp_path, text, outcome):
    assert _panos(tmp_path, text)["paloalto.panos.ntp-authentication"] == outcome


def _rule(action="allow", log_end="yes", log_setting="", disabled="no"):
    setting = f"<log-setting>{log_setting}</log-setting>" if log_setting else ""
    return (f"<entry name=\"r1\"><from><member>trust</member></from><to><member>untrust</member></to>"
            "<source><member>10.0.0.0/8</member></source><destination><member>any</member></destination>"
            "<source-user><member>any</member></source-user><category><member>any</member></category>"
            "<application><member>web-browsing</member></application><service><member>application-default</member></service>"
            f"<action>{action}</action><log-end>{log_end}</log-end>{setting}<disabled>{disabled}</disabled></entry>")


LFP = ("<log-settings><profiles><entry name=\"LFP\"><match-list><entry name=\"t\"><log-type>traffic</log-type>"
       "<send-syslog><member>SYSLOG</member></send-syslog></entry></match-list></entry></profiles>"
       "<syslog><entry name=\"SYSLOG\"><server><entry name=\"s\"><server>192.0.2.5</server></entry></server></entry></syslog>"
       "</log-settings>")


def _panos_logging_xml(rules, profile=True):
    text = _panos_xml(rules=rules)
    if profile:
        text = text.replace("<rulebase>", LFP + "<rulebase>", 1)
    return text


def test_panos_policy_logging_no_finding_requires_forwarding_and_session_end(tmp_path):
    outcomes, rules = _run(tmp_path, PaloAltoPANOSParser, process_panos_conf,
                           _panos_logging_xml(_rule(log_setting="LFP")))
    assert not {"paloalto.panos.policy.log_forwarding", "paloalto.panos.policy.session_logging"} & rules
    assert outcomes["paloalto.panos.policy-logging"] == "evaluated-no-finding"


@pytest.mark.parametrize("text,outcome", [
    (_panos_xml(rules=_rule()), "finding"),
    (_panos_logging_xml(_rule(log_setting="LFP", log_end="no")), "finding"),
    (_panos_xml(rules=_rule(action="deny")), "not-applicable"),
    (_panos_xml(rules=_rule(disabled="yes")), "not-applicable"),
])
def test_panos_policy_logging(tmp_path, text, outcome):
    assert _panos(tmp_path, text)["paloalto.panos.policy-logging"] == outcome


def test_panos_policy_logging_unexported_policy_is_unknown(tmp_path):
    assert _panos(tmp_path, _panos_xml())["paloalto.panos.policy-logging"] == "unknown"
