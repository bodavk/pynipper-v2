"""SC-049 batch 5: control outcomes for F5 BIG-IP and Check Point Gaia."""

import contextlib
import io

import pytest

from src.analyze.checkpoint.core.process_checkpoint_gaia_conf import process_checkpoint_gaia_conf
from src.analyze.common.controls import CONTROLS, control_coverage
from src.analyze.f5.core.process_bigip_conf import process_bigip_conf
from src.devices.checkpoint.gaia import CheckPointGaiaParser
from src.devices.f5.bigip import F5BIGIPParser


BATCH5 = (
    "f5.bigip.self-ip-port-lockdown", "f5.bigip.root-login", "f5.bigip.ssh-source-restriction",
    "f5.bigip.httpd-source-restriction", "f5.bigip.password-policy-enforcement", "f5.bigip.snmp-community",
    "f5.bigip.remote-user-defaults", "checkpoint.gaia.login-lockout", "checkpoint.gaia.password-length",
    "checkpoint.gaia.web-session-timeout", "checkpoint.gaia.cli-idle-timeout", "checkpoint.gaia.login-banner",
    "checkpoint.gaia.management-telnet", "checkpoint.gaia.snmp-community", "checkpoint.gaia.ssh-root-login",
)


def _run(tmp_path, parser_class, processor, text):
    path = tmp_path / "device.conf"
    path.write_text(text, encoding="utf-8")
    parser = parser_class(str(path))
    with contextlib.redirect_stdout(io.StringIO()):
        findings = processor(parser)
    rules = {issue.rule_id for issue in findings.values()}
    coverage = {item["control-id"]: item for item in control_coverage(parser)["results"]}
    for control in BATCH5:
        if control in coverage:
            # Every applicable batch-5 control records an outcome on these inputs.
            assert coverage[control]["outcome"] != "not-recorded", control
            # A recorded finding must coincide with a mapped rule firing, and vice versa.
            assert (coverage[control]["outcome"] == "finding") == bool(set(CONTROLS[control].rule_ids) & rules), control
    return coverage


def test_batch5_controls_are_registered():
    assert all(control in CONTROLS for control in BATCH5)


# --- F5 BIG-IP ---------------------------------------------------------------

def _f5(tmp_path, body, version="16.1.5"):
    header = f"#TMSH-VERSION: {version}\n" if version else ""
    text = header + "sys global-settings {\n    hostname bigip1\n}\n" + body
    return _run(tmp_path, F5BIGIPParser, process_bigip_conf, text)


def _f5_outcome(tmp_path, control, body, version="16.1.5"):
    return _f5(tmp_path, body, version)[control]["outcome"]


def _self(name, allow=""):
    return f"net self {name} {{\n    address 192.0.2.1/24\n{allow}    vlan external\n}}\n"


def test_f5_self_ip_lockdown_is_per_instance(tmp_path):
    body = _self("ext", "    allow-service all\n") + _self("int", "    allow-service none\n") + _self("ha")
    item = _f5(tmp_path, body)["f5.bigip.self-ip-port-lockdown"]
    assert item["outcome"] == "finding"
    assert {row["instance-key"]: row["outcome"] for row in item["instances"]} == {
        "ext": "finding", "int": "evaluated-no-finding", "ha": "evaluated-no-finding"}


@pytest.mark.parametrize("version,body,outcome", [
    ("16.1.5", _self("ext", "    allow-service { tcp:443 }\n"), "finding"),
    ("11.4.1", _self("ext"), "finding"),
    ("11.5.3", _self("ext"), "evaluated-no-finding"),
    ("16.1.5", _self("ext", "    allow-service { tcp:53 }\n"), "evaluated-no-finding"),
    (None, _self("ext"), "unknown"),
    ("16.1.5", "", "not-applicable"),
])
def test_f5_self_ip_lockdown(tmp_path, version, body, outcome):
    assert _f5_outcome(tmp_path, "f5.bigip.self-ip-port-lockdown", body, version) == outcome


SSHD = "sys sshd {\n    allow { 192.0.2.0/255.255.255.0 }\n}\n"
DB = "sys db ui.advisory.enabled {\n    value \"true\"\n}\n"


def _root(value):
    return f"sys db systemauth.disablerootlogin {{\n    value \"{value}\"\n}}\n"


@pytest.mark.parametrize("version,body,outcome", [
    ("16.1.5", SSHD + DB, "finding"),
    ("16.1.5", SSHD + _root("false"), "finding"),
    ("16.1.5", SSHD + _root("true"), "evaluated-no-finding"),
    ("16.1.5", "sys sshd {\n    login disabled\n}\n" + DB, "not-applicable"),
    ("16.1.5", SSHD, "unknown"),
    ("11.5.4", SSHD + DB, "unknown"),
])
def test_f5_root_login(tmp_path, version, body, outcome):
    assert _f5_outcome(tmp_path, "f5.bigip.root-login", body, version) == outcome


@pytest.mark.parametrize("version,body,outcome", [
    ("16.1.5", "sys sshd {\n    inactivity-timeout 600\n}\n", "finding"),
    ("12.1.0", "sys sshd {\n    login enabled\n    allow { all }\n}\n", "finding"),
    ("16.1.5", SSHD, "evaluated-no-finding"),
    ("16.1.5", "sys sshd {\n    login disabled\n}\n", "not-applicable"),
    ("12.1.0", "sys sshd {\n    inactivity-timeout 600\n}\n", "unknown"),
    ("16.1.5", "", "unknown"),
])
def test_f5_ssh_source_restriction(tmp_path, version, body, outcome):
    assert _f5_outcome(tmp_path, "f5.bigip.ssh-source-restriction", body, version) == outcome


@pytest.mark.parametrize("version,body,outcome", [
    ("16.1.5", "sys httpd {\n    allow { All }\n}\n", "finding"),
    ("16.1.5", "sys httpd {\n    redirect-http-to-https enabled\n}\n", "finding"),
    ("16.1.5", "sys httpd {\n    allow { 192.0.2.0/255.255.255.0 }\n}\n", "evaluated-no-finding"),
    ("16.1.5", "sys httpd {\n    allow none\n}\n", "not-applicable"),
    ("12.1.0", "sys httpd {\n    redirect-http-to-https enabled\n}\n", "unknown"),
    ("16.1.5", "", "unknown"),
])
def test_f5_httpd_source_restriction(tmp_path, version, body, outcome):
    assert _f5_outcome(tmp_path, "f5.bigip.httpd-source-restriction", body, version) == outcome


@pytest.mark.parametrize("version,body,outcome", [
    ("16.1.5", "auth password-policy {\n    policy-enforcement disabled\n}\n", "finding"),
    ("13.1.0", "auth password-policy {\n    minimum-length 12\n}\n", "finding"),
    ("13.1.0", "auth password-policy {\n    policy-enforcement enabled\n}\n", "evaluated-no-finding"),
    ("14.1.0", "auth password-policy {\n    minimum-length 12\n}\n", "evaluated-no-finding"),
    ("16.1.5", "", "unknown"),
    (None, "auth password-policy {\n    minimum-length 12\n}\n", "unknown"),
])
def test_f5_password_policy_enforcement(tmp_path, version, body, outcome):
    assert _f5_outcome(tmp_path, "f5.bigip.password-policy-enforcement", body, version) == outcome


def _snmp(allowed, communities):
    return f"sys snmp {{\n{allowed}    communities {{ {communities} }}\n}}\n"


@pytest.mark.parametrize("body,outcome", [
    (_snmp("    allowed-addresses { 192.0.2.0/24 }\n", "/Common/c1 { community-name public access ro }"), "finding"),
    (_snmp("    allowed-addresses { 192.0.2.0/24 }\n", "/Common/c1 { community-name mon1 access rw }"), "finding"),
    (_snmp("    allowed-addresses { 0.0.0.0/0 }\n", "/Common/c1 { community-name mon1 access ro }"), "finding"),
    (_snmp("    allowed-addresses { 192.0.2.0/24 }\n", "/Common/c1 { community-name mon1 access ro }"),
     "evaluated-no-finding"),
    (_snmp("    allowed-addresses { 192.0.2.0/24 }\n", "/Common/c1 { access ro }"), "unknown"),
    (_snmp("", "/Common/c1 { community-name public access rw }"), "not-applicable"),
    (_snmp("    allowed-addresses { 127.0.0.0/8 }\n", "/Common/c1 { community-name public access rw }"),
     "not-applicable"),
    ("", "unknown"),
])
def test_f5_snmp_community(tmp_path, body, outcome):
    assert _f5_outcome(tmp_path, "f5.bigip.snmp-community", body) == outcome


@pytest.mark.parametrize("body,outcome", [
    ("auth remote-user {\n    default-role admin\n}\n", "finding"),
    ("auth remote-user {\n    remote-console-access tmsh\n}\n", "finding"),
    ("auth remote-user {\n    default-role no-access\n    remote-console-access disabled\n}\n", "evaluated-no-finding"),
    ("auth remote-user {\n    default-role operator\n}\n", "evaluated-no-finding"),
    ("auth source {\n    type local\n}\n", "not-applicable"),
    ("auth source {\n    type radius\n}\n", "unknown"),
])
def test_f5_remote_user_defaults(tmp_path, body, outcome):
    assert _f5_outcome(tmp_path, "f5.bigip.remote-user-defaults", body) == outcome


# --- Check Point Gaia --------------------------------------------------------

HEADER = "#\n# Configuration of gw1\n# Language version: 15.0v1\n#\nset hostname gw1\n"
LOCKOUT = "set password-controls deny-on-fail enable on\nset password-controls deny-on-fail failures-allowed 5\n"


def _gaia(tmp_path, control, body):
    return _run(tmp_path, CheckPointGaiaParser, process_checkpoint_gaia_conf, HEADER + body)[control]["outcome"]


@pytest.mark.parametrize("body,outcome", [
    ("", "finding"),
    ("set password-controls deny-on-fail enable off\n", "finding"),
    ("set password-controls deny-on-fail enable on\n", "finding"),
    (LOCKOUT + "set password-controls deny-on-fail allow-after 60\n", "finding"),
    (LOCKOUT, "evaluated-no-finding"),
    (LOCKOUT + "set password-controls deny-on-fail allow-after soon\n", "unknown"),
])
def test_gaia_login_lockout(tmp_path, body, outcome):
    assert _gaia(tmp_path, "checkpoint.gaia.login-lockout", body) == outcome


@pytest.mark.parametrize("body,outcome", [
    ("", "finding"),
    ("set password-controls min-password-length 6\n", "finding"),
    ("set password-controls min-password-length 14\n", "evaluated-no-finding"),
    ("set password-controls min-password-length long\n", "unknown"),
])
def test_gaia_password_length(tmp_path, body, outcome):
    assert _gaia(tmp_path, "checkpoint.gaia.password-length", body) == outcome


@pytest.mark.parametrize("body,outcome", [
    ("", "finding"),
    ("set web session-timeout 30\n", "finding"),
    ("set web session-timeout 10\n", "evaluated-no-finding"),
    ("set web session-timeout x\n", "unknown"),
])
def test_gaia_web_session_timeout(tmp_path, body, outcome):
    assert _gaia(tmp_path, "checkpoint.gaia.web-session-timeout", body) == outcome


@pytest.mark.parametrize("body,outcome", [
    ("set inactivity-timeout 60\n", "finding"),
    ("set inactivity-timeout 5\n", "evaluated-no-finding"),
    ("", "evaluated-no-finding"),
    ("set inactivity-timeout x\n", "unknown"),
])
def test_gaia_cli_idle_timeout(tmp_path, body, outcome):
    assert _gaia(tmp_path, "checkpoint.gaia.cli-idle-timeout", body) == outcome


@pytest.mark.parametrize("body,outcome", [
    ("set message banner off\n", "finding"),
    ("set message banner on msgvalue \"Authorized use only\"\n", "evaluated-no-finding"),
    ("", "evaluated-no-finding"),
    ("set message banner maybe\n", "unknown"),
])
def test_gaia_login_banner(tmp_path, body, outcome):
    assert _gaia(tmp_path, "checkpoint.gaia.login-banner", body) == outcome


@pytest.mark.parametrize("body,outcome", [
    ("set net-access telnet on\n", "finding"),
    ("set net-access telnet off\n", "evaluated-no-finding"),
    ("", "evaluated-no-finding"),
    ("set net-access telnet yes\n", "unknown"),
])
def test_gaia_management_telnet(tmp_path, body, outcome):
    assert _gaia(tmp_path, "checkpoint.gaia.management-telnet", body) == outcome


AGENT = "set snmp agent on\n"


@pytest.mark.parametrize("body,outcome", [
    (AGENT + "add snmp community public read-only\n", "finding"),
    (AGENT + "add snmp community mon1 read-write\n", "finding"),
    (AGENT + "add snmp community mon1 read-only\n", "evaluated-no-finding"),
    (AGENT, "evaluated-no-finding"),
    (AGENT + "add snmp community mon1\n", "unknown"),
    ("add snmp community public read-write\n", "not-applicable"),
    ("set snmp agent off\nadd snmp community public read-write\n", "not-applicable"),
])
def test_gaia_snmp_community(tmp_path, body, outcome):
    assert _gaia(tmp_path, "checkpoint.gaia.snmp-community", body) == outcome


@pytest.mark.parametrize("body,outcome", [
    ("set ssh server permit-root-login yes\n", "finding"),
    ("set ssh server max-auth-tries 3\n", "finding"),
    ("set ssh server permit-root-login no\n", "evaluated-no-finding"),
    ("set ssh server permit-root-login maybe\n", "unknown"),
    ("", "unknown"),
])
def test_gaia_ssh_root_login(tmp_path, body, outcome):
    assert _gaia(tmp_path, "checkpoint.gaia.ssh-root-login", body) == outcome
