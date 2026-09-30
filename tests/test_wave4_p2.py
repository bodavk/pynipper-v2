"""Wave 4 priority 2 checks (SC-026, 027, 028, 030, 032, 033, 036, 037, 038, 040, 042, 043)."""

import contextlib
import io

import pytest

from src.analyze.checkpoint.core.process_checkpoint_gaia_conf import process_checkpoint_gaia_conf
from src.analyze.cisco.asa.core.process_asa_conf import process_asa_conf
from src.analyze.cisco.ios.core.process_cisco_ios_conf import process_cisco_ios_conf
from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis
from src.analyze.common.risky_services import is_risky_port, risky_labels
from src.analyze.f5.core.process_bigip_conf import process_bigip_conf
from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.devices import get_parser


def _run(tmp_path, device, text, processor):
    path = tmp_path / "device.conf"
    path.write_text(text, encoding="utf-8")
    parser = get_parser(device, str(path))
    with contextlib.redirect_stdout(io.StringIO()):
        return list(processor(parser).values())


def _rules(findings, rule):
    return [finding for finding in findings if finding.rule_id == rule]


IOS = "version 15.2\nhostname r1\n"
ASA = "ASA Version 9.16(4)\nhostname asa1\n"
FORTI = "#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0:user=admin\n"
F5 = "#TMSH-VERSION: 16.1.5\nsys global-settings {\n    hostname bigip1\n}\n"


def _ios(tmp_path, body, device="IOS_ROUTER"):
    return _run(tmp_path, device, IOS + body + "end\n", process_cisco_ios_conf)


# --- SC-026 --------------------------------------------------------------------------

@pytest.mark.parametrize("body,expected", [
    ("service pad\n", True),
    ("ip finger\n", True),
    ("ip identd\n", True),
    ("service pad\nno service pad\n", False),
    ("interface GigabitEthernet0/0\n mop enabled\n", True),
    ("interface GigabitEthernet0/0\n mop enabled\n shutdown\n", False),
    ("", False),
])
def test_ios_legacy_services(tmp_path, body, expected):
    assert bool(_rules(_ios(tmp_path, body), "cisco.ios.services.unnecessary")) is expected


def test_ios_remote_shell_tftp_and_gnmi(tmp_path):
    findings = _ios(tmp_path, "ip rcmd rsh-enable\ntftp-server flash:image.bin\ngnxi\ngnxi server\n", "IOS_XE")
    assert _rules(findings, "cisco.ios.services.remote_shell")
    assert _rules(findings, "cisco.ios.services.tftp_server")
    assert _rules(findings, "cisco.ios.management.insecure_protocol")
    clean = _ios(tmp_path, "ip rcmd rsh-enable\nno ip rcmd rsh-enable\ngnxi\ngnxi secure-server\n", "IOS_XE")
    assert not _rules(clean, "cisco.ios.services.remote_shell")
    assert not _rules(clean, "cisco.ios.management.insecure_protocol")


# --- SC-027 --------------------------------------------------------------------------

def test_ios_https_tls(tmp_path):
    body = "ip http secure-server\nip http tls-version TLSv1.1\nip http secure-ciphersuite aes-128-cbc-sha ecdhe-rsa-aes-gcm-sha2\n"
    findings = _ios(tmp_path, body)
    assert _rules(findings, "cisco.ios.tls.minimum_version")
    weak = _rules(findings, "cisco.ios.tls.weak_cipher")
    assert weak and "aes-128-cbc-sha" in weak[0].observation and "gcm" not in weak[0].observation
    assert not _rules(_ios(tmp_path, body.replace("ip http secure-server\n", "")), "cisco.ios.tls.minimum_version")
    assert not _rules(_ios(tmp_path, "ip http secure-server\nip http tls-version TLSv1.2\n"), "cisco.ios.tls.minimum_version")


# --- SC-028 --------------------------------------------------------------------------

@pytest.mark.parametrize("group,expected,basis", [
    (" standby 1 ip 10.0.0.1\n", True, FindingBasis.MISSING_EXPLICIT_SETTING),
    (" standby 1 ip 10.0.0.1\n standby 1 authentication text Secret\n", True, FindingBasis.EXPLICIT_VALUE),
    (" standby 1 ip 10.0.0.1\n standby 1 authentication md5 key-chain HSRP\n", False, None),
    (" vrrp 5 ip 10.0.0.1\n", True, FindingBasis.MISSING_EXPLICIT_SETTING),
    (" glbp 2 ip 10.0.0.1\n glbp 2 authentication md5 key-string Secret\n", False, None),
    (" standby 1 ip 10.0.0.1\n shutdown\n", False, None),
])
def test_ios_fhrp_authentication(tmp_path, group, expected, basis):
    findings = _rules(_ios(tmp_path, "interface Vlan10\n ip address 10.0.0.2 255.255.255.0\n" + group),
                      "cisco.ios.fhrp.authentication")
    assert bool(findings) is expected
    if findings:
        assert findings[0].basis is basis
        assert "Secret" not in " ".join(findings[0].evidence)
        assert guidance_for(findings[0].rule_id) is not None


# --- SC-033 --------------------------------------------------------------------------

def test_ios_ntp_access(tmp_path):
    assert _rules(_ios(tmp_path, "ntp server 192.0.2.1\n"), "cisco.ios.ntp.server_exposed")
    assert not _rules(_ios(tmp_path, "ntp server 192.0.2.1\nntp access-group peer 10\n"), "cisco.ios.ntp.server_exposed")
    assert not _rules(_ios(tmp_path, ""), "cisco.ios.ntp.server_exposed")


def test_fortios_ntp_server_mode(tmp_path):
    base = (FORTI + 'config system interface\n    edit "wan1"\n        set role wan\n    next\n'
            '    edit "internal"\n        set role lan\n    next\nend\n')
    exposed = base + 'config system ntp\n    set server-mode enable\n    set interface "wan1"\nend\n'
    internal = base + 'config system ntp\n    set server-mode enable\n    set interface "internal"\nend\n'
    assert _rules(_run(tmp_path, "FORTIOS", exposed, process_fortios_conf), "fortinet.fortios.ntp.server_exposed")
    assert not _rules(_run(tmp_path, "FORTIOS", internal, process_fortios_conf), "fortinet.fortios.ntp.server_exposed")


# --- SC-036 / SC-037 -----------------------------------------------------------------

def test_ios_embedded_credentials_are_redacted(tmp_path):
    body = ("ip ftp username backup\nip ftp password Secret1\n"
            "archive\n path ftp://backup:Secret2@192.0.2.9/$h\n")
    findings = _ios(tmp_path, body)
    assert _rules(findings, "cisco.ios.credentials.ftp_client_storage")
    assert _rules(findings, "cisco.ios.credentials.url_storage")
    text = " ".join(" ".join(f.evidence) for f in findings)
    assert "Secret1" not in text and "Secret2" not in text


@pytest.mark.parametrize("line,expected", [
    ("snmp-server host 192.0.2.5 public\n", True),
    ("snmp-server host 192.0.2.5 version 2c public\n", True),
    ("snmp-server host 192.0.2.5 version 3 priv monitor\n", False),
    ("snmp-server host 192.0.2.5 public\nno snmp-server host 192.0.2.5\n", False),
])
def test_ios_snmp_notification_version(tmp_path, line, expected):
    findings = _rules(_ios(tmp_path, line), "cisco.ios.snmp.legacy_version")
    assert bool(findings) is expected
    if findings:
        assert "public" not in " ".join(findings[0].evidence)


# --- SC-030 --------------------------------------------------------------------------

def test_f5_admin_access(tmp_path):
    text = F5 + ("auth user /Common/ops {\n    shell bash\n    role admin\n}\n"
                 "auth remote-user {\n    default-role admin\n}\n"
                 'sys db systemauth.disablerootlogin {\n    value "false"\n}\n'
                 "auth password-policy {\n    policy-enforcement enabled\n}\n")
    findings = _run(tmp_path, "F5_BIGIP", text, process_bigip_conf)
    for rule in ("f5.bigip.auth.user_bash_shell", "f5.bigip.auth.remote_default_admin",
                 "f5.bigip.auth.root_login_enabled", "f5.bigip.password_policy.history_disabled"):
        assert _rules(findings, rule), rule
    safe = F5 + ("auth user /Common/ops {\n    shell tmsh\n}\nauth remote-user {\n    default-role no-access\n}\n"
                 'sys db systemauth.disablerootlogin {\n    value "true"\n}\n'
                 "auth password-policy {\n    policy-enforcement enabled\n    password-memory 5\n}\n")
    findings = _run(tmp_path, "F5_BIGIP", safe, process_bigip_conf)
    assert not [f for f in findings if f.rule_id.startswith("f5.bigip.auth.") or "history" in f.rule_id]


def test_gaia_bash_shell(tmp_path):
    text = ("# Language version: 15.0v1\nset hostname gw\nset password-controls deny-on-fail enable on\n"
            "add user ops uid 2000 homedir /home/ops\nset user ops shell /bin/bash\n")
    findings = _run(tmp_path, "CHECKPOINT_GAIA", text, process_checkpoint_gaia_conf)
    assert _rules(findings, "checkpoint.gaia.auth.user_bash_shell")


# --- SC-032 / SC-038 / SC-040 --------------------------------------------------------

def test_asa_logging_transport(tmp_path):
    cleartext = ASA + "logging enable\nlogging trap informational\nlogging host inside 192.0.2.50\n"
    secure = ASA + "logging enable\nlogging trap informational\nlogging host inside 192.0.2.50 tcp/6514 secure\n"
    assert _rules(_run(tmp_path, "ASA", cleartext, process_asa_conf), "cisco.asa.logging.remote_cleartext")
    assert not _rules(_run(tmp_path, "ASA", secure, process_asa_conf), "cisco.asa.logging.remote_cleartext")


@pytest.mark.parametrize("settings,rule", [
    ("    set enc-algorithm low\n", "fortinet.fortios.logging.remote_weak_tls"),
    ("    set certificate-verification disable\n", "fortinet.fortios.logging.remote_identity_unverified"),
])
def test_fortianalyzer_transport(tmp_path, settings, rule):
    text = FORTI + "config log fortianalyzer setting\n    set status enable\n    set server 192.0.2.60\n" + settings + "end\n"
    assert _rules(_run(tmp_path, "FORTIOS", text, process_fortios_conf), rule)
    disabled = text.replace("set status enable", "set status disable")
    assert not _rules(_run(tmp_path, "FORTIOS", disabled, process_fortios_conf), rule)


@pytest.mark.parametrize("settings,expected,basis", [
    ("    set mode a-p\n", True, FindingBasis.DOCUMENTED_DEFAULT),
    ("    set mode a-p\n    set authentication disable\n    set encryption disable\n", True, FindingBasis.EXPLICIT_VALUE),
    ("    set mode a-p\n    set authentication enable\n    set encryption enable\n", False, None),
    ("    set mode standalone\n", False, None),
])
def test_fortios_ha(tmp_path, settings, expected, basis):
    findings = _rules(_run(tmp_path, "FORTIOS", FORTI + "config system ha\n" + settings + "end\n", process_fortios_conf),
                      "fortinet.fortios.ha.heartbeat_protection")
    assert bool(findings) is expected
    if findings:
        assert findings[0].basis is basis


def test_fortios_usb_auto_install(tmp_path):
    enabled = FORTI + "config system auto-install\n    set auto-install-config enable\nend\n"
    assert _rules(_run(tmp_path, "FORTIOS", enabled, process_fortios_conf), "fortinet.fortios.system.usb_auto_install")
    default = FORTI + "config system auto-install\n    set default-config-file fgt.conf\nend\n"
    assert not _rules(_run(tmp_path, "FORTIOS", default, process_fortios_conf), "fortinet.fortios.system.usb_auto_install")


# --- SC-042 --------------------------------------------------------------------------

def test_f5_data_plane(tmp_path):
    text = F5 + ("ltm persistence cookie /Common/app_cookie {\n    cookie-encryption disabled\n    method insert\n}\n"
                 "ltm profile client-ssl /Common/app_ssl {\n    ciphers DEFAULT:RC4-SHA:!EXPORT\n}\n"
                 "ltm virtual /Common/vs_app {\n    destination /Common/192.0.2.10:443\n"
                 "    persist {\n        /Common/app_cookie {\n            default yes\n        }\n    }\n"
                 "    profiles {\n        /Common/app_ssl {\n            context clientside\n        }\n    }\n}\n")
    findings = _run(tmp_path, "F5_BIGIP", text, process_bigip_conf)
    weak = _rules(findings, "f5.bigip.ltm.clientssl_weak_cipher")
    assert weak and "RC4-SHA" in weak[0].observation and "EXPORT" not in weak[0].observation
    assert _rules(findings, "f5.bigip.ltm.cookie_unencrypted")
    fixed = text.replace("cookie-encryption disabled", "cookie-encryption required").replace(":RC4-SHA", "")
    findings = _run(tmp_path, "F5_BIGIP", fixed, process_bigip_conf)
    assert not _rules(findings, "f5.bigip.ltm.clientssl_weak_cipher")
    assert not _rules(findings, "f5.bigip.ltm.cookie_unencrypted")


# --- SC-043 --------------------------------------------------------------------------

def test_risky_catalogue():
    assert risky_labels("tcp", 23, 23) == {"Telnet"}
    assert risky_labels("tcp", 1, 65535) == set()  # broad ranges are broad-service findings
    assert "VNC" in risky_labels("tcp", 5901, 5901)
    assert is_risky_port(445) and not is_risky_port(443)


def test_asa_risky_service(tmp_path):
    text = ASA + ("access-list OUTSIDE extended permit tcp any host 192.0.2.10 eq telnet\n"
                  "access-list OUTSIDE extended permit tcp any host 192.0.2.12 eq https\n"
                  "access-list OUTSIDE extended permit tcp host 198.51.100.1 host 192.0.2.13 eq ftp\n"
                  "access-group OUTSIDE in interface outside\n")
    findings = _rules(_run(tmp_path, "ASA", text, process_asa_conf), "cisco.asa.acl.risky_service_exposure")
    assert len(findings) == 1 and "Telnet" in findings[0].observation


@pytest.mark.parametrize("prefix,expected", [
    ("access-list OUTSIDE extended deny tcp any host 192.0.2.10 eq telnet\n", False),
    ("access-list OUTSIDE extended deny tcp host 198.51.100.1 host 192.0.2.10 eq telnet\n", True),
    ("access-list OUTSIDE extended deny tcp any host 192.0.2.11 eq telnet\n", True),
    ("access-list OUTSIDE extended deny tcp any host 192.0.2.10 eq telnet inactive\n", True),
    ("access-list OUTSIDE extended permit tcp host 198.51.100.1 host 192.0.2.10 eq telnet\n"
     "access-list OUTSIDE extended deny tcp any host 192.0.2.10 eq telnet\n", True),
])
def test_asa_risky_service_respects_prior_deny(tmp_path, prefix, expected):
    text = ASA + prefix + ("access-list OUTSIDE extended permit tcp any host 192.0.2.10 eq telnet\n"
                           "access-group OUTSIDE in interface outside\n")
    findings = _rules(_run(tmp_path, "ASA", text, process_asa_conf),
                      "cisco.asa.acl.risky_service_exposure")
    assert bool(findings) is expected


def test_fortios_risky_service(tmp_path):
    text = FORTI + ('config firewall service custom\n    edit "TELNET"\n        set tcp-portrange 23\n    next\n'
                    '    edit "HTTPS"\n        set tcp-portrange 443\n    next\nend\n'
                    'config firewall policy\n    edit 1\n        set srcintf "wan1"\n        set dstintf "lan"\n'
                    '        set srcaddr "all"\n        set dstaddr "all"\n        set action accept\n'
                    '        set schedule "always"\n        set service "TELNET"\n    next\n'
                    '    edit 2\n        set srcintf "wan1"\n        set dstintf "lan"\n'
                    '        set srcaddr "all"\n        set dstaddr "all"\n        set action accept\n'
                    '        set schedule "always"\n        set service "HTTPS"\n    next\nend\n')
    findings = _rules(_run(tmp_path, "FORTIOS", text, process_fortios_conf), "fortinet.fortios.policy.risky_service_exposure")
    assert len(findings) == 1 and "Telnet" in findings[0].observation


@pytest.mark.parametrize("earlier,expected,explicit_schedule", [
    ("set action deny\n        set srcaddr all\n        set dstaddr all\n"
     "        set service TELNET", False, True),
    ("set action deny\n        set srcaddr all\n        set dstaddr all\n"
     "        set service TELNET", True, False),
    ("set action deny\n        set srcaddr all\n        set dstaddr all\n"
     "        set service HTTPS", True, True),
    ("set action deny\n        set srcaddr all\n        set dstaddr all\n"
     "        set service TELNET\n        set status disable", True, True),
    ("set action deny\n        set srcaddr LIMITED\n        set dstaddr all\n"
     "        set service TELNET", True, True),
])
def test_fortios_risky_service_respects_proven_prior_deny(tmp_path, earlier, expected, explicit_schedule):
    schedule_line = '        set schedule always\n' if explicit_schedule else ''
    text = (FORTI + 'config firewall service custom\n    edit "TELNET"\n'
            '        set tcp-portrange 23\n    next\n'
            '    edit "HTTPS"\n        set tcp-portrange 443\n    next\nend\n'
            'config firewall address\n    edit "LIMITED"\n'
            '        set subnet 198.51.100.0 255.255.255.0\n    next\nend\n'
            'config firewall policy\n    edit 1\n'
            '        set srcintf "wan1"\n        set dstintf "lan"\n'
            f'        {earlier}\n{schedule_line}    next\n'
            '    edit 2\n        set srcintf "wan1"\n        set dstintf "lan"\n'
            '        set srcaddr all\n        set dstaddr all\n'
            '        set action accept\n        set schedule always\n'
            '        set service TELNET\n    next\nend\n')
    findings = _rules(_run(tmp_path, "FORTIOS", text, process_fortios_conf),
                      "fortinet.fortios.policy.risky_service_exposure")
    assert bool(findings) is expected


def test_fortios_prior_accept_prevents_false_deny_shadow_proof(tmp_path):
    text = (FORTI + 'config firewall service custom\n    edit "TELNET"\n'
            '        set tcp-portrange 23\n    next\nend\n'
            'config firewall policy\n'
            '    edit 1\n        set srcintf wan1\n        set dstintf lan\n'
            '        set srcaddr all\n        set dstaddr all\n'
            '        set action accept\n        set schedule always\n'
            '        set service TELNET\n    next\n'
            '    edit 2\n        set srcintf wan1\n        set dstintf lan\n'
            '        set srcaddr all\n        set dstaddr all\n'
            '        set action deny\n        set schedule always\n'
            '        set service TELNET\n    next\n'
            '    edit 3\n        set srcintf wan1\n        set dstintf lan\n'
            '        set srcaddr all\n        set dstaddr all\n'
            '        set action accept\n        set schedule always\n'
            '        set service TELNET\n    next\nend\n')
    findings = _rules(_run(tmp_path, "FORTIOS", text, process_fortios_conf),
                      "fortinet.fortios.policy.risky_service_exposure")
    assert {"1", "3"}.issubset({
        name for finding in findings for name in ("1", "3")
        if f"policy '{name}'" in finding.observation
    })


def test_fortios_risky_service_uses_effective_move_order(tmp_path):
    body = ('config firewall service custom\n    edit "TELNET"\n'
            '        set tcp-portrange 23\n    next\nend\n'
            'config firewall policy\n'
            '    edit 1\n        set srcintf wan1\n        set dstintf lan\n'
            '        set srcaddr all\n        set dstaddr all\n'
            '        set action accept\n        set schedule always\n'
            '        set service TELNET\n    next\n'
            '    edit 2\n        set srcintf wan1\n        set dstintf lan\n'
            '        set srcaddr all\n        set dstaddr all\n'
            '        set action deny\n        set schedule always\n'
            '        set service TELNET\n    next\n')
    before = _rules(_run(tmp_path, "FORTIOS", FORTI + body + 'end\n', process_fortios_conf),
                    "fortinet.fortios.policy.risky_service_exposure")
    after = _rules(_run(tmp_path, "FORTIOS", FORTI + body + '    move 2 before 1\nend\n',
                        process_fortios_conf), "fortinet.fortios.policy.risky_service_exposure")
    assert len(before) == 1
    assert after == []
