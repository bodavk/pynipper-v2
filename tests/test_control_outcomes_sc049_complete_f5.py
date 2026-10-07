"""SC-049 completion for f5.bigip: outcomes for the remaining BIG-IP controls."""

import contextlib
import io

import pytest

from src.analyze.common.controls import CONTROLS, control_coverage
from src.analyze.f5.core.process_bigip_conf import process_bigip_conf
from src.devices.f5.bigip import F5BIGIPParser

F5 = tuple(control for control in CONTROLS if control.startswith("f5.bigip."))
BATCH5 = {
    "f5.bigip.self-ip-port-lockdown", "f5.bigip.root-login", "f5.bigip.ssh-source-restriction",
    "f5.bigip.httpd-source-restriction", "f5.bigip.password-policy-enforcement", "f5.bigip.snmp-community",
    "f5.bigip.remote-user-defaults",
}
COMPLETION = tuple(control for control in F5 if control not in BATCH5)


def run(tmp_path, body, version="16.1.5"):
    header = f"#TMSH-VERSION: {version}\n" if version else ""
    path = tmp_path / "bigip.conf"
    path.write_text(header + "sys global-settings {\n    hostname bigip1\n}\n" + body, encoding="utf-8")
    parser = F5BIGIPParser(str(path))
    with contextlib.redirect_stdout(io.StringIO()):
        findings = process_bigip_conf(parser)
    rules = {issue.rule_id for issue in findings.values()}
    coverage = {item["control-id"]: item for item in control_coverage(parser)["results"]}
    for control in F5:
        outcome = coverage[control]["outcome"]
        # Every F5 control records an outcome, and a finding exactly when a mapped rule fired.
        assert outcome != "not-recorded", control
        assert (outcome == "finding") == bool(set(CONTROLS[control].rule_ids) & rules), (control, outcome)
    return coverage


def outcome(tmp_path, control, body, version="16.1.5"):
    return run(tmp_path, body, version)[control]["outcome"]


def instances(tmp_path, control, body, version="16.1.5"):
    return {row["instance-key"]: row["outcome"] for row in run(tmp_path, body, version)[control]["instances"]}


def test_completion_controls_are_registered():
    assert len(COMPLETION) == 24
    for control in COMPLETION:
        definition = CONTROLS[control]
        assert definition.version == 1 and definition.rule_ids and definition.device_types == frozenset({"F5_BIGIP"})


def test_every_recorded_f5_control_is_registered_and_rule_ids_exist():
    import re
    from pathlib import Path
    source = Path("src/analyze/f5/plugins/bigip_checks_plugin.py").read_text(encoding="utf-8")
    emitted = set(re.findall(r'"(f5\.bigip\.[a-z0-9_]+\.[a-z0-9_.]+)"', source))
    for control in F5:
        assert set(CONTROLS[control].rule_ids) <= emitted, control
    recorded = set(re.findall(r'"(f5\.bigip\.[a-z0-9-]+)"', source))
    assert recorded <= set(CONTROLS), recorded - set(CONTROLS)
    assert set(F5) <= recorded


def test_minimal_export_records_every_control(tmp_path):
    run(tmp_path, "")
    run(tmp_path, "", version=None)


SSHD = "sys sshd {{\n{0}}}\n"


@pytest.mark.parametrize("version,body,expected", [
    ("16.1.5", SSHD.format("    login enabled\n    inactivity-timeout 0\n"), "finding"),
    ("16.1.5", SSHD.format("    allow { 192.0.2.0/24 }\n"), "finding"),
    ("16.1.5", SSHD.format("    inactivity-timeout 600\n"), "evaluated-no-finding"),
    ("16.1.5", SSHD.format("    login disabled\n"), "not-applicable"),
    ("12.1.0", SSHD.format("    allow { 192.0.2.0/24 }\n"), "unknown"),
    ("16.1.5", "", "unknown"),
])
def test_ssh_idle_timeout(tmp_path, version, body, expected):
    assert outcome(tmp_path, "f5.bigip.ssh-idle-timeout", body, version) == expected


@pytest.mark.parametrize("version,extra,expected", [
    ("16.1.5", "    console-inactivity-timeout 0\n", "finding"),
    ("16.1.5", "", "finding"),
    ("16.1.5", "    console-inactivity-timeout 600\n", "evaluated-no-finding"),
    ("12.1.0", "", "unknown"),
])
def test_console_idle_timeout(tmp_path, version, extra, expected):
    path_body = "sys global-settings {\n" + extra + "}\n"
    assert outcome(tmp_path, "f5.bigip.console-idle-timeout", path_body, version) == expected


@pytest.mark.parametrize("version,body,expected", [
    ("16.1.5", "cli global-settings {\n    audit disabled\n}\n", "finding"),
    ("16.1.5", "cli global-settings {\n    audit enabled\n}\n", "evaluated-no-finding"),
    ("16.1.5", "cli global-settings {\n    idle-timeout 10\n}\n", "evaluated-no-finding"),
    ("12.1.0", "cli global-settings {\n    idle-timeout 10\n}\n", "unknown"),
    ("16.1.5", "", "unknown"),
])
def test_cli_audit(tmp_path, version, body, expected):
    assert outcome(tmp_path, "f5.bigip.cli-audit", body, version) == expected


HTTPD = "sys httpd {{\n    allow {{ 192.0.2.0/24 }}\n{0}}}\n"


@pytest.mark.parametrize("control,version,extra,expected", [
    ("f5.bigip.httpd-tls-protocol", "16.1.5", "    ssl-protocol \"all -SSLv2 -SSLv3\"\n", "finding"),
    ("f5.bigip.httpd-tls-protocol", "16.1.5", "", "finding"),
    ("f5.bigip.httpd-tls-protocol", "16.1.5", "    ssl-protocol \"all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1\"\n",
     "evaluated-no-finding"),
    ("f5.bigip.httpd-tls-protocol", "18.0.0", "", "unknown"),
    ("f5.bigip.httpd-cipher-suite", "16.1.5", "    ssl-ciphersuite DES-CBC3-SHA:ECDHE-RSA-AES128-GCM-SHA256\n", "finding"),
    ("f5.bigip.httpd-cipher-suite", "16.1.5", "", "finding"),
    ("f5.bigip.httpd-cipher-suite", "16.1.5", "    ssl-ciphersuite ECDHE-RSA-AES128-GCM-SHA256\n", "evaluated-no-finding"),
    ("f5.bigip.httpd-cipher-suite", "16.1.5", "    ssl-ciphersuite DEFAULT\n", "unknown"),
    ("f5.bigip.httpd-cipher-suite", "12.1.0", "", "unknown"),
])
def test_httpd_tls(tmp_path, control, version, extra, expected):
    assert outcome(tmp_path, control, HTTPD.format(extra), version) == expected


@pytest.mark.parametrize("control", ["f5.bigip.httpd-tls-protocol", "f5.bigip.httpd-cipher-suite"])
def test_httpd_tls_not_applicable_and_unknown(tmp_path, control):
    assert outcome(tmp_path, control, "sys httpd {\n    allow none\n}\n") == "not-applicable"
    assert outcome(tmp_path, control, "") == "unknown"


STRONG = "Ciphers aes256-gcm@openssh.com\\nMACs hmac-sha2-256\\nKexAlgorithms curve25519-sha256"


@pytest.mark.parametrize("body,expected", [
    (SSHD.format('    include "Ciphers aes128-cbc,aes256-ctr"\n'), "finding"),
    (SSHD.format(f'    include "{STRONG}"\n'), "evaluated-no-finding"),
    (SSHD.format('    include "Ciphers aes256-ctr"\n'), "unknown"),
    (SSHD.format("    login disabled\n"), "not-applicable"),
    ("", "unknown"),
])
def test_ssh_algorithms(tmp_path, body, expected):
    assert outcome(tmp_path, "f5.bigip.ssh-algorithms", body) == expected


PP = "auth password-policy {{\n{0}}}\n"


@pytest.mark.parametrize("control,version,extra,expected", [
    ("f5.bigip.password-minimum-length", "16.1.5", "    policy-enforcement enabled\n    minimum-length 0\n", "finding"),
    ("f5.bigip.password-minimum-length", "16.1.5", "    policy-enforcement enabled\n    minimum-length 12\n",
     "evaluated-no-finding"),
    # Omitted minimum-length: documented default 6.
    ("f5.bigip.password-minimum-length", "16.1.5", "    policy-enforcement enabled\n", "evaluated-no-finding"),
    ("f5.bigip.password-minimum-length", "13.1.0", "    password-memory 3\n", "not-applicable"),
    ("f5.bigip.password-minimum-length", "16.1.5", "    minimum-length 0\n", "unknown"),
    ("f5.bigip.password-history", "16.1.5", "    policy-enforcement enabled\n", "finding"),
    ("f5.bigip.password-history", "16.1.5", "    policy-enforcement enabled\n    password-memory 0\n", "finding"),
    ("f5.bigip.password-history", "16.1.5", "    policy-enforcement enabled\n    password-memory 5\n",
     "evaluated-no-finding"),
    ("f5.bigip.password-history", "16.1.5", "    password-memory 5\n", "evaluated-no-finding"),
    ("f5.bigip.password-history", "16.1.5", "    policy-enforcement disabled\n", "not-applicable"),
    ("f5.bigip.password-history", "16.1.5", "    minimum-length 9\n", "unknown"),
])
def test_password_policy(tmp_path, control, version, extra, expected):
    assert outcome(tmp_path, control, PP.format(extra), version) == expected


@pytest.mark.parametrize("control", ["f5.bigip.password-minimum-length", "f5.bigip.password-history"])
def test_password_policy_absent_is_unknown(tmp_path, control):
    assert outcome(tmp_path, control, "") == "unknown"


SOURCE = "auth source {{\n{0}}}\n"
RADIUS = "auth radius /Common/system-auth {{\n    servers {0}\n}}\n"


@pytest.mark.parametrize("control,body,expected", [
    ("f5.bigip.remote-auth-fallback", SOURCE.format("    type radius\n    fallback true\n"), "finding"),
    ("f5.bigip.remote-auth-fallback", SOURCE.format("    type radius\n    fallback false\n"), "evaluated-no-finding"),
    ("f5.bigip.remote-auth-fallback", SOURCE.format("    type radius\n"), "evaluated-no-finding"),
    ("f5.bigip.remote-auth-fallback", SOURCE.format("    type local\n"), "not-applicable"),
    ("f5.bigip.remote-auth-fallback", "", "unknown"),
    ("f5.bigip.remote-auth-servers", SOURCE.format("    type radius\n") + RADIUS.format("none"), "finding"),
    ("f5.bigip.remote-auth-servers", SOURCE.format("    type radius\n") + RADIUS.format("{ /Common/r1 }"),
     "evaluated-no-finding"),
    ("f5.bigip.remote-auth-servers", SOURCE.format("    type radius\n"), "unknown"),
    ("f5.bigip.remote-auth-servers", SOURCE.format("    type local\n"), "not-applicable"),
    ("f5.bigip.remote-auth-servers", "", "unknown"),
])
def test_remote_auth(tmp_path, control, body, expected):
    assert outcome(tmp_path, control, body) == expected


ADMIN_HASH = "$6$abcdefgh$" + "x" * 86


def test_local_credentials_per_user(tmp_path):
    body = ("auth user ops {\n    password secret1\n    shell tmsh\n}\n"
            f"auth user audit {{\n    encrypted-password {ADMIN_HASH}\n    shell tmsh\n}}\n"
            "auth user masked {\n    encrypted-password <redacted>\n}\n")
    assert instances(tmp_path, "f5.bigip.local-credentials", body) == {
        "/Common/ops": "finding", "/Common/audit": "evaluated-no-finding", "/Common/masked": "unknown"}


def test_local_credentials_absent_and_default(tmp_path):
    assert outcome(tmp_path, "f5.bigip.local-credentials", "") == "unknown"
    assert outcome(tmp_path, "f5.bigip.local-credentials", "auth user admin {\n    password admin\n}\n") == "finding"


MONITOR = "ltm monitor http /Common/m1 {{\n    send \"{0}\"\n}}\n"


@pytest.mark.parametrize("body,expected", [
    (MONITOR.format("GET / HTTP/1.1\\r\\nAuthorization: Basic dXNlcjpwYXNz\\r\\n"), "finding"),
    (MONITOR.format("GET / HTTP/1.1\\r\\n"), "evaluated-no-finding"),
    ("", "not-applicable"),
])
def test_monitor_credentials(tmp_path, body, expected):
    assert outcome(tmp_path, "f5.bigip.monitor-credentials", body) == expected


def _snmp(inner):
    return "sys snmp {\n" + inner + "}\n"


COMM = "    communities { /Common/c1 { community-name mon1 access ro } }\n"
REACH = "    allowed-addresses { 192.0.2.0/24 }\n"


@pytest.mark.parametrize("version,body,expected", [
    ("16.1.5", _snmp(REACH + COMM), "finding"),
    ("16.1.5", _snmp("    traps { /Common/t1 { host 192.0.2.5 version 2c } }\n"), "finding"),
    ("16.1.5", _snmp(REACH + COMM + "    snmpv1 disable\n    snmpv2c disable\n"), "evaluated-no-finding"),
    ("16.1.5", _snmp("    traps { /Common/t1 { host 192.0.2.5 version 3 } }\n"), "evaluated-no-finding"),
    ("12.1.0", _snmp(REACH + COMM), "unknown"),
    ("16.1.5", _snmp("    traps { /Common/t1 { host 192.0.2.5 } }\n"), "unknown"),
    ("16.1.5", _snmp(""), "not-applicable"),
    ("16.1.5", "", "unknown"),
])
def test_snmp_legacy_version(tmp_path, version, body, expected):
    assert outcome(tmp_path, "f5.bigip.snmp-legacy-version", body, version) == expected


USERS = ("    users {\n"
         "        /Common/u1 { username u1 security-level auth-privacy auth-protocol sha privacy-protocol aes }\n"
         "        /Common/u2 { username u2 security-level auth-no-privacy auth-protocol sha }\n"
         "        /Common/u3 { username u3 security-level auth-privacy auth-protocol md5 privacy-protocol aes }\n"
         "        /Common/u4 { username u4 }\n"
         "    }\n")


def test_snmpv3_users_per_user(tmp_path):
    assert instances(tmp_path, "f5.bigip.snmpv3-users", _snmp(REACH + USERS)) == {
        "/Common/u1": "evaluated-no-finding", "/Common/u2": "finding", "/Common/u3": "finding", "/Common/u4": "unknown"}


@pytest.mark.parametrize("body,expected", [
    (_snmp(USERS), "not-applicable"),
    (_snmp(REACH), "not-applicable"),
    ("", "unknown"),
])
def test_snmpv3_users_other_states(tmp_path, body, expected):
    assert outcome(tmp_path, "f5.bigip.snmpv3-users", body) == expected


def test_ntp_authentication(tmp_path):
    body = ('sys ntp {\n    servers { 192.0.2.10 }\n'
            '    include "server 192.0.2.11 key 5\\ntrustedkey 5\\nserver 192.0.2.12"\n}\n')
    assert instances(tmp_path, "f5.bigip.ntp-authentication", body) == {
        "tmsh:192.0.2.10": "finding", "include:192.0.2.11": "unknown", "include:192.0.2.12": "finding"}
    assert outcome(tmp_path, "f5.bigip.ntp-authentication", "sys ntp {\n    timezone UTC\n}\n") == "not-applicable"
    assert outcome(tmp_path, "f5.bigip.ntp-authentication", "") == "unknown"


def _db(name, value):
    return f'sys db {name} {{\n    value "{value}"\n}}\n'


PROV = "sys provision {0} {{\n    level nominal\n}}\n"


@pytest.mark.parametrize("body,expected", [
    (PROV.format("afm"), "finding"),
    (PROV.format("afm") + _db("tm.fw.defaultaction", "drop"), "evaluated-no-finding"),
    (PROV.format("afm") + _db("tm.fw.defaultaction", "odd"), "unknown"),
    (PROV.format("ltm"), "not-applicable"),
    ("", "unknown"),
])
def test_afm_default_action(tmp_path, body, expected):
    assert outcome(tmp_path, "f5.bigip.afm-default-action", body) == expected


def _asm(name, extra):
    return f"asm policy /Common/{name} {{\n{extra}}}\n"


def _ltm_policy(name, asm):
    return (f"ltm policy /Common/{name} {{\n    rules {{\n        r1 {{\n            actions {{\n"
            f"                0 {{\n                    asm\n                    enable\n                    policy /Common/{asm}\n"
            "                }\n            }\n        }\n    }\n}\n")


def _virtual(name, extra=""):
    return (f"ltm virtual /Common/{name} {{\n    destination /Common/10.0.0.{len(name)}:443\n"
            f"    ip-protocol tcp\n    source 192.0.2.0/24\n{extra}}}\n")


def test_asm_enforcement_per_binding(tmp_path):
    body = (PROV.format("asm")
            + _asm("a1", "    active\n    blocking-mode enabled\n") + _asm("a2", "    active\n    blocking-mode disabled\n")
            + _asm("a3", "    active\n") + _asm("a4", "")
            + "".join(_ltm_policy(f"p{i}", f"a{i}") for i in range(1, 5))
            + "".join(_virtual("v" * i, f"    policies {{\n        /Common/p{i} {{ }}\n    }}\n") for i in range(1, 5)))
    assert instances(tmp_path, "f5.bigip.asm-enforcement", body) == {
        "/Common/v|/Common/a1": "evaluated-no-finding", "/Common/vv|/Common/a2": "finding",
        "/Common/vvv|/Common/a3": "unknown", "/Common/vvvv|/Common/a4": "finding"}
    assert outcome(tmp_path, "f5.bigip.asm-enforcement", PROV.format("ltm")) == "not-applicable"
    assert outcome(tmp_path, "f5.bigip.asm-enforcement", "") == "unknown"


def _peer(name, extra):
    return f"net ipsec ike-peer /Common/{name} {{\n{extra}}}\n"


def test_ike_peers(tmp_path):
    body = (_peer("p1", "    version { v1 }\n    mode aggressive\n    phase1-auth-method pre-shared-key\n")
            + _peer("p2", "    version { v2 }\n")
            + _peer("p3", "    version { v1 }\n    mode main\n")
            + _peer("p4", "    version { v1 }\n")
            + _peer("p5", "    state disabled\n"))
    assert instances(tmp_path, "f5.bigip.ike-version", body) == {
        "/Common/p1": "finding", "/Common/p2": "evaluated-no-finding", "/Common/p3": "finding",
        "/Common/p4": "finding", "/Common/p5": "not-applicable"}
    assert instances(tmp_path, "f5.bigip.ike-aggressive-mode", body) == {
        "/Common/p1": "finding", "/Common/p2": "evaluated-no-finding", "/Common/p3": "evaluated-no-finding",
        "/Common/p4": "unknown", "/Common/p5": "not-applicable"}
    assert outcome(tmp_path, "f5.bigip.ike-version", "") == "not-applicable"
    assert outcome(tmp_path, "f5.bigip.ike-version", _peer("p1", "    version { v1 }\n"), version=None) == "unknown"


def _client(name, extra):
    return f"ltm profile client-ssl /Common/{name} {{\n{extra}}}\n"


def _bind(virtual, profile, context="clientside"):
    return _virtual(virtual, f"    profiles {{\n        /Common/{profile} {{\n            context {context}\n        }}\n    }}\n")


def test_clientssl_cleartext_per_binding(tmp_path):
    body = (_client("c1", "    mode enabled\n    allow-non-ssl enabled\n")
            + _client("c2", "    allow-non-ssl disabled\n")
            + _client("c3", "    defaults-from /Common/clientssl\n")
            + _client("c4", "    allow-non-ssl enabled\n")
            + _client("c5", "    mode disabled\n    allow-non-ssl enabled\n")
            + _bind("v", "c1") + _bind("vv", "c2") + _bind("vvv", "c3") + _bind("vvvv", "c4") + _bind("vvvvv", "c5")
            + _bind("w", "clientssl") + _bind("ww", "tcp"))
    assert instances(tmp_path, "f5.bigip.clientssl-cleartext", body) == {
        "/Common/v|/Common/c1": "finding", "/Common/vv|/Common/c2": "evaluated-no-finding",
        "/Common/vvv|/Common/c3": "evaluated-no-finding", "/Common/vvvv|/Common/c4": "unknown",
        "/Common/vvvvv|/Common/c5": "not-applicable", "/Common/w|/Common/clientssl": "evaluated-no-finding"}
    assert outcome(tmp_path, "f5.bigip.clientssl-cleartext", "") == "not-applicable"


def test_clientssl_tls_per_binding(tmp_path):
    body = (_client("c1", "    ciphers DEFAULT:+RC4-SHA\n")
            + _client("c2", "    options { no-tlsv1 no-tlsv1.1 }\n")
            + _client("c3", "    ciphers DEFAULT\n")
            + _client("c4", "    ciphers ECDHE+AES-GCM\n")
            + _bind("v", "c1") + _bind("vv", "c2") + _bind("vvv", "c3") + _bind("vvvv", "c4"))
    assert instances(tmp_path, "f5.bigip.clientssl-tls", body) == {
        "/Common/v|/Common/c1": "finding", "/Common/vv|/Common/c2": "evaluated-no-finding",
        "/Common/vvv|/Common/c3": "finding", "/Common/vvvv|/Common/c4": "unknown"}
    assert outcome(tmp_path, "f5.bigip.clientssl-tls", _client("c2", "") + _bind("v", "c2"), version=None) == "unknown"
    assert outcome(tmp_path, "f5.bigip.clientssl-tls", "") == "not-applicable"


def _cookie(name, extra):
    return f"ltm persistence cookie /Common/{name} {{\n{extra}}}\n"


def _persist(virtual, profile):
    return _virtual(virtual, f"    persist {{\n        /Common/{profile} {{\n            default yes\n        }}\n    }}\n")


def test_cookie_encryption_per_binding(tmp_path):
    body = (_cookie("k1", "    cookie-encryption disabled\n") + _cookie("k2", "    cookie-encryption required\n")
            + _cookie("k3", "") + _cookie("k4", "    method hash\n")
            + _cookie("k5", "    defaults-from /Common/k1\n    cookie-encryption bogus\n")
            + _persist("v", "k1") + _persist("vv", "k2") + _persist("vvv", "k3") + _persist("vvvv", "k4")
            + _persist("vvvvv", "k5"))
    assert instances(tmp_path, "f5.bigip.cookie-encryption", body) == {
        "/Common/v|/Common/k1": "finding", "/Common/vv|/Common/k2": "evaluated-no-finding",
        "/Common/vvv|/Common/k3": "finding", "/Common/vvvv|/Common/k4": "not-applicable",
        "/Common/vvvvv|/Common/k5": "unknown"}
    assert outcome(tmp_path, "f5.bigip.cookie-encryption", "") == "not-applicable"


def _server(name, extra):
    return f"ltm profile server-ssl /Common/{name} {{\n{extra}}}\n"


def test_serverssl_validation_per_binding(tmp_path):
    body = (_server("s1", "") + _server("s2", "    peer-cert-mode require\n") + _server("s3", "    peer-cert-mode request\n")
            + _bind("v", "s1", "serverside") + _bind("vv", "s2", "serverside") + _bind("vvv", "s3", "serverside"))
    assert instances(tmp_path, "f5.bigip.serverssl-validation", body) == {
        "/Common/v|/Common/s1": "finding", "/Common/vv|/Common/s2": "evaluated-no-finding",
        "/Common/vvv|/Common/s3": "unknown"}
    assert outcome(tmp_path, "f5.bigip.serverssl-validation", "") == "not-applicable"


def _endpoint(name, port, source="0.0.0.0/0", protocol="    ip-protocol tcp\n"):
    return (f"ltm virtual /Common/{name} {{\n    destination /Common/10.0.0.1:{port}\n{protocol}"
            + (f"    source {source}\n" if source else "") + "}\n")


def test_virtual_risky_services(tmp_path):
    body = (_endpoint("e1", "3389") + _endpoint("e2", "443") + _endpoint("e3", "3389", "192.0.2.0/24")
            + _endpoint("e4", "3389", protocol=""))
    assert instances(tmp_path, "f5.bigip.virtual-risky-services", body, version="18.0.0") == {
        "/Common/e1": "finding", "/Common/e2": "evaluated-no-finding", "/Common/e3": "evaluated-no-finding",
        "/Common/e4": "unknown"}
    assert outcome(tmp_path, "f5.bigip.virtual-risky-services", "") == "not-applicable"
