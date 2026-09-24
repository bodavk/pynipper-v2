"""SC-015/SC-016 first stage: F5 management TLS settings and SNMP access."""

import json

import pytest

from src.analyze.f5.core.process_bigip_conf import process_bigip_conf
from src.devices.f5.bigip import (
    F5BIGIPParser, resolve_ssl_protocols, weak_literal_cipher_suites,
)
from src.main import main


def _parse(tmp_path, content):
    path = tmp_path / "device.scf"
    path.write_text(content, encoding="utf-8")
    return F5BIGIPParser(str(path))


def _ids(parser):
    return sorted(finding.rule_id for finding in process_bigip_conf(parser).values())


@pytest.mark.parametrize(
    "value,expected",
    [
        ("all -SSLv2 -SSLv3", ("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")),
        ("all -SSLv2 -SSLv3 -TLSv1", ("TLSv1.1", "TLSv1.2", "TLSv1.3")),
        ("all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1", ("TLSv1.2", "TLSv1.3")),
        ("TLSv1.2", ("TLSv1.2",)),
        ("TLSv1.2 +SSLv3", ("TLSv1.2", "SSLv3")),
        ("+TLSv1 TLSv1.2", ("TLSv1.2",)),  # a token without a sign replaces the set
        ("all -tlsv1", ("TLSv1.1", "TLSv1.2", "TLSv1.3")),
        ("all -SSLv2 SHOULD-FAIL", None),
        ("", None),
    ],
)
def test_mod_ssl_protocol_resolution(value, expected):
    assert resolve_ssl_protocols(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("ECDHE-RSA-AES128-GCM-SHA256:DES-CBC3-SHA", ("DES-CBC3-SHA",)),
        ("ECDHE-RSA-DES-CBC3-SHA:RC4-SHA:NULL-SHA256", ("ECDHE-RSA-DES-CBC3-SHA", "RC4-SHA", "NULL-SHA256")),
        ("ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384", ()),
        ("DEFAULT:!3DES", None),
        ("ECDHE-RSA-AES128-GCM-SHA256:!DES-CBC3-SHA", None),
    ],
)
def test_literal_cipher_list_evaluation(value, expected):
    assert weak_literal_cipher_suites(value) == expected


def test_legacy_protocols_and_weak_suites_are_reported(tmp_path):
    parser = _parse(tmp_path, """sys httpd {
    allow { 192.0.2.0/24 }
    ssl-protocol "all -SSLv2 -SSLv3"
    ssl-ciphersuite ECDHE-RSA-AES128-GCM-SHA256:DES-CBC3-SHA
}
""")
    findings = {item.rule_id: item for item in process_bigip_conf(parser).values()}
    legacy = findings["f5.bigip.http.legacy_tls_protocol"]
    assert "TLSv1, TLSv1.1" in legacy.observation
    assert legacy.evidence_locations[0].line_number == 3
    assert "DES-CBC3-SHA" in findings["f5.bigip.http.weak_cipher_suite"].observation


@pytest.mark.parametrize(
    "body",
    [
        'allow { 192.0.2.0/24 } ssl-protocol "all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1"',
        'allow { 192.0.2.0/24 } ssl-protocol "TLSv1.2 +TLSv1.3"',
        'allow none ssl-protocol "all -SSLv2 -SSLv3"',  # no management clients admitted
        'allow { 192.0.2.0/24 } ssl-protocol "all -SSLv2 -SSLv3 BOGUS"',  # unknown token
        'allow { 192.0.2.0/24 } ssl-ciphersuite DEFAULT:DES-CBC3-SHA',  # keyword list not proven
        'allow { 192.0.2.0/24 }',  # omitted values use release defaults: not graded
    ],
)
def test_secure_unknown_and_unreachable_tls_settings_are_not_reported(tmp_path, body):
    parser = _parse(tmp_path, f"sys httpd {{ {body} }}\n")
    assert not {rule for rule in _ids(parser) if rule.startswith("f5.bigip.http.")} & {
        "f5.bigip.http.legacy_tls_protocol", "f5.bigip.http.weak_cipher_suite",
    }


def test_last_ssl_protocol_setting_wins(tmp_path):
    parser = _parse(tmp_path, """sys httpd { allow { 192.0.2.0/24 } ssl-protocol "all -SSLv2 -SSLv3" }
sys httpd { ssl-protocol "all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1" }
""")
    assert "f5.bigip.http.legacy_tls_protocol" not in _ids(parser)


SNMP_EXPOSED = """sys snmp {
    allowed-addresses { 0.0.0.0/0 }
    communities {
        /Common/comm-public { community-name public access ro source default }
        /Common/ops { community-name SyntheticCommunitySecret access rw source 192.0.2.40 }
    }
    users {
        /Common/noauth { username noauth security-level no-auth-no-privacy access ro }
        /Common/legacy {
            username legacy auth-protocol md5 auth-password SyntheticAuthSecret
            privacy-protocol des privacy-password SyntheticPrivSecret
            security-level auth-privacy access ro
        }
        /Common/strong {
            username strong auth-protocol sha auth-password SyntheticAuthSecret2
            privacy-protocol aes privacy-password SyntheticPrivSecret2
            security-level auth-privacy access ro
        }
    }
}
"""


def test_exposed_snmp_access_is_reported_per_object(tmp_path):
    parser = _parse(tmp_path, SNMP_EXPOSED)
    findings = list(process_bigip_conf(parser).values())
    by_rule = {}
    for finding in findings:
        by_rule.setdefault(finding.rule_id, []).append(finding)
    assert sorted(by_rule) == [
        "f5.bigip.snmp.community_access",
        "f5.bigip.snmp.default_community",
        "f5.bigip.snmp.v3_security",
        "f5.bigip.snmp.v3_weak_algorithm",
        "f5.bigip.snmp.write_community",
    ]
    assert "comm-public" in by_rule["f5.bigip.snmp.default_community"][0].observation
    assert "ops" in by_rule["f5.bigip.snmp.write_community"][0].observation
    assert "noauth" in by_rule["f5.bigip.snmp.v3_security"][0].observation
    assert "legacy" in by_rule["f5.bigip.snmp.v3_weak_algorithm"][0].observation
    rendered = str([finding.to_dict() for finding in findings]) + str(parser.get_native_config())
    for secret in ("SyntheticCommunitySecret", "SyntheticAuthSecret", "SyntheticPrivSecret"):
        assert secret not in rendered


@pytest.mark.parametrize(
    "allowed,expected",
    [
        ("allowed-addresses { 127. }", []),
        ("allowed-addresses { 127.0.0.1 ::1 }", []),
        ("allowed-addresses none", []),
        ("", []),  # scope not exported: documented default is not graded
        ("allowed-addresses { 192.0.2.0/24 }", [
            "f5.bigip.snmp.default_community", "f5.bigip.snmp.write_community",
        ]),
    ],
)
def test_snmp_findings_require_an_exported_reachable_client_scope(tmp_path, allowed, expected):
    parser = _parse(tmp_path, f"""sys snmp {{
    {allowed}
    communities {{ /Common/c1 {{ community-name private access rw }} }}
}}
""")
    assert _ids(parser) == expected


def test_community_named_like_a_keyword_is_parsed_by_position(tmp_path):
    parser = _parse(tmp_path, """sys snmp {
    allowed-addresses { 192.0.2.0/24 }
    communities { /Common/c1 { community-name access access ro } }
}
""")
    community = parser.get_snmp_communities()[0]
    assert (community.default_name, community.access) == (False, "ro")
    assert _ids(parser) == []


def test_public_reports_keep_snmp_secrets_out(tmp_path):
    source = tmp_path / "device.scf"
    source.write_text(SNMP_EXPOSED, encoding="utf-8")
    for output_type in ("JSON", "HTML"):
        report = tmp_path / f"report.{output_type.lower()}"
        assert main(["-d", "f5-bigip", "-i", str(source), "-o", output_type, "-f", str(report), "-x"]) == 0
        text = report.read_text(encoding="utf-8")
        for secret in ("SyntheticCommunitySecret", "SyntheticAuthSecret", "SyntheticPrivSecret"):
            assert secret not in text
        if output_type == "JSON":
            rules = {item["rule_id"] for item in json.loads(text)["security-audit"].values()}
            assert "f5.bigip.snmp.write_community" in rules
