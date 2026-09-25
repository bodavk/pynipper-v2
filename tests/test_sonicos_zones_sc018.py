"""SC-018: SonicOS per-zone security services, documented global service blocks,
and non-administrator secrets for --show-secrets (SonicOS/X 7 E-CLI Reference Guide)."""

import json

import pytest

from src.analyze.sonicwall.core.process_sonicos_conf import process_sonicos_conf
from src.devices.sonicwall.sonicos import SonicOSParser
from src.report.secret_evidence import collect_secret_evidence

HEADER = 'firmware-version "SonicOS 7.1.2-7019"\nfirewall-name "fw1"\n'
LAN = "interface X0\n  zone LAN\n  ip-address 192.0.2.1\n"
GLOBAL_ON = "intrusion-prevention\n  enable\n  exit\ngateway-antivirus\n  enable\n  exit\nanti-spyware\n  enable\n  exit\n"
ZONE_RULE = "sonicwall.sonicos.zone.security_service_disabled"


def _parse(tmp_path, body):
    path = tmp_path / "fw.txt"
    path.write_text(HEADER + body, encoding="utf-8")
    return SonicOSParser(str(path))


def _rules(parser):
    return [item for item in process_sonicos_conf(parser).values()
            if item.rule_id in {ZONE_RULE, "sonicwall.sonicos.security_services.disabled"}]


def test_documented_global_blocks_are_read(tmp_path):
    parser = _parse(tmp_path, GLOBAL_ON + "capture-atp\n  no enable\n  exit\n")
    services = parser.get_security_services()
    assert services["intrusion-prevention"] is True
    assert services["gateway-anti-virus"] is True
    assert services["anti-spyware"] is True
    assert services["capture-atp"] is False


def test_zone_in_use_with_disabled_service_is_reported(tmp_path):
    parser = _parse(tmp_path, LAN + GLOBAL_ON + 'zone "LAN"\n  no intrusion-prevention\n  gateway-anti-virus\n  exit\n')
    findings = _rules(parser)
    assert [item.rule_id for item in findings] == [ZONE_RULE]
    assert "intrusion prevention" in findings[0].observation and "X0" in findings[0].observation
    assert findings[0].evidence_locations[1].line_number == 16


@pytest.mark.parametrize("body", [
    GLOBAL_ON + 'zone "DMZ"\n  no intrusion-prevention\n  exit\n',  # no interface in the zone
    LAN + GLOBAL_ON + 'zone "LAN"\n  intrusion-prevention\n  exit\n',
    LAN + GLOBAL_ON + 'zone "LAN"\n  exit\n',  # nothing exported: default not assumed
])
def test_not_reported(tmp_path, body):
    assert _rules(_parse(tmp_path, body)) == []


def test_globally_disabled_service_is_reported_once_globally(tmp_path):
    parser = _parse(tmp_path, LAN + "intrusion-prevention\n  no enable\n  exit\n"
                    'zone "LAN"\n  no intrusion-prevention\n  exit\n')
    assert [item.rule_id for item in _rules(parser)] == ["sonicwall.sonicos.security_services.disabled"]


def test_show_secrets_includes_non_administrator_secrets(tmp_path):
    body = (
        "radius\n  server server1 ip 192.0.2.10 port 1812 secret SynRadius1\n  exit\n"
        "snmp\n  community SynCommunity1\n  exit\n"
        "administration\n  password minimum-length 14\n  exit\n"
        'vpn policy site-to-site "T1"\n  auth-method shared-secret\n  shared-secret SynPsk1\n  exit\n'
    )
    entries = collect_secret_evidence(_parse(tmp_path, body))["entries"]
    assert [(item["line-number"], item["context"]) for item in entries] == [
        (4, "radius_secret"), (7, "snmp_community"), (14, "ike_pre_shared_key"),
    ]
    rendered = json.dumps(entries)
    assert "SynPsk1" in rendered and "minimum-length" not in rendered
