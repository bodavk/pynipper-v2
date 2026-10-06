"""CIS FortiGate 4.3.1/4.3.2/3.3: DNS filter botnet blocking and logging, Tor ISDB deny."""

import contextlib
import io

import pytest

from src.analyze.common.issue import FindingBasis
from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.devices.fortinet.fortios import FortiOSParser

HEADER = "#config-version=FGT60F-7.4.1-FW-build1517-230606:opmode=0:vdom=0:user=admin\n"
POLICY = ('config firewall policy\n edit 1\n set name "out"\n set srcintf "lan"\n set dstintf "wan1"\n'
          ' set srcaddr "all"\n set dstaddr "all"\n set action accept\n set schedule "always"\n set service "ALL"\n'
          ' set utm-status enable\n set dnsfilter-profile "dns1"\n next\nend\n')


def _findings(tmp_path, profile, extra=""):
    path = tmp_path / "f.conf"
    path.write_text(HEADER + "config dnsfilter profile\n edit \"dns1\"\n" + profile + " next\nend\n" + POLICY + extra,
                    encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        return {f.rule_id: f for f in process_fortios_conf(FortiOSParser(str(path))).values()}


@pytest.mark.parametrize("profile,basis", [
    ("", FindingBasis.DOCUMENTED_DEFAULT),
    (" set block-botnet disable\n", FindingBasis.EXPLICIT_VALUE),
])
def test_botnet_blocking_not_enabled(tmp_path, profile, basis):
    finding = _findings(tmp_path, profile)["fortinet.fortios.dnsfilter.botnet_blocking_disabled"]
    assert finding.basis is basis


def test_botnet_blocking_enabled_and_logging_clear(tmp_path):
    findings = _findings(tmp_path, " set block-botnet enable\n set log-all-domain enable\n")
    assert "fortinet.fortios.dnsfilter.botnet_blocking_disabled" not in findings
    hygiene = findings.get("fortinet.fortios.hardening.cis_hygiene")
    assert hygiene is None or "4.3.2" not in hygiene.observation


def test_hygiene_lists_dns_logging_and_tor_until_configured(tmp_path):
    hygiene = _findings(tmp_path, " set block-botnet enable\n")["fortinet.fortios.hardening.cis_hygiene"].observation
    assert "CIS 4.3.2" in hygiene and "CIS 3.3" in hygiene
    tor = ('config firewall policy\n edit 2\n set name "tor"\n set srcintf "wan1"\n set dstintf "lan"\n'
           ' set internet-service-src enable\n set internet-service-src-name "Tor-Exit.Node"\n set dstaddr "all"\n'
           ' set action deny\n set schedule "always"\n set service "ALL"\n next\nend\n')
    hygiene = _findings(tmp_path, " set block-botnet enable\n set log-all-domain enable\n", tor).get(
        "fortinet.fortios.hardening.cis_hygiene")
    assert hygiene is None or ("CIS 3.3" not in hygiene.observation and "CIS 4.3.2" not in hygiene.observation)


def test_unattached_profile_is_not_assessed(tmp_path):
    path = tmp_path / "f.conf"
    path.write_text(HEADER + 'config dnsfilter profile\n edit "unused"\n set block-botnet disable\n next\nend\n', encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        rules = {f.rule_id for f in process_fortios_conf(FortiOSParser(str(path))).values()}
    assert "fortinet.fortios.dnsfilter.botnet_blocking_disabled" not in rules
