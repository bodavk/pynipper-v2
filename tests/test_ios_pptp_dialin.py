"""SC-013 IOS PPTP dial-in (Cisco PPTP/MPPE configuration example syntax)."""

import contextlib
import io

import pytest

from src.analyze.cisco.ios.core.process_cisco_ios_conf import process_cisco_ios_conf
from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis, Severity
from src.devices import get_parser

RULE = "cisco.ios.vpn.pptp_gateway"
TEMPLATE = (
    "interface Virtual-Template1\n ip unnumbered FastEthernet0/0\n"
    " ppp encrypt mppe auto\n ppp authentication pap chap ms-chap\n!\n"
)


def _config(vpdn="vpdn enable\n", protocol="pptp", template=TEMPLATE):
    return (
        "version 15.4\nhostname r1\n!\n" + vpdn + "!\nvpdn-group 1\n accept-dialin\n"
        f"  protocol {protocol}\n  virtual-template 1\n!\n" + template + "end\n"
    )


def _run(tmp_path, text, device="IOS_ROUTER"):
    path = tmp_path / "r1.conf"
    path.write_text(text, encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        findings = process_cisco_ios_conf(get_parser(device, str(path))).values()
    return [finding for finding in findings if finding.rule_id == RULE]


def test_pptp_dialin_reported_with_pap_context(tmp_path):
    findings = _run(tmp_path, _config())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.HIGH
    assert finding.basis is FindingBasis.EXPLICIT_VALUE
    assert "Virtual-Template1" in finding.observation
    assert "permits PAP" in finding.observation
    assert any("protocol pptp" in str(item) for item in finding.evidence)
    assert guidance_for(RULE)


def test_protocol_any_and_unresolved_template(tmp_path):
    finding = _run(tmp_path, _config(protocol="any", template=""))[0]
    assert "No explicit PPP authentication" in finding.observation


@pytest.mark.parametrize("vpdn,protocol", [
    ("", "pptp"),
    ("vpdn enable\nno vpdn enable\n", "pptp"),
    ("vpdn enable\n", "l2tp"),
])
def test_not_reported(tmp_path, vpdn, protocol):
    assert not _run(tmp_path, _config(vpdn=vpdn, protocol=protocol))


PAP_RULE = "cisco.ios.ppp.pap_authentication"


def _pap(tmp_path, body):
    path = tmp_path / "r2.conf"
    path.write_text("version 15.4\nhostname r2\n!\n" + body + "end\n", encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        findings = process_cisco_ios_conf(get_parser("IOS_ROUTER", str(path))).values()
    return [finding for finding in findings if finding.rule_id == PAP_RULE]


def test_pap_first_on_serial(tmp_path):
    findings = _pap(tmp_path, "interface Serial0/0\n encapsulation ppp\n ppp authentication pap chap\n!\n")
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert "as the first method" in findings[0].observation
    assert guidance_for(PAP_RULE)


def test_pap_fallback_is_low(tmp_path):
    finding = _pap(tmp_path, "interface Serial0/0\n encapsulation ppp\n ppp authentication chap pap\n!\n")[0]
    assert finding.severity is Severity.LOW
    assert "fallback after chap" in finding.observation


def test_pap_sent_username_redacted(tmp_path):
    body = ("interface Dialer1\n encapsulation ppp\n ppp authentication chap callin\n"
            " ppp pap sent-username isp-user password 0 S3cretPw\n!\n")
    finding = _pap(tmp_path, body)[0]
    assert finding.severity is Severity.MEDIUM
    assert "S3cretPw" not in repr(finding) and "isp-user" not in repr(finding)


@pytest.mark.parametrize("body", [
    "interface Serial0/0\n encapsulation ppp\n ppp authentication pap\n shutdown\n!\n",
    "interface Serial0/0\n encapsulation hdlc\n ppp authentication pap\n!\n",
    "interface Virtual-Template1\n encapsulation ppp\n ppp authentication pap\n!\n",
    "interface Serial0/0\n encapsulation ppp\n ppp authentication chap\n!\n",
])
def test_pap_not_reported(tmp_path, body):
    assert not _pap(tmp_path, body)


L2TP_RULE = "cisco.ios.vpn.l2tp_without_ipsec"



def _l2tp_rules(tmp_path, extra=""):
    path = tmp_path / "l2tp.conf"
    path.write_text(_config(protocol="l2tp").replace("end\n", extra + "end\n"), encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        findings = process_cisco_ios_conf(get_parser("IOS_ROUTER", str(path))).values()
    return [finding for finding in findings if finding.rule_id == L2TP_RULE]


def test_l2tp_without_ipsec(tmp_path):
    findings = _l2tp_rules(tmp_path)
    assert len(findings) == 1 and findings[0].severity is Severity.MEDIUM
    assert "pap chap ms-chap" in findings[0].observation
    assert guidance_for(L2TP_RULE)


def test_l2tp_with_crypto_is_unknown(tmp_path):
    extra = "crypto ipsec transform-set L2TP esp-aes esp-sha-hmac\n mode transport\n!\n"
    assert not _l2tp_rules(tmp_path, extra)
