"""PT-002/PT-003: values spanning several physical lines.

Quoted values (PEM keys, certificates, banner text) and delimited banners must
be parsed as one statement. Their body must never become a parse error, a
separate command, or unredacted evidence, and later line numbers must stay
exact. All key material below is fake.
"""

import json
from pathlib import Path

import pytest

from src.analyze.cisco.ios.core.process_cisco_ios_conf import process_cisco_ios_conf
from src.analyze.hp.core.process_hp_conf import process_hp_conf
from src.analyze.juniper.core.process_screenos_conf import process_screenos_conf
from src.analyze.arista.core.process_arista_conf import process_arista_conf
from src.analyze.sonicwall.core.process_sonicos_conf import process_sonicos_conf
from src.devices import get_parser
from src.devices.common.source_lines import (
    LogicalLine,
    group_double_quoted_lines,
    single_line_evidence,
)
from src.devices.fortinet.fortios import FortiOSParseError, FortiOSParser
from src.main import main


CORPUS = Path(__file__).parent / "test_data" / "regression"
FAKE_KEY_BODY = "FAKEPRIVATEKEYMATERIALFORPT002TESTSONLY"

FORTI_MULTILINE = f'''config system global
set hostname "edge-fw"
end
config vpn certificate local
edit "unused-local"
set comments "first line
set admintimeout 480"
set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIB{FAKE_KEY_BODY}
-----END ENCRYPTED PRIVATE KEY-----"
set certificate "-----BEGIN CERTIFICATE-----
MIIBFAKECERTIFICATEBODY
-----END CERTIFICATE-----"
next
end
config system replacemsg admin "pre_admin-disclaimer-text"
set buffer "<p>Authorized \\"administrators\\" only</p>
end
<p>it's monitored</p>"
end
config system global
set admintimeout 5
end
'''


def _rule_ids(findings):
    return sorted(finding.rule_id for finding in findings.values())


def _write(tmp_path, name, text, newline="\n"):
    path = tmp_path / name
    path.write_bytes(text.replace("\n", newline).encode("utf-8"))
    return path


# Shared grouping helper -----------------------------------------------------

def test_grouping_joins_until_double_quote_closes():
    result = group_double_quoted_lines(['a "one', "two", 'three"', "b"])
    assert result.unterminated_line is None
    assert result.lines == (
        LogicalLine('a "one\ntwo\nthree"', 1, 3),
        LogicalLine("b", 4, 4),
    )


def test_grouping_honours_escaped_quotes_and_ignores_apostrophes():
    result = group_double_quoted_lines(['set x "it\'s \\" still', 'open"', "set y it's"])
    assert [(item.start_line, item.end_line) for item in result.lines] == [(1, 2), (3, 3)]


def test_grouping_comment_prefix_cannot_open_a_value():
    result = group_double_quoted_lines(['# a "comment', "set x 1"], comment_prefixes=("#",))
    assert [item.text for item in result.lines] == ['# a "comment', "set x 1"]


def test_unterminated_value_falls_back_to_physical_lines():
    result = group_double_quoted_lines(["set a 1", 'set b "open', "set c 3"])
    assert result.unterminated_line == 2
    assert [item.text for item in result.lines] == ["set a 1", 'set b "open', "set c 3"]


def test_single_line_evidence_marks_continuation():
    assert single_line_evidence("set a 1") == "set a 1"
    assert single_line_evidence('set b "x\ny"', 7) == 'set b "x ... <value continues to line 7>'
    assert single_line_evidence('set b "x\ny"') == 'set b "x ... <multi-line value continues>'


# FortiOS ---------------------------------------------------------------------

@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_fortios_parses_multiline_key_certificate_and_text(tmp_path, newline):
    parser = FortiOSParser(str(_write(tmp_path, "fortigate.conf", FORTI_MULTILINE, newline)))
    native = parser.get_native_config()
    local = native["vpn certificate local"]["unused-local"]
    assert local["certificate"].startswith("-----BEGIN CERTIFICATE-----\n")
    assert local["comments"] == "first line\nset admintimeout 480"
    # Text inside the comment and replacement message is not a command.
    assert native["system global"]["admintimeout"] == "5"
    assert (
        native['system replacemsg admin pre_admin-disclaimer-text']["buffer"].count("\n") == 2
    )

    evidence = {path[-1]: item for path, item in parser.evidence.items()}
    assert evidence["private-key"].text == "set private-key <redacted>"
    assert evidence["private-key"].line_number == 8
    assert evidence["certificate"].text == "set certificate <public certificate material omitted>"
    assert evidence["comments"].text == 'set comments "first line ... <value continues to line 7>'
    # Line numbers after the multi-line values remain physical line numbers.
    assert parser.field_evidence(("system global", "admintimeout"))[0].line_number == 22
    assert all(FAKE_KEY_BODY not in item.text for item in parser.evidence.values())


def test_fortios_single_line_escaped_pem_is_still_supported(tmp_path):
    source = _write(
        tmp_path,
        "escaped.conf",
        'config vpn certificate local\nedit "c"\n'
        'set certificate "-----BEGIN CERTIFICATE-----\\nMIIB\\n-----END CERTIFICATE-----"\n'
        "next\nend\n",
    )
    native = FortiOSParser(str(source)).get_native_config()
    assert native["vpn certificate local"]["c"]["certificate"] == (
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
    )


def test_fortios_unterminated_value_reports_its_first_line(tmp_path):
    source = _write(
        tmp_path,
        "open.conf",
        'config system global\nset hostname "fw"\nend\n'
        'config vpn certificate local\nedit "c"\nset private-key "-----BEGIN\nMIIB\n',
    )
    with pytest.raises(FortiOSParseError, match="Invalid quoting") as error:
        FortiOSParser(str(source))
    assert error.value.line_number == 6
    assert "MIIB" not in str(error.value)


def test_fortios_public_reports_keep_multiline_key_redacted(tmp_path):
    source = _write(tmp_path, "fortigate.conf", FORTI_MULTILINE)
    for output_type in ("JSON", "HTML"):
        report = tmp_path / f"report.{output_type.lower()}"
        assert main(["-d", "fortios", "-i", str(source), "-o", output_type,
                     "-f", str(report), "-x"]) == 0
        text = report.read_text(encoding="utf-8")
        assert FAKE_KEY_BODY not in text
        if output_type == "JSON":
            coverage = json.loads(text)["coverage"]
            assert all(field["knowledge-state"] != "parse_error" for field in coverage["fields"])


def test_fortios_secret_appendix_contains_whole_multiline_value(tmp_path):
    source = _write(tmp_path, "fortigate.conf", FORTI_MULTILINE)
    report = tmp_path / "sensitive.json"
    assert main(["-d", "fortios", "-i", str(source), "-o", "JSON", "-f", str(report),
                 "-x", "--show-secrets"]) == 0
    payload = json.loads(report.read_text(encoding="utf-8"))
    entries = {entry["line-number"]: entry for entry in payload["secret-evidence"]["entries"]}
    assert FAKE_KEY_BODY in entries[8]["source-line"]
    assert entries[8]["source-line"].endswith('-----END ENCRYPTED PRIVATE KEY-----"')
    assert FAKE_KEY_BODY not in str(payload["security-audit"])


# Junos display-set -----------------------------------------------------------

def test_junos_set_format_accepts_multiline_quoted_message(tmp_path):
    source = _write(
        tmp_path,
        "junos.conf",
        'set version 22.4R1.10\nset system login message "Authorized only\n'
        'set system services telnet"\nset system host-name edge\n',
    )
    parser = get_parser("JUNOS", str(source))
    assert parser.format == "set"
    assert parser.parse_error == ""
    assert parser.get_hostname() == "edge"
    assert not any(statement.path[:3] == ("system", "services", "telnet")
                   for statement in parser.statements)
    message = next(s for s in parser.statements if s.path[:3] == ("system", "login", "message"))
    assert message.evidence.line_number == 2
    assert message.evidence.text.endswith("<value continues to line 3>")


def test_junos_set_format_unterminated_message_is_parse_error(tmp_path):
    source = _write(tmp_path, "junos.conf", 'set system host-name edge\nset system login message "open\n')
    parser = get_parser("JUNOS", str(source))
    assert parser.parse_error == "line 2: unterminated quoted string"


# Banner bodies must not be read as commands ----------------------------------

def _insert_after(source: Path, count: int, snippet: str, target: Path) -> Path:
    lines = source.read_text(encoding="utf-8").splitlines(keepends=True)
    target.write_text("".join(lines[:count]) + snippet + "".join(lines[count:]), encoding="utf-8")
    return target


@pytest.mark.parametrize(
    "device,corpus,processor,after,banner",
    [
        ("IOS_ROUTER", "cisco_ios/secure.conf", process_cisco_ios_conf, 2,
         "banner motd ^C\nNotice\nsnmp-server community public RW\n^C\n"),
        ("IOS_XE", "cisco_iosxe/secure.conf", None, 2,
         "banner exec #\nsnmp-server community public RW\n#\n"),
        ("ARISTA_EOS", "arista_eos/secure.conf", process_arista_conf, 2,
         "banner login\nusername admin privilege 15 secret 0 Plain\nEOF\n"),
        ("HP_PROCURVE", "hp_procurve/secure.conf", process_hp_conf, 2,
         'banner motd "Notice\nsnmp-server community \\"public\\" unrestricted\nip ssh"\n'),
        ("SCREENOS", "screenos/secure.conf", process_screenos_conf, 3,
         'set admin auth banner console login "Notice\nset console timeout 0\nset admin password password"\n'),
        ("SONICOS", "sonicos/secure.txt", process_sonicos_conf, 3,
         'cli banner login "Notice\nfirewall-name "\nno logging"\n'),
    ],
)
def test_banner_body_is_not_parsed_as_commands(tmp_path, device, corpus, processor, after, banner):
    if processor is None:
        from src.analyze.cisco.iosxe.core.process_iosxe_conf import process_iosxe_conf as processor
    source = CORPUS / corpus
    target = _insert_after(source, after, banner, tmp_path / Path(corpus).name)
    baseline = _rule_ids(processor(get_parser(device, str(source))))
    assert _rule_ids(processor(get_parser(device, str(target)))) == baseline


def test_hp_multiline_banner_is_recognized(tmp_path):
    target = _insert_after(CORPUS / "hp_procurve/vulnerable.conf", 2,
                           'banner motd "Authorized\nit\'s monitored"\n', tmp_path / "hp.conf")
    policy = get_parser("HP_PROCURVE", str(target)).get_login_banner_policy()
    assert policy.resolution_state == "explicit"
    assert policy.evidence[0].line_number == 3
    assert policy.evidence[0].text.endswith("<value continues to line 4>")


def test_eos_banner_eof_block_is_masked_but_banner_is_known(tmp_path):
    target = _insert_after(CORPUS / "arista_eos/vulnerable.conf", 2,
                           "banner login\nAuthorized \"only\"\nEOF\n", tmp_path / "eos.conf")
    parser = get_parser("ARISTA_EOS", str(target))
    assert parser.get_banner_policy().login_enabled is True
    assert not any(command.text == "EOF" for command in parser.commands)


def test_unclosed_ios_banner_is_left_unchanged(tmp_path):
    source = _write(tmp_path, "ios.conf", "hostname r1\nbanner motd ^C\nNotice\n")
    parser = get_parser("IOS_ROUTER", str(source))
    assert parser._source_lines == ["hostname r1", "banner motd ^C", "Notice"]


# Cisco line numbers stay physical --------------------------------------------

@pytest.mark.parametrize("device", ["IOS_ROUTER", "ASA"])
def test_cisco_blank_lines_do_not_shift_line_numbers(tmp_path, device):
    source = _write(
        tmp_path,
        "cisco.conf",
        "Building configuration...\n\nCurrent configuration : 100 bytes\n\n"
        "hostname r1\n\n\nlogging host 192.0.2.10\n",
    )
    parser = get_parser(device, str(source))
    cisco_lines = parser.get_native_config().ioscfg
    physical = source.read_text(encoding="utf-8").splitlines()
    assert len(cisco_lines) == len(physical)
    for number, line in enumerate(physical, start=1):
        if line.strip():
            assert cisco_lines[number - 1] == line
    if device == "IOS_ROUTER":
        logging = parser.get_normalized_config().logging_destinations.items
        assert [item.evidence[0].line_number for item in logging] == [8]


# Formats with a structural grammar -------------------------------------------

def test_f5_multiline_quoted_banner_and_irule_are_accepted(tmp_path):
    target = tmp_path / "bigip.scf"
    target.write_text(
        (CORPUS / "f5_bigip/secure.scf").read_text(encoding="utf-8")
        + 'sys global-settings {\n    gui-security-banner-text "Line one\nit\'s {braced}\nline three"\n}\n'
        + 'ltm rule /Common/r {\n    when HTTP_REQUEST {\n        if { [HTTP::uri] eq "/a" } { reject }\n    }\n}\n',
        encoding="utf-8",
    )
    parser = get_parser("F5_BIGIP", str(target))
    assert parser.get_hostname() == get_parser("F5_BIGIP", str(CORPUS / "f5_bigip/secure.scf")).get_hostname()
