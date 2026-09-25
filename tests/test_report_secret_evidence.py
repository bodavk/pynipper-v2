import json
from pathlib import Path

import pytest

from src.main import main
from src.common.assessment import AssessmentContext
from src.devices import get_parser
from src.report.secret_evidence import collect_secret_evidence


CORPUS = Path(__file__).parent / "test_data" / "regression"


@pytest.mark.parametrize(
    "device,source,secret",
    [
        ("cisco-ios", "cisco_ios/vulnerable.conf", "Password123"),
        ("cisco-asa", "cisco_asa/vulnerable.conf", "password cisco"),
        ("screenos", "screenos/vulnerable.conf", 'password "password"'),
        ("arista-eos", "arista_eos/vulnerable.conf", "ArbitraryUnlistedPlaintext"),
        ("fortios", "fortios/vulnerable.conf", "regression-secret"),
        ("hp-procurve", "hp_procurve/vulnerable.conf", "unsafe-secret"),
    ],
)
def test_explicit_secret_report_has_separate_credential_appendix(tmp_path, device, source, secret, capsys):
    report = tmp_path / "sensitive.json"
    assert main([
        "-d", device, "-i", str(CORPUS / source), "-o", "JSON",
        "-f", str(report), "-x", "--show-secrets",
    ]) == 0
    payload = json.loads(report.read_text(encoding="utf-8"))
    excerpts = payload["secret-evidence"]
    assert excerpts["status"] == "unmasked-credential-lines"
    assert any(secret in entry["source-line"] for entry in excerpts["entries"])
    assert payload["data"]["assessment-policy"]["report-secret-evidence"] is True
    assert secret not in str(payload["security-audit"])
    assert secret not in capsys.readouterr().out


def test_default_report_stays_masked(tmp_path):
    report = tmp_path / "masked.json"
    assert main([
        "-d", "cisco-ios", "-i", str(CORPUS / "cisco_ios/vulnerable.conf"),
        "-o", "JSON", "-f", str(report), "-x",
    ]) == 0
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert "secret-evidence" not in payload
    assert "Password123" not in report.read_text(encoding="utf-8")
    assert payload["data"]["assessment-policy"]["report-secret-evidence"] is False


def test_only_effective_credential_source_line_is_included(tmp_path):
    source = tmp_path / "ios.conf"
    source.write_text(
        "version 15.2\nusername audit secret 0 OldValue\n"
        "username audit secret 0 NewValue\n"
        "no username audit\nusername audit secret 0 FinalValue\n",
        encoding="utf-8",
    )
    parser = get_parser("IOS_ROUTER", str(source))
    result = collect_secret_evidence(parser)
    assert [entry["source-line"] for entry in result["entries"]] == [
        "username audit secret 0 FinalValue"
    ]


def test_empty_source_has_no_qualified_secret_lines(tmp_path):
    source = tmp_path / "empty.conf"
    source.write_text("", encoding="utf-8")
    assert collect_secret_evidence(get_parser("IOS_ROUTER", str(source)))["entries"] == []


def test_junos_set_credential_source_line_is_available(tmp_path):
    source = tmp_path / "junos.conf"
    source.write_text(
        'set version 22.4R1.10\n'
        'set system login user audit authentication plain-text-password "JunosSecret"\n',
        encoding="utf-8",
    )
    result = collect_secret_evidence(get_parser("JUNOS", str(source)))
    assert len(result["entries"]) == 1
    assert "JunosSecret" in result["entries"][0]["source-line"]


def test_html_escapes_unmasked_source_line(tmp_path):
    source = tmp_path / "ios.conf"
    source.write_text('version 15.2\nusername audit secret 0 "<script>alert(1)</script>"\n', encoding="utf-8")
    report = tmp_path / "sensitive.html"
    assert main([
        "-d", "cisco-ios", "-i", str(source), "-o", "HTML",
        "-f", str(report), "-x", "--show-secrets",
    ]) == 0
    html = report.read_text(encoding="utf-8")
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>alert(1)</script>" not in html


def test_secret_report_refuses_existing_output(tmp_path, capsys):
    report = tmp_path / "existing.json"
    report.write_text("keep", encoding="utf-8")
    with pytest.raises(SystemExit) as error:
        main([
            "-d", "cisco-ios", "-i", str(CORPUS / "cisco_ios/vulnerable.conf"),
            "-o", "JSON", "-f", str(report), "-x", "--show-secrets",
        ])
    assert error.value.code == 2
    assert report.read_text(encoding="utf-8") == "keep"
    assert "requires a new output path" in capsys.readouterr().err


def test_secret_report_requires_explicit_output_path(capsys):
    with pytest.raises(SystemExit) as error:
        main([
            "-d", "cisco-ios", "-i", str(CORPUS / "cisco_ios/vulnerable.conf"),
            "-x", "--show-secrets",
        ])
    assert error.value.code == 2
    assert "requires an explicit -f" in capsys.readouterr().err


@pytest.mark.parametrize("show_secrets", [False, True])
def test_report_cannot_overwrite_input_config(tmp_path, capsys, show_secrets):
    source = tmp_path / "ios.conf"
    original = "version 15.2\nusername audit secret 0 PreserveMe\n"
    source.write_text(original, encoding="utf-8")
    argv = ["-d", "cisco-ios", "-i", str(source), "-f", str(source), "-x"]
    if show_secrets:
        argv.append("--show-secrets")
    with pytest.raises(SystemExit) as error:
        main(argv)
    assert error.value.code == 2
    assert source.read_text(encoding="utf-8") == original
    assert "must differ from the input" in capsys.readouterr().err


def test_secret_report_refuses_unsupported_family(tmp_path, capsys):
    with pytest.raises(SystemExit) as error:
        main([
            "-d", "checkpoint-fw1", "-i", str(CORPUS / "checkpoint_fw1/vulnerable"),
            "-f", str(tmp_path / "report.html"), "-x", "--show-secrets",
        ])
    assert error.value.code == 2
    assert "not supported for this family" in capsys.readouterr().err


def test_f5_user_secret_report_is_opt_in_and_uses_last_value(tmp_path):
    source = tmp_path / "bigip.scf"
    source.write_text(
        "#TMSH-VERSION: 16.1.5\n"
        "auth user /Common/audit { password OldF5Secret }\n"
        "auth user /Common/audit { encrypted-password NewF5Hash }\n",
        encoding="utf-8",
    )
    parser = get_parser("F5_BIGIP", str(source))
    assert "OldF5Secret" not in str(parser.get_native_config())
    assert "NewF5Hash" not in str(parser.get_native_config())
    result = collect_secret_evidence(parser)
    assert [entry["source-line"] for entry in result["entries"]] == [
        "auth user /Common/audit { encrypted-password NewF5Hash }"
    ]
    report = tmp_path / "sensitive.json"
    assert main([
        "-d", "f5-bigip", "-i", str(source), "-o", "JSON",
        "-f", str(report), "-x", "--show-secrets",
    ]) == 0
    assert "NewF5Hash" in report.read_text(encoding="utf-8")
    source.write_text(source.read_text(encoding="utf-8") + "# changed\n", encoding="utf-8")
    with pytest.raises(ValueError, match="configuration changed"):
        collect_secret_evidence(parser)


def test_fortios_secret_lines_follow_effective_set_and_unset(tmp_path):
    source = tmp_path / "fortios.conf"
    source.write_text(
        "config system admin\nedit admin\n"
        "set password OldSecret\nset password FinalSecret\n"
        "set secret RemovedSecret\nunset secret\nnext\nend\n",
        encoding="utf-8",
    )
    parser = get_parser("FORTIOS", str(source))
    result = collect_secret_evidence(parser)
    assert [entry["source-line"] for entry in result["entries"]] == [
        "set password FinalSecret"
    ]
    source.write_text(source.read_text(encoding="utf-8") + "# modified\n", encoding="utf-8")
    with pytest.raises(ValueError, match="configuration changed"):
        collect_secret_evidence(parser)


def test_sonicos_secret_report_only_shows_current_administrator_passwords(tmp_path):
    source = tmp_path / "sonicos.txt"
    source.write_text(
        'firmware-version "SonicOS 7.1.2"\n'
        'administration\n  admin password OldBuiltin\n  admin password FinalBuiltin\n'
        'user local-users\n'
        '  user auditor password OldLocal member-of "SonicWall Administrators"\n'
        '  user auditor password FinalLocal member-of "SonicWall Administrators"\n'
        '  user removed member-of "SonicWall Administrators"\n'
        '    password encrypted RemovedSecret\n'
        '  no user removed\n'
        '  user ordinary password UnrelatedSecret\n',
        encoding="utf-8",
    )
    parser = get_parser("SONICOS", str(source))
    result = collect_secret_evidence(parser)
    assert [entry["source-line"] for entry in result["entries"]] == [
        "admin password FinalBuiltin",
        'user auditor password FinalLocal member-of "SonicWall Administrators"',
    ]
    report = tmp_path / "sensitive.json"
    assert main([
        "-d", "sonicos", "-i", str(source), "-o", "JSON", "-f", str(report),
        "-x", "--show-secrets",
    ]) == 0
    rendered = report.read_text(encoding="utf-8")
    assert "FinalBuiltin" in rendered and "FinalLocal" in rendered
    assert "OldBuiltin" not in rendered and "OldLocal" not in rendered
    assert "RemovedSecret" not in rendered and "UnrelatedSecret" not in rendered
    source.write_text(source.read_text(encoding="utf-8") + "# changed\n", encoding="utf-8")
    with pytest.raises(ValueError, match="configuration changed"):
        collect_secret_evidence(parser)


def test_sonicos_secret_report_honors_password_removal_and_ambiguous_admin_sections(tmp_path):
    source = tmp_path / "sonicos.txt"
    source.write_text(
        'firmware-version "SonicOS 7.1.2"\n'
        'administration\n  admin password OldBuiltin\n'
        'administration\n  admin password MaybeCurrent\n'
        'user local-users\n'
        '  user auditor member-of "SonicWall Administrators"\n'
        '    password encrypted OldLocal\n'
        '    no password\n',
        encoding="utf-8",
    )
    assert collect_secret_evidence(get_parser("SONICOS", str(source)))["entries"] == []


def test_sonicos_nested_admin_password_is_opt_in_and_html_escaped(tmp_path):
    source = tmp_path / "sonicos.txt"
    source.write_text(
        'firmware-version "SonicOS 7.3.0"\n'
        'user local-users\n'
        '  user auditor member-of "SonicWall Administrators"\n'
        '    password encrypted "<SyntheticHash>"\n',
        encoding="utf-8",
    )
    masked = tmp_path / "masked.json"
    assert main(["-d", "sonicos", "-i", str(source), "-o", "JSON",
                 "-f", str(masked), "-x"]) == 0
    assert "<SyntheticHash>" not in masked.read_text(encoding="utf-8")

    sensitive = tmp_path / "sensitive.html"
    assert main(["-d", "sonicos", "-i", str(source), "-o", "HTML",
                 "-f", str(sensitive), "-x", "--show-secrets"]) == 0
    html = sensitive.read_text(encoding="utf-8")
    assert "&lt;SyntheticHash&gt;" in html
    assert "<SyntheticHash>" not in html


def test_policy_file_cannot_enable_secret_reporting():
    with pytest.raises(ValueError, match="unknown assessment policy fields"):
        AssessmentContext.from_mapping({"report_secret_evidence": True})
