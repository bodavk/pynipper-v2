import json
from pathlib import Path

import pytest

from src import main as main_module
from src.devices.detection import DeviceDetectionError, detect_device_type
from src.devices.registry import get_device_definition, get_recommended_device_choices


CORPUS = Path(__file__).parent / "test_data" / "regression"


@pytest.mark.parametrize(
    "source,expected",
    [
        ("arista_eos/vulnerable.conf", "ARISTA_EOS"),
        ("cisco_asa/vulnerable.conf", "ASA"),
        ("cisco_iosxe/vulnerable.conf", "IOS_XE"),
        ("f5_bigip/vulnerable.scf", "F5_BIGIP"),
        ("fortios/vulnerable.conf", "FORTIOS"),
        ("hp_procurve/vulnerable.conf", "HP_PROCURVE"),
        ("junos/vulnerable.conf", "JUNOS"),
        ("panos/vulnerable.xml", "PAN_OS"),
        ("screenos/vulnerable.conf", "SCREENOS"),
        ("sonicos/vulnerable.txt", "SONICOS"),
        ("checkpoint_fw1/vulnerable", "CHECKPOINT_FW1"),
    ],
)
def test_auto_detects_distinctive_regression_exports(source, expected):
    assert detect_device_type(str(CORPUS / source)) == expected


def test_ios_fifteen_remains_ambiguous_between_ios_and_ios_xe():
    with pytest.raises(DeviceDetectionError, match="IOS and IOS-XE"):
        detect_device_type(str(CORPUS / "cisco_ios/vulnerable.conf"))


def test_auto_refuses_conflicting_signatures_without_echoing_input(tmp_path):
    source = tmp_path / "mixed.conf"
    source.write_text(
        "#TMSH-VERSION: 16.1.5\n#config-version=FGT60F-7.4.6\n"
        "password secret-value\n",
        encoding="utf-8",
    )
    with pytest.raises(DeviceDetectionError, match="conflicting") as error:
        detect_device_type(str(source))
    assert "secret-value" not in str(error.value)


def test_recommended_names_resolve_and_hide_role_variants():
    choices = get_recommended_device_choices()
    assert "cisco-ios" in choices
    assert "IOS_SWITCH" not in choices
    assert len({get_device_definition(choice).canonical_id for choice in choices}) == len(choices)


def test_cli_help_shows_short_names_without_legacy_choice_wall(monkeypatch, capsys):
    monkeypatch.setattr(main_module, "display_banner", lambda: None)
    with pytest.raises(SystemExit) as error:
        main_module.main(["--help"])
    assert error.value.code == 0
    help_text = capsys.readouterr().out
    assert "cisco-ios, cisco-ios-xe, cisco-asa" in help_text
    assert "CISCO_IOS_SWITCH" not in help_text


def test_cli_defaults_to_auto_and_passes_detected_family(monkeypatch):
    calls = []
    monkeypatch.setattr(main_module, "display_banner", lambda: None)
    monkeypatch.setattr(main_module, "analyze_device", lambda *args: calls.append(args))
    assert main_module.main(["-i", str(CORPUS / "f5_bigip/vulnerable.scf")]) == 0
    assert calls[0][0] == "F5_BIGIP"


def test_cli_accepts_friendly_name_and_legacy_alias(monkeypatch):
    calls = []
    monkeypatch.setattr(main_module, "display_banner", lambda: None)
    monkeypatch.setattr(main_module, "analyze_device", lambda *args: calls.append(args))
    for choice in ("cisco-ios", "CISCO_IOS_SWITCH"):
        assert main_module.main(["-d", choice, "-i", "unused.conf"]) == 0
    assert [call[0] for call in calls] == ["IOS_ROUTER", "IOS_SWITCH"]


def test_cli_auto_ambiguity_requests_explicit_choice(monkeypatch, capsys):
    monkeypatch.setattr(main_module, "display_banner", lambda: None)
    with pytest.raises(SystemExit) as error:
        main_module.main(["-i", str(CORPUS / "cisco_ios/vulnerable.conf")])
    assert error.value.code == 2
    assert "choose -d cisco-ios or -d cisco-ios-xe" in capsys.readouterr().err


def test_auto_selected_family_is_recorded_in_json_report(tmp_path):
    report = tmp_path / "f5.json"
    assert main_module.main([
        "-i", str(CORPUS / "f5_bigip/vulnerable.scf"),
        "-o", "JSON", "-f", str(report), "-x",
    ]) == 0
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["data"]["device-type"] == "F5_BIGIP"
    assert data["coverage"]["device-type"] == "F5_BIGIP"
