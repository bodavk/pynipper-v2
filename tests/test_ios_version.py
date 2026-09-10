import pytest

from src.devices.cisco.ios import CiscoIOSParser


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("version 12.3", "12.3"),
        ("version 15.2(4)M7", "15.2(4)M7"),
        ("version 12.4(24)T8", "12.4(24)T8"),
        ("version 17.09.04a", "17.09.04a"),
        ("version", "?"),
        ("hostname router", "?"),
    ],
)
def test_ios_version_is_preserved_without_fabrication(tmp_path, line, expected):
    path = tmp_path / "ios.conf"
    path.write_text(line + "\n", encoding="utf-8")
    parser = CiscoIOSParser(str(path))

    assert parser.get_version() == expected
    assert not (expected == "12.3" and parser.get_version() == "12.3(1)")
