import pytest

from src.analyze.cisco.ios.plugins.http_plugin import PluginHTTP
from src.devices.cisco.ios import CiscoIOSParser, ConfigurationState


def _analyze(tmp_path, config: str):
    path = tmp_path / "ios.conf"
    path.write_text(config, encoding="utf-8")
    parser = CiscoIOSParser(str(path))
    plugin = PluginHTTP()
    plugin.analyze(parser)
    return parser, {issue.rule_id for issue in plugin.get_issues()}


@pytest.mark.parametrize(
    ("commands", "expected_state", "expected_rules"),
    [
        ("hostname router\n", ConfigurationState.ABSENT, set()),
        ("no ip http server\n", ConfigurationState.DISABLED, set()),
        (
            "ip http server\nno ip http server\n",
            ConfigurationState.DISABLED,
            set(),
        ),
        (
            "no ip http server\nip http server\n",
            ConfigurationState.ENABLED,
            {
                "cisco.ios.http.cleartext_service",
                "cisco.ios.http.access_restriction",
                "cisco.ios.http.authentication",
            },
        ),
        ("ip http secure-server\n", ConfigurationState.ABSENT, set()),
        (
            "no ip http server\nip http access-class MGMT\nip http authentication local\n",
            ConfigurationState.DISABLED,
            set(),
        ),
    ],
)
def test_http_effective_state(tmp_path, commands, expected_state, expected_rules):
    parser, rules = _analyze(tmp_path, commands)
    assert parser.get_http_server_state() == expected_state
    assert rules == expected_rules


@pytest.mark.parametrize("access_class", ["23", "MGMT-SOURCES"])
@pytest.mark.parametrize(
    "authentication",
    [
        "local",
        "enable",
        "tacacs",
        "aaa",
        "aaa login-authentication HTTP-LOGIN",
    ],
)
def test_http_accepts_named_and_numbered_acls_and_full_authentication(
    tmp_path,
    access_class,
    authentication,
):
    parser, rules = _analyze(
        tmp_path,
        "\n".join(
            (
                "ip http server",
                f"ip http access-class {access_class}",
                f"ip http authentication {authentication}",
            )
        ),
    )

    assert parser.get_http_access_class() == access_class
    assert parser.get_http_authentication() == authentication
    assert rules == {"cisco.ios.http.cleartext_service"}


def test_http_malformed_values_do_not_crash(tmp_path):
    _, rules = _analyze(
        tmp_path,
        "ip http server\nip http access-class\nip http authentication nonsense\n",
    )

    assert rules == {
        "cisco.ios.http.cleartext_service",
        "cisco.ios.http.access_restriction",
        "cisco.ios.http.authentication",
    }
