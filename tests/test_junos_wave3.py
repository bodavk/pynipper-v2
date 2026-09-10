import pytest

from src.analyze.juniper.junos.plugins.junos_checks_plugin import PluginJunOSChecks
from src.devices.juniper.junos import JunOSParser


def _analyze(tmp_path, config):
    path = tmp_path / "junos.conf"
    path.write_text(config, encoding="utf-8")
    parser = JunOSParser(str(path))
    plugin = PluginJunOSChecks()
    plugin.analyze(parser)
    return parser, plugin.get_issues()


def test_inactive_deleted_and_https_only_services_do_not_trigger(tmp_path):
    _, issues = _analyze(
        tmp_path,
        """set system services telnet
deactivate system services telnet
set system services web-management http
delete system services web-management http
set system services web-management https system-generated-certificate
""",
    )
    assert "juniper.junos.management.insecure_protocol" not in {
        issue.rule_id for issue in issues
    }


def test_filter_terms_are_assembled_and_only_attached_active_accepts_trigger(tmp_path):
    config = """set firewall family inet filter EDGE term restricted from source-address 10.0.0.0/8
set firewall family inet filter EDGE term restricted then accept
set firewall family inet filter EDGE term broad then accept
set firewall family inet filter UNUSED term broad then accept
set firewall family inet filter EDGE term inactive-any then accept
deactivate firewall family inet filter EDGE term inactive-any
set interfaces ge-0/0/0 unit 0 family inet filter input EDGE
"""
    _, issues = _analyze(tmp_path, config)
    broad = [issue for issue in issues if issue.rule_id == "juniper.junos.filter.broad_accept"]
    assert len(broad) == 1
    assert "term 'broad'" in broad[0].observation
    assert "UNUSED" not in broad[0].observation


def test_prior_terminal_discard_makes_later_accept_unreachable(tmp_path):
    config = """set firewall family inet filter EDGE term reject-all then discard
set firewall family inet filter EDGE term broad then accept
set interfaces ge-0/0/0 unit 0 family inet filter input EDGE
"""
    _, issues = _analyze(tmp_path, config)
    assert "juniper.junos.filter.broad_accept" not in {issue.rule_id for issue in issues}


@pytest.mark.parametrize(
    ("root_value", "expects_finding"),
    [("allow", True), ("deny-password", True), ("deny", False)],
)
def test_effective_ssh_root_login_values(tmp_path, root_value, expects_finding):
    _, issues = _analyze(
        tmp_path,
        f"set system services ssh root-login allow\nset system services ssh root-login {root_value}\n",
    )
    assert ("juniper.junos.ssh.root_login" in {issue.rule_id for issue in issues}) is expects_finding


def test_deleted_root_login_value_is_not_effective(tmp_path):
    _, issues = _analyze(
        tmp_path,
        "set system services ssh root-login allow\ndelete system services ssh root-login\n",
    )
    assert "juniper.junos.ssh.root_login" not in {issue.rule_id for issue in issues}
