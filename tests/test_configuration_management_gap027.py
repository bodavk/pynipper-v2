import pytest

from src.analyze.cisco.ios.plugins.baseline_plugin import PluginIOSBaseline
from src.analyze.fortinet.plugins.fortios_baseline_plugin import PluginFortiOSBaseline
from src.analyze.juniper.junos.plugins.baseline_plugin import PluginJunOSBaseline
from src.common.assessment import AssessmentContext
from src.devices.cisco.ios import CiscoIOSParser
from src.devices.fortinet.fortios import FortiOSParser
from src.devices.juniper.junos import JunOSParser


def _ios(tmp_path, body, backup_scope="unspecified"):
    path = tmp_path / "ios-configuration-management.conf"
    path.write_text("version 17.9\n" + body, encoding="utf-8")
    parser = CiscoIOSParser(str(path))
    parser.set_assessment_context(AssessmentContext.from_mapping({
        "configuration_backup_scope": backup_scope,
    }))
    return parser


def _junos(tmp_path, body, backup_scope="unspecified"):
    path = tmp_path / "junos-configuration-management.conf"
    path.write_text("set version 22.4R1.10\n" + body, encoding="utf-8")
    parser = JunOSParser(str(path))
    parser.set_assessment_context(AssessmentContext.from_mapping({
        "configuration_backup_scope": backup_scope,
    }))
    return parser


def _fortios(tmp_path, body, backup_scope="unspecified", version="7.4.6"):
    path = tmp_path / "fortios-configuration-management.conf"
    header = (
        f"#config-version=FGT100F-{version}-FW-build0001-240101:"
        "opmode=0:vdom=0:user=admin\n"
        if version
        else ""
    )
    path.write_text(header + body, encoding="utf-8")
    parser = FortiOSParser(str(path))
    parser.set_assessment_context(AssessmentContext.from_mapping({
        "configuration_backup_scope": backup_scope,
    }))
    return parser


def _ios_findings(parser):
    plugin = PluginIOSBaseline()
    plugin.check_configuration_management(parser)
    return plugin.get_issues()


def _junos_findings(parser):
    plugin = PluginJunOSBaseline()
    plugin.check_configuration_management(parser)
    return plugin.get_issues()


def _fortios_findings(parser):
    plugin = PluginFortiOSBaseline()
    plugin.check_configuration_backups(parser)
    return plugin.get_issues()


def test_ios_resolves_secure_archive_and_change_audit_without_exposing_credentials(tmp_path):
    parser = _ios(
        tmp_path,
        """archive
 path scp://backup:TOPSECRET@192.0.2.40/configs/$h
 maximum 14
 time-period 1440
 write-memory
 log config
  logging enable
  logging size 200
  hidekeys
  notify syslog
  logging persistent
""",
    )
    state = parser.get_configuration_management()
    assert state.destination == "scp://<credentials>@192.0.2.40/configs/$h"
    assert state.transport_security == "secure"
    assert state.schedule_state == "effective"
    assert (state.write_memory, state.time_period_minutes, state.maximum_versions) == (
        True,
        1440,
        14,
    )
    assert (state.change_logging, state.hide_keys, state.notify_syslog) == (True, True, True)
    assert "TOPSECRET" not in " ".join(item.text for item in state.evidence)
    assert _ios_findings(parser) == []


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("hostname edge\n", ["cisco.ios.configuration.change_logging"]),
        (
            "archive\n log config\n  logging enable\n",
            [
                "cisco.ios.configuration.change_logging_secrets",
                "cisco.ios.configuration.change_notification",
            ],
        ),
        (
            "archive\n path bootflash:archive\n time-period 1440\n no time-period\n"
            " log config\n  logging enable\n  hidekeys\n  notify syslog\n",
            ["cisco.ios.configuration.archive_incomplete"],
        ),
    ],
)
def test_ios_reports_missing_audit_controls_and_effective_schedule_removal(
    tmp_path, body, expected
):
    assert [item.rule_id for item in _ios_findings(_ios(tmp_path, body))] == expected


def test_ios_reports_insecure_effective_destination_and_sanitizes_finding(tmp_path):
    parser = _ios(
        tmp_path,
        """archive
 path ftp://backup:CLEARSECRET@192.0.2.41/configs/$h
 time-period 60
 log config
  logging enable
  hidekeys
  notify syslog
""",
    )
    findings = _ios_findings(parser)
    assert [item.rule_id for item in findings] == [
        "cisco.ios.configuration.archive_transport"
    ]
    rendered = " ".join(findings[0].evidence) + findings[0].observation
    assert "CLEARSECRET" not in rendered
    assert "<credentials>" in rendered


def test_ios_backup_policy_distinguishes_external_management_from_on_device_requirement(tmp_path):
    audit_only = """archive
 log config
  logging enable
  hidekeys
  notify syslog
"""
    assert _ios_findings(_ios(tmp_path, audit_only, "external-managed")) == []
    assert [item.rule_id for item in _ios_findings(
        _ios(tmp_path, audit_only, "on-device-required")
    )] == ["cisco.ios.configuration.archive_required"]


def test_ios_last_archive_destination_wins(tmp_path):
    parser = _ios(
        tmp_path,
        """archive
 path ftp://user:old@192.0.2.1/old
 path scp://user:new@192.0.2.2/new
 write-memory
 log config
  logging enable
  hidekeys
  notify syslog
""",
    )
    state = parser.get_configuration_management()
    assert state.protocol == "scp"
    assert "192.0.2.2" in state.destination
    assert _ios_findings(parser) == []


def test_junos_resolves_secure_multi_site_archive_and_change_log_selector(tmp_path):
    parser = _junos(
        tmp_path,
        """set system archival configuration archive-sites sftp://backup:TOPSECRET@192.0.2.50/configs
set system archival configuration archive-sites scp://backup@192.0.2.51/configs
set system archival configuration routing-instance mgmt_junos
set system archival configuration transfer-on-commit
set system syslog host 192.0.2.30 change-log info
""",
    )
    state = parser.get_configuration_management()
    assert [site.protocol for site in state.sites] == ["sftp", "scp"]
    assert all(site.transport_security == "secure" for site in state.sites)
    assert state.schedule_state == "effective"
    assert state.routing_instance == "mgmt_junos"
    assert state.change_audit_state == "effective"
    assert "TOPSECRET" not in " ".join(item.text for item in state.evidence)
    assert _junos_findings(parser) == []


def test_junos_reports_each_insecure_site_but_accepts_multiple_fallbacks(tmp_path):
    parser = _junos(
        tmp_path,
        """set system archival configuration archive-sites ftp://backup:SECRET@192.0.2.50/configs
set system archival configuration archive-sites scp://backup@192.0.2.51/configs
set system archival configuration transfer-interval 60
set system syslog file audit change-log info
""",
    )
    findings = _junos_findings(parser)
    assert [item.rule_id for item in findings] == [
        "juniper.junos.configuration.archive_transport"
    ]
    assert "SECRET" not in findings[0].observation + " ".join(findings[0].evidence)


def test_junos_delete_and_invalid_or_conflicting_schedule_are_not_effective(tmp_path):
    deleted = _junos(
        tmp_path,
        """set system archival configuration archive-sites scp://backup@192.0.2.50/configs
set system archival configuration transfer-on-commit
delete system archival configuration transfer-on-commit
set system syslog file audit change-log info
""",
    )
    assert deleted.get_configuration_management().schedule_state == "missing"
    assert [item.rule_id for item in _junos_findings(deleted)] == [
        "juniper.junos.configuration.archive_incomplete"
    ]

    invalid = _junos(
        tmp_path,
        """set system archival configuration archive-sites scp://backup@192.0.2.50/configs
set system archival configuration transfer-interval 5
set system syslog file audit change-log info
""",
    )
    assert invalid.get_configuration_management().schedule_state == "invalid"

    conflict = _junos(
        tmp_path,
        """set system archival configuration archive-sites scp://backup@192.0.2.50/configs
set system archival configuration transfer-interval 60
set system archival configuration transfer-on-commit
set system syslog file audit change-log info
""",
    )
    assert conflict.get_configuration_management().schedule_state == "conflict"


def test_junos_backup_policy_and_inheritance_preserve_external_unknowns(tmp_path):
    audit_only = "set system syslog file audit change-log info\n"
    assert _junos_findings(_junos(tmp_path, audit_only, "external-managed")) == []
    assert [item.rule_id for item in _junos_findings(
        _junos(tmp_path, audit_only, "on-device-required")
    )] == ["juniper.junos.configuration.archive_required"]

    inherited = _junos(
        tmp_path,
        "set system apply-groups CONFIGURATION-BACKUP\n",
        "on-device-required",
    )
    assert inherited.get_configuration_management().inheritance_unknown
    assert _junos_findings(inherited) == []


def test_junos_local_administration_requires_change_audit_but_remote_accounting_is_not_duplicated(tmp_path):
    local = _junos(tmp_path, "set system login user admin class super-user\n")
    assert [item.rule_id for item in _junos_findings(local)] == [
        "juniper.junos.configuration.change_audit"
    ]

    remote = _junos(
        tmp_path,
        "set system authentication-order tacplus\nset system tacplus-server 192.0.2.5 secret redacted\n",
    )
    assert _junos_findings(remote) == []


def test_fortios_resolves_recurring_sftp_backup_without_exposing_credentials(tmp_path):
    parser = _fortios(
        tmp_path,
        '''config system auto-script
    edit "nightly-backup"
        set interval 86400
        set repeat 0
        set start auto
        set script "execute backup config sftp edge.conf sftp://backup:URLSECRET@192.0.2.60/configs backup TOPSECRET ARCHIVESECRET"
    next
end
''',
        "on-device-required",
    )
    backups = parser.get_configuration_backups()
    assert len(backups) == 1
    backup = backups[0]
    assert (backup.protocol, backup.destination, backup.transport_security) == (
        "sftp",
        "sftp://<credentials>@192.0.2.60/configs",
        "secure",
    )
    assert (backup.interval_seconds, backup.repeat_count, backup.schedule_state) == (
        86400,
        0,
        "effective",
    )
    rendered = " ".join(item.text for item in backup.evidence)
    assert "TOPSECRET" not in rendered
    assert "ARCHIVESECRET" not in rendered
    assert "URLSECRET" not in rendered
    assert "192.0.2.60" in rendered
    assert _fortios_findings(parser) == []


def test_fortios_flags_insecure_transport_and_keeps_multiple_destinations_separate(tmp_path):
    parser = _fortios(
        tmp_path,
        '''config system auto-script
    edit "legacy-copy"
        set interval 3600
        set repeat 0
        set start auto
        set script "execute backup config ftp edge.conf 192.0.2.61 backup CLEARSECRET ARCHIVESECRET"
    next
    edit "secure-copy"
        set interval 86400
        set repeat 0
        set start auto
        set script "execute backup full-config sftp full.conf 192.0.2.62 backup OTHERSECRET"
    next
end
''',
    )
    findings = _fortios_findings(parser)
    assert [item.rule_id for item in findings] == [
        "fortinet.fortios.configuration.backup_transport"
    ]
    rendered = findings[0].observation + " ".join(findings[0].evidence)
    assert "192.0.2.61" in rendered
    assert "CLEARSECRET" not in rendered
    assert "ARCHIVESECRET" not in rendered
    assert "OTHERSECRET" not in rendered


def test_fortios_backup_scope_and_release_keep_external_processes_unknown(tmp_path):
    assert _fortios_findings(_fortios(tmp_path, "", "external-managed")) == []
    assert [item.rule_id for item in _fortios_findings(
        _fortios(tmp_path, "", "on-device-required")
    )] == ["fortinet.fortios.configuration.backup_required"]
    assert _fortios_findings(
        _fortios(tmp_path, "", "on-device-required", version="")
    ) == []


def test_fortios_overrides_and_finite_or_invalid_automatic_schedules_do_not_pass(tmp_path):
    overridden = _fortios(
        tmp_path,
        '''config system auto-script
    edit "manual-copy"
        set interval 86400
        set repeat 0
        set start auto
        unset start
        set script "execute backup config sftp edge.conf 192.0.2.63 backup REDACTED"
    next
end
''',
        "on-device-required",
    )
    assert overridden.get_configuration_backups()[0].schedule_state == "manual"
    assert [item.rule_id for item in _fortios_findings(overridden)] == [
        "fortinet.fortios.configuration.backup_required"
    ]

    finite = _fortios(
        tmp_path,
        '''config system auto-script
    edit "temporary-copy"
        set interval 86400
        set repeat 2
        set start auto
        set script "execute backup config sftp edge.conf 192.0.2.64 backup REDACTED"
    next
end
''',
    )
    assert finite.get_configuration_backups()[0].schedule_state == "finite"
    assert [item.rule_id for item in _fortios_findings(finite)] == [
        "fortinet.fortios.configuration.backup_incomplete"
    ]

    invalid = _fortios(
        tmp_path,
        '''config system auto-script
    edit "broken-copy"
        set interval 0
        set repeat 0
        set start auto
        set script "execute backup config sftp edge.conf"
    next
end
''',
    )
    backup = invalid.get_configuration_backups()[0]
    assert (backup.destination, backup.schedule_state) == (None, "invalid")
    assert [item.rule_id for item in _fortios_findings(invalid)] == [
        "fortinet.fortios.configuration.backup_incomplete"
    ]
