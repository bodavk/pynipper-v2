from src.analyze.arista.plugins.arista_checks_plugin import PluginAristaChecks
from src.analyze.cisco.asa.core.process_asa_conf import process_asa_conf
from src.analyze.cisco.ios.core.process_cisco_ios_conf import process_cisco_ios_conf
from src.analyze.juniper.junos.plugins.baseline_plugin import PluginJunOSBaseline
from src.analyze.juniper.plugins.screenos_baseline_plugin import PluginScreenOSBaseline
from src.devices.arista.eos import AristaEOSParser
from src.devices.cisco.asa import CiscoASAParser
from src.devices.cisco.ios import CiscoIOSParser
from src.devices.common.models import (
    CredentialStorageAssessment as Storage,
    DefaultCredentialAssessment as Default,
)
from src.devices.juniper.junos import JunOSParser
from src.devices.juniper.screenos import JuniperScreenOSParser
from src.report.report import _generate_html_report, _generate_json_report


def _parser(tmp_path, parser_type, content, name="device.conf"):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return parser_type(str(path))


def _by_account(parser):
    return {item.account: item for item in parser.get_credential_metadata()}


def test_ios_credential_formats_and_effective_account_state_are_typed(tmp_path):
    parser = _parser(
        tmp_path,
        CiscoIOSParser,
        """version 17.9
username removed password 0 DoNotExposeRemoved
no username removed
username changed password 0 DoNotExposeOld
username changed secret 8 $8$salt$hash
username weak secret 5 $1$salt$hash
username reversible password 7 02050D480809
username future secret 42 $future$opaque
username malformed secret 9 not-an-encoded-value
enable secret 9 $9$salt$hash
no enable secret
enable password 0 ArbitraryUnlistedPlaintext
""",
    )

    credentials = _by_account(parser)
    assert "removed" not in credentials
    assert credentials["changed"].storage_assessment == Storage.APPROVED_HASH
    assert credentials["weak"].storage_assessment == Storage.WEAK_HASH
    assert credentials["reversible"].storage_assessment == Storage.WEAK_REVERSIBLE
    assert credentials["future"].storage_assessment == Storage.UNKNOWN
    assert credentials["malformed"].storage_assessment == Storage.MALFORMED
    assert credentials["enable"].storage_assessment == Storage.PLAINTEXT
    assert credentials["enable"].default_assessment == Default.NO_MATCH

    findings = list(process_cisco_ios_conf(parser).values())
    credential_findings = [item for item in findings if ".credentials." in item.rule_id]
    assert [item.rule_id for item in credential_findings].count(
        "cisco.ios.credentials.local_storage"
    ) == 2
    assert [item.rule_id for item in credential_findings].count(
        "cisco.ios.credentials.enable_storage"
    ) == 1
    rendered = " ".join(str(item) for item in credential_findings)
    assert "DoNotExpose" not in rendered
    assert "ArbitraryUnlistedPlaintext" not in rendered
    assert parser.get_users()[0]["raw_line"].endswith("<credential redacted>")


def test_asa_md5_pbkdf2_defaults_and_deletion_are_separate_properties(tmp_path):
    parser = _parser(
        tmp_path,
        CiscoASAParser,
        """ASA Version 9.18(4)
username removed password RemoveMe privilege 15
no username removed
username legacy password opaque-md5 encrypted privilege 15
username secure password $sha512$5000$salt$hash pbkdf2 privilege 15
username arbitrary password ArbitraryUnlistedPlaintext privilege 5
enable password opaque-md5 encrypted
""",
    )
    credentials = _by_account(parser)
    assert "removed" not in credentials
    assert credentials["legacy"].storage_assessment == Storage.WEAK_HASH
    assert credentials["legacy"].default_assessment == Default.NOT_EVALUATED
    assert credentials["secure"].storage_assessment == Storage.APPROVED_HASH
    assert credentials["arbitrary"].storage_assessment == Storage.PLAINTEXT
    assert credentials["arbitrary"].default_assessment == Default.NO_MATCH
    assert credentials["enable"].storage_assessment == Storage.WEAK_HASH
    assert parser.get_enable_password() == "<redacted>"
    assert all("ArbitraryUnlistedPlaintext" not in user["raw_line"] for user in parser.get_users())

    findings = list(process_asa_conf(parser).values())
    ids = [item.rule_id for item in findings]
    assert ids.count("cisco.asa.credentials.local_user_storage") == 2
    assert ids.count("cisco.asa.credentials.weak_enable_password") == 1
    assert "ArbitraryUnlistedPlaintext" not in " ".join(str(item) for item in findings)


def test_eos_formats_defaults_overrides_and_deletion_are_conservative(tmp_path):
    parser = _parser(
        tmp_path,
        AristaEOSParser,
        """username clear secret 0 ArbitraryUnlistedPlaintext
username legacy secret 5 $1$salt$hash
username secure secret sha512 $6$salt$hash
username empty nopassword
username changed secret 0 DoNotExposeOld
username changed secret sha512 $6$new$hash
username changed role network-admin
username gone secret 0 DoNotExposeRemoved
no username gone
username future secret sha512 not-an-encoded-value
""",
    )
    credentials = _by_account(parser)
    assert "gone" not in credentials
    assert credentials["clear"].storage_assessment == Storage.PLAINTEXT
    assert credentials["clear"].default_assessment == Default.NO_MATCH
    assert credentials["legacy"].storage_assessment == Storage.WEAK_HASH
    assert credentials["secure"].storage_assessment == Storage.APPROVED_HASH
    assert credentials["empty"].storage_assessment == Storage.EMPTY
    assert credentials["changed"].storage_assessment == Storage.APPROVED_HASH
    assert credentials["future"].storage_assessment == Storage.MALFORMED

    plugin = PluginAristaChecks()
    plugin.check_credentials(parser)
    findings = plugin.get_issues()
    assert {item.rule_id for item in findings} == {"arista.eos.credentials.local_storage"}
    assert len(findings) == 3
    assert "ArbitraryUnlistedPlaintext" not in " ".join(str(item) for item in findings)
    assert {user["username"] for user in parser.get_users()} == {
        "clear", "legacy", "secure", "empty", "changed", "future"
    }


def test_junos_hash_types_root_scope_unknown_and_delete_are_preserved(tmp_path):
    parser = _parser(
        tmp_path,
        JunOSParser,
        """set system login user weak authentication encrypted-password "$1$salt$hash"
set system login user strong authentication encrypted-password "$6$salt$hash"
set system login user future authentication encrypted-password "$y$opaque"
set system login user invalid authentication encrypted-password "Never Emit This Invalid Value"
set system login user gone authentication encrypted-password "$1$salt$hash"
delete system login user gone
set system root-authentication encrypted-password "$9$obfuscated"
""",
    )
    credentials = _by_account(parser)
    assert "gone" not in credentials
    assert credentials["weak"].storage_assessment == Storage.WEAK_HASH
    assert credentials["strong"].storage_assessment == Storage.APPROVED_HASH
    assert credentials["future"].storage_assessment == Storage.UNKNOWN
    assert credentials["invalid"].storage_assessment == Storage.MALFORMED
    assert "Never Emit This Invalid Value" not in credentials["invalid"].evidence[0].text
    assert credentials["root"].context == "root"
    assert credentials["root"].storage_assessment == Storage.WEAK_REVERSIBLE

    plugin = PluginJunOSBaseline()
    plugin.check_authentication(parser)
    weak = [item for item in plugin.get_issues() if item.rule_id.endswith("weak_storage")]
    assert len(weak) == 2
    assert "obfuscated" not in " ".join(str(item) for item in weak)


def test_screenos_exact_defaults_do_not_turn_unknown_storage_into_strength(tmp_path):
    parser = _parser(
        tmp_path,
        JuniperScreenOSParser,
        """set admin password "password"
set admin password "OpaqueUnlistedValue"
set admin user "bad" password "admin" privilege "read-only"
set admin user "changed" password "password" privilege "all"
set admin user "changed" password "OpaqueReplacement" privilege "all"
set admin user "gone" password "password" privilege "all"
unset admin user "gone"
set admin user "quoted" password "Never Emit This Value" privilege "all"
""",
    )
    credentials = _by_account(parser)
    assert "gone" not in credentials
    assert credentials["primary admin"].storage_assessment == Storage.UNKNOWN
    assert credentials["primary admin"].default_assessment == Default.NO_MATCH
    assert credentials["bad"].storage_assessment == Storage.PLAINTEXT
    assert credentials["bad"].default_assessment == Default.MATCH
    assert credentials["changed"].storage_assessment == Storage.UNKNOWN
    assert credentials["changed"].default_assessment == Default.NO_MATCH
    assert "Never Emit This Value" not in " ".join(
        evidence.text
        for credential in credentials.values()
        for evidence in credential.evidence
    )

    plugin = PluginScreenOSBaseline()
    plugin.check_credentials_and_banner(parser)
    defaults = [item for item in plugin.get_issues() if item.rule_id.endswith("default_or_empty")]
    assert len(defaults) == 1
    assert "Opaque" not in " ".join(str(item) for item in defaults)


def test_credential_secrets_do_not_reach_console_html_json_logs_or_diagnostics(
    tmp_path, capsys, caplog
):
    secret = "NeverEmitThisCredentialValue"
    parser = _parser(
        tmp_path,
        CiscoIOSParser,
        f"username audit password 0 {secret}\nenable password 0 {secret}\n",
    )
    issues = process_cisco_ios_conf(parser)
    console = capsys.readouterr().out
    html = tmp_path / "credential-report.html"
    json_report = tmp_path / "credential-report.json"
    data = {"device-type": parser.device_type, "hostname": parser.get_hostname()}
    _generate_html_report(str(html), issues, [], data)
    _generate_json_report(str(json_report), issues, [], data)

    assert secret not in console
    assert secret not in caplog.text
    assert secret not in html.read_text(encoding="utf-8")
    assert secret not in json_report.read_text(encoding="utf-8")
    identities = [(item.rule_id, item.evidence) for item in issues.values()]
    assert len(identities) == len(set(identities))

    malformed = _parser(
        tmp_path,
        JunOSParser,
        f'set system login user audit authentication encrypted-password "{secret}\n',
        "malformed-junos.conf",
    )
    assert secret not in malformed.parse_error
    assert all(secret not in diagnostic for diagnostic in malformed.diagnostics)
