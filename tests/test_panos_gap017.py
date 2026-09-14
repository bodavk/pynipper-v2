from src.analyze.paloalto.core.process_panos_conf import process_panos_conf
from src.analyze.paloalto.plugins.panos_checks_plugin import PluginPANOSChecks
from src.devices.paloalto.panos import PaloAltoPANOSParser


def _parse(tmp_path, content: str, name: str = "panos-gap017.xml"):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return PaloAltoPANOSParser(str(path))


def _administrative_findings(parser):
    plugin = PluginPANOSChecks()
    plugin.check_administrative_policy(parser)
    return plugin.get_issues()


def test_explicit_management_authentication_and_session_limits_are_independent(tmp_path):
    parser = _parse(
        tmp_path,
        """<config version="12.1.2"><devices><entry name="fw-a"><deviceconfig>
        <system><login-banner>Authorized use only</login-banner><ack-login-banner>no</ack-login-banner></system>
        <setting><management><idle-timeout>0</idle-timeout>
        <admin-lockout><failed-attempts>8</failed-attempts><lockout-time>15</lockout-time></admin-lockout>
        <admin-session><max-session-count>0</max-session-count><max-session-time>invalid</max-session-time></admin-session>
        </management></setting></deviceconfig></entry></devices></config>""",
    )
    settings = parser.get_administrative_settings()[0]
    assert settings.idle_timeout_minutes == 0
    assert settings.failed_attempts == 8
    assert settings.lockout_minutes == 15
    assert settings.max_session_count == 0
    assert settings.max_session_time_state == "invalid"
    assert {item.rule_id for item in _administrative_findings(parser)} == {
        "paloalto.panos.admin.login_banner_acknowledgement",
        "paloalto.panos.admin.idle_timeout",
        "paloalto.panos.admin.login_attempts",
        "paloalto.panos.admin.lockout_time",
        "paloalto.panos.admin.concurrent_sessions",
    }


def test_absent_and_malformed_numeric_settings_remain_ungraded(tmp_path):
    parser = _parse(
        tmp_path,
        """<config version="12.1.2"><devices><entry name="fw-a"><deviceconfig>
        <system/><setting><management><idle-timeout>bad</idle-timeout>
        <admin-lockout><failed-attempts>-1</failed-attempts><lockout-time>unknown</lockout-time></admin-lockout>
        </management></setting></deviceconfig></entry></devices></config>""",
    )
    settings = parser.get_administrative_settings()[0]
    assert settings.idle_timeout_state == "invalid"
    assert settings.failed_attempts_state == "invalid"
    assert settings.lockout_state == "invalid"
    assert settings.max_session_count_state == "absent"
    assert {item.rule_id for item in _administrative_findings(parser)} == {
        "paloalto.panos.admin.login_banner"
    }


def test_administrator_role_authentication_and_mfa_resolution(tmp_path):
    parser = _parse(
        tmp_path,
        """<config version="12.1.2">
        <mgt-config><roles><entry name="Auditor"/></roles><users>
          <entry name="auditor"><authentication-profile>REMOTE-MFA</authentication-profile><permissions><role-based><custom><profile>Auditor</profile></custom></role-based></permissions></entry>
          <entry name="sequenced"><authentication-profile>REMOTE-SEQUENCE</authentication-profile><permissions><role-based><superreader>yes</superreader></role-based></permissions></entry>
          <entry name="broken"><authentication-profile>MISSING</authentication-profile><permissions><role-based><custom><profile>Ghost</profile></custom></role-based></permissions></entry>
        </users></mgt-config>
        <shared><authentication-profile><entry name="REMOTE-MFA"><method><radius><server-profile>RADIUS-A</server-profile></radius></method><multi-factor-auth><mfa-enable>yes</mfa-enable><factors><member>DUO</member></factors></multi-factor-auth></entry></authentication-profile><authentication-sequence><entry name="REMOTE-SEQUENCE"><authentication-profiles><member>REMOTE-MFA</member></authentication-profiles></entry></authentication-sequence></shared>
        </config>""",
    )
    policies = {item.username: item for item in parser.get_administrator_policies()}
    assert policies["auditor"].role_resolution == "known"
    assert policies["auditor"].authentication_method == "radius"
    assert policies["auditor"].mfa_state == "configured"
    assert policies["sequenced"].authentication_resolution == "known"
    assert policies["sequenced"].authentication_method == "sequence:radius"
    assert policies["sequenced"].mfa_state == "configured"
    assert policies["broken"].role_resolution == "unresolved"
    assert policies["broken"].authentication_resolution == "unresolved"
    assert {item.rule_id for item in _administrative_findings(parser)} == {
        "paloalto.panos.admin.role_assignment",
        "paloalto.panos.admin.authentication_profile_unresolved",
    }


def test_global_external_administrator_profile_or_sequence_is_resolved(tmp_path):
    unresolved = _parse(
        tmp_path,
        """<config version="12.1.2"><devices><entry name="fw-a"><deviceconfig><system>
        <authentication-profile>GHOST</authentication-profile><login-banner>Notice</login-banner><ack-login-banner>yes</ack-login-banner>
        </system></deviceconfig></entry></devices></config>""",
        "global-unresolved.xml",
    )
    assert unresolved.get_administrative_settings()[0].authentication_resolution == "unresolved"
    assert "paloalto.panos.admin.authentication_profile_unresolved" in {
        item.rule_id for item in _administrative_findings(unresolved)
    }

    known = _parse(
        tmp_path,
        """<config version="12.1.2"><devices><entry name="fw-a"><deviceconfig><system>
        <authentication-profile>REMOTE-SEQUENCE</authentication-profile><login-banner>Notice</login-banner><ack-login-banner>yes</ack-login-banner>
        </system></deviceconfig></entry></devices><shared>
        <authentication-profile><entry name="REMOTE"><method><saml-idp><server-profile>IDP</server-profile></saml-idp></method></entry></authentication-profile>
        <authentication-sequence><entry name="REMOTE-SEQUENCE"><authentication-profiles><member>REMOTE</member></authentication-profiles></entry></authentication-sequence>
        </shared></config>""",
        "global-known.xml",
    )
    settings = known.get_administrative_settings()[0]
    assert settings.authentication_resolution == "known"
    assert settings.authentication_method == "sequence:saml-idp"
    assert settings.mfa_state == "external-unknown"
    assert "paloalto.panos.admin.authentication_profile_unresolved" not in {
        item.rule_id for item in _administrative_findings(known)
    }


def test_panorama_inheritance_suppresses_new_absence_and_reference_findings(tmp_path):
    parser = _parse(
        tmp_path,
        """<config version="12.1.2"><mgt-config><users><entry name="admin"><authentication-profile>INHERITED</authentication-profile></entry></users></mgt-config>
        <devices><entry name="local"><deviceconfig><system><service><disable-ssh>no</disable-ssh></service></system></deviceconfig><template><entry name="TEMPLATE"/></template></entry></devices></config>""",
    )
    account = parser.get_administrator_policies()[0]
    assert account.role_resolution == "unknown-inherited"
    assert account.authentication_resolution == "unknown-inherited"
    assert parser.get_ssh_management_policies()[0].resolution_state == "unknown-inherited"
    assert _administrative_findings(parser) == []


def test_management_ssh_profile_attachment_and_algorithm_resolution(tmp_path):
    def xml(profile: str, selected: str = "MGMT", version: str = "12.1.2") -> str:
        return f"""<config version="{version}"><devices><entry name="fw-a"><deviceconfig><system>
        <service><disable-ssh>no</disable-ssh></service>{profile}<login-banner>Notice</login-banner><ack-login-banner>yes</ack-login-banner>
        </system></deviceconfig></entry></devices></config>"""

    missing = _parse(tmp_path, xml(""), "missing.xml")
    assert {
        item.rule_id for item in _administrative_findings(missing)
        if ".ssh_" in item.rule_id
    } == {"paloalto.panos.admin.ssh_profile_missing"}

    unresolved_xml = "<ssh><mgmt><server-profile>GHOST</server-profile></mgmt></ssh>"
    unresolved = _parse(tmp_path, xml(unresolved_xml), "unresolved.xml")
    assert {
        item.rule_id for item in _administrative_findings(unresolved)
        if ".ssh_" in item.rule_id
    } == {"paloalto.panos.admin.ssh_profile_unresolved"}

    weak_xml = """<ssh><profiles><mgmt-profiles><server-profiles><entry name="MGMT">
      <ciphers><aes256-cbc/></ciphers><kex><diffie-hellman-group14-sha1/></kex><mac><hmac-sha1/></mac>
      </entry></server-profiles></mgmt-profiles></profiles><mgmt><server-profile>MGMT</server-profile></mgmt></ssh>"""
    weak = _parse(tmp_path, xml(weak_xml), "weak.xml")
    assert weak.get_ssh_management_policies()[0].ciphers == ("aes256-cbc",)
    assert {
        item.rule_id for item in _administrative_findings(weak)
        if ".ssh_" in item.rule_id
    } == {"paloalto.panos.admin.ssh_profile_algorithms"}

    strong_xml = """<ssh><profiles><mgmt-profiles><server-profiles><entry name="MGMT">
      <ciphers><member>aes256-gcm</member></ciphers><kex><member>ecdh-sha2-nistp384</member></kex><mac><member>hmac-sha2-512</member></mac>
      </entry></server-profiles></mgmt-profiles></profiles><mgmt><server-profile>MGMT</server-profile></mgmt></ssh>"""
    strong = _parse(tmp_path, xml(strong_xml), "strong.xml")
    assert not any(".ssh_" in item.rule_id for item in _administrative_findings(strong))

    legacy = _parse(tmp_path, xml("", version="9.1.0"), "legacy.xml")
    assert not any(".ssh_" in item.rule_id for item in _administrative_findings(legacy))


def test_new_panos_findings_reach_public_processor_with_references(tmp_path):
    parser = _parse(
        tmp_path,
        """<config version="12.1.2"><devices><entry name="fw-a"><deviceconfig>
        <system><service><disable-ssh>no</disable-ssh></service></system>
        <setting><management><idle-timeout>60</idle-timeout><admin-lockout><failed-attempts>0</failed-attempts></admin-lockout><admin-session><max-session-count>0</max-session-count></admin-session></management></setting>
        </deviceconfig></entry></devices></config>""",
    )
    findings = list(process_panos_conf(parser).values())
    administrative = [item for item in findings if item.rule_id.startswith("paloalto.panos.admin.")]
    assert {
        "paloalto.panos.admin.login_banner",
        "paloalto.panos.admin.idle_timeout",
        "paloalto.panos.admin.login_attempts",
        "paloalto.panos.admin.concurrent_sessions",
        "paloalto.panos.admin.ssh_profile_missing",
    }.issubset({item.rule_id for item in administrative})
    assert all(item.references for item in administrative)
    identities = [(item.rule_id, item.evidence) for item in findings]
    assert len(identities) == len(set(identities))
