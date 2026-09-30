import pytest

from src.devices.fortinet.fortios import FortiOSParser
from src.analyze.fortinet.plugins.fortios_baseline_plugin import PluginFortiOSBaseline
from src.main import main


PROFILE = 'config system accprofile\n edit "automation"\n set sysgrp read-write\n next\nend\n'
ACCOUNT = '''config system api-user
 edit "robot"
  set accprofile "automation"
  set api-key "NeverExposeThisToken"
  set vdom "root"
  set peer-auth disable
  config trusthost
   edit 1
    set type ipv4-trusthost
    set ipv4-trusthost 0.0.0.0 0.0.0.0
   next
  end
 next
end
'''


def scan(tmp_path, text):
    path = tmp_path / "forti.conf"
    path.write_text("#config-version=FGT60F-7.0.13-FW-build0000\n" + text, encoding="utf-8")
    parser = FortiOSParser(str(path))
    plugin = PluginFortiOSBaseline()
    plugin.check_api_identities(parser)
    return parser, plugin.get_issues()


def test_explicit_api_privilege_binding_and_safe_evidence(tmp_path):
    parser, findings = scan(tmp_path, PROFILE + ACCOUNT)
    identity, = parser.get_api_identities()
    assert identity.role.privileged_state == "privileged"
    assert identity.vdoms == ("root",)
    assert identity.peer_authentication == "disable"
    assert identity.broad_families == ("IPv4",)
    assert len(findings) == 1 and findings[0].evidence_locations
    assert "NeverExposeThisToken" not in repr(identity)
    assert "NeverExposeThisToken" not in repr(parser.evidence)


@pytest.mark.parametrize("old,new", [
    ("0.0.0.0 0.0.0.0", "192.0.2.0 255.255.255.0"),
    ("0.0.0.0 0.0.0.0", "invalid 0.0.0.0"),
    ("set type ipv4-trusthost", "unset type"),
    ('set accprofile "automation"', 'set accprofile "read_only"'),
    ('set accprofile "automation"', 'set accprofile "missing"'),
    ('set accprofile "automation"', 'unset accprofile'),
    ("set ipv4-trusthost 0.0.0.0 0.0.0.0", "unset ipv4-trusthost"),
])
def test_restricted_unknown_and_read_only_do_not_raise(tmp_path, old, new):
    assert scan(tmp_path, PROFILE + ACCOUNT.replace(old, new))[1] == []


def test_ipv6_independent_and_peer_metadata(tmp_path):
    text = ACCOUNT.replace("set peer-auth disable", 'set peer-auth enable\n set peer-group "clients"')
    text = text.replace("   next", "   next\n edit 2\n set type ipv6-trusthost\n set ipv6-trusthost ::/0\n next")
    text = text.replace("0.0.0.0 0.0.0.0", "192.0.2.0 255.255.255.0")
    parser, findings = scan(tmp_path, PROFILE + text)
    identity, = parser.get_api_identities()
    assert identity.broad_families == ("IPv6",)
    assert identity.peer_group == "clients" and identity.peer_authentication == "enable"
    assert identity.peer_group_state == "unresolved"
    assert len(findings) == 1


@pytest.mark.parametrize("entries,family", [
    (("0.0.0.0 128.0.0.0", "128.0.0.0 128.0.0.0"), "IPv4"),
    (("::/1", "8000::/1"), "IPv6"),
])
def test_multiple_explicit_trusthosts_can_collectively_cover_all_sources(tmp_path, entries, family):
    address_type = "ipv4-trusthost" if family == "IPv4" else "ipv6-trusthost"
    account = ACCOUNT.replace(
        '    set ipv4-trusthost 0.0.0.0 0.0.0.0',
        f'    set {address_type} {entries[0]}\n   next\n'
        f'   edit 2\n    set type {address_type}\n    set {address_type} {entries[1]}',
    ).replace('set type ipv4-trusthost', f'set type {address_type}')
    parser, findings = scan(tmp_path, PROFILE + account)
    assert parser.get_api_identities()[0].broad_families == (family,)
    assert len(findings) == 1
    assert "collectively covering every" in findings[0].observation
    assert "NeverExposeThisToken" not in str(findings[0])


def test_incomplete_or_malformed_trusthost_union_does_not_imply_every_source(tmp_path):
    account = ACCOUNT.replace(
        '    set ipv4-trusthost 0.0.0.0 0.0.0.0',
        '    set ipv4-trusthost 0.0.0.0 128.0.0.0\n   next\n'
        '   edit 2\n    set type ipv4-trusthost\n'
        '    set ipv4-trusthost invalid 128.0.0.0',
    )
    parser, findings = scan(tmp_path, PROFILE + account)
    assert parser.get_api_identities()[0].broad_families == ()
    assert findings == []


def test_peer_group_reference_resolution_without_authentication_claim(tmp_path):
    peer = ('config user peer\n edit client-a\n set ca ClientCA\n next\nend\n'
            'config user peergrp\n edit clients\n set member client-a\n next\nend\n')
    account = ACCOUNT.replace('set peer-auth disable',
                              'set peer-auth enable\n  set peer-group clients')
    parser, findings = scan(tmp_path, PROFILE + peer + account)
    identity, = parser.get_api_identities()
    assert identity.peer_group_state == "resolved"
    assert len(findings) == 1
    assert "client-a" in repr(identity.evidence)
    parser, findings = scan(tmp_path, PROFILE + peer.replace('edit client-a', 'edit other') + account)
    assert parser.get_api_identities()[0].peer_group_state == "unresolved"
    assert len(findings) == 1


def test_peer_group_scope_isolated(tmp_path):
    group = 'config user peergrp\n edit clients\n set member client-a\n next\nend\n'
    peer = 'config user peer\n edit client-a\n next\nend\n'
    account = ACCOUNT.replace('set peer-auth disable',
                              'set peer-auth enable\n  set peer-group clients')
    text = 'config vdom\n edit other\n' + peer + group + 'next\n edit tenant\n' + PROFILE + account + 'next\nend\n'
    parser, findings = scan(tmp_path, text)
    assert parser.get_api_identities()[0].peer_group_state == "unresolved"
    assert len(findings) == 1


def test_deletion_and_restriction_override(tmp_path):
    assert scan(tmp_path, PROFILE + ACCOUNT + 'config system api-user\n delete "robot"\nend\n')[1] == []
    restricted = ACCOUNT.replace("0.0.0.0 0.0.0.0", "192.0.2.0 255.255.255.0")
    assert scan(tmp_path, PROFILE + ACCOUNT + restricted)[1] == []


def test_profile_scope_cannot_be_borrowed_from_other_vdom(tmp_path):
    text = 'config vdom\n edit "other"\n' + PROFILE + 'next\n edit "tenant"\n' + ACCOUNT + 'next\nend\n'
    parser, findings = scan(tmp_path, text)
    assert parser.get_api_identities()[0].role.resolution_state == "unresolved"
    assert findings == []


@pytest.mark.parametrize("format", ["JSON", "HTML"])
def test_public_reports(tmp_path, format):
    parser, _ = scan(tmp_path, PROFILE + ACCOUNT)
    output = tmp_path / ("report." + format.lower())
    assert main(["-d", "fortios", "-i", parser.config_filepath, "-o", format, "-f", str(output)]) == 0
    report = output.read_text(encoding="utf-8")
    assert "Write-capable API account explicitly trusts every source" in report
    assert "NeverExposeThisToken" not in report
