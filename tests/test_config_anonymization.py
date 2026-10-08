"""Adversarial tests for the separate offline pseudonymization boundary."""
import json
import ipaddress
from pathlib import Path
import socket
import subprocess
import sys

import pytest

from src.anonymize.__main__ import main
from src.anonymize import service
from src.anonymize.service import anonymize_text, prepare_file
from src.devices.common.anonymization import AnonymizationError, SourceToken, statements
from src.devices.fortinet.fortios import FortiOSParser
from src.devices.cisco.ios import CiscoIOSParser
from src.devices.cisco.asa import CiscoASAParser
from src.main import main as audit_main


FORTI = '''#config-version=FGT100F-7.4.6-FW-build0001:opmode=0:vdom=0:user=PrivateOperator
# private-client-contact@example.net
config system global
    set hostname "firewall.client.example.net"
    set strong-crypto disable
end
config system interface
    edit "customer-lan"
        set ip 10.20.30.1 255.255.255.0
        set allowaccess http ssh
        set description "Private office with password HiddenDescription"
    next
end
config system admin
    edit "PrivateOperator"
        set accprofile "super_admin"
        set password ENC SecretPassword987
        set trusthost1 10.20.30.0 255.255.255.0
    next
end
config firewall address
    edit "PrivateSegment"
        set subnet 10.20.30.0 255.255.255.0
    next
    edit "PrivateServer"
        set type fqdn
        set fqdn "firewall.client.example.net"
    next
end
config firewall policy
    edit 10
        set name "PrivateRule"
        set srcintf "customer-lan"
        set dstintf "any"
        set srcaddr "PrivateSegment"
        set dstaddr "all"
        set service "ALL"
        set schedule "always"
        set action accept
        set logtraffic disable
    next
    edit 20
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set schedule "always"
        set action accept
    next
end
config log syslogd setting
    set status enable
    set server 10.20.30.50
end
'''

IOS = '''version 15.2(4)M7
hostname PrivateRouter
ip domain name client.example.net
username PrivateOperator privilege 15 password 0 SecretPassword987
enable secret 5 $1$Original$AbCd0123456789abcdefghij
snmp-server community SecretPassword987 RO
interface GigabitEthernet0/1
 description Private office
 ip address 10.20.30.1 255.255.255.0
 no shutdown
 ip access-group PrivateACL in
!
ip access-list extended PrivateACL
 permit tcp 10.20.30.0 0.0.0.255 host 10.20.30.50 eq 443
 deny ip any any log
!
line vty 0 4
 login local
 transport input ssh
 access-class PrivateACL in
logging host 10.20.30.50
ntp server 10.20.30.50 key 1
ntp authentication-key 1 md5 PrivateKey987
'''

ASA = '''ASA Version 9.18(4)
hostname PrivateASA
domain-name client.example.net
username PrivateOperator password SecretPassword987 privilege 15
interface GigabitEthernet0/0
 nameif CustomerOutside
 security-level 0
 ip address 10.20.30.1 255.255.255.0
!
object network PrivateServer
 host 10.20.30.50
!
object-group network PrivateGroup
 network-object object PrivateServer
!
access-list PrivateACL extended permit tcp object-group PrivateGroup any eq https
access-list PrivateACL extended deny ip any any log
access-group PrivateACL in interface CustomerOutside
ssh 10.20.30.0 255.255.255.0 CustomerOutside
banner login Private organization: customer@example.net
'''


@pytest.fixture(autouse=True)
def networking_forbidden(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("sample preparation or audit attempted network access")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


def write(tmp_path, text, name="source.conf"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8", newline="")
    return path


@pytest.mark.parametrize("family,text", [("fortigate", FORTI), ("cisco-ios", IOS),
                                         ("IOS_XE", IOS), ("cisco-asa", ASA)])
def test_consistent_replacement_and_no_private_summary(family, text):
    output, summary = anonymize_text(text, family)
    for private in ("Private", "customer", "Customer", "SecretPassword987", "10.20.30", "client.example.net", "$1$Original$"):
        assert private not in output
        assert private not in json.dumps(summary)
    assert text.count("\n") == output.count("\n")
    assert summary["grammar-validation"] == "passed"
    assert summary["test-equivalence"] == "not-certified"
    assert "mapping" not in summary
    assert anonymize_text(text, family)[0] != output


def test_fortios_relationships_and_native_reparse(tmp_path):
    original = FortiOSParser(str(write(tmp_path, FORTI)))
    output, _ = anonymize_text(FORTI, "fortios")
    sanitized = FortiOSParser(str(write(tmp_path, output, "sanitized.conf")))
    assert original.get_version() == sanitized.get_version() == "7.4.6"
    tokens = [row.tokens for row in statements(output, comments=("#",)) if row.tokens]
    hosts = [row[2].value for row in tokens if len(row) == 4 and row[1].value in {"ip", "trusthost1", "subnet"}]
    assert len(hosts) == 3
    assert ipaddress.ip_address(hosts[0]) in ipaddress.ip_network(hosts[1] + "/24")
    assert hosts[1] == hosts[2]
    definitions = [row[1].value for row in tokens if row[0].value == "edit" and not row[1].value.isdigit()]
    interface = next(name for name in definitions if name.startswith("iface_"))
    addr = next(name for name in definitions if name.startswith("addr_"))
    assert f'set srcintf "{interface}"' in output
    assert f'set srcaddr "{addr}"' in output
    domains = [row[2].value for row in tokens if len(row) == 3 and row[1].value in {"hostname", "fqdn"}]
    assert domains[0] == domains[1] and domains[0].endswith(".invalid")


@pytest.mark.parametrize("family,text,parser", [("cisco-ios", IOS, CiscoIOSParser), ("cisco-asa", ASA, CiscoASAParser)])
def test_cisco_native_reparse_and_binding(family, text, parser, tmp_path):
    output, _ = anonymize_text(text, family)
    parsed = parser(str(write(tmp_path, output)))
    assert parsed.get_hostname().startswith("host-")
    assert "GigabitEthernet0/" in output
    assert "255.255.255.0" in output
    assert "0.0.0.255" in output if family == "cisco-ios" else "object-group netgrp_" in output
    acl_names = [row.tokens[1].value for row in statements(output, comments=("!",))
                 if row.tokens and row.tokens[0].value == "access-list"]
    if acl_names:
        assert len(set(acl_names)) == 1


def tenant(name, addr):
    return f'''edit "{name}"
config firewall address
edit "SameObject"
set subnet {addr} 255.255.255.0
next
end
config firewall policy
edit 1
set srcaddr "SameObject"
set dstaddr "all"
set service "ALL"
set action accept
next
end
next
'''


def test_vdom_isolation_forward_references_and_custom_builtin():
    text = "config vdom\n" + tenant("PrivateA", "10.20.1.0") + tenant("PrivateB", "10.20.2.0") + "end\n"
    output, _ = anonymize_text(text, "fortios")
    names = [row.tokens[1].value for row in statements(output, comments=("#",))
             if row.tokens and row.tokens[0].value == "edit" and row.tokens[1].value.startswith("addr_")]
    assert len(names) == 2 and names[0] != names[1]
    for name in names:
        assert f'set srcaddr "{name}"' in output
    text = 'config firewall policy\nedit 1\nset srcaddr "HTTP"\nset service "HTTP"\nnext\nend\nconfig firewall address\nedit "HTTP"\nset subnet 10.3.4.0 255.255.255.0\nnext\nend\n'
    output, _ = anonymize_text(text, "fortios")
    assert 'set srcaddr "HTTP"' not in output
    assert 'set srcaddr "addr_' in output
    assert 'set service "HTTP"' in output


def test_fortios_global_reference_and_user_group_resolution():
    text = '''config global
config user radius
edit PrivateRadius
set server 10.1.2.3
set secret ENC PrivateSecret
next
end
end
config vdom
edit PrivateVDOM
config user group
edit PrivateGroup
set member PrivateRadius
next
end
next
end
'''
    output, _ = anonymize_text(text, "fortios")
    radius = next(row.tokens[1].value for row in statements(output, comments=("#",))
                  if len(row.tokens) == 2 and row.tokens[1].value.startswith("radius_"))
    assert f"set member {radius}" in output


def test_fortios_ordered_edit_remove_clone_and_move():
    text = '''config firewall address
edit PrivateObject
set subnet 10.4.5.0 255.255.255.0
unset subnet
set subnet 10.4.6.0 255.255.255.0
next
clone PrivateObject to PrivateCopy
rename PrivateCopy to PrivateRenamed
delete PrivateRenamed
end
config firewall policy
edit 1
set srcaddr PrivateObject
set action accept
next
edit 2
set status disable
next
move 2 before 1
delete 2
end
'''
    output, _ = anonymize_text(text, "fortios")
    assert "unset subnet" in output and "move 2 before 1" in output and "delete 2" in output
    assert "Private" not in output
    assert output.count("clone ") == output.count("rename ") == 1


def test_ipv6_and_cross_prefix_range_translation():
    text = '''config firewall address6
edit PrivateV6
set ip6-address fd12:3456:789a::/64
next
end
config system admin
edit PrivateAdmin
set ip6-trusthost1 fd12:3456:789a::5/128
next
end
config firewall ippool
edit PrivatePool
set start-ip 10.10.0.250
set end-ip 10.10.1.20
next
end
'''
    output, _ = anonymize_text(text, "fortios")
    rows = {row.tokens[1].value: row.tokens[2].value for row in statements(output, comments=("#",))
            if len(row.tokens) == 3 and row.tokens[0].value == "set"}
    assert ipaddress.ip_interface(rows["ip6-trusthost1"]).ip in ipaddress.ip_network(rows["ip6-address"])
    assert int(ipaddress.ip_address(rows["end-ip"])) - int(ipaddress.ip_address(rows["start-ip"])) == 26


def test_multiline_free_text_and_banner_command_injection():
    text = 'config system interface\nedit port1\nset description "Private\nset password SECRET\nCompany"\nnext\nend\n'
    output, _ = anonymize_text(text, "fortios")
    assert "SECRET" not in output and "Private" not in output and "Company" not in output
    assert text.count("\n") == output.count("\n")
    text = 'version 15.2\nbanner login ^CPrivate\nusername leaked secret 5 hash\n"unterminated prose\n^C\nhostname PrivateRouter\n'
    output, _ = anonymize_text(text, "cisco-ios")
    assert "leaked" not in output and "hash" not in output and "prose" not in output
    assert "banner login ^C" in output
    assert output.count("\n") == text.count("\n")


@pytest.mark.parametrize("family,text", [
    ("fortios", 'config system global\nset private-custom-value TOPSECRET\nend\n'),
    ("fortios", 'config vpn certificate local\nedit x\nset certificate "PRIVATE PEM"\nnext\nend\n'),
    ("fortios", 'config system auto-script\nedit x\nset script "run token TOPSECRET"\nnext\nend\n'),
    ("fortios", 'config system global\nset hostname "unclosed\nend\n'),
    ("fortios", 'config system global\nset strong-crypto COMPANY\nend\n'),
    ("fortios", 'config system interface\nedit Private\nset ip not-an-ip 255.255.255.0\nnext\nend\n'),
    ("fortios", 'config system interface\nedit Private\nset ip 10.0.0.1 255.0.0.0\nnext\nend\n'),
    ("fortios", 'config user radius\nedit Private\nset server 999.999.999.999\nnext\nend\n'),
    ("cisco-ios", 'version 15.2\ncrypto pki certificate chain Private\n certificate ca 01\n'),
    ("cisco-ios", 'banner login ^CPrivate unclosed\n'),
    ("cisco-ios", 'access-list 100 permit tcp 10.1.2.0 0.255.0.255 any\n'),
    ("cisco-ios", 'username Private password 7 20ABCDEF\n'),
    ("cisco-asa", 'ASA Version 9.18(4)\nnat (inside,outside) source static Private Private\n'),
    ("pan-os", '<config version="11.2.3"><private>SECRET</private></config>'),
    ("PIX", 'PIX Version 6.3\nhostname Private\n'),
])
def test_unknown_malformed_and_unqualified_state_blocks(family, text):
    with pytest.raises(AnonymizationError) as error:
        anonymize_text(text, family)
    assert "TOPSECRET" not in str(error.value) and "Private" not in str(error.value)


def test_private_records_have_no_source_repr():
    from src.devices.fortinet.anonymization import Frame
    assert "TOPSECRET" not in repr(Frame("system admin", "TOPSECRET", "TOPSECRET"))
    token = SourceToken(0, 11, 1, "TOPSECRET")
    assert "TOPSECRET" not in repr(token)
    for row in statements('hostname TOPSECRET\n', comments=("!",)):
        assert "TOPSECRET" not in repr(row)


def test_safe_publication_and_check_only(tmp_path):
    source = write(tmp_path, FORTI, "PrivateClient.conf")
    original = source.read_bytes()
    destination = tmp_path / "shareable"
    check = prepare_file(source, "fortios", destination, check_only=True)
    assert check["grammar-validation"] == "passed" and not destination.exists()
    summary = prepare_file(source, "fortios", destination)
    assert source.read_bytes() == original
    assert sorted(path.name for path in destination.iterdir()) == ["config.conf", "sanitization-summary.json"]
    assert json.loads((destination / "sanitization-summary.json").read_text()) == summary
    with pytest.raises(AnonymizationError):
        prepare_file(source, "fortios", destination)
    assert source.read_bytes() == original


def test_fail_before_output_unknown_permissions_and_io(tmp_path, monkeypatch, capsys):
    source = write(tmp_path, 'config system global\nset private-custom-value TOPSECRET\nend\n', "PrivateClient.conf")
    destination = tmp_path / "shareable"
    assert main(["-i", str(source), "-d", "fortios", "--output-dir", str(destination)]) == 2
    assert not destination.exists()
    assert "TOPSECRET" not in capsys.readouterr().err
    source.write_text(FORTI)
    monkeypatch.setattr(service, "_restrict_directory", lambda path: False)
    assert main(["-i", str(source), "-d", "fortios", "--output-dir", str(destination)]) == 3
    assert destination.is_dir() and list(destination.iterdir()) == []
    assert "PrivateClient" not in capsys.readouterr().err


def test_bad_encoding_empty_and_size_gates(tmp_path, monkeypatch):
    source = tmp_path / "private.conf"
    source.write_bytes(b"hostname \xff\n")
    with pytest.raises(AnonymizationError, match="UTF-8"):
        prepare_file(source, "cisco-ios", tmp_path / "out")
    with pytest.raises(AnonymizationError):
        anonymize_text("", "cisco-ios")
    monkeypatch.setattr(service, "MAX_INPUT_BYTES", 3)
    with pytest.raises(AnonymizationError, match="budget"):
        anonymize_text(IOS, "cisco-ios")


@pytest.mark.parametrize("family,text", [("fortios", FORTI), ("cisco-ios", IOS), ("cisco-asa", ASA)])
@pytest.mark.parametrize("format", ["JSON", "HTML"])
def test_public_offline_audit_of_prepared_samples(tmp_path, family, text, format):
    source = write(tmp_path, text)
    destination = tmp_path / "share"
    prepare_file(source, family, destination)
    before = tmp_path / ("before." + format.lower())
    after = tmp_path / ("after." + format.lower())
    assert audit_main(["-i", str(source), "-d", family, "-o", format, "-f", str(before)]) == 0
    assert audit_main(["-i", str(destination / "config.conf"), "-d", family, "-o", format, "-f", str(after)]) == 0
    output = after.read_text(encoding="utf-8")
    assert "Private" not in output and "SecretPassword987" not in output and "10.20.30" not in output
    if format == "JSON":
        old = json.loads(before.read_text())
        new = json.loads(output)
        # Qualified sample controls, not a universal equality certification.
        def policy_rules(data):
            return sorted(item["rule_id"] for item in data["security-audit"].values()
                          if ".policy." in item["rule_id"])
        assert policy_rules(old) == policy_rules(new)


def test_script_entrypoint_help_and_automatic_selection(tmp_path):
    script = Path(__file__).resolve().parents[1] / "scripts" / "anonymize_config.py"
    result = subprocess.run([sys.executable, str(script), "--help"], capture_output=True, text=True)
    assert result.returncode == 0 and "--check-only" in result.stdout
    source = write(tmp_path, FORTI)
    assert main(["-i", str(source), "--check-only"]) == 0
    source.write_text("version 15.2\nhostname PrivateRouter\n")
    assert main(["-i", str(source), "--check-only"]) == 2


def test_zone_and_vip_bindings_are_not_repaired_or_broken():
    text = '''config system zone
edit PrivateZone
set interface port1
next
end
config firewall vip
edit PrivateVIP
set extip 10.1.1.8
set mappedip 10.2.2.8
next
end
config firewall policy
edit 1
set srcintf PrivateZone
set dstaddr PrivateVIP
set srcaddr UndefinedAddress
set service ALL
set action accept
next
end
'''
    output, _ = anonymize_text(text, "fortios")
    rows = [row.tokens for row in statements(output, comments=("#",)) if row.tokens]
    zone = next(row[1].value for row in rows if row[0].value == "edit" and row[1].value.startswith("zone_"))
    vip = next(row[1].value for row in rows if row[0].value == "edit" and row[1].value.startswith("vip_"))
    assert f"set srcintf {zone}" in output and f"set dstaddr {vip}" in output
    undefined = next(row[2].value for row in rows if row[0].value == "set" and row[1].value == "srcaddr")
    assert undefined not in {row[1].value for row in rows if row[0].value == "edit"}


def test_nested_api_family_bindings_and_numeric_snmp_identifier():
    text = '''config system api-user
edit PrivateAPI
set api-key ENC PrivateAPIKey
config trusthost
edit 1
set type ipv4-trusthost
set ipv4-trusthost 10.5.6.0 255.255.255.0
next
edit 2
set type ipv6-trusthost
set ipv6-trusthost fd12:3456::/64
next
end
next
end
config system snmp community
edit 1
set name PrivateCommunity
set status enable
next
end
'''
    output, _ = anonymize_text(text, "fortios")
    assert "Private" not in output
    assert "edit 1" in output and "edit 2" in output
    assert "ipv4-trusthost" in output and "ipv6-trusthost" in output


@pytest.mark.parametrize("family,text", [
    ("fortios", 'config system global\nconfig ipv6\nset ip6-address fd12::1/64\nend\nend\n'),
    ("fortios", 'config system interface\nedit ""\nset ip 10.1.2.3 255.255.255.0\nnext\nend\n'),
    ("cisco-ios", 'hostname Private\ninterface Loopback1\n ip address 127.0.0.1 255.255.255.0\nip access-list standard PrivateACL\n permit 127.0.0.0 0.0.0.255\n'),
])
def test_invalid_scope_empty_identity_and_special_address_conflicts(family, text):
    with pytest.raises(AnonymizationError):
        anonymize_text(text, family)


def test_all_documentation_blocks_have_noncolliding_translation():
    text = '''interface GigabitEthernet0/0
 ip address 192.0.2.1 255.255.255.0
interface GigabitEthernet0/1
 ip address 198.51.100.1 255.255.255.0
interface GigabitEthernet0/2
 ip address 203.0.113.1 255.255.255.0
'''
    for _ in range(8):
        output, _ = anonymize_text(text, "cisco-ios")
        old = [row.tokens[2].value for row in statements(text, comments=("!",)) if len(row.tokens) == 4]
        new = [row.tokens[2].value for row in statements(output, comments=("!",)) if len(row.tokens) == 4]
        assert len(set(new)) == 3
        assert all(a != b for a, b in zip(old, new))


def test_wildcards_unrestricted_and_noncanonical_zero_prefix_hosts():
    text = '''interface Loopback0
 ipv6 address fd12:3456::8/0
line vty 0 4
 ipv6 access-class PrivateACL in
ipv6 access-list PrivateACL
 permit ipv6 ::/0 ::/0
'''
    output, _ = anonymize_text(text, "cisco-ios")
    assert "fd12:3456" not in output and "permit ipv6 ::/0 ::/0" in output
    prefix = next(row.tokens[2].value for row in statements(output, comments=("!",))
                  if len(row.tokens) == 3 and row.tokens[1].value == "address")
    assert ipaddress.ip_interface(prefix).ip != ipaddress.IPv6Address("::")
    assert prefix.endswith("/0")


def test_crlf_source_and_privacy_preserving_argument_errors(tmp_path, capsys):
    text = FORTI.replace("\n", "\r\n")
    output, _ = anonymize_text(text, "fortios")
    assert output.count("\r\n") == text.count("\r\n")
    source = write(tmp_path, IOS, "PrivateClient.conf")
    with pytest.raises(AnonymizationError):
        prepare_file(source, "cisco-ios", tmp_path)
    with pytest.raises(SystemExit):
        main(["--PrivateClient"])
    assert "PrivateClient" not in capsys.readouterr().err


def test_permission_protocol_prevents_publication_and_has_bounded_wait(tmp_path, monkeypatch):
    # Validate Windows helper without changing os.name for pathlib globally.
    monkeypatch.setattr(service, "os", type("Windows", (), {"name": "nt"})())
    monkeypatch.setattr(service.subprocess, "CREATE_NO_WINDOW", 0, raising=False)
    calls = []
    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        if args[0] == "whoami":
            return subprocess.CompletedProcess(args, 0, '"domain\\operator","S-1-5-21-123-456-789-1001"\n', '')
        return subprocess.CompletedProcess(args, 0, '', '')
    monkeypatch.setattr(service.subprocess, "run", fake_run)
    assert service._restrict_directory(tmp_path)
    assert len(calls) == 2 and all(call[1]["timeout"] == 15 for call in calls)
    assert "(OI)(CI)F" in calls[1][0][-1]


@pytest.mark.parametrize("storage,value", [
    ("0", "SecretPassword987"), ("7", "04480E051A33490E"),
    ("5", "$1$Original$AbCd0123456789abcdefghij"),
    ("8", "$8$Original$AbCd0123456789abcdefghij"),
    ("9", "$9$Original$AbCd0123456789abcdefghij"),
])
def test_cisco_storage_types_and_ordered_removals(storage, value, tmp_path):
    text = f"version 15.2\nusername PrivateUser secret {storage} {value}\nusername Retired password 0 PrivateRetiredSecret\nno username Retired\n"
    output, _ = anonymize_text(text, "cisco-ios")
    old = CiscoIOSParser(str(write(tmp_path, text))).get_credential_metadata()
    new = CiscoIOSParser(str(write(tmp_path, output, "sanitized.conf"))).get_credential_metadata()
    assert len(old) == len(new) == 1
    assert old[0].storage_type == new[0].storage_type
    assert old[0].storage_assessment == new[0].storage_assessment
    assert value not in output and "PrivateRetiredSecret" not in output


@pytest.mark.parametrize("marker", ["encrypted", "pbkdf2"])
def test_asa_enable_hashes_and_native_masking_markers(marker):
    text = f"ASA Version 9.18(4)\nenable password ABCDEFabcdef1234 {marker}\n"
    output, _ = anonymize_text(text, "cisco-asa")
    assert "ABCDEFabcdef1234" not in output and output.endswith(marker + "\n")
    text = 'config user radius\nedit PrivateRadius\nset secret "<redacted>"\nnext\nend\n'
    output, summary = anonymize_text(text, "fortios")
    assert 'set secret "<redacted>"' in output
    assert any("masked" in value for value in summary["retained-structural-constants"])


def test_domain_wildcard_suffix_relationships():
    text = '''config firewall address
edit PrivateOne
set type fqdn
set fqdn "server.branch.company.test"
next
edit PrivateTwo
set type fqdn
set fqdn "*.branch.company.test"
next
edit PrivateThree
set type fqdn
set fqdn "company.test"
next
end
'''
    output, _ = anonymize_text(text, "fortios")
    fqdn = [row.tokens[2].value for row in statements(output, comments=("#",))
            if len(row.tokens) == 3 and row.tokens[1].value == "fqdn"]
    assert fqdn[0].endswith(fqdn[1][1:])
    assert fqdn[1].endswith("." + fqdn[2])


def test_reserved_root_vdom_and_native_interface_namespace_collisions():
    text = '''config vdom
edit root
config system zone
edit port1
set interface port2
next
end
config firewall policy
edit 1
set srcintf port1
set dstaddr all
set action accept
next
end
next
end
'''
    output, _ = anonymize_text(text, "fortios")
    assert "edit root" in output and "set interface port2" in output
    assert "set srcintf zone_" in output and "edit zone_" in output


def test_uuid_consistency_and_vrf_segment_names():
    original_uuid = "048a4a2c-befd-41fb-930d-610c9a0f4c31"
    text = f'''config firewall address
edit PrivateAddr
set uuid {original_uuid}
set subnet 10.2.3.0 255.255.255.0
next
end
config firewall policy
edit 1
set uuid {original_uuid}
set srcaddr PrivateAddr
set action accept
next
end
'''
    output, _ = anonymize_text(text, "fortios")
    identifiers = [row.tokens[2].value for row in statements(output, comments=("#",))
                   if len(row.tokens) == 3 and row.tokens[1].value == "uuid"]
    assert identifiers[0] == identifiers[1] != original_uuid
    text = '''ip vrf PrivateVRF
 rd 65000:1
 route-target export 65000:1
vlan 20
 name PrivateSegment
interface Vlan20
 ip vrf forwarding PrivateVRF
 ip address 10.5.6.1 255.255.255.0
'''
    output, _ = anonymize_text(text, "cisco-ios")
    assert "Private" not in output and "interface Vlan20" in output and "rd 65000:1" in output
    assert "ip vrf vrf_" in output and "ip vrf forwarding vrf_" in output and "name segment_" in output


def test_interrupted_summary_write_never_publishes_approval(tmp_path, monkeypatch):
    source = write(tmp_path, FORTI)
    original = source.read_bytes()
    destination = tmp_path / "out"
    original_fsync = service.os.fsync
    calls = 0
    def interrupted(fd):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("failure contains private path")
        return original_fsync(fd)
    monkeypatch.setattr(service.os, "fsync", interrupted)
    with pytest.raises(OSError):
        prepare_file(source, "fortios", destination)
    assert (destination / "sanitization-summary.json").read_bytes() == b""
    assert (destination / "sanitization-summary.pending").exists()
    assert source.read_bytes() == original


def test_hostname_labels_and_unsupported_dns_service_labels():
    import re
    output, _ = anonymize_text(IOS, "cisco-ios")
    names = [row.tokens[-1].value for row in statements(output, comments=("!",))
             if row.tokens and (row.tokens[0].value == "hostname" or row.tokens[:2] and row.tokens[0].value == "ip" and row.tokens[1].value == "domain")]
    assert names
    for name in names:
        assert len(name) <= 253
        assert all(re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label) for label in name.split("."))
    for original in ("_ldap._tcp.company.test", "-broken.company.test", "a" * 64 + ".test"):
        text = f'config user radius\nedit Server\nset server "{original}"\nnext\nend\n'
        with pytest.raises(AnonymizationError):
            anonymize_text(text, "fortios")


@pytest.mark.parametrize("text", ["hostname\u00a0Private\n", "hostname Private\u2028Secret\n"])
def test_unqualified_unicode_whitespace_is_bounded_and_blocked(text):
    with pytest.raises(AnonymizationError):
        anonymize_text(text, "cisco-ios")


@pytest.mark.parametrize("path", [r"\\PrivateServer\share\source.conf", "//PrivateServer/share/source.conf", "https://private.invalid/source.conf"])
def test_remote_filesystem_paths_block_before_access(path):
    with pytest.raises(AnonymizationError, match="local") as error:
        prepare_file(path, "fortios", None, check_only=True)
    assert "PrivateServer" not in str(error.value)


def test_empty_banners_stay_empty_and_multiline_newlines_are_preserved():
    source = "banner login ^C^C\n"
    output, _ = anonymize_text(source, "cisco-ios")
    assert output == source
    source = 'version 15.2\r\nbanner login ^CPrivate\r\nClient \"Text\r\n^C\r\n'
    output, _ = anonymize_text(source, "cisco-ios")
    assert output.count("\r\n") == source.count("\r\n")
    assert "Private" not in output and "Text" not in output


def test_lexer_and_domain_budgets_fail_closed(monkeypatch):
    from src.devices.common import anonymization as grammar
    from src.anonymize.engine import Mapping, AddressMap
    from src.devices.common.anonymization import RewritePlan
    monkeypatch.setattr(grammar, "MAX_SOURCE_TOKENS", 2)
    with pytest.raises(AnonymizationError, match="budget"):
        statements("hostname Private extra\n", comments=("!",))
    monkeypatch.setattr("src.anonymize.engine.MAX_REWRITES", 1)
    mapping = Mapping(AddressMap(RewritePlan()))
    with pytest.raises(AnonymizationError, match="budget"):
        mapping.domain("a.b")


def test_exported_factory_all_object_retains_broad_policy_semantics(tmp_path):
    text = '''config firewall address
edit all
set uuid 048a4a2c-befd-41fb-930d-610c9a0f4c31
next
end
config firewall policy
edit 1
set srcintf any
set dstintf any
set srcaddr all
set dstaddr all
set service ALL
set schedule always
set action accept
next
end
'''
    output, _ = anonymize_text(text, "fortios")
    assert "edit all" in output and "set srcaddr all" in output and "set dstaddr all" in output
    from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
    old = process_fortios_conf(FortiOSParser(str(write(tmp_path, text))))
    new = process_fortios_conf(FortiOSParser(str(write(tmp_path, output, "sanitized.conf"))))
    assert sorted(item.rule_id for item in old.values()) == sorted(item.rule_id for item in new.values())
    assert old  # a silent no-op test must not certify preservation


@pytest.mark.parametrize("family,text", [
    ("cisco-ios", "username PrivateUser password 0 Secret\nno username privateuser\n"),
    ("fortios", "config firewall address\nedit PrivateObject\nset subnet 10.1.2.0 255.255.255.0\nnext\nend\nconfig firewall policy\nedit 1\nset srcaddr privateobject\nnext\nend\n"),
])
def test_unqualified_case_variant_bindings_block_instead_of_changing_effective_state(family, text):
    with pytest.raises(AnonymizationError, match="case-variant"):
        anonymize_text(text, family)


def test_empty_values_are_never_filled_to_invent_configured_state():
    text = 'config system global\nset hostname ""\nend\nconfig system ha\nset mode a-p\nset group-name ""\nend\n'
    output, _ = anonymize_text(text, "fortios")
    assert 'set hostname ""' in output and 'set group-name ""' in output
    text = 'hostname ""\nbanner login ""\n'
    output, _ = anonymize_text(text, "cisco-asa")
    assert output == text
