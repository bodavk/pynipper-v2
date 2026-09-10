from src.devices.common.models import ConfigurationState, KnowledgeState
from src.devices.juniper.junos import JunOSParser


HIERARCHICAL_CONFIG = r'''## Model: SRX345
version 22.4R1.10;
system {
    host-name edge-a;
    services {
        inactive: telnet;
        ssh {
            root-login deny;
            ciphers [ aes256-ctr aes256-gcm@openssh.com ];
            macs [ hmac-sha2-256 hmac-sha2-512 ];
        }
        web-management {
            https {
                system-generated-certificate;
            }
        }
    }
    login {
        user audit {
            class super-user;
            authentication {
                encrypted-password "$6$redacted";
            }
        }
    }
    syslog {
        host 192.0.2.30 {
            any informational;
        }
    }
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 192.0.2.1/24;
                filter {
                    input MGMT;
                }
            }
        }
    }
}
security {
    zones {
        security-zone trust {
            interfaces ge-0/0/0.0;
        }
    }
}
firewall {
    family inet {
        filter MGMT {
            term allow-ssh {
                from {
                    source-address {
                        10.0.0.0/8;
                    }
                    protocol tcp;
                }
                then {
                    log;
                    accept;
                }
            }
            inactive: term old-any {
                from {
                    source-address 0.0.0.0/0;
                }
                then accept;
            }
        }
    }
}
'''


SET_CONFIG = r'''## Model: SRX345
set version 22.4R1.10
set system host-name edge-a
set system services telnet
deactivate system services telnet
set system services ssh root-login deny
set system services ssh ciphers [ aes256-ctr aes256-gcm@openssh.com ]
set system services ssh macs [ hmac-sha2-256 hmac-sha2-512 ]
set system services web-management https system-generated-certificate
set system login user audit class super-user
set system login user audit authentication encrypted-password "$6$redacted"
set system syslog host 192.0.2.30 any informational
set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24
set interfaces ge-0/0/0 unit 0 family inet filter input MGMT
set security zones security-zone trust interfaces ge-0/0/0.0
set firewall family inet filter MGMT term allow-ssh from source-address 10.0.0.0/8
set firewall family inet filter MGMT term allow-ssh from protocol tcp
set firewall family inet filter MGMT term allow-ssh then log
set firewall family inet filter MGMT term allow-ssh then accept
set firewall family inet filter MGMT term old-any from source-address 0.0.0.0/0
set firewall family inet filter MGMT term old-any then accept
deactivate firewall family inet filter MGMT term old-any
'''


def _parse(tmp_path, name, config):
    path = tmp_path / name
    path.write_text(config, encoding="utf-8")
    return JunOSParser(str(path))


def _term_projection(parser):
    return [
        (
            term.family,
            term.filter_name,
            term.term_name,
            term.position,
            term.active,
            term.sources,
            term.destinations,
            term.protocols,
            term.actions,
            term.attachments,
        )
        for term in parser.get_filter_terms()
    ]


def test_hierarchy_and_display_set_have_equivalent_semantics(tmp_path):
    hierarchy = _parse(tmp_path, "hierarchy.conf", HIERARCHICAL_CONFIG)
    display_set = _parse(tmp_path, "set.conf", SET_CONFIG)

    assert hierarchy.format == "hierarchical"
    assert display_set.format == "set"
    assert hierarchy.get_hostname() == display_set.get_hostname() == "edge-a"
    assert hierarchy.get_version() == display_set.get_version() == "22.4R1.10"
    assert hierarchy.get_model() == display_set.get_model() == "SRX345"
    assert hierarchy.get_services() == display_set.get_services() == {
        "telnet": False,
        "ssh": True,
        "http": False,
        "https": True,
    }
    assert [user["username"] for user in hierarchy.get_users()] == ["audit"]
    assert [user["username"] for user in display_set.get_users()] == ["audit"]
    assert _term_projection(hierarchy) == _term_projection(display_set)

    normalized = hierarchy.get_normalized_config()
    assert normalized.hostname.value == "edge-a"
    assert normalized.software_version.value == "22.4R1.10"
    assert normalized.device_model.value == "SRX345"
    assert normalized.users.items[0].role == "super-user"
    assert normalized.interfaces.items[0].zone == "trust"
    assert normalized.interfaces.items[0].addresses == ("192.0.2.1/24",)
    assert normalized.policies.items[0].action == "accept"
    assert normalized.policies.items[1].state == ConfigurationState.DISABLED
    display_normalized = display_set.get_normalized_config()
    assert [
        (item.destination_type, item.address, item.severity)
        for item in normalized.logging_destinations.items
    ] == [
        (item.destination_type, item.address, item.severity)
        for item in display_normalized.logging_destinations.items
    ]
    assert [
        (item.name, item.value) for item in normalized.crypto_settings.items
    ] == [
        (item.name, item.value) for item in display_normalized.crypto_settings.items
    ]


def test_display_set_delete_deactivate_and_activate_are_effective(tmp_path):
    parser = _parse(
        tmp_path,
        "mutations.conf",
        """set system services telnet
delete system services telnet
set system services ssh
deactivate system services ssh
activate system services ssh
set system services web-management http
deactivate system services web-management
""",
    )

    assert parser.get_services() == {
        "telnet": False,
        "ssh": True,
        "http": False,
        "https": False,
    }
    assert all("telnet" not in line for line in parser.get_native_config())


def test_delete_clears_deactivated_state_before_recreation(tmp_path):
    parser = _parse(
        tmp_path,
        "recreated.conf",
        """set system services telnet
deactivate system services telnet
delete system services telnet
set system services telnet
""",
    )
    assert parser.get_services()["telnet"] is True


def test_inactive_hierarchy_is_preserved_but_not_effective(tmp_path):
    parser = _parse(
        tmp_path,
        "inactive.conf",
        """system {
 inactive: services {
  telnet;
  web-management { http; }
 }
 services { ssh; }
}
""",
    )
    assert parser.get_services() == {
        "telnet": False,
        "ssh": True,
        "http": False,
        "https": False,
    }
    assert any(not statement.active for statement in parser.statements)


def test_apply_groups_is_preserved_with_explicit_unsupported_diagnostic(tmp_path):
    parser = _parse(
        tmp_path,
        "groups.conf",
        "set groups management system services ssh\nset apply-groups management\n",
    )
    assert "set apply-groups management" in parser.get_native_config()
    assert any("not expanded" in diagnostic for diagnostic in parser.diagnostics)
    assert parser.get_services()["ssh"] is False


def test_malformed_hierarchy_surfaces_parse_error(tmp_path):
    parser = _parse(tmp_path, "broken.conf", "system { services { ssh; }\n")
    assert parser.statements == []
    assert any("unclosed" in diagnostic for diagnostic in parser.diagnostics)
    normalized = parser.get_normalized_config()
    assert normalized.management_services.state == KnowledgeState.PARSE_ERROR
