# Report evidence inventory — 2026-10-07

Measured from the 39 permanent, sanitized regression configurations through the public parser and processor pipelines. Counts are finding instances across fixtures, not distinct checks or production prevalence. Absence/default evidence often has no physical line by design; an unlocated statement is a review candidate, not automatically an evidence defect. Rich context means an EvidenceContext is attached. Existing located evidence can already be sufficient.

| Family | Finding instances | With context | All evidence unlocated |
|---|---:|---:|---:|
| F5_BIGIP | 27 | 0 | 0 |
| IOS_ROUTER | 56 | 0 | 16 |
| IOS_XE | 34 | 0 | 19 |
| ASA | 32 | 0 | 15 |
| FORTIOS | 54 | 39 | 13 |
| JUNOS | 35 | 0 | 7 |
| SCREENOS | 22 | 0 | 7 |
| CHECKPOINT_FW1 | 14 | 0 | 0 |
| PAN_OS | 25 | 0 | 8 |
| HP_PROCURVE | 18 | 0 | 9 |
| ARISTA_EOS | 17 | 0 | 7 |
| SONICOS | 16 | 0 | 9 |
| CHECKPOINT_GAIA | 17 | 0 | 4 |

## Rule inventory

Examples below are sanitized evidence already emitted by the project. Repeated occurrences of a rule are grouped; these examples do not cover every branch, supported syntax or export dialect. Review the parser and relationship before deciding whether to add context.

### F5_BIGIP

| Rule | Instances | With context | Unlocated | Sample current evidence |
|---|---:|---:|---:|---|
| `f5.bigip.auth.active_remote_servers_none` | 1 | 0 | 0 | line 43: auth source type radius; line 46: auth radius /Common/system-auth servers none ssl unknown ssl-check-peer unknown |
| `f5.bigip.auth.remote_default_admin` | 1 | 0 | 0 | line 82: auth remote-user default-role admin |
| `f5.bigip.cli.audit_disabled` | 1 | 0 | 0 | line 35: cli global-settings audit disabled |
| `f5.bigip.cli.idle_timeout_disabled` | 1 | 0 | 0 | line 36: cli global-settings idle-timeout disabled |
| `f5.bigip.console.idle_timeout_disabled` | 1 | 0 | 0 | line 4: sys global-settings console-inactivity-timeout 0 |
| `f5.bigip.credentials.local_plaintext` | 1 | 0 | 0 | line 50: auth user /Common/audit password <redacted> |
| `f5.bigip.credentials.monitor_storage` | 1 | 0 | 0 | line 90: ltm monitor http /Common/app_mon send <Authorization: Basic redacted> |
| `f5.bigip.http.legacy_tls_protocol` | 1 | 0 | 0 | line 14: sys httpd ssl-protocol all -SSLv2 -SSLv3 |
| `f5.bigip.http.redirect_disabled` | 1 | 0 | 0 | line 13: sys httpd redirect-http-to-https disabled |
| `f5.bigip.http.unrestricted_sources` | 1 | 0 | 0 | line 12: sys httpd allow unrestricted |
| `f5.bigip.http.weak_cipher_suite` | 1 | 0 | 0 | line 15: sys httpd ssl-ciphersuite ECDHE-RSA-AES128-GCM-SHA256:DES-CBC3-SHA |
| `f5.bigip.logging.syslog_remote_none` | 1 | 0 | 0 | line 53: sys syslog remote-servers none |
| `f5.bigip.ltm.clientssl_cleartext_enabled` | 1 | 0 | 0 | line 62: ltm virtual /Common/application enabled; line 58: ltm profile client-ssl /Common/unsafe_ssl allow-non-ssl enabled |
| `f5.bigip.ltm.clientssl_legacy_tls` | 1 | 0 | 0 | line 62: ltm virtual /Common/application enabled; line 58: ltm profile client-ssl /Common/unsafe_ssl allow-non-ssl enabled |
| `f5.bigip.management.self_ip_port_lockdown` | 1 | 0 | 0 | line 73: net self external-self allow-service all |
| `f5.bigip.ntp.unauthenticated_server` | 1 | 0 | 0 | line 68: sys ntp servers 192.0.2.123 |
| `f5.bigip.password_policy.enforcement_disabled` | 1 | 0 | 0 | line 39: auth password-policy policy-enforcement disabled |
| `f5.bigip.password_policy.login_lockout_disabled` | 1 | 0 | 0 | line 40: auth password-policy max-login-failures 0 |
| `f5.bigip.snmp.community_access` | 1 | 0 | 0 | line 18: sys snmp allowed-addresses unrestricted; line 20: sys snmp communities /Common/comm-public community-name <known default> access rw source any |
| `f5.bigip.snmp.default_community` | 1 | 0 | 0 | line 18: sys snmp allowed-addresses unrestricted; line 20: sys snmp communities /Common/comm-public community-name <known default> access rw source any |
| `f5.bigip.snmp.legacy_version` | 1 | 0 | 0 | line 18: sys snmp allowed-addresses unrestricted; sys snmp snmpv1/snmpv2c absent: default enable |
| `f5.bigip.snmp.v3_security` | 1 | 0 | 0 | line 18: sys snmp allowed-addresses unrestricted; line 27: sys snmp users /Common/monitor security-level no-auth-no-privacy auth-protocol unknown privacy-protocol unknown access ro |
| `f5.bigip.snmp.write_community` | 1 | 0 | 0 | line 18: sys snmp allowed-addresses unrestricted; line 20: sys snmp communities /Common/comm-public community-name <known default> access rw source any |
| `f5.bigip.ssh.idle_timeout_disabled` | 1 | 0 | 0 | line 9: sys sshd inactivity-timeout 0 |
| `f5.bigip.ssh.unrestricted_sources` | 1 | 0 | 0 | line 8: sys sshd allow unrestricted |
| `f5.bigip.vpn.ike_aggressive_mode` | 1 | 0 | 0 | line 77: net ipsec ike-peer /Common/branch mode aggressive phase1-auth-method pre-shared-key version v1 |
| `f5.bigip.vpn.ikev1` | 1 | 0 | 0 | line 77: net ipsec ike-peer /Common/branch mode aggressive phase1-auth-method pre-shared-key version v1 |

### IOS_ROUTER

| Rule | Instances | With context | Unlocated | Sample current evidence |
|---|---:|---:|---:|---|
| `cisco.ios.aaa.new_model` | 1 | 0 | 1 | aaa new-model not present or negated |
| `cisco.ios.authentication.login_lockout` | 2 | 0 | 2 | login block-for absent |
| `cisco.ios.auxiliary.authentication` | 1 | 0 | 0 | line 18: line aux 0; line 19: exec; line 20: exec-timeout 0 0; line 21: transport input all; line 22: transport output telnet |
| `cisco.ios.auxiliary.enabled` | 1 | 0 | 0 | line 18: line aux 0; line 19: exec; line 20: exec-timeout 0 0; line 21: transport input all; line 22: transport output telnet |
| `cisco.ios.auxiliary.session_timeout` | 1 | 0 | 0 | line 18: line aux 0; line 19: exec; line 20: exec-timeout 0 0; line 21: transport input all |
| `cisco.ios.banner.login` | 1 | 0 | 1 | No banner login or banner motd command |
| `cisco.ios.configuration.change_logging` | 1 | 0 | 1 | archive log config logging enable absent |
| `cisco.ios.console.authentication` | 1 | 0 | 0 | line 16: line con 0; line 17: exec-timeout 0 0 |
| `cisco.ios.console.session_timeout` | 1 | 0 | 0 | line 16: line con 0; line 17: exec-timeout 0 0 |
| `cisco.ios.control_plane.copp` | 1 | 0 | 1 | No control-plane service-policy input |
| `cisco.ios.credentials.enable_storage` | 1 | 0 | 0 | line 4: enable password 0 <credential redacted> |
| `cisco.ios.credentials.ftp_client_storage` | 1 | 0 | 0 | line 40: ip ftp password <redacted> |
| `cisco.ios.credentials.isakmp_pre_shared_key_storage` | 1 | 0 | 0 | line 37: isakmp peer 198.51.100.9 key 0 <credential redacted> |
| `cisco.ios.credentials.known_default_value` | 1 | 0 | 0 | line 25: line vty 0 4 password 0 <credential redacted> |
| `cisco.ios.credentials.line_password_storage` | 1 | 0 | 0 | line 25: line vty 0 4 password 0 <credential redacted> |
| `cisco.ios.credentials.local_storage` | 1 | 0 | 0 | line 3: username admin password 0 <credential redacted> |
| `cisco.ios.crypto.legacy_ike` | 1 | 0 | 0 | line 27: crypto isakmp policy 10; line 28: encryption 3des; line 29: hash md5; line 30: group 2 |
| `cisco.ios.crypto.legacy_ipsec` | 1 | 0 | 0 | line 31: crypto ipsec transform-set WEAK esp-3des esp-md5-hmac |
| `cisco.ios.discovery.cdp.external` | 1 | 0 | 0 | line 13: interface GigabitEthernet0/0; line 15: no shutdown; assessment policy: GigabitEthernet0/0 role external |
| `cisco.ios.fhrp.authentication` | 1 | 0 | 0 | line 44: standby 1 ip 10.20.0.1 |
| `cisco.ios.hardening.cis_hygiene` | 2 | 0 | 2 | 10 CIS hygiene item(s) absent; see observation |
| `cisco.ios.http.access_restriction` | 1 | 0 | 0 | line 5: ip http server |
| `cisco.ios.http.cleartext_service` | 1 | 0 | 0 | line 5: ip http server |
| `cisco.ios.interface.ip_hardening` | 2 | 0 | 0 | line 13: interface GigabitEthernet0/0; no ip redirects; no ip proxy-arp |
| `cisco.ios.ip.source_route` | 1 | 0 | 1 | no ip source-route absent |
| `cisco.ios.logging.remote_cleartext` | 1 | 0 | 0 | line 17: logging host 192.0.2.50 |
| `cisco.ios.logging.remote_destination` | 1 | 0 | 1 | No logging host command |
| `cisco.ios.ntp.authentication` | 1 | 0 | 0 | line 12: ntp server 192.0.2.123 |
| `cisco.ios.ntp.server_exposed` | 1 | 0 | 0 | line 12: ntp server 192.0.2.123 |
| `cisco.ios.routing.bgp.authentication` | 1 | 0 | 0 | line 32: router bgp 65000; line 33: neighbor 192.0.2.10 remote-as 65100 |
| `cisco.ios.routing.bgp.inbound_policy` | 1 | 0 | 0 | line 32: router bgp 65000; line 33: neighbor 192.0.2.10 remote-as 65100 |
| `cisco.ios.routing.bgp.outbound_policy` | 1 | 0 | 0 | line 32: router bgp 65000; line 33: neighbor 192.0.2.10 remote-as 65100 |
| `cisco.ios.routing.bgp.prefix_limit` | 1 | 0 | 0 | line 32: router bgp 65000; line 33: neighbor 192.0.2.10 remote-as 65100 |
| `cisco.ios.routing.ospf.authentication` | 1 | 0 | 0 | line 35: interface GigabitEthernet0/1; line 36: ip ospf 1 area 0; line 34: router ospf 1 |
| `cisco.ios.services.default_enabled` | 2 | 0 | 2 | pad: 'no service pad' absent; PAD is enabled by default; bootp server: 'no ip bootp server' absent; BOOTP service is enabled by default; mop: 'no mop enabled' absent on Ethernet interface(s) GigabitEthernet0/0 |
| `cisco.ios.services.dns_lookup` | 2 | 0 | 2 | ip domain lookup: default enabled |
| `cisco.ios.services.remote_shell` | 1 | 0 | 0 | line 38: ip rcmd rsh-enable |
| `cisco.ios.services.tcp_keepalives` | 2 | 0 | 2 | service tcp-keepalives-in absent |
| `cisco.ios.services.unnecessary` | 1 | 0 | 0 | line 10: service tcp-small-servers |
| `cisco.ios.snmp.default_community` | 1 | 0 | 0 | line 11: snmp-server community <redacted> rw |
| `cisco.ios.snmp.legacy_community` | 1 | 0 | 0 | line 11: snmp-server community <redacted> rw |
| `cisco.ios.snmp.legacy_version` | 1 | 0 | 0 | line 41: snmp-server host 192.0.2.40 version 2c <community or user redacted> |
| `cisco.ios.ssh.authentication_retries` | 1 | 0 | 0 | line 8: ip ssh authentication-retries 7 |
| `cisco.ios.ssh.negotiation_timeout` | 1 | 0 | 0 | line 9: ip ssh time-out 90 |
| `cisco.ios.ssh.protocol_version` | 1 | 0 | 0 | line 7: ip ssh version 1 |
| `cisco.ios.ssh.vty_access_restriction` | 1 | 0 | 0 | line 23: line vty 0 4 |
| `cisco.ios.vpn.ike_aggressive_mode` | 1 | 0 | 0 | line 37: isakmp peer 198.51.100.9 pre-shared key <redacted> |
| `cisco.ios.vty.authentication` | 1 | 0 | 0 | line 23: line vty 0 4; line 26: transport input all |
| `cisco.ios.vty.session_timeout` | 1 | 0 | 0 | line 23: line vty 0 4; line 24: exec-timeout 0 0; line 26: transport input all |
| `cisco.ios.vty.telnet` | 1 | 0 | 0 | line 23: line vty 0 4; line 24: exec-timeout 0 0; line 26: transport input all |

### IOS_XE

| Rule | Instances | With context | Unlocated | Sample current evidence |
|---|---:|---:|---:|---|
| `cisco.ios.aaa.new_model` | 1 | 0 | 1 | aaa new-model not present or negated |
| `cisco.ios.authentication.login_lockout` | 2 | 0 | 2 | login block-for absent |
| `cisco.ios.banner.login` | 1 | 0 | 1 | No banner login or banner motd command |
| `cisco.ios.configuration.change_logging` | 1 | 0 | 1 | archive log config logging enable absent |
| `cisco.ios.control_plane.copp` | 1 | 0 | 1 | No control-plane service-policy input |
| `cisco.ios.hardening.cis_hygiene` | 2 | 0 | 2 | 8 CIS hygiene item(s) absent; see observation |
| `cisco.ios.http.cleartext_service` | 1 | 0 | 0 | line 3: ip http server |
| `cisco.ios.http.unrestricted_sources` | 1 | 0 | 0 | ip http access-class MGMT; line 7: permit any |
| `cisco.ios.ip.source_route` | 1 | 0 | 1 | no ip source-route absent |
| `cisco.ios.layer2.access_edge.arp_inspection` | 1 | 0 | 0 | line 16: interface GigabitEthernet1; line 17: switchport mode access; line 18: switchport access vlan 10; assessment policy: GigabitEthernet1 role access-edge |
| `cisco.ios.layer2.access_edge.dhcp_snooping` | 1 | 0 | 0 | line 16: interface GigabitEthernet1; line 17: switchport mode access; line 18: switchport access vlan 10; assessment policy: GigabitEthernet1 role access-edge |
| `cisco.ios.layer2.access_edge.port_security` | 1 | 0 | 0 | line 16: interface GigabitEthernet1; line 17: switchport mode access; line 18: switchport access vlan 10; assessment policy: GigabitEthernet1 role access-edge |
| `cisco.ios.layer2.access_edge.source_guard` | 1 | 0 | 0 | line 16: interface GigabitEthernet1; line 17: switchport mode access; line 18: switchport access vlan 10; assessment policy: GigabitEthernet1 role access-edge |
| `cisco.ios.logging.remote_cleartext` | 1 | 0 | 0 | line 15: logging host 192.0.2.50 |
| `cisco.ios.logging.remote_destination` | 1 | 0 | 1 | No logging host command |
| `cisco.ios.ntp.servers` | 1 | 0 | 1 | No ntp server or peer command |
| `cisco.ios.ntp.weak_algorithm` | 1 | 0 | 0 | line 25: ntp server 192.0.2.123 key 1; line 23: ntp authentication-key 1 md5 <key redacted> |
| `cisco.ios.services.default_enabled` | 2 | 0 | 2 | pad: 'no service pad' absent; PAD is enabled by default; bootp server: 'no ip bootp server' absent; BOOTP service is enabled by default |
| `cisco.ios.services.dns_lookup` | 2 | 0 | 2 | ip domain lookup: default enabled |
| `cisco.ios.services.smart_install` | 1 | 0 | 0 | line 26: vstack |
| `cisco.ios.services.tcp_keepalives` | 2 | 0 | 2 | service tcp-keepalives-in absent |
| `cisco.ios.ssh.authentication_retries` | 1 | 0 | 0 | line 11: ip ssh authentication-retries 7 |
| `cisco.ios.ssh.negotiation_timeout` | 1 | 0 | 0 | line 12: ip ssh time-out 90 |
| `cisco.ios.ssh.protocol_version` | 1 | 0 | 0 | line 10: ip ssh version 1 |
| `cisco.ios.ssh.unrestricted_sources` | 1 | 0 | 0 | VTY lines 0, 1, 2, 3, 4; line 9: permit ip any any |
| `cisco.ios.ssh.weak_algorithms` | 2 | 0 | 2 | kex: default list includes diffie-hellman-group14-sha1; mac: default list includes hmac-sha1 |
| `cisco.ios.vty.authentication` | 1 | 0 | 0 | line 13: line vty 0 4; line 14: transport input ssh |
| `cisco.iosxe.crypto.legacy_ikev2` | 1 | 0 | 0 | line 19: crypto ikev2 proposal WEAK; line 20: encryption 3des; line 21: integrity md5; line 22: prf sha1; line 23: group 2 |

### ASA

| Rule | Instances | With context | Unlocated | Sample current evidence |
|---|---:|---:|---:|---|
| `cisco.asa.aaa.management_accounting` | 1 | 0 | 1 | active ssh management grant; aaa accounting ssh console: not configured |
| `cisco.asa.aaa.management_authentication` | 2 | 0 | 2 | active http management grant; aaa authentication http console: not configured |
| `cisco.asa.aaa.management_authorization` | 1 | 0 | 1 | aaa authorization command/exec absent |
| `cisco.asa.console.session_timeout` | 1 | 0 | 1 | console timeout defaults to 0 |
| `cisco.asa.credentials.local_user_storage` | 1 | 0 | 0 | line 3: username admin password <redacted> plaintext |
| `cisco.asa.credentials.tunnel_group_pre_shared_key_storage` | 1 | 0 | 0 | line 23: tunnel-group 198.51.100.9 ikev1 pre-shared-key <redacted> |
| `cisco.asa.crypto.legacy_transform` | 1 | 0 | 0 | line 16: crypto ipsec ikev1 transform-set WEAK esp-3des esp-md5-hmac; line 17: crypto map VPN 10 set ikev1 transform-set WEAK; line 18: crypto map VPN interface outside |
| `cisco.asa.crypto.legacy_vpn` | 1 | 0 | 0 | line 12: crypto ikev1 policy 10; line 13: encryption 3des; line 14: hash md5; line 15: group 2 |
| `cisco.asa.failover.authentication` | 1 | 0 | 0 | line 19: failover |
| `cisco.asa.hardening.cis_hygiene` | 2 | 0 | 2 | 10 CIS hygiene item(s) absent; see observation |
| `cisco.asa.interface.icmp_unrestricted` | 3 | 0 | 0 | line 4: interface GigabitEthernet0/0; line 5: nameif outside; icmp rules absent |
| `cisco.asa.interface.reverse_path` | 2 | 0 | 2 | interface outside |
| `cisco.asa.logging.missing` | 1 | 0 | 0 | line 24: logging host inside 192.0.2.60 |
| `cisco.asa.management.certificate` | 1 | 0 | 0 | line 9: http server enable |
| `cisco.asa.management.unrestricted_http` | 1 | 0 | 0 | line 10: http 0.0.0.0 0.0.0.0 outside |
| `cisco.asa.management.unrestricted_ssh` | 1 | 0 | 0 | line 8: ssh 0.0.0.0 0.0.0.0 outside |
| `cisco.asa.ntp.authentication` | 1 | 0 | 0 | line 11: ntp server 192.0.2.123 source inside |
| `cisco.asa.platform.password_recovery` | 2 | 0 | 2 | service password-recovery absent: documented default enabled |
| `cisco.asa.ssh.weak_algorithms` | 2 | 0 | 0 | line 1: ASA Version 9.18(4); encryption: medium level with CBC-mode ciphers (default) |
| `cisco.asa.threat_detection.basic` | 1 | 0 | 1 | threat-detection basic-threat absent or negated |
| `cisco.asa.tls.minimum_version` | 1 | 0 | 1 | ASDM (http server enable); ssl server-version absent: default tlsv1 |
| `cisco.asa.tls.weak_cipher` | 2 | 0 | 2 | ASDM (http server enable); ssl cipher tlsv1.2 absent: default medium |
| `cisco.asa.vpn.ike_aggressive_mode` | 1 | 0 | 0 | line 20: crypto ikev1 enable outside; line 23: tunnel-group 198.51.100.9 ikev1 pre-shared-key <redacted> |
| `cisco.asa.vpn.sysopt_permit_vpn` | 1 | 0 | 0 | line 18: crypto map VPN interface outside; line 20: crypto ikev1 enable outside; no sysopt connection permit-vpn absent |

### FORTIOS

| Rule | Instances | With context | Unlocated | Sample current evidence |
|---|---:|---:|---:|---|
| `fortinet.fortios.aaa.radius_message_authenticator` | 1 | 1 | 0 | line 52: set server 192.0.2.21; line 54: set transport-protocol udp; line 55: set require-message-authenticator disable |
| `fortinet.fortios.aaa.radsec_server_identity` | 1 | 1 | 0 | line 45: set server radius.example.test; line 47: set transport-protocol tls; line 48: set server-identity-check disable; line 49: set tls-min-proto-version TLSv1-1 |
| `fortinet.fortios.aaa.radsec_tls_version` | 1 | 1 | 0 | line 45: set server radius.example.test; line 47: set transport-protocol tls; line 48: set server-identity-check disable; line 49: set tls-min-proto-version TLSv1-1 |
| `fortinet.fortios.admin.centralized_authentication` | 2 | 2 | 0 | line 14: edit admin |
| `fortinet.fortios.admin.default_account_name` | 1 | 1 | 0 | line 14: edit admin |
| `fortinet.fortios.admin.local_login_unrestricted` | 2 | 2 | 0 | admin-restrict-local absent: documented default disable; line 14: edit admin |
| `fortinet.fortios.admin.lockout` | 1 | 1 | 0 | line 2: config system global |
| `fortinet.fortios.admin.mfa` | 1 | 1 | 0 | line 14: edit admin |
| `fortinet.fortios.admin.session_timeout` | 1 | 1 | 0 | line 11: set admintimeout 30 |
| `fortinet.fortios.admin.trusted_hosts` | 1 | 1 | 0 | line 14: edit admin |
| `fortinet.fortios.api.trusted_hosts` | 1 | 1 | 0 | line 31: set accprofile API-AUTOMATION; line 25: edit API-AUTOMATION; line 26: set sysgrp read-write; line 37: set type ipv4-trusthost; line 38: set ipv4-trusthost 0.0.0.0 0.0.0.0; line 33: set vdom root; line 34: set peer-auth disable |
| `fortinet.fortios.banner.login_disabled` | 3 | 0 | 3 | pre-login-banner absent: default disable |
| `fortinet.fortios.banner.post_login_disabled` | 2 | 0 | 2 | post-login-banner absent: default disable |
| `fortinet.fortios.cli.audit_disabled` | 3 | 0 | 3 | cli-audit-log absent: documented default disable |
| `fortinet.fortios.credentials.private_data_storage` | 2 | 0 | 0 | line 16: set password <redacted>; line 32: set api-key <redacted>; line 46: set secret <redacted> |
| `fortinet.fortios.crypto.admin_ssh_v1` | 1 | 1 | 0 | line 6: set admin-ssh-v1 enable |
| `fortinet.fortios.crypto.dh_parameters` | 1 | 1 | 0 | line 5: set dh-params 1024 |
| `fortinet.fortios.crypto.ssl_static_key_ciphers` | 1 | 1 | 0 | line 4: set ssl-static-key-ciphers enable |
| `fortinet.fortios.crypto.strong_crypto` | 1 | 1 | 0 | line 3: set strong-crypto disable |
| `fortinet.fortios.dos.wan_policy_missing` | 2 | 2 | 0 | line 67: edit wan1 |
| `fortinet.fortios.ha.heartbeat_protection` | 1 | 1 | 0 | line 108: set mode a-p |
| `fortinet.fortios.hardening.cis_hygiene` | 3 | 0 | 3 | 5 CIS hygiene item(s) absent; see observation |
| `fortinet.fortios.https.management_certificate` | 1 | 0 | 1 | admin-server-cert absent |
| `fortinet.fortios.logging.missing` | 1 | 0 | 1 | No supported logging target configured |
| `fortinet.fortios.logging.remote_cleartext` | 2 | 2 | 0 | line 117: set status enable; line 118: set server 192.0.2.20 |
| `fortinet.fortios.management.auxiliary_services` | 1 | 1 | 0 | line 71: set allowaccess http ssh snmp fgfm |
| `fortinet.fortios.management.default_admin_ports` | 2 | 2 | 0 | line 2: config system global |
| `fortinet.fortios.management.insecure_protocol` | 1 | 1 | 0 | line 71: set allowaccess http ssh snmp fgfm |
| `fortinet.fortios.ntp.synchronization` | 1 | 1 | 0 | line 80: set ntpsync disable |
| `fortinet.fortios.password_policy.disabled` | 1 | 1 | 0 | line 64: set status disable |
| `fortinet.fortios.policy.broad_accept` | 1 | 1 | 0 | line 83: edit 1 |
| `fortinet.fortios.policy.disabled_permissive_rule` | 1 | 1 | 0 | line 46: edit 100 |
| `fortinet.fortios.snmp.legacy_community` | 1 | 1 | 0 | line 75: edit <redacted> |
| `fortinet.fortios.snmp.secure_user_missing` | 1 | 1 | 0 | line 71: set allowaccess http ssh snmp fgfm |
| `fortinet.fortios.ssh.weak_enc_algo` | 1 | 1 | 0 | line 8: set ssh-enc-algo aes128-cbc aes256-ctr |
| `fortinet.fortios.sslvpn.factory_certificate` | 1 | 1 | 0 | line 94: set servercert "Fortinet_Factory"; line 97: set source-interface "wan1" |
| `fortinet.fortios.sslvpn.legacy_tls` | 1 | 1 | 0 | line 95: set ssl-min-proto-ver tls1-1; line 97: set source-interface "wan1" |
| `fortinet.fortios.sslvpn.unlimited_login_attempts` | 1 | 1 | 0 | line 96: set login-attempt-limit 0; line 97: set source-interface "wan1" |
| `fortinet.fortios.system.usb_auto_install` | 1 | 1 | 0 | line 112: set auto-install-config enable |
| `fortinet.fortios.tls.minimum_version` | 1 | 1 | 0 | line 7: set ssl-min-proto-version TLSv1-1 |
| `fortinet.fortios.vpn.ike_aggressive_mode` | 1 | 1 | 0 | line 102: set mode aggressive |

### JUNOS

| Rule | Instances | With context | Unlocated | Sample current evidence |
|---|---:|---:|---:|---|
| `juniper.junos.administration.web_session_limit` | 1 | 0 | 0 | line 15: set system services web-management https system-generated-certificate; line 16: set system services web-management session idle-timeout 60 |
| `juniper.junos.administration.web_session_timeout` | 1 | 0 | 0 | line 15: set system services web-management https system-generated-certificate; line 16: set system services web-management session idle-timeout 60 |
| `juniper.junos.authentication.accounting_destination` | 1 | 0 | 0 | line 9: set system tacplus-server 192.0.2.5 secret <redacted> |
| `juniper.junos.authentication.accounting_events` | 1 | 0 | 0 | line 9: set system tacplus-server 192.0.2.5 secret <redacted> |
| `juniper.junos.authentication.idle_timeout` | 1 | 0 | 0 | line 10: set system login user admin class super-user |
| `juniper.junos.authentication.lockout` | 1 | 0 | 1 | system login retry-options lockout-period absent |
| `juniper.junos.authentication.login_banner` | 1 | 0 | 1 | system login message absent |
| `juniper.junos.authentication.super_user` | 1 | 0 | 0 | line 10: set system login user admin class super-user |
| `juniper.junos.control_plane.lo0_filter` | 1 | 0 | 1 | interfaces lo0 family filter input absent |
| `juniper.junos.discovery.lldp.external` | 1 | 0 | 0 | line 22: set protocols lldp interface all; assessment policy: ge-0/0/0 role external |
| `juniper.junos.fhrp.authentication` | 1 | 0 | 0 | line 41: set interfaces ge-0/0/5 unit 0 family inet address 10.5.0.2/24 vrrp-group 5 |
| `juniper.junos.filter.broad_accept` | 1 | 0 | 0 | line 19: set firewall family inet filter EDGE term permit-any from source-address 0.0.0.0/0; line 20: set firewall family inet filter EDGE term permit-any then accept |
| `juniper.junos.hardening.cis_hygiene` | 2 | 0 | 2 | 23 CIS hygiene item(s) absent; see observation |
| `juniper.junos.host_inbound.management_exposed` | 1 | 0 | 0 | line 26: set security zones security-zone untrust interfaces ge-0/0/0.0; line 28: set security zones security-zone untrust host-inbound-traffic system-services all; line 15: set system services web-management https system-generated-certificate; line 17: snmp community/v3 configured <redacted>; line 12: set system services ssh root-login allow; line 13: set system services ssh protocol-version v1; line 14: set system services ssh ciphers [ 3des-cbc aes256-ctr ]; line 11: set system services telnet; assessment policy: ge-0/0/0.0 role external |
| `juniper.junos.interfaces.redirects` | 1 | 0 | 1 | system no-redirects absent |
| `juniper.junos.logging.event_coverage` | 1 | 0 | 0 | line 53: set system syslog host 192.0.2.31 authorization warning; line 54: set system syslog host 192.0.2.31 transport tls |
| `juniper.junos.logging.remote_destination` | 1 | 0 | 1 | system syslog host absent |
| `juniper.junos.management.grpc_cleartext` | 1 | 0 | 0 | line 6: set system services extension-service request-response grpc clear-text address 192.0.2.1; line 7: set system services extension-service request-response grpc clear-text port 50051 |
| `juniper.junos.management.insecure_protocol` | 1 | 0 | 0 | line 11: set system services telnet |
| `juniper.junos.management.rest_http` | 1 | 0 | 0 | line 4: set system services rest http addresses 192.0.2.1; line 5: set system services rest http port 3000 |
| `juniper.junos.management.unrestricted_rest` | 1 | 0 | 0 | line 4: set system services rest http addresses 192.0.2.1; line 5: set system services rest http port 3000 |
| `juniper.junos.ntp.authentication` | 1 | 0 | 0 | line 18: set system ntp server 192.0.2.20 |
| `juniper.junos.policy.idp_nonblocking` | 1 | 0 | 0 | line 38: set security policies from-zone trust to-zone untrust policy web-out then permit application-services idp-policy log-only-idp; line 39: set security idp idp-policy log-only-idp rulebase-ips rule observe match application default; line 40: set security idp idp-policy log-only-idp rulebase-ips rule observe then action no-action |
| `juniper.junos.routing.bgp.authentication` | 1 | 0 | 0 | line 23: set protocols bgp group TRANSIT type external; line 24: set protocols bgp group TRANSIT neighbor 192.0.2.10 |
| `juniper.junos.routing.bgp.inbound_policy` | 1 | 0 | 0 | line 23: set protocols bgp group TRANSIT type external; line 24: set protocols bgp group TRANSIT neighbor 192.0.2.10 |
| `juniper.junos.routing.bgp.outbound_policy` | 1 | 0 | 0 | line 23: set protocols bgp group TRANSIT type external; line 24: set protocols bgp group TRANSIT neighbor 192.0.2.10 |
| `juniper.junos.routing.bgp.prefix_limit` | 1 | 0 | 0 | line 23: set protocols bgp group TRANSIT type external; line 24: set protocols bgp group TRANSIT neighbor 192.0.2.10 |
| `juniper.junos.routing.ospf.authentication` | 1 | 0 | 0 | line 25: set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 |
| `juniper.junos.screen.icmp_flood_inactive` | 1 | 0 | 0 | line 27: set security zones security-zone untrust screen exposed-screen; line 29: set security screen ids-option exposed-screen tcp syn-flood attack-threshold 625; line 31: set security screen ids-option exposed-screen udp flood threshold 1000; line 32: set security screen ids-option exposed-screen icmp flood threshold 1000; line 34: set security screen ids-option exposed-screen alarm-without-drop; assessment policy: ge-0/0/0.0 role external |
| `juniper.junos.screen.syn_flood_inactive` | 1 | 0 | 0 | line 27: set security zones security-zone untrust screen exposed-screen; line 29: set security screen ids-option exposed-screen tcp syn-flood attack-threshold 625; line 31: set security screen ids-option exposed-screen udp flood threshold 1000; line 32: set security screen ids-option exposed-screen icmp flood threshold 1000; line 34: set security screen ids-option exposed-screen alarm-without-drop; assessment policy: ge-0/0/0.0 role external |
| `juniper.junos.screen.udp_flood_alarm_only` | 1 | 0 | 0 | line 27: set security zones security-zone untrust screen exposed-screen; line 29: set security screen ids-option exposed-screen tcp syn-flood attack-threshold 625; line 31: set security screen ids-option exposed-screen udp flood threshold 1000; line 32: set security screen ids-option exposed-screen icmp flood threshold 1000; line 34: set security screen ids-option exposed-screen alarm-without-drop; assessment policy: ge-0/0/0.0 role external |
| `juniper.junos.snmp.legacy_community` | 1 | 0 | 0 | line 17: set snmp community <redacted> authorization read-write |
| `juniper.junos.ssh.root_login` | 1 | 0 | 0 | line 12: set system services ssh root-login allow |
| `juniper.junos.ssh.weak_ciphers` | 1 | 0 | 0 | line 14: set system services ssh ciphers [ 3des-cbc aes256-ctr ] |

### SCREENOS

| Rule | Instances | With context | Unlocated | Sample current evidence |
|---|---:|---:|---:|---|
| `juniper.screenos.administration.login_attempts` | 1 | 0 | 0 | line 6: set admin access attempts 7 |
| `juniper.screenos.administration.login_banner` | 1 | 0 | 1 | admin auth banner absent |
| `juniper.screenos.administration.manager_sources` | 1 | 0 | 1 | admin/interface manager-IP restrictions absent |
| `juniper.screenos.administration.remote_session_timeout` | 1 | 0 | 0 | line 11: set admin auth server "auditors"; line 10: set auth-server "auditors" timeout 30 |
| `juniper.screenos.administration.session_timeout` | 1 | 0 | 0 | line 12: set console timeout 0 |
| `juniper.screenos.administration.web_session_timeout` | 1 | 0 | 0 | line 7: set admin auth web timeout 30 |
| `juniper.screenos.credentials.default_or_empty` | 1 | 0 | 0 | line 5: set admin password <redacted> |
| `juniper.screenos.https.legacy_cipher` | 1 | 0 | 0 | line 17: set ssl encrypt rc4 md5 |
| `juniper.screenos.lifecycle.end_of_life` | 3 | 0 | 3 | ScreenOS version 6.3.0r27.0 |
| `juniper.screenos.logging.remote_destination` | 1 | 0 | 1 | enabled syslog destination absent |
| `juniper.screenos.management.http` | 1 | 0 | 0 | line 13: set interface "ethernet0/0" zone "Untrust"; line 14: set interface "ethernet0/0" manage telnet web ssh ssl snmp |
| `juniper.screenos.management.telnet` | 1 | 0 | 0 | line 13: set interface "ethernet0/0" zone "Untrust"; line 14: set interface "ethernet0/0" manage telnet web ssh ssl snmp |
| `juniper.screenos.ntp.servers` | 1 | 0 | 1 | ntp server absent |
| `juniper.screenos.policy.broad_permit` | 1 | 0 | 0 | line 20: set policy id 10 from "Untrust" to "Trust" "Any" "Any" "ANY" permit; line 21: set ike p1-proposal "LEGACY-P1" preshare pre-g2 3des md5 second 28800; line 22: set ike gateway "PARTNER" address 192.0.2.50 Main outgoing-interface ethernet0/0 proposal "LEGACY-P1" |
| `juniper.screenos.policy.broad_service` | 1 | 0 | 0 | line 19: set policy id 10 from "Untrust" to "Trust" "Any" "Any" "ANY" permit log; line 20: set policy id 10; line 21: set dst-address "RestrictedServer"; line 22: unset dst-address "Any" |
| `juniper.screenos.policy.default_permit` | 1 | 0 | 0 | line 19: set policy default-permit-all |
| `juniper.screenos.policy.unlogged_permit` | 1 | 0 | 0 | line 20: set policy id 10 from "Untrust" to "Trust" "Any" "Any" "ANY" permit; line 21: set ike p1-proposal "LEGACY-P1" preshare pre-g2 3des md5 second 28800; line 22: set ike gateway "PARTNER" address 192.0.2.50 Main outgoing-interface ethernet0/0 proposal "LEGACY-P1" |
| `juniper.screenos.snmp.legacy_community` | 1 | 0 | 0 | line 18: set snmp community <redacted> read-write version any |
| `juniper.screenos.ssh.protocol_version` | 1 | 0 | 0 | line 15: set ssh version v1 |
| `juniper.screenos.vpn.weak_proposal` | 1 | 0 | 0 | line 21: set ike p1-proposal "LEGACY-P1" preshare pre-g2 3des md5 second 28800 |

### CHECKPOINT_FW1

| Rule | Instances | With context | Unlocated | Sample current evidence |
|---|---:|---:|---:|---|
| `checkpoint.fw1.layer.stealth_rule_missing` | 1 | 0 | 0 | line 5: Check Point layer 'rule-base / Network-Layer' rule 1 'Broad first' |
| `checkpoint.fw1.policy.broad_accept` | 2 | 0 | 0 | line 5: Check Point layer 'rule-base / Network-Layer' rule 1 'Broad first' |
| `checkpoint.fw1.policy.expired_rule` | 1 | 0 | 0 | line 22: Check Point layer 'rule-base / Network-Layer' rule 4 'Expired exception' |
| `checkpoint.fw1.policy.install_scope_any` | 2 | 0 | 0 | line 5: Check Point layer 'rule-base / Network-Layer' rule 1 'Broad first' |
| `checkpoint.fw1.policy.redundant_rule` | 2 | 0 | 0 | line 17: Check Point layer 'rule-base / Network-Layer' rule 3 'Redundant broad'; line 5: Check Point layer 'rule-base / Network-Layer' rule 1 'Broad first' |
| `checkpoint.fw1.policy.risky_service_exposure` | 1 | 0 | 0 | line 30: Check Point layer 'rule-base / Network-Layer' rule 5 'Legacy administration' |
| `checkpoint.fw1.policy.sensitive_accept_untracked` | 2 | 0 | 0 | line 5: Check Point layer 'rule-base / Network-Layer' rule 1 'Broad first' |
| `checkpoint.fw1.policy.shadowed_rule` | 3 | 0 | 0 | line 10: Check Point layer 'rule-base / Network-Layer' rule 2 'Shadowed deny'; line 5: Check Point layer 'rule-base / Network-Layer' rule 1 'Broad first' |

### PAN_OS

| Rule | Instances | With context | Unlocated | Sample current evidence |
|---|---:|---:|---:|---|
| `paloalto.panos.admin.centralized_authentication` | 1 | 0 | 0 | line 2: mgt-config user admin |
| `paloalto.panos.admin.concurrent_sessions` | 1 | 0 | 0 | line 4: localhost.localdomain: administrative management settings |
| `paloalto.panos.admin.idle_timeout` | 1 | 0 | 0 | line 4: localhost.localdomain: administrative management settings |
| `paloalto.panos.admin.lockout_time` | 1 | 0 | 0 | line 4: localhost.localdomain: administrative management settings |
| `paloalto.panos.admin.login_attempts` | 1 | 0 | 0 | line 4: localhost.localdomain: administrative management settings |
| `paloalto.panos.admin.login_banner` | 1 | 0 | 0 | line 4: localhost.localdomain: administrative management settings |
| `paloalto.panos.admin.ssh_profile_missing` | 1 | 0 | 1 | localhost.localdomain: management SSH profile absent |
| `paloalto.panos.analysis.panorama_inheritance_unknown` | 1 | 0 | 1 | Panorama device-group/template inheritance is present and is not resolved by an individual-file audit |
| `paloalto.panos.credentials.password_complexity` | 1 | 0 | 0 | line 4: mgt-config password-complexity |
| `paloalto.panos.credentials.password_history_disabled` | 1 | 0 | 0 | line 4: mgt-config password-complexity |
| `paloalto.panos.credentials.username_inclusion_allowed` | 1 | 0 | 0 | line 4: mgt-config password-complexity |
| `paloalto.panos.dns.servers` | 1 | 0 | 1 | deviceconfig system dns-setting servers absent |
| `paloalto.panos.hardening.cis_hygiene` | 1 | 0 | 1 | 5 CIS hygiene item(s) absent; see observation |
| `paloalto.panos.logging.system_forwarding` | 1 | 0 | 1 | deviceconfig system log-settings system syslog destination absent |
| `paloalto.panos.management.http` | 1 | 0 | 0 | line 6: localhost.localdomain: interface-management-profile WAN-MGMT; line 7: vsys1: interface ethernet1/1 |
| `paloalto.panos.management.tls_profile_missing` | 1 | 0 | 0 | line 4: localhost.localdomain: deviceconfig system management TLS |
| `paloalto.panos.management.unrestricted_secure_service` | 1 | 0 | 0 | line 6: localhost.localdomain: interface-management-profile WAN-MGMT; line 7: vsys1: interface ethernet1/1 |
| `paloalto.panos.ntp.servers` | 1 | 0 | 1 | deviceconfig system ntp-servers absent |
| `paloalto.panos.policy.broad_allow` | 1 | 0 | 0 | line 13: localhost.localdomain/vsys1/rulebase: security rule 1 ANY-ALLOW |
| `paloalto.panos.policy.disabled_permissive_rule` | 1 | 0 | 0 | line 14: localhost.localdomain/vsys1/rulebase: security rule 2 DISABLED-ANY |
| `paloalto.panos.policy.log_forwarding` | 1 | 0 | 0 | line 13: localhost.localdomain/vsys1/rulebase: security rule 1 ANY-ALLOW |
| `paloalto.panos.policy.security_profiles` | 1 | 0 | 0 | line 13: localhost.localdomain/vsys1/rulebase: security rule 1 ANY-ALLOW |
| `paloalto.panos.policy.session_logging` | 1 | 0 | 0 | line 13: localhost.localdomain/vsys1/rulebase: security rule 1 ANY-ALLOW |
| `paloalto.panos.snmp.secure_user_missing` | 1 | 0 | 1 | attached SNMP management without secure SNMPv3 user |
| `paloalto.panos.updates.threat_content` | 1 | 0 | 1 | deviceconfig system update-schedule threats: not configured |

### HP_PROCURVE

| Rule | Instances | With context | Unlocated | Sample current evidence |
|---|---:|---:|---:|---|
| `hp.procurve.admin.login_banner` | 1 | 0 | 1 | banner motd absent from supported AOS-S export |
| `hp.procurve.admin.remote_cli_idle_timeout` | 1 | 0 | 1 | AOS-S YA.16.10.0023 documented remote CLI idle-timeout default is disabled |
| `hp.procurve.admin.serial_idle_timeout` | 1 | 0 | 1 | AOS-S YA.16.10.0023 documented serial/USB idle-timeout default is disabled |
| `hp.procurve.authentication.centralized` | 1 | 0 | 0 | AOS-S YA.16.10.0023 documented default for telnet; line 3: ip ssh; AOS-S YA.16.10.0023 documented default for http; AOS-S YA.16.10.0023 documented default for https |
| `hp.procurve.credentials.password_complexity` | 1 | 0 | 1 | AOS-S 16.10 password configuration-control default is disabled |
| `hp.procurve.layer2.access_edge.arp_protection` | 1 | 0 | 0 | line 8: untagged 1; assessment policy: port 1 role access-edge |
| `hp.procurve.layer2.access_edge.port_security` | 1 | 0 | 0 | line 8: untagged 1; assessment policy: port 1 role access-edge |
| `hp.procurve.layer2.access_edge.source_lockdown` | 1 | 0 | 0 | line 8: untagged 1; assessment policy: port 1 role access-edge |
| `hp.procurve.layer2.dhcp_snooping` | 1 | 0 | 1 | vlan 10 without dhcp-snooping |
| `hp.procurve.logging.remote_destination` | 1 | 0 | 1 | remote logging destination absent |
| `hp.procurve.management.http` | 1 | 0 | 1 | AOS-S YA.16.10.0023 documented default for http |
| `hp.procurve.management.source_restriction` | 1 | 0 | 0 | line 3: ip ssh |
| `hp.procurve.management.telnet` | 1 | 0 | 1 | AOS-S YA.16.10.0023 documented default for telnet |
| `hp.procurve.ntp.servers` | 1 | 0 | 1 | SNTP server absent |
| `hp.procurve.snmp.community_access` | 1 | 0 | 0 | line 5: credential configured |
| `hp.procurve.snmp.default_community` | 1 | 0 | 0 | line 5: credential configured |
| `hp.procurve.snmp.secure_user_missing` | 1 | 0 | 0 | line 5: credential configured |
| `hp.procurve.ssh.weak_algorithms` | 1 | 0 | 0 | line 3: ip ssh |

### ARISTA_EOS

| Rule | Instances | With context | Unlocated | Sample current evidence |
|---|---:|---:|---:|---|
| `arista.eos.admin.idle_timeout` | 1 | 0 | 0 | line 8: management ssh |
| `arista.eos.admin.login_banner` | 1 | 0 | 1 | banner login absent from identified EOS configuration |
| `arista.eos.authentication.centralized` | 1 | 0 | 1 | active eAPI without parsed centralized AAA |
| `arista.eos.authentication.lockout_disabled` | 1 | 0 | 1 | identified EOS release default: AAA time-based lockout disabled |
| `arista.eos.credentials.local_storage` | 1 | 0 | 0 | line 3: username admin secret 0 <credential redacted> |
| `arista.eos.eapi.https_disabled` | 1 | 0 | 0 | line 4: management api http-commands; line 5: protocol http; line 6: no protocol https; line 7: no shutdown |
| `arista.eos.eapi.insecure_http` | 1 | 0 | 0 | line 4: management api http-commands; line 5: protocol http; line 6: no protocol https; line 7: no shutdown |
| `arista.eos.eapi.source_restriction` | 1 | 0 | 0 | line 4: management api http-commands; line 5: protocol http; line 6: no protocol https; line 7: no shutdown |
| `arista.eos.hardening.cis_hygiene` | 2 | 0 | 2 | 4 CIS hygiene item(s) absent; see observation |
| `arista.eos.logging.remote_destination` | 1 | 0 | 1 | remote logging destination absent |
| `arista.eos.ntp.servers` | 1 | 0 | 1 | NTP server absent |
| `arista.eos.snmp.default_community` | 1 | 0 | 0 | line 13: snmp-server community <redacted> |
| `arista.eos.snmp.secure_user_missing` | 1 | 0 | 0 | line 13: snmp-server community <redacted> |
| `arista.eos.ssh.empty_passwords` | 1 | 0 | 0 | line 8: management ssh; line 9: authentication empty-passwords permit; line 10: cipher 3des-cbc; line 11: key-exchange diffie-hellman-group1-sha1; line 12: mac hmac-sha1 |
| `arista.eos.ssh.source_restriction` | 1 | 0 | 0 | line 8: management ssh; line 9: authentication empty-passwords permit; line 10: cipher 3des-cbc; line 11: key-exchange diffie-hellman-group1-sha1; line 12: mac hmac-sha1 |
| `arista.eos.ssh.weak_algorithms` | 1 | 0 | 0 | line 8: management ssh; line 9: authentication empty-passwords permit; line 10: cipher 3des-cbc; line 11: key-exchange diffie-hellman-group1-sha1; line 12: mac hmac-sha1 |

### SONICOS

| Rule | Instances | With context | Unlocated | Sample current evidence |
|---|---:|---:|---:|---|
| `sonicwall.sonicos.admin.connection_banner` | 1 | 0 | 1 | SonicOS 7.0-7.2 documented CLI connection banner default: absent |
| `sonicwall.sonicos.admin.lockout_disabled` | 1 | 0 | 1 | SonicOS 7.0-7.2 documented user-lockout default: disabled |
| `sonicwall.sonicos.admin.mfa_missing` | 1 | 0 | 1 | SonicOS 7.0-7.2 documented default: built-in administrator TOTP disabled |
| `sonicwall.sonicos.capture_atp.dependencies` | 1 | 0 | 0 | line 22: capture-atp enable; line 19: no gateway-anti-virus enable; line 23: no cloud-gateway-anti-virus enable |
| `sonicwall.sonicos.logging.remote_destination` | 1 | 0 | 1 | enabled syslog destination absent |
| `sonicwall.sonicos.management.external_interface` | 1 | 0 | 0 | line 4: interface X1; line 5: zone WAN; line 6: ip-address 198.51.100.1; line 7: management http https ssh snmp |
| `sonicwall.sonicos.management.http` | 1 | 0 | 0 | line 4: interface X1; line 5: zone WAN; line 6: ip-address 198.51.100.1; line 7: management http https ssh snmp |
| `sonicwall.sonicos.management.self_signed_certificate` | 1 | 0 | 1 | SonicOS 7.0-7.2 documented certificate-selection default: self-signed |
| `sonicwall.sonicos.ntp.servers` | 1 | 0 | 1 | custom NTP server absent |
| `sonicwall.sonicos.password.complexity` | 1 | 0 | 1 | SonicOS 7.0-7.2 documented password-complexity default: none |
| `sonicwall.sonicos.password.minimum_length` | 1 | 0 | 1 | SonicOS 7.0-7.2 documented minimum-length default: 8 |
| `sonicwall.sonicos.policy.broad_allow` | 1 | 0 | 0 | line 8: access-rule ipv4 from any to any action allow source address any service any destination address any schedule always-on; line 9: name "BROAD"; line 10: enable; line 11: no logging |
| `sonicwall.sonicos.policy.logging` | 1 | 0 | 0 | line 8: access-rule ipv4 from any to any action allow source address any service any destination address any schedule always-on; line 9: name "BROAD"; line 10: enable; line 11: no logging |
| `sonicwall.sonicos.security_services.disabled` | 1 | 0 | 0 | line 19: no gateway-anti-virus enable; line 23: no cloud-gateway-anti-virus enable; line 20: no intrusion-prevention enable; line 21: no anti-spyware enable |
| `sonicwall.sonicos.snmp.secure_user_missing` | 1 | 0 | 1 | SNMP interface management enabled without secure SNMPv3 user |
| `sonicwall.sonicos.vpn.weak_proposal` | 1 | 0 | 0 | line 12: vpn policy site-to-site "LEGACY-TUNNEL"; line 13: enable; line 14: proposal ike encryption triple-des; line 15: proposal ike authentication sha1; line 16: proposal ike dh-group 2; line 17: proposal ipsec encryption des; line 18: proposal ipsec authentication md5 |

### CHECKPOINT_GAIA

| Rule | Instances | With context | Unlocated | Sample current evidence |
|---|---:|---:|---:|---|
| `checkpoint.gaia.auth.user_bash_shell` | 1 | 0 | 0 | line 21: set user labadmin shell /bin/bash |
| `checkpoint.gaia.banner.login_disabled` | 1 | 0 | 0 | line 10: set message banner off |
| `checkpoint.gaia.cli.idle_timeout_excessive` | 1 | 0 | 0 | line 9: set inactivity-timeout 60 |
| `checkpoint.gaia.management.telnet` | 1 | 0 | 0 | line 8: set net-access telnet on |
| `checkpoint.gaia.password_policy.complexity` | 1 | 0 | 0 | line 11: set password-controls complexity 1 |
| `checkpoint.gaia.password_policy.history_disabled` | 1 | 0 | 0 | line 13: set password-controls history-checking off |
| `checkpoint.gaia.password_policy.lockout_disabled` | 1 | 0 | 0 | line 14: set password-controls deny-on-fail enable off |
| `checkpoint.gaia.password_policy.lockout_threshold` | 1 | 0 | 0 | line 14: set password-controls deny-on-fail enable on |
| `checkpoint.gaia.password_policy.minimum_length` | 1 | 0 | 0 | line 12: set password-controls min-password-length 6 |
| `checkpoint.gaia.password_policy.nonuse_lockout_disabled` | 2 | 0 | 2 | no set password-controls deny-on-nonuse enable |
| `checkpoint.gaia.snmp.default_community` | 1 | 0 | 0 | line 15: set snmp agent on; line 17: add snmp community <redacted> read-only |
| `checkpoint.gaia.snmp.legacy_version` | 1 | 0 | 0 | line 15: set snmp agent on; line 16: set snmp agent-version any |
| `checkpoint.gaia.snmp.v3_security` | 1 | 0 | 0 | line 19: add snmp usm user monitor security-level authNoPriv auth-pass-phrase <redacted> |
| `checkpoint.gaia.snmp.write_community` | 1 | 0 | 0 | line 15: set snmp agent on; line 18: add snmp community <redacted> read-write |
| `checkpoint.gaia.web.session_timeout_excessive` | 2 | 0 | 2 | set web session-timeout: not configured (default 15) |
