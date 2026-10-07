"""SC-049 completion for cisco.ios: services, VPN, routing, Layer-2 and IOS-XE control outcomes."""

import hashlib
from datetime import datetime, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tests.test_control_outcomes_sc049_complete_ios import outcome, run

COMMISSIONED = {"device_lifecycle": "commissioned"}
EDGE = {"interface_roles": {"GigabitEthernet1/0/1": "access-edge"}}
EXTERNAL = {"interface_roles": {"GigabitEthernet0/0": "external"}}
TIME = "2026-09-23T12:00:00Z"


@pytest.mark.parametrize("control,body,expected,device", [
    ("cisco.ios.legacy-services", "service tcp-small-servers\nno service pad\nno ip bootp server\n", "finding",
     "IOS_ROUTER"),
    ("cisco.ios.legacy-services", "", "finding", "IOS_ROUTER"),
    ("cisco.ios.legacy-services", "no service pad\nno ip bootp server\n", "evaluated-no-finding", "IOS_ROUTER"),
    ("cisco.ios.file-shell-servers", "ip rcmd rsh-enable\n", "finding", "IOS_ROUTER"),
    ("cisco.ios.file-shell-servers", "tftp-server flash:image.bin\n", "finding", "IOS_ROUTER"),
    ("cisco.ios.file-shell-servers", "", "evaluated-no-finding", "IOS_ROUTER"),
    ("cisco.ios.dns-lookup", "", "finding", "IOS_ROUTER"),
    ("cisco.ios.dns-lookup", "no ip domain lookup\n", "evaluated-no-finding", "IOS_ROUTER"),
    ("cisco.ios.tcp-keepalives", "", "finding", "IOS_ROUTER"),
    ("cisco.ios.tcp-keepalives", "service tcp-keepalives-in\n", "evaluated-no-finding", "IOS_ROUTER"),
    ("cisco.ios.ip-source-route", "", "finding", "IOS_ROUTER"),
    ("cisco.ios.ip-source-route", "no ip source-route\n", "evaluated-no-finding", "IOS_ROUTER"),
    ("cisco.ios.interface-ip-hardening", "interface GigabitEthernet0/0\n ip address 192.0.2.1 255.255.255.0\n",
     "finding", "IOS_ROUTER"),
    ("cisco.ios.interface-ip-hardening", "interface GigabitEthernet0/0\n ip address 192.0.2.1 255.255.255.0\n"
     " no ip redirects\n no ip proxy-arp\n", "evaluated-no-finding", "IOS_ROUTER"),
    ("cisco.ios.interface-ip-hardening", "interface GigabitEthernet0/0\n no ip address\n", "not-applicable",
     "IOS_ROUTER"),
    ("cisco.ios.control-plane-policing", "", "finding", "IOS_ROUTER"),
    ("cisco.ios.control-plane-policing", "control-plane\n service-policy input MISSING\n", "finding", "IOS_ROUTER"),
    ("cisco.ios.control-plane-policing", "ip access-list extended COPP-SSH\n permit tcp 192.0.2.0 0.0.0.255 any eq 22\n"
     "class-map match-any COPP-SSH\n match access-group name COPP-SSH\npolicy-map HOST-POLICY\n class COPP-SSH\n"
     "  police cir 128000 conform-action transmit exceed-action drop\ncontrol-plane host\n"
     " service-policy input HOST-POLICY\n", "evaluated-no-finding", "IOS_XE"),
    ("cisco.ios.fhrp-authentication", "interface GigabitEthernet0/0\n ip address 192.0.2.2 255.255.255.0\n"
     " standby 1 ip 192.0.2.1\n", "finding", "IOS_ROUTER"),
    ("cisco.ios.fhrp-authentication", "interface GigabitEthernet0/0\n ip address 192.0.2.2 255.255.255.0\n"
     " standby 1 ip 192.0.2.1\n standby 1 authentication md5 key-string KEYVALUE\n", "evaluated-no-finding",
     "IOS_ROUTER"),
    ("cisco.ios.fhrp-authentication", "", "not-applicable", "IOS_ROUTER"),
    ("cisco.ios.ppp-pap", "interface Serial0/0\n encapsulation ppp\n ppp authentication pap\n", "finding",
     "IOS_ROUTER"),
    ("cisco.ios.ppp-pap", "interface Serial0/0\n encapsulation ppp\n ppp authentication chap\n",
     "evaluated-no-finding", "IOS_ROUTER"),
    ("cisco.ios.on-demand-routing", "router odr\n", "finding", "IOS_XE"),
    ("cisco.ios.on-demand-routing", "", "evaluated-no-finding", "IOS_XE"),
    ("cisco.ios.vtp-mode", "", "finding", "IOS_SWITCH"),
    ("cisco.ios.vtp-mode", "vtp mode transparent\n", "evaluated-no-finding", "IOS_SWITCH"),
    ("cisco.ios.acl-order", "access-list 101 permit ip any any\naccess-list 101 deny tcp any any eq 23\n"
     "interface GigabitEthernet0/0\n ip address 192.0.2.1 255.255.255.0\n ip access-group 101 in\n", "finding",
     "IOS_ROUTER"),
    ("cisco.ios.acl-order", "access-list 101 deny tcp any any eq 23\naccess-list 101 permit ip any any\n"
     "interface GigabitEthernet0/0\n ip address 192.0.2.1 255.255.255.0\n ip access-group 101 in\n",
     "evaluated-no-finding", "IOS_ROUTER"),
    ("cisco.ios.acl-order", "", "not-applicable", "IOS_ROUTER"),
])
def test_service_and_interface_controls(tmp_path, control, body, expected, device):
    assert outcome(tmp_path, control, body, device) == expected


def test_legacy_services_unknown_where_the_train_default_changes(tmp_path):
    header = "version 12.1\nhostname r1\n!\n"
    body = "no service pad\nno ip bootp server\n"
    assert outcome(tmp_path, "cisco.ios.legacy-services", body, header=header) == "unknown"


@pytest.mark.parametrize("control,body,expected,policy", [
    ("cisco.ios.boot-provisioning", "boot network tftp://192.0.2.7/network-confg\nservice config\n", "finding",
     COMMISSIONED),
    ("cisco.ios.boot-provisioning", "", "evaluated-no-finding", COMMISSIONED),
    ("cisco.ios.boot-provisioning", "boot network tftp://192.0.2.7/network-confg\nservice config\n",
     "not-applicable", None),
    ("cisco.ios.discovery-external", "cdp run\ninterface GigabitEthernet0/0\n ip address 192.0.2.1 255.255.255.0\n",
     "finding", EXTERNAL),
    ("cisco.ios.discovery-external", "no cdp run\ninterface GigabitEthernet0/0\n ip address 192.0.2.1 255.255.255.0\n",
     "evaluated-no-finding", EXTERNAL),
    ("cisco.ios.discovery-external", "", "not-applicable", None),
])
def test_policy_scoped_controls(tmp_path, control, body, expected, policy):
    assert outcome(tmp_path, control, body, policy=policy) == expected


ISAKMP_KEY = "crypto isakmp key 0 SharedSecret1 address 192.0.2.50\n"
STRONG_POLICY = "crypto isakmp policy 10\n encryption aes 256\n hash sha256\n group 19\n authentication pre-share\n"


@pytest.mark.parametrize("control,body,expected,device", [
    ("cisco.ios.ike-aggressive-mode", STRONG_POLICY + ISAKMP_KEY, "finding", "IOS_ROUTER"),
    ("cisco.ios.ike-aggressive-mode", STRONG_POLICY + ISAKMP_KEY + "crypto isakmp aggressive-mode disable\n",
     "evaluated-no-finding", "IOS_ROUTER"),
    ("cisco.ios.vpn-crypto", "crypto isakmp policy 10\n encryption 3des\n hash md5\n group 2\n", "finding",
     "IOS_ROUTER"),
    ("cisco.ios.vpn-crypto", "crypto isakmp policy 10\n hash sha256\n", "finding", "IOS_ROUTER"),
    ("cisco.ios.vpn-crypto", STRONG_POLICY + "crypto ipsec transform-set TS esp-aes 256 esp-sha256-hmac\n",
     "evaluated-no-finding", "IOS_ROUTER"),
    ("cisco.ios.vpn-crypto", "crypto ipsec transform-set TS esp-3des esp-md5-hmac\n", "finding", "IOS_ROUTER"),
    ("cisco.ios.vpn-crypto", ISAKMP_KEY, "finding", "IOS_ROUTER"),
    ("cisco.ios.vpn-crypto", "crypto ikev2 profile P1\n match identity remote any\n", "finding", "IOS_XE"),
    ("cisco.ios.vpn-crypto", "crypto ikev2 proposal PR\n encryption aes-gcm-256\n prf sha384\n group 19\n"
     "crypto ikev2 profile P1\n match identity remote any\n", "unknown", "IOS_ROUTER"),
    ("cisco.ios.vpn-crypto", "", "not-applicable", "IOS_ROUTER"),
    ("cisco.ios.l2tp-ipsec", "vpdn enable\nvpdn-group L2TP\n accept-dialin\n  protocol l2tp\n  virtual-template 1\n",
     "finding", "IOS_ROUTER"),
    ("cisco.ios.l2tp-ipsec", "vpdn enable\nvpdn-group L2TP\n accept-dialin\n  protocol l2tp\n  virtual-template 1\n"
     "crypto ipsec transform-set TS esp-aes 256 esp-sha256-hmac\n", "unknown", "IOS_ROUTER"),
    ("cisco.ios.l2tp-ipsec", "", "not-applicable", "IOS_ROUTER"),
    ("cisco.iosxe.vpn-crypto", "crypto isakmp policy 10\n encryption aes 256\n", "finding", "IOS_XE"),
    ("cisco.iosxe.vpn-crypto", STRONG_POLICY, "evaluated-no-finding", "IOS_XE"),
    ("cisco.iosxe.vpn-crypto", "crypto ikev2 policy POL\n proposal MISSING\n", "unknown", "IOS_XE"),
    ("cisco.iosxe.vpn-crypto", "", "not-applicable", "IOS_XE"),
])
def test_vpn_controls(tmp_path, control, body, expected, device):
    assert outcome(tmp_path, control, body, device) == expected


PORT = "interface GigabitEthernet0/0\n ip address 192.0.2.1 255.255.255.0\n"
CHAIN = "key chain EDGE\n key 1\n  key-string 7 syntheticprivate\n"
EIGRP = "router eigrp 10\n network 192.0.2.0 0.0.0.255\n"
RIP = "router rip\n version 2\n network 192.0.2.0\n"
RIP_PORT = PORT + " ip rip receive version 2\n"
OSPF = "router ospf 1\n" + PORT + " ip ospf 1 area 0\n"
BGP = "router bgp 65000\n neighbor 192.0.2.9 remote-as 65100\n"
BGP_GOOD = (BGP + " neighbor 192.0.2.9 password syntheticprivate\n neighbor 192.0.2.9 maximum-prefix 1000\n"
            " neighbor 192.0.2.9 prefix-list IN in\n neighbor 192.0.2.9 prefix-list OUT out\n"
            "ip prefix-list IN permit 198.51.100.0/24\nip prefix-list OUT permit 203.0.113.0/24\n")
ISIS = "router isis CORE\n net 49.0001.1921.6800.1001.00\n is-type level-2-only\ninterface GigabitEthernet0/0\n ip router isis CORE\n"
EXPIRED = ("  send-lifetime 00:00:00 Jan 1 2020 00:00:00 Jan 1 2021\n"
           "  accept-lifetime 00:00:00 Jan 1 2020 00:00:00 Jan 1 2021\n")
EIGRP_AUTH = EIGRP + PORT + " ip authentication mode eigrp 10 md5\n ip authentication key-chain eigrp 10 EDGE\n"


@pytest.mark.parametrize("control,body,expected", [
    ("cisco.ios.bgp-authentication", BGP, "finding"),
    ("cisco.ios.bgp-authentication", BGP_GOOD, "evaluated-no-finding"),
    ("cisco.ios.bgp-authentication", "", "not-applicable"),
    ("cisco.ios.bgp-external-policy", BGP, "finding"),
    ("cisco.ios.bgp-external-policy", BGP_GOOD, "evaluated-no-finding"),
    ("cisco.ios.bgp-external-policy", "router bgp 65000\n neighbor 192.0.2.9 remote-as 65000\n", "not-applicable"),
    ("cisco.ios.ospf-authentication", OSPF, "finding"),
    ("cisco.ios.ospf-authentication", OSPF + " ip ospf authentication\n ip ospf authentication-key KEYVALUE\n",
     "finding"),
    ("cisco.ios.ospf-authentication", OSPF + " ip ospf authentication message-digest\n"
     " ip ospf message-digest-key 1 md5 KEYVALUE\n", "evaluated-no-finding"),
    ("cisco.ios.ospf-authentication", "", "not-applicable"),
    ("cisco.ios.rip-authentication", RIP + RIP_PORT, "finding"),
    ("cisco.ios.rip-authentication", RIP + CHAIN + RIP_PORT + " ip rip authentication mode md5\n"
     " ip rip authentication key-chain EDGE\n", "evaluated-no-finding"),
    ("cisco.ios.rip-authentication", "", "not-applicable"),
    ("cisco.ios.eigrp-authentication", EIGRP + PORT, "finding"),
    ("cisco.ios.eigrp-authentication", CHAIN + EIGRP_AUTH, "evaluated-no-finding"),
    ("cisco.ios.eigrp-authentication", "", "not-applicable"),
    ("cisco.ios.isis-authentication-mode", ISIS + " isis authentication mode text level-2\n", "finding"),
    ("cisco.ios.isis-authentication-mode", CHAIN + ISIS.replace(" is-type level-2-only\n", " is-type level-2-only\n"
     " authentication mode md5 level-2\n authentication key-chain EDGE level-2\n")
     + " isis authentication mode md5 level-2\n isis authentication key-chain EDGE level-2\n", "evaluated-no-finding"),
    ("cisco.ios.isis-authentication-mode", CHAIN + ISIS + " isis authentication mode md5 level-2\n"
     " isis authentication key-chain EDGE level-2\n", "unknown"),
    ("cisco.ios.isis-authentication-mode", "", "not-applicable"),
    ("cisco.ios.routing-key-lifetime", "", "not-applicable"),
])
def test_routing_controls(tmp_path, control, body, expected):
    assert outcome(tmp_path, control, body) == expected


@pytest.mark.parametrize("chain,policy,expected", [
    (CHAIN + EXPIRED, {"assessment_time": TIME}, "finding"),
    (CHAIN, {"assessment_time": TIME}, "evaluated-no-finding"),
    (CHAIN + EXPIRED, None, "unknown"),
])
def test_routing_key_lifetime(tmp_path, chain, policy, expected):
    header = "version 15.4\nhostname r1\nclock timezone UTC 0\n!\n"
    assert outcome(tmp_path, "cisco.ios.routing-key-lifetime", chain + EIGRP_AUTH, policy=policy,
                   header=header) == expected


EDGE_PORT = "interface GigabitEthernet1/0/1\n switchport mode access\n switchport access vlan 10\n"
HARDENED = ("ip dhcp snooping\nip dhcp snooping vlan 10\nip arp inspection vlan 10\n" + EDGE_PORT
            + " ip verify source\n switchport port-security\n")
RA_POLICIES = ("ipv6 nd raguard policy ROUTERS\n device-role router\nipv6 nd raguard policy HOSTS\n"
               " device-role host\n")


@pytest.mark.parametrize("control,body,expected", [
    ("cisco.ios.access-edge-l2", EDGE_PORT, "finding"),
    ("cisco.ios.access-edge-l2", HARDENED, "evaluated-no-finding"),
    ("cisco.ios.access-edge-l2", "interface GigabitEthernet1/0/1\n switchport mode trunk\n", "finding"),
    ("cisco.ios.access-edge-ipv6-trust", RA_POLICIES + EDGE_PORT + " ipv6 nd raguard attach-policy ROUTERS\n",
     "finding"),
    ("cisco.ios.access-edge-ipv6-trust", RA_POLICIES + EDGE_PORT + " ipv6 nd raguard attach-policy HOSTS\n",
     "evaluated-no-finding"),
    ("cisco.ios.access-edge-ipv6-trust", RA_POLICIES + EDGE_PORT + " ipv6 nd raguard attach-policy MISSING\n",
     "unknown"),
    ("cisco.ios.access-edge-dot1x", "dot1x system-auth-control\n" + EDGE_PORT
     + " authentication port-control force-authorized\n", "finding"),
    ("cisco.ios.access-edge-dot1x", "dot1x system-auth-control\n" + EDGE_PORT + " authentication port-control auto\n",
     "evaluated-no-finding"),
    ("cisco.ios.access-edge-dot1x", EDGE_PORT + " authentication port-control auto\n", "unknown"),
    ("cisco.ios.access-edge-dot1x", EDGE_PORT, "not-applicable"),
    ("cisco.ios.access-edge-bpdu-guard", EDGE_PORT + " spanning-tree bpduguard disable\n", "finding"),
    ("cisco.ios.access-edge-bpdu-guard", EDGE_PORT + " spanning-tree bpduguard enable\n"
     " spanning-tree bpdufilter enable\n", "finding"),
    ("cisco.ios.access-edge-bpdu-guard", EDGE_PORT + " spanning-tree bpduguard enable\n", "evaluated-no-finding"),
    ("cisco.ios.access-edge-bpdu-guard", EDGE_PORT, "unknown"),
])
def test_access_edge_controls(tmp_path, control, body, expected):
    assert outcome(tmp_path, control, body, "IOS_XE", policy=EDGE) == expected


def test_access_edge_controls_not_applicable_without_roles(tmp_path):
    coverage, _ = run(tmp_path, EDGE_PORT, "IOS_XE")
    for control in ("cisco.ios.access-edge-l2", "cisco.ios.access-edge-ipv6-trust",
                    "cisco.ios.access-edge-dot1x", "cisco.ios.access-edge-bpdu-guard"):
        assert coverage[control]["outcome"] == "not-applicable"


MACSEC_PORT = "interface GigabitEthernet1/0/2\n switchport mode trunk\n"


@pytest.mark.parametrize("body,expected", [
    (MACSEC_PORT + " macsec network-link\n", "finding"),
    ("mka policy MKA\n macsec-cipher-suite gcm-aes-256\nkey chain KC macsec\n key 01\n  key-string 7 ABCDEF\n"
     + MACSEC_PORT + " macsec network-link\n mka policy MKA\n mka pre-shared-key key-chain KC\n",
     "evaluated-no-finding"),
    ("", "not-applicable"),
])
def test_iosxe_macsec(tmp_path, body, expected):
    assert outcome(tmp_path, "cisco.iosxe.macsec-links", body, "IOS_XE") == expected


def _chain_hex(*, bits=2048, dns="xe1.example.test"):
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic Root")])
    start, end = datetime(2025, 1, 1, tzinfo=timezone.utc), datetime(2030, 1, 1, tzinfo=timezone.utc)
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(1).not_valid_before(start).not_valid_after(end)
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns)]))
            .issuer_name(ca_name).public_key(leaf_key.public_key()).serial_number(2)
            .not_valid_before(start).not_valid_after(end)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    as_hex = [item.public_bytes(serialization.Encoding.DER).hex().upper() for item in (ca, leaf)]
    return as_hex, hashlib.sha256(ca.public_bytes(serialization.Encoding.DER)).hexdigest()


def _https_body(ca_hex, leaf_hex):
    def block(kind, value):
        return f" certificate {kind}\n" + "\n".join(
            f"  {value[index:index + 64]}" for index in range(0, len(value), 64)) + "\n  quit\n"
    return ("ip http secure-server\nip http secure-trustpoint TP\ncrypto pki trustpoint TP\n enrollment terminal\n"
            "crypto pki certificate chain TP\n" + block("ca 01", ca_hex) + block("02", leaf_hex))


@pytest.mark.parametrize("bits,trusted,expected", [
    (1024, False, "finding"),
    (2048, True, "evaluated-no-finding"),
    (2048, False, "unknown"),
])
def test_https_certificate(tmp_path, bits, trusted, expected):
    (ca_hex, leaf_hex), fingerprint = _chain_hex(bits=bits)
    policy = {"assessment_time": TIME, "management_certificate_identities": {"ios-https": "xe1.example.test"}}
    if trusted:
        policy["trusted_certificate_sha256"] = [fingerprint]
    assert outcome(tmp_path, "cisco.ios.https-certificate", _https_body(ca_hex, leaf_hex), "IOS_XE",
                   policy=policy) == expected
