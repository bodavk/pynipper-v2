import base64
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from src.analyze.cisco.asa.plugins.baseline_plugin import PluginASABaseline
from src.analyze.cisco.asa.core.process_asa_conf import process_asa_conf
from src.analyze.fortinet.plugins.fortios_baseline_plugin import PluginFortiOSBaseline
from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.analyze.paloalto.core.process_panos_conf import process_panos_conf
from src.analyze.paloalto.plugins.panos_checks_plugin import PluginPANOSChecks
from src.common.assessment import AssessmentContext
from src.common.certificates import assess_public_certificate, load_public_certificate
from src.devices.cisco.asa import CiscoASAParser
from src.devices.fortinet.fortios import FortiOSParser
from src.devices.paloalto.panos import PaloAltoPANOSParser


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


def _panos(tmp_path, certificate_object, context=None):
    parser = PaloAltoPANOSParser(_write(tmp_path, "panos-cert.xml", f'''<config version="12.1.2">
<devices><entry name="localhost.localdomain">
<deviceconfig><system><ssl-tls-service-profile>MGMT-TLS</ssl-tls-service-profile></system></deviceconfig>
<network><profiles><interface-management-profile><entry name="MGMT"><https>yes</https></entry></interface-management-profile></profiles><interface><ethernet><entry name="ethernet1/1"><layer3><interface-management-profile>MGMT</interface-management-profile></layer3></entry></ethernet></interface></network>
<vsys><entry name="vsys1"><ssl-tls-service-profile><entry name="MGMT-TLS"><certificate>VSYS-CERT</certificate><protocol-settings><min-version>tls1-0</min-version></protocol-settings></entry></ssl-tls-service-profile></entry></vsys>
</entry></devices>
<shared><ssl-tls-service-profile><entry name="MGMT-TLS"><certificate>MGMT-CERT</certificate><protocol-settings><min-version>tls1-2</min-version></protocol-settings></entry></ssl-tls-service-profile>{certificate_object}</shared>
</config>'''))
    if context is not None:
        parser.set_assessment_context(context)
    return parser


def _fortios(tmp_path, certificate_sections, context=None, selected="CORP-MGMT"):
    parser = FortiOSParser(_write(tmp_path, "fortios-cert.conf", f'''#config-version=FGT100F-7.4.6-FW-build0001-240101:opmode=0:vdom=0:user=admin
config system global
set admin-server-cert "{selected}"
end
config system interface
edit "mgmt"
set allowaccess https
next
end
{certificate_sections}
'''))
    if context is not None:
        parser.set_assessment_context(context)
    return parser


def _certificate_chain(dns_name="fw.example.test", key_size=2048, prefix="Test"):
    before = datetime(2025, 1, 1, tzinfo=timezone.utc)
    after = datetime(2030, 1, 1, tzinfo=timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{prefix} CA")])
    ca = (
        x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(before).not_valid_after(after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns_name)]))
        .issuer_name(ca.subject).public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(before).not_valid_after(after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns_name)]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, True, False, False, False, False, False, False),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    def encoded(certificate):
        return base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode()

    return encoded(leaf), encoded(ca), ca.fingerprint(hashes.SHA256()).hex()


def test_panos_resolves_only_attached_public_certificate_and_never_retains_private_key(tmp_path):
    leaf, ca, fingerprint = _certificate_chain()
    context = AssessmentContext.from_mapping({
        "assessment_time": "2026-09-14T12:00:00Z",
        "management_certificate_identities": {"localhost.localdomain": "fw.example.test"},
        "trusted_certificate_sha256": [fingerprint],
    })
    parser = _panos(tmp_path, f'''<certificate><entry name="MGMT-CERT"><certificate>{leaf}</certificate><private-key>NEVER-SERIALIZE-THIS</private-key></entry><entry name="TEST-CA"><certificate>{ca}</certificate></entry><entry name="UNBOUND"><certificate>not-base64</certificate></entry></certificate>''', context)
    objects = {item.name: item for item in parser.get_certificate_objects()}
    binding = parser.get_management_certificate_bindings()[0]
    assert binding.resolution == "resolved"
    assert binding.certificate == "MGMT-CERT"  # Shared object wins over same-name vsys profile.
    assert binding.public_material_state == "parsed"
    assert binding.assessment.validity_state == "valid-at-assessment-time"
    assert binding.assessment.identity_state == "match"
    assert binding.assessment.trust_state == "trusted"
    assert objects["MGMT-CERT"].private_key_present is True
    assert "NEVER-SERIALIZE-THIS" not in repr(objects)

    plugin = PluginPANOSChecks()
    plugin.check_management_tls(parser)
    assert not any("certificate_" in item.rule_id for item in plugin.get_issues())


def test_panos_x509_time_identity_algorithm_and_trust_are_independent(tmp_path):
    leaf, ca, fingerprint = _certificate_chain(key_size=1024)
    wrong_leaf, wrong_ca, wrong_fingerprint = _certificate_chain(prefix="Wrong")
    del wrong_leaf, fingerprint
    objects = f'''<certificate><entry name="MGMT-CERT"><certificate>{leaf}</certificate></entry><entry name="ISSUER"><certificate>{ca}</certificate></entry><entry name="WRONG-CA"><certificate>{wrong_ca}</certificate></entry></certificate>'''
    context = AssessmentContext.from_mapping({
        "assessment_time": "2031-01-01T00:00:00Z",
        "management_certificate_identities": {"localhost.localdomain": "wrong.example.test"},
        "trusted_certificate_sha256": [wrong_fingerprint],
    })
    parser = _panos(tmp_path, objects, context)
    plugin = PluginPANOSChecks()
    plugin.check_management_tls(parser)
    ids = {item.rule_id for item in plugin.get_issues()}
    assert "paloalto.panos.management.certificate_validity" in ids
    assert "paloalto.panos.management.certificate_identity" in ids
    assert "paloalto.panos.management.certificate_algorithm" in ids
    assert "paloalto.panos.management.certificate_trust" not in ids

    trust_context = AssessmentContext.from_mapping({
        "assessment_time": "2026-09-14T12:00:00Z",
        "management_certificate_identities": {"localhost.localdomain": "fw.example.test"},
        "trusted_certificate_sha256": [wrong_fingerprint],
    })
    parser = _panos(tmp_path, objects, trust_context)
    plugin = PluginPANOSChecks()
    plugin.check_management_tls(parser)
    assert "paloalto.panos.management.certificate_trust" in {
        item.rule_id for item in plugin.get_issues()
    }


def test_x509_validity_boundaries_are_inclusive_and_missing_anchor_is_unknown():
    leaf, ca, _ = _certificate_chain()
    certificate = load_public_certificate(leaf)
    issuer = load_public_certificate(ca)
    for boundary in (
        datetime(2025, 1, 1, tzinfo=timezone.utc),
        datetime(2030, 1, 1, tzinfo=timezone.utc),
    ):
        result = assess_public_certificate(
            certificate, (certificate, issuer), (), "fw.example.test", boundary
        )
        assert result.validity_state == "valid-at-assessment-time"
        assert result.trust_state == "unknown"
    assert assess_public_certificate(
        certificate,
        (certificate, issuer),
        (),
        "fw.example.test",
        datetime(2030, 1, 1, 0, 0, 0, 1, tzinfo=timezone.utc),
    ).validity_state == "expired"


def test_panos_reports_unresolved_and_malformed_attached_objects_only(tmp_path):
    missing = _panos(tmp_path, "")
    plugin = PluginPANOSChecks()
    plugin.check_management_tls(missing)
    assert "paloalto.panos.management.certificate_unresolved" in {
        item.rule_id for item in plugin.get_issues()
    }

    malformed = _panos(tmp_path, '''<certificate><entry name="MGMT-CERT"><certificate>not-base64</certificate></entry></certificate>''')
    plugin = PluginPANOSChecks()
    plugin.check_management_tls(malformed)
    assert "paloalto.panos.management.certificate_material_malformed" in {
        item.rule_id for item in plugin.get_issues()
    }

    malformed_pem = _panos(tmp_path, '''<certificate><entry name="MGMT-CERT"><certificate>-----BEGIN CERTIFICATE-----
not-a-certificate
-----END CERTIFICATE-----</certificate></entry></certificate>''')
    assert malformed_pem.get_certificate_objects()[0].public_material_state == "malformed"


def _asa(tmp_path, extra, context=None):
    parser = CiscoASAParser(_write(tmp_path, "asa-cert.conf", f'''ASA Version 9.18(4)
hostname cert-test
http server enable
http 192.0.2.0 255.255.255.0 outside
ssl trust-point MGMT-CERT outside
{extra}
'''))
    if context is not None:
        parser.set_assessment_context(context)
    return parser


def test_asa_resolves_assigned_trustpoint_and_identity_chain_material(tmp_path):
    leaf, ca, fingerprint = _certificate_chain(dns_name="asa.example.test")
    leaf_hex = base64.b64decode(leaf).hex()
    ca_hex = base64.b64decode(ca).hex()
    context = AssessmentContext.from_mapping({
        "assessment_time": "2026-09-14T12:00:00Z",
        "management_certificate_identities": {"outside": "asa.example.test"},
        "trusted_certificate_sha256": [fingerprint],
    })
    parser = _asa(tmp_path, f'''crypto ca trustpoint MGMT-CERT
 enrollment terminal
 subject-name CN=asa.example.test
crypto ca certificate chain MGMT-CERT
 certificate 01
  {leaf_hex}
 certificate ca 02
  {ca_hex}''', context)
    binding = parser.get_management_certificate_bindings()[0]
    assert binding.trustpoint_configured is True
    assert binding.certificate_chain_present is True
    assert binding.identity_certificate_present is True
    assert binding.public_material_state == "parsed"
    assert binding.assessment.trust_state == "trusted"
    assert leaf_hex not in repr(binding)

    plugin = PluginASABaseline()
    plugin.check_http_management(parser)
    assert not any("certificate" in item.rule_id for item in plugin.get_issues())


def test_asa_distinguishes_unresolved_trustpoint_from_ca_only_chain(tmp_path):
    parser = _asa(tmp_path, "")
    plugin = PluginASABaseline()
    plugin.check_http_management(parser)
    assert {item.rule_id for item in plugin.get_issues()} == {
        "cisco.asa.management.certificate_unresolved"
    }

    parser = _asa(tmp_path, '''crypto ca trustpoint MGMT-CERT
 enrollment terminal
crypto ca certificate chain MGMT-CERT
 certificate ca 02
  3003020102''')
    plugin = PluginASABaseline()
    plugin.check_http_management(parser)
    assert {item.rule_id for item in plugin.get_issues()} == {
        "cisco.asa.management.certificate_identity_missing"
    }


def test_asa_malformed_identity_material_is_not_treated_as_a_valid_certificate(tmp_path):
    parser = _asa(tmp_path, '''crypto ca trustpoint MGMT-CERT
 enrollment terminal
crypto ca certificate chain MGMT-CERT
 certificate 01
  00''')
    binding = parser.get_management_certificate_bindings()[0]
    assert binding.public_material_state == "malformed"
    assert binding.assessment is None
    plugin = PluginASABaseline()
    plugin.check_http_management(parser)
    assert {item.rule_id for item in plugin.get_issues()} == {
        "cisco.asa.management.certificate_material_malformed"
    }


def test_certificate_material_findings_reach_public_processors(tmp_path):
    panos = _panos(
        tmp_path,
        '<certificate><entry name="MGMT-CERT"><certificate>not-base64</certificate></entry></certificate>',
    )
    assert "paloalto.panos.management.certificate_material_malformed" in {
        item.rule_id for item in process_panos_conf(panos).values()
    }
    asa = _asa(tmp_path, '''crypto ca trustpoint MGMT-CERT
 enrollment terminal
crypto ca certificate chain MGMT-CERT
 certificate 01
  00''')
    assert "cisco.asa.management.certificate_material_malformed" in {
        item.rule_id for item in process_asa_conf(asa).values()
    }


def test_fortios_resolves_selected_public_certificate_and_approved_chain(tmp_path):
    leaf, ca, fingerprint = _certificate_chain(dns_name="fortigate.example.test")
    context = AssessmentContext.from_mapping({
        "assessment_time": "2026-01-01T00:00:00+00:00",
        "management_certificate_identities": {"root": "fortigate.example.test"},
        "trusted_certificate_sha256": [fingerprint],
    })
    parser = _fortios(tmp_path, f'''config vpn certificate local
edit "CORP-MGMT"
set certificate "{leaf}"
set private-key "NEVER-SERIALIZE-THIS"
next
end
config vpn certificate ca
edit "CORP-CA"
set ca "{ca}"
next
end''', context)
    binding = parser.get_management_certificate_bindings()[0]
    assert binding.reference_state == "resolved"
    assert binding.public_material_state == "parsed"
    assert binding.assessment.validity_state == "valid-at-assessment-time"
    assert binding.assessment.identity_state == "match"
    assert binding.assessment.algorithm_state == "acceptable"
    assert binding.assessment.trust_state == "trusted"
    assert leaf not in repr(binding)
    assert "NEVER-SERIALIZE-THIS" not in repr(binding)
    plugin = PluginFortiOSBaseline()
    plugin.check_management_certificates(parser)
    assert plugin.get_issues() == []


def test_fortios_reports_malformed_and_unresolved_selected_certificates(tmp_path):
    malformed = _fortios(tmp_path, '''config certificate local
edit CORP-MGMT
set certificate "not-base64"
next
end''')
    plugin = PluginFortiOSBaseline()
    plugin.check_management_certificates(malformed)
    assert [item.rule_id for item in plugin.get_issues()] == [
        "fortinet.fortios.https.certificate_material_malformed"
    ]
    assert "not-base64" not in " ".join(plugin.get_issues()[0].evidence)

    unresolved = _fortios(tmp_path, '''config certificate local
edit OTHER-CERTIFICATE
set certificate "not-base64"
next
end''', selected="MISSING-MGMT")
    plugin = PluginFortiOSBaseline()
    plugin.check_management_certificates(unresolved)
    assert [item.rule_id for item in plugin.get_issues()] == [
        "fortinet.fortios.https.certificate_unresolved"
    ]


def test_fortios_certificate_assessment_keeps_time_identity_and_algorithm_independent(tmp_path):
    leaf, ca, fingerprint = _certificate_chain(
        dns_name="actual.example.test", key_size=1024, prefix="FortiWeak"
    )
    context = AssessmentContext.from_mapping({
        "assessment_time": "2026-01-01T00:00:00+00:00",
        "management_certificate_identities": {"root": "expected.example.test"},
        "trusted_certificate_sha256": [fingerprint],
    })
    parser = _fortios(tmp_path, f'''config vpn certificate local
edit CORP-MGMT
set certificate "{leaf}"
next
end
config vpn certificate ca
edit CORP-CA
set ca "{ca}"
next
end''', context)
    plugin = PluginFortiOSBaseline()
    plugin.check_management_certificates(parser)
    assert {item.rule_id for item in plugin.get_issues()} == {
        "fortinet.fortios.https.certificate_identity",
        "fortinet.fortios.https.certificate_algorithm",
        "fortinet.fortios.https.certificate_trust",
    }


def test_fortios_escaped_pem_and_inactive_https_certificate_boundary(tmp_path):
    leaf, _, _ = _certificate_chain(dns_name="fortigate.example.test")
    pem = load_public_certificate(leaf).public_bytes(serialization.Encoding.PEM).decode()
    escaped_pem = pem.replace("\n", r"\n")
    parser = _fortios(tmp_path, f'''config certificate local
edit CORP-MGMT
set certificate "{escaped_pem}"
next
end''')
    assert parser.get_management_certificate_bindings()[0].public_material_state == "parsed"
    assert "BEGIN CERTIFICATE" not in repr(parser.get_management_certificate_bindings())

    inactive = FortiOSParser(_write(tmp_path, "fortios-inactive-https.conf", '''#config-version=FGT100F-7.4.6-FW-build0001-240101:opmode=0:vdom=0:user=admin
config system global
set admin-server-cert MISSING
end
config system interface
edit mgmt
set allowaccess ssh
next
end
config certificate local
edit OTHER
set certificate not-base64
next
end
'''))
    plugin = PluginFortiOSBaseline()
    plugin.check_management_certificates(inactive)
    assert plugin.get_issues() == []


def test_fortios_certificate_failure_reaches_public_processor(tmp_path):
    parser = _fortios(tmp_path, '''config certificate local
edit CORP-MGMT
set certificate "not-base64"
next
end''')
    assert "fortinet.fortios.https.certificate_material_malformed" in {
        item.rule_id for item in process_fortios_conf(parser).values()
    }
