"""SC-021: selected IOS HTTPS public-certificate assessment only."""

from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from src.analyze.cisco.ios.plugins.baseline_plugin import PluginIOSBaseline
from src.common.assessment import AssessmentContext
from src.devices.cisco.ios import CiscoIOSParser


TIME = "2026-09-23T12:00:00Z"
PREFIX = "cisco.ios.management.https_certificate_"


def _certificate(*, dns="router.example.test", bits=2048, end=2030):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns)])
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(private_key.public_key()).serial_number(12345)
        .not_valid_before(datetime(2025, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(end, 1, 1, tzinfo=timezone.utc))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER).hex().upper()


def _scan(tmp_path, certificate_hex, *, enabled=True, selected="EDGE", context=None):
    path = tmp_path / "router.conf"
    path.write_text(
        "version 17.9\nhostname edge\n"
        + ("ip http secure-server\n" if enabled else "no ip http secure-server\n")
        + f"ip http secure-trustpoint {selected}\n"
        "crypto pki trustpoint EDGE\n enrollment terminal\n"
        "crypto pki certificate chain EDGE\n certificate 01\n"
        + "\n".join(f"  {certificate_hex[index:index + 64]}" for index in range(0, len(certificate_hex), 64))
        + "\n quit\n",
        encoding="utf-8",
    )
    parser = CiscoIOSParser(str(path))
    if context:
        parser.set_assessment_context(context)
    plugin = PluginIOSBaseline()
    plugin.check_https_public_certificate(parser)
    return parser, [item for item in plugin.get_issues() if item.rule_id.startswith(PREFIX)]


def test_selected_exported_expired_certificate(tmp_path):
    context = AssessmentContext.from_mapping({
        "assessment_time": TIME,
        "management_certificate_identities": {"ios-https": "router.example.test"},
    })
    parser, findings = _scan(tmp_path, _certificate(end=2026), context=context)
    assert parser.get_https_selected_public_certificate() is not None
    assert [item.rule_id for item in findings] == [PREFIX + "validity"]
    assert not any("3082" in " ".join(item.evidence) for item in findings)


def test_explicit_identity_mismatch(tmp_path):
    context = AssessmentContext.from_mapping({
        "assessment_time": TIME,
        "management_certificate_identities": {"ios-https": "different.example.test"},
    })
    _, findings = _scan(tmp_path, _certificate(), context=context)
    assert [item.rule_id for item in findings] == [PREFIX + "identity"]


def test_weak_public_key_without_identity_or_time_context(tmp_path):
    _, findings = _scan(tmp_path, _certificate(bits=1024))
    assert [item.rule_id for item in findings] == [PREFIX + "algorithm"]


def test_unselected_or_disabled_public_material_is_not_graded(tmp_path):
    _, findings = _scan(tmp_path, _certificate(bits=1024), enabled=False)
    assert findings == []
    parser, findings = _scan(tmp_path, _certificate(bits=1024), selected="OTHER")
    assert parser.get_https_selected_public_certificate() is None
    assert findings == []


def test_missing_or_malformed_public_material_is_unknown(tmp_path):
    parser, findings = _scan(tmp_path, "00")
    assert parser.get_https_selected_public_certificate() is None
    assert findings == []
