"""Secret-free, deterministic X.509 public-certificate assessment helpers."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime
import ipaddress
import re
from typing import Iterable

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError


@dataclass(frozen=True)
class CertificateMetadata:
    sha256: str
    subject: str
    issuer: str
    san_dns: tuple[str, ...]
    san_ips: tuple[str, ...]
    not_before: str
    not_after: str
    public_key_algorithm: str
    public_key_size: int | None
    signature_hash_algorithm: str
    is_ca: bool | None
    self_issued: bool


@dataclass(frozen=True)
class CertificateAssessment:
    metadata: CertificateMetadata
    validity_state: str
    identity_state: str
    trust_state: str
    algorithm_state: str


def load_public_certificate(value: str) -> x509.Certificate:
    """Parse a single PEM or base64-DER certificate; raise ValueError when malformed."""

    data = value.strip().encode("ascii")
    if b"-----BEGIN CERTIFICATE-----" in data:
        return x509.load_pem_x509_certificate(data)
    compact = re.sub(rb"\s+", b"", data)
    try:
        der = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("certificate is not valid base64 DER") from error
    return x509.load_der_x509_certificate(der)


def certificate_metadata(certificate: x509.Certificate) -> CertificateMetadata:
    dns_names: tuple[str, ...] = ()
    ip_addresses: tuple[str, ...] = ()
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_names = tuple(san.get_values_for_type(x509.DNSName))
        ip_addresses = tuple(str(item) for item in san.get_values_for_type(x509.IPAddress))
    except x509.ExtensionNotFound:
        pass
    try:
        is_ca = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        is_ca = None

    public_key = certificate.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        key_algorithm, key_size = "rsa", public_key.key_size
    elif isinstance(public_key, dsa.DSAPublicKey):
        key_algorithm, key_size = "dsa", public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_algorithm, key_size = "ec", public_key.key_size
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        key_algorithm, key_size = "ed25519", None
    elif isinstance(public_key, ed448.Ed448PublicKey):
        key_algorithm, key_size = "ed448", None
    else:
        key_algorithm, key_size = certificate.public_key_algorithm_oid.dotted_string, None
    try:
        signature_hash = certificate.signature_hash_algorithm.name
    except UnsupportedAlgorithm:  # EdDSA and unknown algorithms have no separate hash object.
        signature_hash = "intrinsic-or-unknown"

    return CertificateMetadata(
        sha256=certificate.fingerprint(hashes.SHA256()).hex(),
        subject=certificate.subject.rfc4514_string(),
        issuer=certificate.issuer.rfc4514_string(),
        san_dns=dns_names,
        san_ips=ip_addresses,
        not_before=certificate.not_valid_before_utc.isoformat(),
        not_after=certificate.not_valid_after_utc.isoformat(),
        public_key_algorithm=key_algorithm,
        public_key_size=key_size,
        signature_hash_algorithm=signature_hash,
        is_ca=is_ca,
        self_issued=certificate.subject == certificate.issuer,
    )


def _dns_matches(pattern: str, hostname: str) -> bool:
    pattern = pattern.rstrip(".").casefold()
    hostname = hostname.rstrip(".").casefold()
    if not pattern.startswith("*."):
        return pattern == hostname
    return hostname.count(".") == pattern.count(".") and hostname.endswith(pattern[1:])


def certificate_matches_identity(certificate: x509.Certificate, identity: str) -> bool:
    try:
        expected_ip = ipaddress.ip_address(identity)
    except ValueError:
        expected_ip = None
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return False
    if expected_ip is not None:
        return expected_ip in san.get_values_for_type(x509.IPAddress)
    return any(_dns_matches(name, identity) for name in san.get_values_for_type(x509.DNSName))


def assess_public_certificate(
    certificate: x509.Certificate,
    available_certificates: Iterable[x509.Certificate],
    trusted_sha256: Iterable[str],
    identity: str | None,
    assessment_time: datetime | None,
) -> CertificateAssessment:
    metadata = certificate_metadata(certificate)
    validity = "unknown"
    if assessment_time is not None:
        if assessment_time < certificate.not_valid_before_utc:
            validity = "not-yet-valid"
        elif assessment_time > certificate.not_valid_after_utc:
            validity = "expired"
        else:
            validity = "valid-at-assessment-time"

    identity_state = "unknown"
    if identity:
        identity_state = "match" if certificate_matches_identity(certificate, identity) else "mismatch"

    weak_key = (
        metadata.public_key_algorithm in {"rsa", "dsa"}
        and (metadata.public_key_size or 0) < 2048
    ) or (
        metadata.public_key_algorithm == "ec" and (metadata.public_key_size or 0) < 224
    )
    algorithm_state = (
        "weak" if weak_key or metadata.signature_hash_algorithm in {"md5", "sha1"} else "acceptable"
    )

    trusted = {item.casefold() for item in trusted_sha256}
    candidates = list(available_certificates)
    anchors = [item for item in candidates if certificate_metadata(item).sha256 in trusted]
    trust_state = "unknown"
    if anchors and identity and assessment_time is not None:
        subject = (
            x509.IPAddress(ipaddress.ip_address(identity))
            if _is_ip(identity)
            else x509.DNSName(identity)
        )
        intermediates = [
            item for item in candidates
            if item != certificate and item not in anchors
        ]
        try:
            verifier = (
                PolicyBuilder().store(Store(anchors)).time(assessment_time)
                .build_server_verifier(subject)
            )
            verifier.verify(certificate, intermediates)
            trust_state = "trusted"
        except (ValueError, VerificationError):
            trust_state = "verification-failed"

    return CertificateAssessment(
        metadata=metadata,
        validity_state=validity,
        identity_state=identity_state,
        trust_state=trust_state,
        algorithm_state=algorithm_state,
    )


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


__all__ = [
    "CertificateAssessment", "CertificateMetadata", "assess_public_certificate",
    "certificate_metadata", "load_public_certificate",
]
