"""Normalized, vendor-neutral configuration records.

These models separate "not present" from "not parsed".  An empty collection is
meaningful only when its knowledge state is ``KNOWN``; parsers that have not yet
implemented a field must return ``UNKNOWN`` or ``UNSUPPORTED`` explicitly.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Generic, Optional, Tuple, TypeVar


class KnowledgeState(str, Enum):
    KNOWN = "known"
    UNKNOWN = "unknown"
    UNSUPPORTED = "unsupported"
    PARSE_ERROR = "parse_error"


class ConfigurationState(str, Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    CONFIGURED = "configured"
    UNKNOWN = "unknown"


class CredentialStorageAssessment(str, Enum):
    """What the supplied configuration proves about credential storage."""

    EMPTY = "empty"
    PLAINTEXT = "plaintext"
    WEAK_REVERSIBLE = "weak_reversible"
    WEAK_HASH = "weak_hash"
    APPROVED_REVERSIBLE = "approved_reversible"
    APPROVED_HASH = "approved_hash"
    UNKNOWN = "unknown"
    MALFORMED = "malformed"


class DefaultCredentialAssessment(str, Enum):
    """Exact known-default comparison, deliberately separate from strength."""

    MATCH = "match"
    NO_MATCH = "no_match"
    NOT_EVALUATED = "not_evaluated"


class BlocklistCredentialAssessment(str, Enum):
    """Optional policy blocklist comparison without retaining the credential."""

    MATCH = "match"
    NO_MATCH = "no_match"
    NOT_EVALUATED = "not_evaluated"

    @classmethod
    def from_optional_match(cls, result: bool | None) -> "BlocklistCredentialAssessment":
        if result is None:
            return cls.NOT_EVALUATED
        return cls.MATCH if result else cls.NO_MATCH


@dataclass(frozen=True)
class ConfigEvidence:
    text: str
    source: str
    line_number: Optional[int] = None

    def __post_init__(self):
        if not self.text.strip():
            raise ValueError("Evidence text must not be empty")
        if not self.source.strip():
            raise ValueError("Evidence source must not be empty")
        if self.line_number is not None and self.line_number < 1:
            raise ValueError("Evidence line_number must be positive")


@dataclass(frozen=True)
class CredentialMetadata:
    """Secret-free metadata produced at a parser's credential boundary."""

    account: str
    context: str
    method: str
    storage_type: str
    storage_assessment: CredentialStorageAssessment
    default_assessment: DefaultCredentialAssessment
    plaintext_length: Optional[int] = None
    blocklist_assessment: BlocklistCredentialAssessment = (
        BlocklistCredentialAssessment.NOT_EVALUATED
    )
    evidence: Tuple[ConfigEvidence, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.plaintext_length is not None and self.plaintext_length < 0:
            raise ValueError("Credential plaintext_length must not be negative")
        if (
            self.plaintext_length is not None
            and self.storage_assessment != CredentialStorageAssessment.PLAINTEXT
        ):
            raise ValueError("Credential plaintext_length is valid only for plaintext storage")

    @property
    def is_default(self) -> bool:
        """Compatibility view for older parser consumers."""

        return self.default_assessment == DefaultCredentialAssessment.MATCH

    @property
    def raw_line_redacted(self) -> str:
        """Compatibility view for the former ASA credential record."""

        return self.evidence[0].text if self.evidence else "credential <redacted>"


T = TypeVar("T")


@dataclass(frozen=True)
class NormalizedValue(Generic[T]):
    state: KnowledgeState
    value: Optional[T] = None
    evidence: Tuple[ConfigEvidence, ...] = field(default_factory=tuple)
    detail: str = ""

    def __post_init__(self):
        if self.state == KnowledgeState.KNOWN and self.value is None:
            raise ValueError("A known normalized value must contain a value")
        if self.state != KnowledgeState.KNOWN and self.value is not None:
            raise ValueError("Only known normalized values may contain a value")

    @classmethod
    def known(cls, value: T, *evidence: ConfigEvidence) -> "NormalizedValue[T]":
        return cls(KnowledgeState.KNOWN, value, tuple(evidence))

    @classmethod
    def unknown(cls, detail: str = "Not parsed") -> "NormalizedValue[T]":
        return cls(KnowledgeState.UNKNOWN, detail=detail)

    @classmethod
    def unsupported(cls, detail: str) -> "NormalizedValue[T]":
        return cls(KnowledgeState.UNSUPPORTED, detail=detail)

    @classmethod
    def parse_error(cls, detail: str, *evidence: ConfigEvidence) -> "NormalizedValue[T]":
        return cls(KnowledgeState.PARSE_ERROR, evidence=tuple(evidence), detail=detail)


@dataclass(frozen=True)
class ManagementService:
    protocol: str
    state: ConfigurationState
    interface: Optional[str] = None
    zone: Optional[str] = None
    scope: Optional[str] = None
    permitted_sources: Tuple[str, ...] = field(default_factory=tuple)
    evidence: Tuple[ConfigEvidence, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class LocalUser:
    username: str
    state: ConfigurationState
    role: Optional[str] = None
    privilege: Optional[int] = None
    authentication: Optional[str] = None
    scope: Optional[str] = None
    evidence: Tuple[ConfigEvidence, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class NetworkInterface:
    name: str
    state: ConfigurationState
    zone: Optional[str] = None
    scope: Optional[str] = None
    addresses: Tuple[str, ...] = field(default_factory=tuple)
    evidence: Tuple[ConfigEvidence, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class SecurityPolicy:
    name: str
    state: ConfigurationState
    action: str
    position: Optional[int] = None
    scope: Optional[str] = None
    source_interfaces: Tuple[str, ...] = field(default_factory=tuple)
    destination_interfaces: Tuple[str, ...] = field(default_factory=tuple)
    sources: Tuple[str, ...] = field(default_factory=tuple)
    destinations: Tuple[str, ...] = field(default_factory=tuple)
    services: Tuple[str, ...] = field(default_factory=tuple)
    tracking: Optional[str] = None
    install_on: Tuple[str, ...] = field(default_factory=tuple)
    evidence: Tuple[ConfigEvidence, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class LoggingDestination:
    destination_type: str
    state: ConfigurationState
    address: Optional[str] = None
    severity: Optional[str] = None
    scope: Optional[str] = None
    evidence: Tuple[ConfigEvidence, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class CryptoSetting:
    name: str
    value: str
    state: ConfigurationState
    scope: Optional[str] = None
    evidence: Tuple[ConfigEvidence, ...] = field(default_factory=tuple)


U = TypeVar("U")


@dataclass(frozen=True)
class NormalizedCollection(Generic[U]):
    state: KnowledgeState
    items: Tuple[U, ...] = field(default_factory=tuple)
    detail: str = ""

    def __post_init__(self):
        if self.state != KnowledgeState.KNOWN and self.items:
            raise ValueError("Only known normalized collections may contain items")

    @classmethod
    def known(cls, *items: U) -> "NormalizedCollection[U]":
        return cls(KnowledgeState.KNOWN, tuple(items))

    @classmethod
    def unknown(cls, detail: str = "Not parsed") -> "NormalizedCollection[U]":
        return cls(KnowledgeState.UNKNOWN, detail=detail)

    @classmethod
    def unsupported(cls, detail: str) -> "NormalizedCollection[U]":
        return cls(KnowledgeState.UNSUPPORTED, detail=detail)

    @classmethod
    def parse_error(cls, detail: str) -> "NormalizedCollection[U]":
        return cls(KnowledgeState.PARSE_ERROR, detail=detail)


@dataclass(frozen=True)
class NormalizedConfig:
    device_type: str
    hostname: NormalizedValue[str]
    device_model: NormalizedValue[str]
    software_version: NormalizedValue[str]
    management_services: NormalizedCollection[ManagementService]
    users: NormalizedCollection[LocalUser]
    interfaces: NormalizedCollection[NetworkInterface]
    policies: NormalizedCollection[SecurityPolicy]
    logging_destinations: NormalizedCollection[LoggingDestination]
    crypto_settings: NormalizedCollection[CryptoSetting]

    @classmethod
    def unknown(cls, device_type: str) -> "NormalizedConfig":
        return cls(
            device_type=device_type,
            hostname=NormalizedValue.unknown("Hostname has not been normalized"),
            device_model=NormalizedValue.unknown("Device model has not been normalized"),
            software_version=NormalizedValue.unknown("Software version has not been normalized"),
            management_services=NormalizedCollection.unknown(
                "Management services have not been normalized"
            ),
            users=NormalizedCollection.unknown("Local users have not been normalized"),
            interfaces=NormalizedCollection.unknown("Interfaces have not been normalized"),
            policies=NormalizedCollection.unknown("Security policies have not been normalized"),
            logging_destinations=NormalizedCollection.unknown(
                "Logging destinations have not been normalized"
            ),
            crypto_settings=NormalizedCollection.unknown(
                "Cryptographic settings have not been normalized"
            ),
        )


__all__ = [
    "ConfigEvidence",
    "BlocklistCredentialAssessment",
    "ConfigurationState",
    "CredentialMetadata",
    "CredentialStorageAssessment",
    "CryptoSetting",
    "DefaultCredentialAssessment",
    "KnowledgeState",
    "LocalUser",
    "LoggingDestination",
    "ManagementService",
    "NetworkInterface",
    "NormalizedCollection",
    "NormalizedConfig",
    "NormalizedValue",
    "SecurityPolicy",
]
