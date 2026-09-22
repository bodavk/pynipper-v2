"""Shared, secret-free credential property evaluation.

Vendor parsers remain responsible for classifying their storage syntax and for
discarding credential values.  This module applies common policy only to the
resulting metadata; it must never receive or recover a secret.
"""

from dataclasses import dataclass
from enum import Enum

from src.common.assessment import AssessmentContext
from src.devices.common.models import (
    BlocklistCredentialAssessment,
    CredentialMetadata,
    CredentialStorageAssessment,
    DefaultCredentialAssessment,
)


class CredentialPropertyState(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"
    NOT_EVALUATED = "not_evaluated"


@dataclass(frozen=True)
class CredentialPolicy:
    version: str = "pynipper-v2/credential-v1"
    minimum_plaintext_length: int | None = None

    def __post_init__(self) -> None:
        if not self.version.strip():
            raise ValueError("Credential policy version must not be empty")
        if self.minimum_plaintext_length is not None and self.minimum_plaintext_length < 1:
            raise ValueError("Minimum plaintext length must be positive")


@dataclass(frozen=True)
class CredentialPropertyResult:
    account: str
    context: str
    policy_version: str
    storage_state: CredentialPropertyState
    storage_assessment: CredentialStorageAssessment
    default_state: CredentialPropertyState
    default_assessment: DefaultCredentialAssessment
    blocklist_state: CredentialPropertyState
    blocklist_assessment: BlocklistCredentialAssessment
    plaintext_length_state: CredentialPropertyState
    plaintext_length: int | None
    minimum_plaintext_length: int | None

    @property
    def unsafe_storage(self) -> bool:
        return self.storage_state == CredentialPropertyState.FAIL

    @property
    def default_summary(self) -> str:
        return {
            DefaultCredentialAssessment.MATCH: "matched an exact known-default fingerprint",
            DefaultCredentialAssessment.NO_MATCH: "did not match the exact known-default list",
            DefaultCredentialAssessment.NOT_EVALUATED: "was not applicable to this representation",
        }[self.default_assessment]

    @property
    def plaintext_length_summary(self) -> str:
        if self.plaintext_length_state == CredentialPropertyState.NOT_EVALUATED:
            return "plaintext length was not evaluated by policy"
        if self.plaintext_length_state == CredentialPropertyState.UNKNOWN:
            return "plaintext length is unknown"
        comparison = "meets" if self.plaintext_length_state == CredentialPropertyState.PASS else "is below"
        return (
            f"plaintext length {self.plaintext_length} {comparison} policy minimum "
            f"{self.minimum_plaintext_length}"
        )

    @property
    def blocklist_summary(self) -> str:
        return {
            BlocklistCredentialAssessment.MATCH: "matched the supplied credential blocklist",
            BlocklistCredentialAssessment.NO_MATCH: "did not match the supplied credential blocklist",
            BlocklistCredentialAssessment.NOT_EVALUATED: "was not evaluated against a supplied credential blocklist",
        }[self.blocklist_assessment]


DEFAULT_CREDENTIAL_POLICY = CredentialPolicy()


def credential_policy_from_context(context: AssessmentContext) -> CredentialPolicy:
    return CredentialPolicy(
        version=context.policy_version,
        minimum_plaintext_length=context.minimum_plaintext_credential_length,
    )


def evaluate_credential(
    credential: CredentialMetadata,
    policy: CredentialPolicy = DEFAULT_CREDENTIAL_POLICY,
) -> CredentialPropertyResult:
    """Evaluate common properties without reinterpreting vendor storage syntax."""

    unsafe = {
        CredentialStorageAssessment.EMPTY,
        CredentialStorageAssessment.PLAINTEXT,
        CredentialStorageAssessment.WEAK_HASH,
        CredentialStorageAssessment.WEAK_REVERSIBLE,
    }
    approved = {
        CredentialStorageAssessment.APPROVED_HASH,
        CredentialStorageAssessment.APPROVED_REVERSIBLE,
    }
    storage_state = (
        CredentialPropertyState.FAIL
        if credential.storage_assessment in unsafe
        else CredentialPropertyState.PASS
        if credential.storage_assessment in approved
        else CredentialPropertyState.UNKNOWN
    )
    default_state = {
        DefaultCredentialAssessment.MATCH: CredentialPropertyState.FAIL,
        DefaultCredentialAssessment.NO_MATCH: CredentialPropertyState.PASS,
        DefaultCredentialAssessment.NOT_EVALUATED: CredentialPropertyState.NOT_EVALUATED,
    }[credential.default_assessment]
    blocklist_state = {
        BlocklistCredentialAssessment.MATCH: CredentialPropertyState.FAIL,
        BlocklistCredentialAssessment.NO_MATCH: CredentialPropertyState.PASS,
        BlocklistCredentialAssessment.NOT_EVALUATED: CredentialPropertyState.NOT_EVALUATED,
    }[credential.blocklist_assessment]
    if credential.storage_assessment != CredentialStorageAssessment.PLAINTEXT:
        length_state = CredentialPropertyState.NOT_EVALUATED
    elif policy.minimum_plaintext_length is None:
        length_state = CredentialPropertyState.NOT_EVALUATED
    elif credential.plaintext_length is None:
        length_state = CredentialPropertyState.UNKNOWN
    elif credential.plaintext_length < policy.minimum_plaintext_length:
        length_state = CredentialPropertyState.FAIL
    else:
        length_state = CredentialPropertyState.PASS
    return CredentialPropertyResult(
        account=credential.account,
        context=credential.context,
        policy_version=policy.version,
        storage_state=storage_state,
        storage_assessment=credential.storage_assessment,
        default_state=default_state,
        default_assessment=credential.default_assessment,
        blocklist_state=blocklist_state,
        blocklist_assessment=credential.blocklist_assessment,
        plaintext_length_state=length_state,
        plaintext_length=credential.plaintext_length,
        minimum_plaintext_length=policy.minimum_plaintext_length,
    )


def evaluate_credentials(
    credentials: list[CredentialMetadata] | tuple[CredentialMetadata, ...],
    policy: CredentialPolicy = DEFAULT_CREDENTIAL_POLICY,
) -> tuple[CredentialPropertyResult, ...]:
    return tuple(evaluate_credential(credential, policy) for credential in credentials)


__all__ = [
    "CredentialPolicy",
    "CredentialPropertyResult",
    "CredentialPropertyState",
    "DEFAULT_CREDENTIAL_POLICY",
    "credential_policy_from_context",
    "evaluate_credential",
    "evaluate_credentials",
]
