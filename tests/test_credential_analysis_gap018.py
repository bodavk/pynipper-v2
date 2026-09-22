import hashlib

import pytest

from src.analyze.common.credentials import (
    CredentialPolicy,
    CredentialPropertyState as State,
    credential_policy_from_context,
    evaluate_credential,
    evaluate_credentials,
)
from src.devices.cisco.ios import CiscoIOSParser
from src.devices.common.models import (
    BlocklistCredentialAssessment as Blocklist,
    ConfigEvidence,
    CredentialMetadata,
    CredentialStorageAssessment as Storage,
    DefaultCredentialAssessment as Default,
)
from src.devices.juniper.junos import JunOSParser
from src.common.assessment import AssessmentContext


def _metadata(
    storage,
    default=Default.NOT_EVALUATED,
    plaintext_length=None,
    account="operator",
):
    return CredentialMetadata(
        account=account,
        context="local_user",
        method="password",
        storage_type=storage.value,
        storage_assessment=storage,
        default_assessment=default,
        plaintext_length=plaintext_length,
        evidence=(ConfigEvidence("credential <redacted>", "fixture.conf", 1),),
    )


def test_shared_policy_keeps_storage_default_and_plaintext_length_independent():
    policy = CredentialPolicy(version="organization/credential-v2", minimum_plaintext_length=12)
    result = evaluate_credential(
        _metadata(Storage.PLAINTEXT, Default.NO_MATCH, plaintext_length=11),
        policy,
    )
    assert result.policy_version == "organization/credential-v2"
    assert result.storage_state == State.FAIL
    assert result.default_state == State.PASS
    assert result.plaintext_length_state == State.FAIL
    assert result.plaintext_length == 11

    default = evaluate_credential(
        _metadata(Storage.PLAINTEXT, Default.MATCH, plaintext_length=20),
        policy,
    )
    assert default.default_state == State.FAIL
    assert default.plaintext_length_state == State.PASS


def test_assessment_context_provides_versioned_credential_policy():
    context = AssessmentContext.from_mapping({
        "policy_version": "organization/credential-v2",
        "minimum_plaintext_credential_length": 15,
    })
    policy = credential_policy_from_context(context)
    assert policy == CredentialPolicy(
        version="organization/credential-v2",
        minimum_plaintext_length=15,
    )
    assert context.to_dict()["minimum-plaintext-credential-length"] == 15


def test_optional_sha256_blocklist_is_compared_inside_parser_and_not_reported(tmp_path):
    blocked_value = "OrganizationSpecificWeakValue"
    fingerprint = hashlib.sha256(blocked_value.encode("utf-8")).hexdigest()
    context = AssessmentContext.from_mapping({
        "policy_version": "organization/blocklist-v1",
        "credential_blocklist_sha256": [fingerprint],
    })
    path = tmp_path / "blocked.conf"
    path.write_text(
        f"version 17.9\nusername audit password 0 {blocked_value}\n",
        encoding="utf-8",
    )
    parser = CiscoIOSParser(str(path))
    parser.set_assessment_context(context)
    credential = parser.get_credential_metadata()[0]
    result = evaluate_credential(credential, credential_policy_from_context(context))
    assert credential.blocklist_assessment == Blocklist.MATCH
    assert result.blocklist_state == State.FAIL
    assert result.blocklist_summary == "matched the supplied credential blocklist"
    serialized = context.to_dict()
    assert serialized["credential-blocklist-sha256-count"] == 1
    assert fingerprint not in str(serialized)
    assert blocked_value not in str(credential)


@pytest.mark.parametrize(
    ("storage", "expected"),
    [
        (Storage.EMPTY, State.FAIL),
        (Storage.PLAINTEXT, State.FAIL),
        (Storage.WEAK_REVERSIBLE, State.FAIL),
        (Storage.WEAK_HASH, State.FAIL),
        (Storage.APPROVED_REVERSIBLE, State.PASS),
        (Storage.APPROVED_HASH, State.PASS),
        (Storage.UNKNOWN, State.UNKNOWN),
        (Storage.MALFORMED, State.UNKNOWN),
    ],
)
def test_shared_storage_classification_preserves_vendor_unknowns(storage, expected):
    result = evaluate_credential(_metadata(storage))
    assert result.storage_state == expected
    assert result.plaintext_length_state == State.NOT_EVALUATED


def test_credential_policy_and_metadata_validation_fail_closed():
    with pytest.raises(ValueError, match="version"):
        CredentialPolicy(version=" ")
    with pytest.raises(ValueError, match="positive"):
        CredentialPolicy(minimum_plaintext_length=0)
    with pytest.raises(ValueError, match="plaintext_length"):
        _metadata(Storage.APPROVED_HASH, plaintext_length=12)


def test_parser_boundary_exposes_only_length_and_redacted_evidence(tmp_path):
    ios_path = tmp_path / "ios.conf"
    ios_path.write_text(
        "version 17.9\nusername audit password 0 NēverEmitThisValue\n",
        encoding="utf-8",
    )
    ios = CiscoIOSParser(str(ios_path)).get_credential_metadata()[0]
    assert ios.plaintext_length == len("NēverEmitThisValue")
    assert "NēverEmitThisValue" not in " ".join(item.text for item in ios.evidence)

    junos_path = tmp_path / "junos.conf"
    junos_path.write_text(
        'set system login user audit authentication plain-text-password "AnotherSecret"\n',
        encoding="utf-8",
    )
    junos = JunOSParser(str(junos_path)).get_credential_metadata()[0]
    assert junos.plaintext_length == len("AnotherSecret")
    assert "AnotherSecret" not in " ".join(item.text for item in junos.evidence)

    results = evaluate_credentials([ios, junos], CredentialPolicy(minimum_plaintext_length=20))
    assert [item.account for item in results] == ["audit", "audit"]
    assert all(item.plaintext_length_state == State.FAIL for item in results)
