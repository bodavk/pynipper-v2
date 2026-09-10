import pytest

from src.devices import DEVICE_REGISTRY, get_parser
from src.devices.common.models import (
    ConfigEvidence,
    KnowledgeState,
    NormalizedCollection,
    NormalizedConfig,
    NormalizedValue,
)


def _minimal_config_source(tmp_path, canonical_id):
    if canonical_id == "CHECKPOINT_FW1":
        source = tmp_path / canonical_id.lower()
        source.mkdir()
        return str(source)

    source = tmp_path / f"{canonical_id.lower()}.conf"
    source.write_text("<config />" if canonical_id == "PAN_OS" else "", encoding="utf-8")
    return str(source)


@pytest.mark.parametrize("canonical_id", DEVICE_REGISTRY)
def test_every_parser_exposes_complete_normalized_contract(tmp_path, canonical_id):
    parser = get_parser(canonical_id, _minimal_config_source(tmp_path, canonical_id))
    normalized = parser.get_normalized_config()

    assert isinstance(normalized, NormalizedConfig)
    assert normalized.device_type == canonical_id

    scalar_fields = (normalized.hostname, normalized.device_model, normalized.software_version)
    collection_fields = (
        normalized.management_services,
        normalized.users,
        normalized.interfaces,
        normalized.policies,
        normalized.logging_destinations,
        normalized.crypto_settings,
    )
    assert all(isinstance(value, NormalizedValue) for value in scalar_fields)
    assert all(isinstance(value, NormalizedCollection) for value in collection_fields)
    for value in scalar_fields:
        if value.state == KnowledgeState.KNOWN:
            assert value.value is not None
        else:
            assert value.value is None
            assert value.detail
    for value in collection_fields:
        if value.state != KnowledgeState.KNOWN:
            assert value.items == ()
            assert value.detail


@pytest.mark.parametrize("canonical_id", DEVICE_REGISTRY)
def test_raw_config_compatibility_alias_returns_native_object(tmp_path, canonical_id):
    parser = get_parser(canonical_id, _minimal_config_source(tmp_path, canonical_id))
    assert parser.get_raw_config() is parser.get_native_config()


def test_unknown_collection_cannot_silently_contain_items():
    with pytest.raises(ValueError, match="Only known"):
        NormalizedCollection(KnowledgeState.UNKNOWN, ("unexpected",))


def test_unknown_scalar_cannot_silently_contain_value():
    with pytest.raises(ValueError, match="Only known"):
        NormalizedValue(KnowledgeState.UNKNOWN, "unexpected")


def test_known_scalar_requires_a_value():
    with pytest.raises(ValueError, match="must contain a value"):
        NormalizedValue(KnowledgeState.KNOWN)


def test_evidence_requires_source_text_and_positive_line_number():
    with pytest.raises(ValueError, match="text"):
        ConfigEvidence("", "config.txt", 1)
    with pytest.raises(ValueError, match="source"):
        ConfigEvidence("set service ssh", "", 1)
    with pytest.raises(ValueError, match="positive"):
        ConfigEvidence("set service ssh", "config.txt", 0)
