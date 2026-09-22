"""Immutable, explicit policy context for one offline assessment."""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Iterable, Mapping


_ROLES = {
    "unknown", "internal", "external", "management", "access-edge",
    "uplink", "voice-fabric",
}
_CONFIGURATION_BACKUP_SCOPES = {"unspecified", "external-managed", "on-device-required"}
_REPORT_INVENTORY_CATEGORIES = {
    "interfaces", "logging-destinations", "management-services", "policies"
}


@dataclass(frozen=True)
class AssessmentContext:
    """Policy metadata and operator-supplied roles; never inferred from names."""

    policy_version: str = "pynipper-v2/default-v1"
    device_role: str = "unknown"
    interface_roles: tuple[tuple[str, str], ...] = ()
    protected_aaa_profiles: tuple[str, ...] = ()
    assessment_time: str | None = None
    management_certificate_identities: tuple[tuple[str, str], ...] = ()
    trusted_certificate_sha256: tuple[str, ...] = ()
    configuration_backup_scope: str = "unspecified"
    minimum_plaintext_credential_length: int | None = None
    credential_blocklist_sha256: tuple[str, ...] = ()
    report_inventory: tuple[str, ...] = ()
    excluded_categories: frozenset[str] = frozenset()
    provenance: str = "built-in default"

    def __post_init__(self) -> None:
        if not self.policy_version.strip():
            raise ValueError("assessment policy_version must not be empty")
        if self.device_role not in _ROLES:
            raise ValueError(f"unsupported assessment device_role: {self.device_role}")
        seen = set()
        for interface, role in self.interface_roles:
            key = interface.casefold()
            if not interface.strip() or key in seen:
                raise ValueError("assessment interface roles must have unique non-empty names")
            if role not in _ROLES:
                raise ValueError(f"unsupported interface role for {interface}: {role}")
            seen.add(key)
        protected = [item.casefold() for item in self.protected_aaa_profiles]
        if any(
            not item.partition(":")[0].strip() or not item.partition(":")[2].strip()
            for item in self.protected_aaa_profiles
        ):
            raise ValueError("protected AAA profiles must use non-empty 'scope:name' selectors")
        if len(protected) != len(set(protected)):
            raise ValueError("protected AAA profile selectors must be unique")
        if self.assessment_time is not None:
            try:
                parsed_time = datetime.fromisoformat(self.assessment_time.replace("Z", "+00:00"))
            except ValueError as error:
                raise ValueError("assessment_time must be an ISO-8601 timestamp") from error
            if parsed_time.tzinfo is None or parsed_time.utcoffset() is None:
                raise ValueError("assessment_time must include a UTC offset")
        identity_scopes = [scope.casefold() for scope, _ in self.management_certificate_identities]
        if any(not scope.strip() or not identity.strip() for scope, identity in self.management_certificate_identities):
            raise ValueError("management certificate identities require non-empty scope and identity")
        if len(identity_scopes) != len(set(identity_scopes)):
            raise ValueError("management certificate identity scopes must be unique")
        if any(
            len(fingerprint) != 64
            or any(character not in "0123456789abcdefABCDEF" for character in fingerprint)
            for fingerprint in self.trusted_certificate_sha256
        ):
            raise ValueError("trusted certificate SHA-256 fingerprints must be 64 hexadecimal characters")
        if len({item.casefold() for item in self.trusted_certificate_sha256}) != len(
            self.trusted_certificate_sha256
        ):
            raise ValueError("trusted certificate SHA-256 fingerprints must be unique")
        if self.configuration_backup_scope not in _CONFIGURATION_BACKUP_SCOPES:
            raise ValueError(
                "assessment configuration_backup_scope must be unspecified, "
                "external-managed, or on-device-required"
            )
        if (
            self.minimum_plaintext_credential_length is not None
            and (
                isinstance(self.minimum_plaintext_credential_length, bool)
                or not 1 <= self.minimum_plaintext_credential_length <= 1024
            )
        ):
            raise ValueError(
                "assessment minimum_plaintext_credential_length must be an integer from 1 to 1024"
            )
        if any(
            len(fingerprint) != 64
            or any(character not in "0123456789abcdefABCDEF" for character in fingerprint)
            for fingerprint in self.credential_blocklist_sha256
        ):
            raise ValueError(
                "credential blocklist SHA-256 fingerprints must be 64 hexadecimal characters"
            )
        if len({item.casefold() for item in self.credential_blocklist_sha256}) != len(
            self.credential_blocklist_sha256
        ):
            raise ValueError("credential blocklist SHA-256 fingerprints must be unique")
        if len(set(self.report_inventory)) != len(self.report_inventory) or any(
            item not in _REPORT_INVENTORY_CATEGORIES for item in self.report_inventory
        ):
            raise ValueError(
                "assessment report_inventory entries must be unique supported inventory categories"
            )
        if any(not item or not item.replace("-", "_").isalnum() for item in self.excluded_categories):
            raise ValueError("assessment category names must be non-empty words")

    @classmethod
    def from_mapping(cls, value: Mapping, provenance: str = "explicit mapping") -> "AssessmentContext":
        allowed = {
            "policy_version", "device_role", "interface_roles",
            "protected_aaa_profiles", "assessment_time",
            "management_certificate_identities", "trusted_certificate_sha256",
            "configuration_backup_scope", "minimum_plaintext_credential_length",
            "credential_blocklist_sha256", "report_inventory", "excluded_categories",
        }
        unknown = set(value) - allowed
        if unknown:
            raise ValueError(f"unknown assessment policy fields: {', '.join(sorted(unknown))}")
        roles = value.get("interface_roles", {})
        if not isinstance(roles, Mapping):
            raise ValueError("assessment interface_roles must be an object")
        categories = value.get("excluded_categories", [])
        if not isinstance(categories, list) or any(not isinstance(item, str) for item in categories):
            raise ValueError("assessment excluded_categories must be a string list")
        protected_profiles = value.get("protected_aaa_profiles", [])
        if not isinstance(protected_profiles, list) or any(
            not isinstance(item, str) for item in protected_profiles
        ):
            raise ValueError("assessment protected_aaa_profiles must be a string list")
        certificate_identities = value.get("management_certificate_identities", {})
        if not isinstance(certificate_identities, Mapping) or any(
            not isinstance(identity, str) for identity in certificate_identities.values()
        ):
            raise ValueError("assessment management_certificate_identities must be a string object")
        trusted_fingerprints = value.get("trusted_certificate_sha256", [])
        if not isinstance(trusted_fingerprints, list) or any(
            not isinstance(item, str) for item in trusted_fingerprints
        ):
            raise ValueError("assessment trusted_certificate_sha256 must be a string list")
        assessment_time = value.get("assessment_time")
        if assessment_time is not None and not isinstance(assessment_time, str):
            raise ValueError("assessment assessment_time must be a string")
        minimum_credential_length = value.get("minimum_plaintext_credential_length")
        if minimum_credential_length is not None and (
            isinstance(minimum_credential_length, bool)
            or not isinstance(minimum_credential_length, int)
        ):
            raise ValueError(
                "assessment minimum_plaintext_credential_length must be an integer"
            )
        credential_blocklist = value.get("credential_blocklist_sha256", [])
        if not isinstance(credential_blocklist, list) or any(
            not isinstance(item, str) for item in credential_blocklist
        ):
            raise ValueError("assessment credential_blocklist_sha256 must be a string list")
        report_inventory = value.get("report_inventory", [])
        if not isinstance(report_inventory, list) or any(
            not isinstance(item, str) for item in report_inventory
        ):
            raise ValueError("assessment report_inventory must be a string list")
        return cls(
            policy_version=str(value.get("policy_version", "pynipper-v2/default-v1")),
            device_role=str(value.get("device_role", "unknown")).casefold(),
            interface_roles=tuple((str(name), str(role).casefold()) for name, role in roles.items()),
            protected_aaa_profiles=tuple(protected_profiles),
            assessment_time=assessment_time,
            management_certificate_identities=tuple(
                (str(scope), identity) for scope, identity in certificate_identities.items()
            ),
            trusted_certificate_sha256=tuple(item.casefold() for item in trusted_fingerprints),
            configuration_backup_scope=str(
                value.get("configuration_backup_scope", "unspecified")
            ).casefold(),
            minimum_plaintext_credential_length=minimum_credential_length,
            credential_blocklist_sha256=tuple(
                item.casefold() for item in credential_blocklist
            ),
            report_inventory=tuple(item.casefold() for item in report_inventory),
            excluded_categories=frozenset(item.casefold() for item in categories),
            provenance=provenance,
        )

    @classmethod
    def from_file(cls, filename: str) -> "AssessmentContext":
        path = Path(filename)
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"invalid assessment policy file: {error}") from error
        if not isinstance(value, dict):
            raise ValueError("assessment policy root must be an object")
        return cls.from_mapping(value, provenance=f"policy file: {path.name}")

    def role_for_interface(self, interface: str) -> str:
        roles = MappingProxyType({name.casefold(): role for name, role in self.interface_roles})
        return roles.get(interface.casefold(), "unknown")

    def aaa_profile_has_protected_path(self, scope: str, name: str) -> bool:
        """Return only an exact operator declaration; never infer tunnel routing."""

        selector = f"{scope}:{name}".casefold()
        return selector in {item.casefold() for item in self.protected_aaa_profiles}

    def assessment_datetime(self) -> datetime | None:
        if self.assessment_time is None:
            return None
        return datetime.fromisoformat(self.assessment_time.replace("Z", "+00:00"))

    def plaintext_credential_blocklisted(self, value: str) -> bool | None:
        """Compare internally; never serialize either the value or verifier set."""

        if not self.credential_blocklist_sha256:
            return None
        fingerprint = hashlib.sha256(value.encode("utf-8")).hexdigest()
        return fingerprint in self.credential_blocklist_sha256

    def management_identity_for_scope(self, scope: str) -> str | None:
        identities = MappingProxyType({
            name.casefold(): identity for name, identity in self.management_certificate_identities
        })
        return identities.get(scope.casefold())

    def permits_rule(self, rule_id: str) -> bool:
        tokens = {token.casefold().replace("-", "_") for token in rule_id.split(".")}
        return not tokens.intersection(
            item.replace("-", "_") for item in self.excluded_categories
        )

    def filter_findings(self, findings: Iterable) -> list:
        return [finding for finding in findings if self.permits_rule(finding.rule_id)]

    def to_dict(self) -> dict:
        return {
            "policy-version": self.policy_version,
            "device-role": self.device_role,
            "interface-roles": dict(self.interface_roles),
            "protected-aaa-profiles": list(self.protected_aaa_profiles),
            "assessment-time": self.assessment_time,
            "management-certificate-identities": dict(self.management_certificate_identities),
            "trusted-certificate-sha256": list(self.trusted_certificate_sha256),
            "configuration-backup-scope": self.configuration_backup_scope,
            "minimum-plaintext-credential-length": self.minimum_plaintext_credential_length,
            "credential-blocklist-sha256-count": len(self.credential_blocklist_sha256),
            "report-inventory": list(self.report_inventory),
            "excluded-categories": sorted(self.excluded_categories),
            "provenance": self.provenance,
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
        }
