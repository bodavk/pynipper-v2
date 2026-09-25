"""Vendor-neutral security finding model."""

from dataclasses import dataclass
from enum import Enum
from pathlib import PurePath
from typing import Iterable, Optional, Tuple, Union

from src.devices.common.models import ConfigEvidence


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"
    UNKNOWN = "Unknown"

    @classmethod
    def parse(cls, value: Union["Severity", str]) -> "Severity":
        if isinstance(value, cls):
            return value
        normalized = str(value).strip().lower()
        for severity in cls:
            if normalized in {severity.name.lower(), severity.value.lower()}:
                return severity
        allowed = ", ".join(severity.value for severity in cls)
        raise ValueError(f"Invalid severity {value!r}. Expected one of: {allowed}")


class FindingBasis(str, Enum):
    """Why a finding was raised (PT-009). Set by the rule where it creates the finding.

    ``EXPLICIT_VALUE``: the configuration explicitly sets an insecure value.
    ``DOCUMENTED_DEFAULT``: nothing is set, and the vendor documents an insecure
    default for the assessed release.
    ``MISSING_EXPLICIT_SETTING``: a recommended hardening setting is not
    explicitly configured; the release default was not assessed, so the effective
    value may already be safe.
    ``REQUIRED_SETTING_MISSING``: a control the baseline requires is absent and
    the device does not provide it by default (for example, no NTP server or
    remote log destination exists unless one is configured).
    """

    EXPLICIT_VALUE = "explicit-value"
    DOCUMENTED_DEFAULT = "documented-default"
    MISSING_EXPLICIT_SETTING = "missing-explicit-setting"
    REQUIRED_SETTING_MISSING = "required-setting-missing"


@dataclass(frozen=True)
class EvidenceLocation:
    """Sanitized evidence text with its source position when the parser knows it.

    ``origin`` records how the line was established: ``parser`` means it was
    copied from parser-owned ``ConfigEvidence``; ``source-match`` means the
    evidence text equals exactly one line of the input file (see
    ``BaseDeviceParser.locate_source_line``). Evidence with neither, such as
    a statement that a setting is absent, has no line. ``source`` is the file
    name only, which matters for multi-file inputs such as Check Point exports.
    """

    text: str
    line_number: Optional[int] = None
    source: Optional[str] = None
    origin: Optional[str] = None

    @classmethod
    def from_item(cls, item: Union[str, ConfigEvidence]) -> "EvidenceLocation":
        if isinstance(item, ConfigEvidence):
            return cls(
                item.text,
                item.line_number,
                PurePath(item.source).name or None,
                "parser" if item.line_number is not None else None,
            )
        return cls(item)

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "line": self.line_number,
            "source": self.source,
            "line_origin": self.origin,
        }


class Finding:
    """A validated finding shared by every device plugin."""

    def __init__(
        self,
        *,
        rule_id: str,
        device: str,
        title: str,
        observation: str,
        impact: str,
        recommendation: str,
        severity: Union[Severity, str] = Severity.UNKNOWN,
        exploitability: str = "",
        evidence: Iterable[Union[str, ConfigEvidence]] = (),
        references: Iterable[str] = (),
        basis: Optional[Union[FindingBasis, str]] = None,
    ):
        required = {
            "rule_id": rule_id,
            "device": device,
            "title": title,
            "observation": observation,
            "impact": impact,
            "recommendation": recommendation,
        }
        for field, value in required.items():
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field} must be a non-empty string")
        if not isinstance(exploitability, str):
            raise TypeError("exploitability must be a string")

        # Plugins pass parser ConfigEvidence where available so the report can
        # cite the source line; plain strings remain valid (no known line).
        locations = []
        for item in evidence:
            text = item.text if isinstance(item, ConfigEvidence) else item
            if not isinstance(text, str) or not text.strip():
                raise ValueError("evidence entries must be non-empty strings or ConfigEvidence")
            locations.append(EvidenceLocation.from_item(item))
        normalized_references = tuple(references)
        if any(
            not isinstance(item, str) or not item.strip()
            for item in normalized_references
        ):
            raise ValueError("reference entries must be non-empty strings")

        self.rule_id = rule_id.strip()
        self.device = device.strip()
        self.title = title.strip()
        self.observation = observation.strip()
        self.impact = impact.strip()
        self.recommendation = recommendation.strip()
        self.severity = Severity.parse(severity)
        self.exploitability = exploitability.strip()
        self.evidence: Tuple[str, ...] = tuple(location.text for location in locations)
        self.evidence_locations: Tuple[EvidenceLocation, ...] = tuple(locations)
        self.references: Tuple[str, ...] = normalized_references
        # None means the rule has not declared a basis yet; the report then shows no note.
        self.basis: Optional[FindingBasis] = None if basis is None else FindingBasis(basis)

    def locate_evidence(self, locate_line, source_name: Optional[str]) -> None:
        """Fill missing line numbers using a conservative exact-line lookup."""

        located = []
        for location in self.evidence_locations:
            if location.line_number is None:
                number = locate_line(location.text)
                if number is not None:
                    location = EvidenceLocation(
                        location.text, number, location.source or source_name, "source-match"
                    )
            located.append(location)
        self.evidence_locations = tuple(located)

    @property
    def ease(self) -> str:
        """Compatibility view for legacy templates and report consumers."""

        return self.exploitability

    def __str__(self) -> str:
        result = f"Finding {self.rule_id} — {self.title}:\n"
        result += "=" * 100 + "\n"
        result += f"Device: {self.device}\n"
        result += f"Severity: {self.severity.value}\n"
        result += f"Observation: {self.observation}\n"
        result += f"Impact: {self.impact}\n"
        result += f"Exploitability: {self.exploitability}\n"
        result += f"Recommendation: {self.recommendation}\n"
        if self.evidence:
            result += f"Evidence: {'; '.join(self.evidence)}\n"
        if self.references:
            result += f"References: {'; '.join(self.references)}\n"
        result += "-" * 100 + "\n"
        return result

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "device": self.device,
            "title": self.title,
            "observation": self.observation,
            "impact": self.impact,
            "severity": self.severity.value,
            "exploitability": self.exploitability,
            # Retained for report-reader compatibility during schema migration.
            "ease": self.exploitability,
            "recommendation": self.recommendation,
            "evidence": list(self.evidence),
            # Additive: the same evidence with source line/file where known.
            "evidence_locations": [location.to_dict() for location in self.evidence_locations],
            "references": list(self.references),
            # Additive (PT-009): explicit-value, documented-default,
            # missing-explicit-setting, or null when the rule has not declared one.
            "basis": self.basis.value if self.basis is not None else None,
        }


# Compatibility name for callers that imported the old generic class.
Issue = Finding

__all__ = ["EvidenceLocation", "Finding", "FindingBasis", "Issue", "Severity"]
