"""Vendor-neutral security finding model."""

from enum import Enum
from typing import Iterable, Tuple, Union


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
        evidence: Iterable[str] = (),
        references: Iterable[str] = (),
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

        normalized_evidence = tuple(evidence)
        if any(not isinstance(item, str) or not item.strip() for item in normalized_evidence):
            raise ValueError("evidence entries must be non-empty strings")
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
        self.evidence: Tuple[str, ...] = normalized_evidence
        self.references: Tuple[str, ...] = normalized_references

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
            "references": list(self.references),
        }


# Compatibility name for callers that imported the old generic class.
Issue = Finding

__all__ = ["Finding", "Issue", "Severity"]
