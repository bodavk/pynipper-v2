"""Neutral software-advisory record for the report (PT-010)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class SoftwareAdvisory:
    """One CVE that the data source lists as affecting the assessed release.

    The attribute names ``title``, ``summary``, ``cves``, ``cvss`` and ``url``
    match the legacy advisory rows the report template already renders.
    """

    cve_id: str
    summary: str
    cvss: Optional[float]
    cvss_version: str
    severity: str
    url: str
    published: str = ""
    nvd_status: str = ""
    kev_date: str = ""
    kev_name: str = ""
    conditional: bool = False
    matched_cpe: tuple[str, ...] = field(default_factory=tuple)
    source: str = "NVD"

    @property
    def title(self) -> str:
        return self.cve_id

    @property
    def cves(self) -> tuple[str, ...]:
        return (self.cve_id,)

    @property
    def severity_class(self) -> str:
        """CSS class for the report badge; CVSS "None" and unknown values stay neutral."""

        value = self.severity.casefold()
        return value if value in {"critical", "high", "medium", "low"} else "unknown"

    @property
    def known_exploited(self) -> bool:
        return bool(self.kev_date)

    def sort_key(self) -> tuple:
        return (not self.known_exploited, -(self.cvss if self.cvss is not None else -1.0), self.cve_id)

    def to_dict(self) -> dict:
        return {
            "cve": self.cve_id,
            "title": self.title,
            "summary": self.summary,
            "cves": list(self.cves),
            "cvss": self.cvss,
            "cvss-version": self.cvss_version,
            "severity": self.severity,
            "url": self.url,
            "published": self.published,
            "nvd-status": self.nvd_status,
            "known-exploited": self.known_exploited,
            "kev-date-added": self.kev_date or None,
            "kev-name": self.kev_name or None,
            "conditional": self.conditional,
            "matched-cpe": list(self.matched_cpe),
            "source": self.source,
        }


__all__ = ["SoftwareAdvisory"]
