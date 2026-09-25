"""Opt-in software advisory (CVE) lookup for the configured release (PT-010)."""

from .model import SoftwareAdvisory
from .service import AdvisoryRequest, lookup_software_advisories, not_requested_status


def software_advisories(device, parser, request):
    """Analyzer helper: advisories and report status for ``parser``'s configured version."""

    try:
        version = parser.get_version()
    except Exception:  # a parser without a readable version still gets a status
        version = ""
    advisories, status = lookup_software_advisories(str(device), version, request)
    if status["status"] in {"completed", "unavailable", "error"}:
        print(f"CVE lookup: {status['status']}"
              + (f" ({status['count']} CVEs)" if status["status"] == "completed" else f": {status.get('reason', '')}"))
    return advisories, status


__all__ = [
    "AdvisoryRequest", "SoftwareAdvisory", "lookup_software_advisories",
    "not_requested_status", "software_advisories",
]
