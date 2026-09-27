"""Opt-in software advisory (CVE) lookup for the configured release (PT-010)."""

from .model import SoftwareAdvisory
from .service import AdvisoryRequest, lookup_software_advisories, not_requested_status


def software_advisories(device, parser, request):
    """Analyzer helper: advisories and report status for ``parser``'s configured version."""

    if request is not None and request.online:
        return [], {"status": "unavailable", "reason-code": "offline-audit",
                    "reason": "Audits use local advisory bundles. Run the separate advisory fetch command first."}

    try:
        version = parser.get_version()
    except Exception:  # a parser without a readable version still gets a status
        version = ""
    modules_of = getattr(parser, "get_provisioned_modules", None)
    modules = modules_of() if callable(modules_of) else None
    try:
        advisories, status = lookup_software_advisories(str(device), version, request, modules=modules)
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        # Bundles are untrusted local data. Never expose their content through
        # exception messages or let malformed nested records abort an audit.
        advisories, status = [], {"status": "error", "reason-code": "invalid-bundle",
                                 "reason": "The local advisory bundle contains invalid data."}
    if status["status"] in {"completed", "unavailable", "error"}:
        print(f"CVE lookup: {status['status']}"
              + (f" ({status['count']} CVEs)" if status["status"] == "completed" else f": {status.get('reason', '')}"))
    return advisories, status


__all__ = [
    "AdvisoryRequest", "SoftwareAdvisory", "lookup_software_advisories",
    "not_requested_status", "software_advisories",
]
