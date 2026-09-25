"""Opt-in software advisory lookup for the configured release (PT-010).

Default runs never call this network path. ``AdvisoryRequest`` is created at
the CLI boundary. The result is a list of ``SoftwareAdvisory`` records and a
status dictionary for the report. Every outcome, including failures, yields a
status; a report is always produced.
"""

from __future__ import annotations

import datetime
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from .model import SoftwareAdvisory
from .nvd import NVD_CVE_URL, NVDClient, NVDError
from .versions import ProductVersion, VersionUnavailable, product_version, split_cpe

BUNDLE_FORMAT = "pynipper-nvd-bundle"
BUNDLE_VERSION = 1

LIMITATIONS = (
    "Matches come from NVD applicability data for the exact release. NVD may not yet have "
    "product data for recent CVEs, so the list can be incomplete.",
    "A version match does not prove exploitability: most CVEs need a specific feature, "
    "interface exposure or hardware platform, which this lookup does not check against the configuration.",
    "The configuration records the release it was saved with; the running release may differ.",
)


@dataclass(frozen=True)
class AdvisoryRequest:
    """How the operator asked for advisories. ``api_key`` is never serialized."""

    online: bool = False
    bundle_path: Optional[str] = None
    save_path: Optional[str] = None
    software_version: Optional[str] = None
    api_key: Optional[str] = None

    @property
    def requested(self) -> bool:
        return self.online or bool(self.bundle_path)


def not_requested_status() -> dict:
    return {
        "status": "not-requested",
        "reason": "CVE lookup was not requested. Use --cve-lookup (online, NVD) or --cve-data (saved bundle).",
    }


def _status(status: str, **fields) -> dict:
    record = {"status": status, "limitations": list(LIMITATIONS)}
    record.update({key: value for key, value in fields.items() if value is not None})
    return record


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def select_cpe_names(target: ProductVersion, cpe_pages: list[dict]) -> list[str]:
    """Non-deprecated dictionary names for exactly this product release."""

    names = []
    for page in cpe_pages:
        for product in page.get("products", ()):
            cpe = product.get("cpe", {})
            name = cpe.get("cpeName", "")
            if not name or cpe.get("deprecated"):
                continue
            fields = split_cpe(name)
            if len(fields) < 7 or fields[2:5] != [target.part, target.vendor, target.product]:
                continue
            if fields[5] != target.version.casefold():
                continue
            update = fields[6]
            if target.update:
                if update != target.update:
                    continue
            elif update not in {"*", "-", ""}:
                continue
            if name not in names:
                names.append(name)
    return names


def _metric(metrics: dict) -> tuple[Optional[float], str, str]:
    for key, label in (("cvssMetricV31", "3.1"), ("cvssMetricV40", "4.0"),
                       ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = next((item for item in entries if item.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData", {})
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or entry.get("baseSeverity") or ""
        return (float(score) if score is not None else None), label, str(severity).capitalize()
    return None, "", "Unknown"


def _conditional(cve: dict, target: ProductVersion) -> bool:
    """True when every applicability statement naming this product combines it (AND) with another condition."""

    relevant = []
    for configuration in cve.get("configurations", ()):
        names_product = any(
            match.get("vulnerable") and split_cpe(match.get("criteria", ""))[2:5]
            == [target.part, target.vendor, target.product]
            for node in configuration.get("nodes", ())
            for match in node.get("cpeMatch", ())
        )
        if names_product:
            relevant.append(configuration)
    return bool(relevant) and all(
        str(item.get("operator", "")).upper() == "AND" or any(
            str(node.get("operator", "")).upper() == "AND" for node in item.get("nodes", ())
        )
        for item in relevant
    )


def advisories_from_pages(target: ProductVersion, cve_pages: dict[str, list[dict]]) -> list[SoftwareAdvisory]:
    found: dict[str, SoftwareAdvisory] = {}
    matched: dict[str, list[str]] = {}
    for cpe_name, pages in cve_pages.items():
        for page in pages:
            for item in page.get("vulnerabilities", ()):
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                if not cve_id:
                    continue
                matched.setdefault(cve_id, [])
                if cpe_name not in matched[cve_id]:
                    matched[cve_id].append(cpe_name)
                if cve_id in found:
                    continue
                description = next(
                    (entry.get("value", "") for entry in cve.get("descriptions", ()) if entry.get("lang") == "en"),
                    "",
                )
                score, version, severity = _metric(cve.get("metrics", {}))
                found[cve_id] = SoftwareAdvisory(
                    cve_id=cve_id,
                    summary=description.strip() or "No English description is available.",
                    cvss=score,
                    cvss_version=version,
                    severity=severity,
                    url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    published=str(cve.get("published", ""))[:10],
                    nvd_status=str(cve.get("vulnStatus", "")),
                    kev_date=str(cve.get("cisaExploitAdd") or ""),
                    kev_name=str(cve.get("cisaVulnerabilityName") or ""),
                    conditional=_conditional(cve, target),
                )
    result = [
        SoftwareAdvisory(**{**advisory.__dict__, "matched_cpe": tuple(matched[advisory.cve_id])})
        for advisory in found.values()
    ]
    return sorted(result, key=SoftwareAdvisory.sort_key)


def _load_bundle(path: str, target: ProductVersion) -> dict:
    with open(path, encoding="utf-8") as handle:
        bundle = json.load(handle)
    if not isinstance(bundle, dict) or bundle.get("format") != BUNDLE_FORMAT:
        raise ValueError("The file is not a pynipper NVD bundle.")
    if bundle.get("format-version") != BUNDLE_VERSION:
        raise ValueError("The bundle format version is not supported.")
    if bundle.get("product") != target.to_dict():
        stored = bundle.get("product") or {}
        raise LookupError(
            f"The bundle is for {stored.get('product', '?')} {stored.get('version', '?')}"
            f"{' ' + stored['update'] if stored.get('update') else ''}, not {target.product} {target.display}."
        )
    return bundle


def _save_bundle(path: str, bundle: dict) -> None:
    # Exclusive creation: never overwrite an existing file.
    with open(path, "x", encoding="utf-8") as handle:
        json.dump(bundle, handle, indent=1, sort_keys=True)


def lookup_software_advisories(
    device: str,
    configured_version: str,
    request: Optional[AdvisoryRequest],
    client_factory: Callable[..., NVDClient] = NVDClient,
) -> tuple[list[SoftwareAdvisory], dict]:
    if request is None or not request.requested:
        return [], not_requested_status()
    origin = "operator" if request.software_version else "configuration"
    version = request.software_version or configured_version
    base = {"device": str(device), "configured-version": configured_version or None,
            "version-origin": origin}
    try:
        target = product_version(device, version)
    except VersionUnavailable as error:
        return [], _status("unavailable", reason=str(error), **{"reason-code": error.reason}, **base)
    base.update({"product": target.product_prefix, "version": target.display, "note": target.note or None})
    try:
        if request.bundle_path:
            bundle = _load_bundle(request.bundle_path, target)
            source = f"Saved NVD bundle ({Path(request.bundle_path).name})"
        else:
            client = client_factory(api_key=request.api_key)
            cpe_pages = client.cpe_pages(target.match_string())
            names = select_cpe_names(target, cpe_pages)
            bundle = {
                "format": BUNDLE_FORMAT, "format-version": BUNDLE_VERSION,
                "retrieved-at": _now(), "source": NVD_CVE_URL,
                "product": target.to_dict(), "cpe-names": names,
                "cpe-pages": cpe_pages,
                "cve-pages": {name: client.cve_pages(name) for name in names},
            }
            source = "NVD CVE API 2.0"
    except LookupError as error:
        return [], _status("unavailable", reason=str(error), **{"reason-code": "bundle-mismatch"}, **base)
    except (NVDError, OSError, ValueError, KeyError, TypeError) as error:
        return [], _status("error", reason=f"CVE lookup failed: {error}", **base)

    if request.save_path and not request.bundle_path:
        try:
            _save_bundle(request.save_path, bundle)
            base["saved-bundle"] = Path(request.save_path).name
        except OSError as error:
            base["save-error"] = f"The NVD bundle was not saved: {error.strerror or error}"
    names = bundle.get("cpe-names") or []
    base.update({"source": source, "retrieved-at": bundle.get("retrieved-at"), "cpe-names": names})
    if not names:
        return [], _status(
            "unavailable", reason=(
                f"NVD's CPE dictionary has no entry for {target.product} {target.display}, so NVD cannot "
                "match CVEs to it. This is not evidence that the release has no CVEs."
            ), **{"reason-code": "not-in-cpe-dictionary"}, **base,
        )
    advisories = advisories_from_pages(target, bundle.get("cve-pages") or {})
    return advisories, _status(
        "completed", count=len(advisories),
        **{"known-exploited": sum(item.known_exploited for item in advisories),
           "conditional": sum(item.conditional for item in advisories)},
        **base,
    )


def api_key_from(configuration_path: Optional[str]) -> Optional[str]:
    """NVD API key from ``NVD_API_KEY`` or the ``[NVD] API_KEY`` configuration entry."""

    key = os.environ.get("NVD_API_KEY", "").strip()
    if key:
        return key
    if configuration_path and os.path.isfile(configuration_path):
        import configparser

        config = configparser.ConfigParser()
        config.read(configuration_path)
        if config.has_option("NVD", "API_KEY"):
            return config["NVD"]["API_KEY"].strip() or None
    return None


__all__ = [
    "AdvisoryRequest", "LIMITATIONS", "advisories_from_pages", "api_key_from",
    "lookup_software_advisories", "not_requested_status", "select_cpe_names",
]
