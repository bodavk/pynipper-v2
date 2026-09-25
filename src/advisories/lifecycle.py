"""Software lifecycle (end-of-support) status from endoflife.date (SC-022).

endoflife.date is a free, community-maintained dataset with a public API
(https://endoflife.date/docs/api/v1/). The project keeps no lifecycle list of its
own. Only the product page is requested (for example ``fortios``); the device
version is never sent. Matching is exact on the release cycle (major.minor), and
the end dates are compared with the assessment date, so a replayed bundle gives
the same answer on the same day.
"""

from __future__ import annotations

import datetime
import re
from typing import Callable, Optional

ENDOFLIFE_API = "https://endoflife.date/api/v1/products/{product}"

# Registry family -> endoflife.date product (verified 2026-09-25; schema 1.2.1).
LIFECYCLE_PRODUCTS = {
    "FORTIOS": "fortios",
    "PAN_OS": "panos",
    "IOS_XE": "cisco-ios-xe",
    "F5_BIGIP": "big-ip",
}
_IOS_FAMILIES = {"IOS_SWITCH", "IOS_ROUTER", "IOS_CATALYST"}


def release_cycle(device: str, version: str) -> Optional[tuple[str, str]]:
    """``(product, cycle)`` for a covered family and parsable release, else ``None``.

    A release train is enough here (IOS-XE ``17.9`` maps to cycle ``17.9``).
    Classic IOS releases (12.x/15.x) are not covered by endoflife.date.
    """
    device = str(device).upper()
    match = re.match(r"(\d+)\.(\d+)", (version or "").strip())
    if not match:
        return None
    major, minor = int(match.group(1)), int(match.group(2))
    product = LIFECYCLE_PRODUCTS.get(device)
    if device in _IOS_FAMILIES and major >= 16:
        product = "cisco-ios-xe"
    if product is None:
        return None
    return product, f"{major}.{minor}"


def _date(value) -> Optional[datetime.date]:
    try:
        return datetime.date.fromisoformat(str(value)[:10]) if value else None
    except ValueError:
        return None


def assess(document: dict, product: str, cycle: str, today: datetime.date) -> dict:
    """Lifecycle status for ``cycle`` from an endoflife.date v1 product document."""

    result = document.get("result") or {}
    if result.get("name") != product:
        raise ValueError("The lifecycle data is for a different product.")
    labels = result.get("labels") or {}
    base = {
        "source": "endoflife.date",
        "source-url": (result.get("links") or {}).get("html") or f"https://endoflife.date/{product}",
        "dataset-generated-at": document.get("generated_at"),
        "product": result.get("label") or product,
        "cycle": cycle,
        "assessment-date": today.isoformat(),
    }
    release = next((item for item in result.get("releases", ()) if str(item.get("name")) == cycle), None)
    if release is None:
        return {**base, "status": "unlisted",
                "reason": f"endoflife.date does not list the {cycle} release cycle for {base['product']}."}
    eol, eoas = _date(release.get("eolFrom")), _date(release.get("eoasFrom"))
    latest = (release.get("latest") or {}).get("name") or None
    base.update({
        "release": release.get("label") or cycle,
        "eol-from": eol.isoformat() if eol else None,
        "eol-label": labels.get("eol") or "End of life",
        "eoas-from": eoas.isoformat() if eoas else None,
        "eoas-label": labels.get("eoas"),
        "latest-in-cycle": latest,
    })
    if eol and eol <= today:
        status = "end-of-life"
    elif eoas and eoas <= today:
        status = "limited-support"
    elif eol or eoas:
        status = "supported"
    else:
        status = "unknown"
    return {**base, "status": status}


def fetch(product: str, http_get: Callable[..., dict]) -> dict:
    return http_get(ENDOFLIFE_API.format(product=product), {}, 30)


__all__ = ["ENDOFLIFE_API", "LIFECYCLE_PRODUCTS", "assess", "fetch", "release_cycle"]
