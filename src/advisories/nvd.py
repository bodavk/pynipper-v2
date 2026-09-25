"""Small NVD API 2.0 client (PT-010).

Uses the CPE API to confirm that the exact product release exists in the
official CPE dictionary, then the CVE API with ``cpeName`` and
``isVulnerable`` so NVD applies its own version-range matching. Requests are
rate limited (about one per six seconds without an API key) and time out. The
HTTP function is injectable so tests never use the network.
"""

from __future__ import annotations

import time
from typing import Callable, Optional
from urllib.parse import urlencode

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
# NVD documents a maximum of 2000, but on 2026-09-25 a request for exactly 2000
# (and the default, which is 2000) returned an empty page with a non-zero
# totalResults. 1000 returned the full result set.
PAGE_SIZE = 1000
TIMEOUT_SECONDS = 30
MAX_PAGES = 20


_sleep = time.sleep


class NVDError(RuntimeError):
    """A request to NVD failed or returned an unexpected document."""


_TLS_HINT = (
    "The HTTPS certificate of NVD could not be verified. This usually means a proxy, firewall "
    "or antivirus inspects HTTPS with its own certificate authority. Install the requirements "
    "again (pynipper uses the 'truststore' package to trust the operating-system certificate "
    "store), or set REQUESTS_CA_BUNDLE to your organization's CA file. Alternatively, save a "
    "bundle on a machine that can reach NVD and use --cve-data."
)


def _tls_reason(error: BaseException) -> str:
    """A short, secret-free reason such as CERTIFICATE_VERIFY_FAILED."""

    text = str(error)
    for marker in ("CERTIFICATE_VERIFY_FAILED", "WRONG_VERSION_NUMBER", "UNEXPECTED_EOF",
                   "TLSV1_ALERT", "hostname mismatch", "self-signed certificate",
                   "unable to get local issuer certificate", "certificate has expired"):
        if marker.casefold() in text.casefold():
            return marker
    return type(error).__name__


def _requests_get(url: str, headers: dict, timeout: int) -> dict:
    import requests  # imported lazily: offline runs never need it

    # Verify NVD's certificate against the operating-system trust store when the
    # optional 'truststore' package is present, so HTTPS inspection CAs that the
    # organization installed in Windows/macOS are honored. The injection is undone
    # after the request.
    try:
        import truststore
    except ImportError:
        truststore = None
    if truststore is not None:
        truststore.inject_into_ssl()
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
    except requests.exceptions.SSLError as error:
        raise NVDError(f"NVD request failed: TLS verification error ({_tls_reason(error)}). {_TLS_HINT}") from None
    except requests.exceptions.ProxyError:
        raise NVDError("NVD request failed: the configured HTTP(S) proxy refused or could not reach NVD") from None
    except requests.exceptions.Timeout:
        raise NVDError("NVD request failed: the request timed out") from None
    except requests.RequestException as error:
        raise NVDError(f"NVD request failed: {type(error).__name__}") from None
    finally:
        if truststore is not None:
            truststore.extract_from_ssl()
    if response.status_code != 200:
        raise NVDError(f"NVD returned HTTP {response.status_code}")
    try:
        return response.json()
    except ValueError:
        raise NVDError("NVD returned a response that is not JSON") from None


class NVDClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        http_get: Optional[Callable[[str, dict, int], dict]] = None,
        sleep: Optional[Callable[[float], None]] = None,
        clock: Optional[Callable[[], float]] = None,
    ):
        self._headers = {"apiKey": api_key} if api_key else {}
        self._interval = 0.7 if api_key else 6.0
        # Resolved at construction so tests can replace the module-level functions.
        self._http_get = http_get or _requests_get
        self._sleep = sleep or _sleep
        self._clock = clock or time.monotonic
        self._last: Optional[float] = None
        self.requests_made = 0

    def _get(self, base: str, params: dict, flags: tuple[str, ...] = ()) -> dict:
        if self._last is not None:
            wait = self._interval - (self._clock() - self._last)
            if wait > 0:
                self._sleep(wait)
        query = urlencode(params)
        if flags:
            query = "&".join([query, *flags])
        self._last = self._clock()
        self.requests_made += 1
        document = self._http_get(f"{base}?{query}", dict(self._headers), TIMEOUT_SECONDS)
        if not isinstance(document, dict) or "totalResults" not in document:
            raise NVDError("NVD returned an unexpected document")
        return document

    def _pages(self, base: str, params: dict, flags: tuple[str, ...] = ()) -> list[dict]:
        pages = []
        start = 0
        while True:
            page = self._get(base, {**params, "resultsPerPage": PAGE_SIZE, "startIndex": start}, flags)
            returned = int(page.get("resultsPerPage") or 0)
            total = int(page.get("totalResults") or 0)
            if returned == 0 and total > start:
                # Never turn an empty page into "no CVEs".
                raise NVDError(
                    f"NVD reported {total} results but returned none (startIndex {start}); "
                    "the lookup is incomplete, try again later"
                )
            pages.append(page)
            start += returned
            if start >= int(page.get("totalResults") or 0) or not page.get("resultsPerPage"):
                return pages
            if len(pages) >= MAX_PAGES:
                raise NVDError("NVD result set is larger than this tool accepts")

    def cpe_pages(self, match_string: str) -> list[dict]:
        return self._pages(NVD_CPE_URL, {"cpeMatchString": match_string})

    def cve_pages(self, cpe_name: str) -> list[dict]:
        return self._pages(NVD_CVE_URL, {"cpeName": cpe_name}, ("isVulnerable",))


__all__ = ["NVDClient", "NVDError", "NVD_CPE_URL", "NVD_CVE_URL"]
