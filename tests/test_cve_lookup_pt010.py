"""PT-010: opt-in CVE lookup for the configured release (NVD API 2.0), no network."""

import json
from urllib.parse import parse_qs, urlsplit

import pytest

import src.advisories.nvd as nvd
from src.advisories.nvd import NVDClient, NVDError
from src.advisories.service import (
    AdvisoryRequest, lookup_software_advisories, select_cpe_names,
)
from src.advisories.versions import VersionUnavailable, product_version, split_cpe
from src.main import main
from tests.test_report_readability_pt005_007 import CORPUS

FORTIOS = CORPUS / "fortios" / "vulnerable.conf"  # FortiOS 7.4.6
CPE = "cpe:2.3:o:fortinet:fortios:7.4.6:*:*:*:*:*:*:*"


@pytest.mark.parametrize("device,version,expected", [
    ("FORTIOS", "7.4.6", ("fortios", "7.4.6", "")),
    ("JUNOS", "22.4R1.10", ("junos", "22.4", "r1")),
    ("JUNOS", "21.4R3-S2.3", ("junos", "21.4", "r3-s2")),
    ("JUNOS", "15.1X49-D200.5", ("junos", "15.1x49", "d200")),
    ("PAN_OS", "11.2.3", ("pan-os", "11.2.3", "")),
    ("PAN_OS", "10.2.9-h1", ("pan-os", "10.2.9", "h1")),
    ("ARISTA_EOS", "4.29.2F", ("eos", "4.29.2f", "")),
    ("ASA", "9.18(4)", ("adaptive_security_appliance_software", "9.18.4", "")),
    ("ASA", "9.18(4)22", ("adaptive_security_appliance_software", "9.18.4.22", "")),
    ("IOS_ROUTER", "15.2(4)M7", ("ios", "15.2(4)m7", "")),
    ("IOS_XE", "17.09.04a", ("ios_xe", "17.9.4a", "")),
    ("IOS_SWITCH", "16.12.4", ("ios_xe", "16.12.4", "")),
    ("SONICOS", "7.1.2-7019", ("sonicos", "7.1.2-7019", "")),
    ("F5_BIGIP", "16.1.5", ("big-ip_local_traffic_manager", "16.1.5", "")),
    ("SCREENOS", "6.3.0r27.0", ("screenos", "6.3.0", "r27")),
    ("HP_PROCURVE", "YA.16.10.0023", ("arubaos-switch", "16.10.0023", "")),
    ("HP_PROCURVE", "16.11.0005", ("arubaos-switch", "16.11.0005", "")),
])
def test_version_mapping(device, version, expected):
    target = product_version(device, version)
    assert (target.product, target.version, target.update) == expected


def test_cpe_escaping_round_trips():
    target = product_version("IOS_ROUTER", "15.2(4)M7")
    assert target.match_string() == "cpe:2.3:o:cisco:ios:15.2\\(4\\)m7"
    assert split_cpe(target.match_string())[5] == "15.2(4)m7"


@pytest.mark.parametrize("device,version,reason", [
    ("IOS_XE", "17.9", "imprecise-version"),
    ("IOS_ROUTER", "15.2", "imprecise-version"),
    ("FORTIOS", "?", "no-version"),
    ("CHECKPOINT_FW1", "unknown", "unsupported-family"),
    ("HP_PROCURVE", "K.15.18.0013", "unsupported-family"),
])
def test_imprecise_or_unsupported_versions_are_not_looked_up(device, version, reason):
    with pytest.raises(VersionUnavailable) as error:
        product_version(device, version)
    assert error.value.reason == reason
    advisories, status = lookup_software_advisories(device, version, AdvisoryRequest(online=True),
                                                    client_factory=_forbidden_client)
    assert advisories == [] and status["status"] == "unavailable"
    assert status["reason-code"] == reason


def _forbidden_client(**_):
    raise AssertionError("no request expected")


def _cve(cve_id, metrics, configurations, **extra):
    return {"cve": {"id": cve_id, "published": "2024-02-08T12:00:00.000", "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "es", "value": "x"}, {"lang": "en", "value": f"Issue {cve_id}."}],
                    "metrics": metrics, "configurations": configurations, **extra}}


OR_CONFIG = [{"nodes": [{"operator": "OR", "cpeMatch": [
    {"vulnerable": True, "criteria": "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
     "versionStartIncluding": "7.4.0", "versionEndExcluding": "7.4.7"}]}]}]
AND_CONFIG = [{"operator": "AND", "nodes": [
    {"operator": "OR", "cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:o:fortinet:fortios:7.4.6:*:*:*:*:*:*:*"}]},
    {"operator": "OR", "cpeMatch": [{"vulnerable": False, "criteria": "cpe:2.3:h:fortinet:fortigate-60f:-:*:*:*:*:*:*:*"}]},
]}]
CVES = [
    _cve("CVE-2024-0002", {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 5.3, "baseSeverity": "MEDIUM"}}]}, AND_CONFIG),
    _cve("CVE-2024-0003", {"cvssMetricV2": [{"type": "Primary", "baseSeverity": "HIGH", "cvssData": {"baseScore": 7.5}}]}, OR_CONFIG),
    _cve("CVE-2024-0001", {"cvssMetricV31": [{"type": "Secondary", "cvssData": {"baseScore": 9.1, "baseSeverity": "CRITICAL"}},
                                             {"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
         OR_CONFIG, cisaExploitAdd="2024-02-09", cisaVulnerabilityName="FortiOS Out-of-Bound Write"),
]
CPE_PRODUCTS = [
    {"cpe": {"cpeName": CPE, "deprecated": False}},
    {"cpe": {"cpeName": "cpe:2.3:o:fortinet:fortios:7.4.6:beta1:*:*:*:*:*:*", "deprecated": False}},
    {"cpe": {"cpeName": "cpe:2.3:o:fortinet:fortios:7.4.6:-:*:*:*:*:*:*", "deprecated": True}},
]


class FakeNVD:
    def __init__(self, products=CPE_PRODUCTS, cves=CVES, page=2, fail=None):
        self.products, self.cves, self.page, self.fail = products, cves, page, fail
        self.calls = []

    def __call__(self, url, headers, timeout):
        self.calls.append((url, headers, timeout))
        if self.fail:
            raise NVDError(self.fail)
        parts = urlsplit(url)
        query = parse_qs(parts.query, keep_blank_values=True)
        start = int(query["startIndex"][0])
        if parts.path.endswith("/cpes/2.0"):
            assert query["cpeMatchString"] == ["cpe:2.3:o:fortinet:fortios:7.4.6"]
            items, key = self.products, "products"
        else:
            assert query["cpeName"] == [CPE] and "isVulnerable" in parts.query.split("&")
            items, key = self.cves, "vulnerabilities"
        assert query["resultsPerPage"] == ["1000"]
        chunk = items[start:start + self.page]
        return {"resultsPerPage": len(chunk), "startIndex": start, "totalResults": len(items), key: chunk}


def _client(fake, sleeps=None):
    return lambda api_key=None: NVDClient(api_key=api_key, http_get=fake,
                                          sleep=(sleeps.append if sleeps is not None else lambda _: None),
                                          clock=lambda: 0.0)


def test_select_cpe_names_requires_exact_release_and_skips_deprecated():
    target = product_version("FORTIOS", "7.4.6")
    assert select_cpe_names(target, [{"products": CPE_PRODUCTS}]) == [CPE]
    junos = product_version("JUNOS", "22.4R1.10")
    pages = [{"products": [{"cpe": {"cpeName": "cpe:2.3:o:juniper:junos:22.4:r1:*:*:*:*:*:*"}},
                           {"cpe": {"cpeName": "cpe:2.3:o:juniper:junos:22.4:r1-s1:*:*:*:*:*:*"}},
                           {"cpe": {"cpeName": "cpe:2.3:o:juniper:junos:22.4:-:*:*:*:*:*:*"}}]}]
    assert select_cpe_names(junos, pages) == ["cpe:2.3:o:juniper:junos:22.4:r1:*:*:*:*:*:*"]


def test_online_lookup_pages_rate_limits_and_orders_results():
    fake, sleeps = FakeNVD(), []
    advisories, status = lookup_software_advisories(
        "FORTIOS", "7.4.6", AdvisoryRequest(online=True, api_key="secret-key"), client_factory=_client(fake, sleeps))
    assert [item.cve_id for item in advisories] == ["CVE-2024-0001", "CVE-2024-0003", "CVE-2024-0002"]
    kev, v2, conditional = advisories
    assert (kev.cvss, kev.severity, kev.cvss_version, kev.kev_date) == (9.8, "Critical", "3.1", "2024-02-09")
    assert (v2.cvss, v2.severity, v2.cvss_version, v2.known_exploited) == (7.5, "High", "2.0", False)
    assert conditional.conditional and not kev.conditional
    assert kev.summary == "Issue CVE-2024-0001." and kev.url.endswith("/CVE-2024-0001")
    assert status["status"] == "completed" and status["count"] == 3
    assert (status["known-exploited"], status["conditional"]) == (1, 1)
    assert status["cpe-names"] == [CPE] and status["version-origin"] == "configuration"
    # CPE: 2 pages of 2 items; CVE: 2 pages. The key goes in the header only.
    assert len(fake.calls) == 4
    assert all(headers == {"apiKey": "secret-key"} and "secret-key" not in url for url, headers, _ in fake.calls)
    assert sleeps == [0.7, 0.7, 0.7]
    assert "secret-key" not in json.dumps(status)


def test_release_missing_from_cpe_dictionary_is_not_reported_as_clean():
    advisories, status = lookup_software_advisories(
        "FORTIOS", "7.4.6", AdvisoryRequest(online=True), client_factory=_client(FakeNVD(products=[])))
    assert advisories == [] and status["status"] == "unavailable"
    assert status["reason-code"] == "not-in-cpe-dictionary"
    assert "not evidence" in status["reason"]


def test_network_failure_yields_error_status():
    advisories, status = lookup_software_advisories(
        "FORTIOS", "7.4.6", AdvisoryRequest(online=True), client_factory=_client(FakeNVD(fail="NVD returned HTTP 503")))
    assert advisories == [] and status["status"] == "error" and "503" in status["reason"]


def test_unexpected_document_is_an_error():
    client = NVDClient(http_get=lambda *_: {"message": "rate limited"}, sleep=lambda _: None)
    with pytest.raises(NVDError):
        client.cve_pages(CPE)


def _report(tmp_path, *extra, name="r.json"):
    output = tmp_path / name
    code = main(["-d", "fortios", "-i", str(FORTIOS), "-o", "JSON", "-f", str(output), *extra])
    return code, json.loads(output.read_text(encoding="utf-8")) if output.exists() else None


@pytest.fixture
def fake_network(monkeypatch):
    fake = FakeNVD()
    monkeypatch.setattr(nvd, "_requests_get", fake)
    monkeypatch.setattr(nvd, "_sleep", lambda _: None)
    return fake


def test_default_runs_make_no_request(tmp_path, fake_network):
    code, report = _report(tmp_path)
    assert code == 0 and fake_network.calls == []
    assert report["software-advisory-lookup"]["status"] == "not-requested"
    assert report["vulnerabilities"] == []


def test_cli_lookup_save_and_offline_replay(tmp_path, fake_network, monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "env-secret-key")
    bundle = tmp_path / "fortios-7.4.6.nvd.json"
    code, report = _report(tmp_path, "--cve-lookup", "--cve-save", str(bundle))
    assert code == 0 and len(fake_network.calls) == 4
    lookup = report["software-advisory-lookup"]
    assert lookup["status"] == "completed" and lookup["saved-bundle"] == bundle.name
    assert [item["cve"] for item in report["vulnerabilities"]] == ["CVE-2024-0001", "CVE-2024-0003", "CVE-2024-0002"]
    assert report["vulnerabilities"][0]["known-exploited"] is True
    assert "env-secret-key" not in json.dumps(report) + bundle.read_text(encoding="utf-8")

    calls = len(fake_network.calls)
    code, replay = _report(tmp_path, "-x", "--cve-data", str(bundle), name="replay.json")
    assert code == 0 and len(fake_network.calls) == calls
    assert replay["vulnerabilities"] == report["vulnerabilities"]
    assert replay["software-advisory-lookup"]["source"].startswith("Saved NVD bundle")

    code, other = _report(tmp_path, "-x", "--cve-data", str(bundle), "--software-version", "7.4.5", name="o.json")
    assert other["software-advisory-lookup"]["reason-code"] == "bundle-mismatch"
    assert other["vulnerabilities"] == []


def test_html_shows_status_kev_and_limitations(tmp_path, fake_network):
    output = tmp_path / "r.html"
    assert main(["-d", "fortios", "-i", str(FORTIOS), "-o", "HTML", "-f", str(output), "--cve-lookup"]) == 0
    html = output.read_text(encoding="utf-8")
    section = html.split('id="security-vulns"')[1].split("</section>")[0]
    assert "3 CVEs listed by NVD CVE API 2.0" in section
    assert "1 is in the CISA Known Exploited Vulnerabilities catalog" in section
    assert section.index("CVE-2024-0001") < section.index("CVE-2024-0003") < section.index("CVE-2024-0002")
    assert "KEV</span> added 2024-02-09" in section
    assert "another platform or component condition" in section
    assert "does not prove exploitability" in section


def test_html_default_explains_how_to_request(tmp_path):
    output = tmp_path / "r.html"
    assert main(["-d", "fortios", "-i", str(FORTIOS), "-o", "HTML", "-f", str(output), "-x"]) == 0
    assert "CVE lookup was not requested" in output.read_text(encoding="utf-8")


def test_train_only_version_needs_operator_release(tmp_path, fake_network):
    source = CORPUS / "cisco_iosxe" / "vulnerable.conf"
    output = tmp_path / "xe.json"
    assert main(["-d", "IOS_XE", "-i", str(source), "-o", "JSON", "-f", str(output), "--cve-lookup"]) == 0
    lookup = json.loads(output.read_text(encoding="utf-8"))["software-advisory-lookup"]
    assert lookup["reason-code"] == "imprecise-version" and "--software-version" in lookup["reason"]
    assert fake_network.calls == []


@pytest.mark.parametrize("args,message", [
    (["--cve-lookup", "-x"], "cannot be combined"),
    (["--cve-save", "x.json"], "requires --cve-lookup"),
    (["--software-version", "7.4.6"], "only used with"),
    (["--cve-data", "missing.json"], "does not exist"),
])
def test_cli_rejects_inconsistent_options(tmp_path, capsys, args, message):
    with pytest.raises(SystemExit):
        main(["-d", "fortios", "-i", str(FORTIOS), "-f", str(tmp_path / "r.html"), *args])
    assert message in capsys.readouterr().err


def test_cli_refuses_to_overwrite_a_bundle(tmp_path, capsys):
    existing = tmp_path / "b.json"
    existing.write_text("{}", encoding="utf-8")
    with pytest.raises(SystemExit):
        main(["-d", "fortios", "-i", str(FORTIOS), "-f", str(tmp_path / "r.html"),
              "--cve-lookup", "--cve-save", str(existing)])
    assert "new file" in capsys.readouterr().err


def test_tls_failure_explains_the_likely_cause(monkeypatch):
    import sys
    import types

    import requests

    calls = []
    fake_truststore = types.SimpleNamespace(
        inject_into_ssl=lambda: calls.append("inject"),
        extract_from_ssl=lambda: calls.append("extract"),
    )
    monkeypatch.setitem(sys.modules, "truststore", fake_truststore)

    def failing_get(*_, **__):
        calls.append("get")
        raise requests.exceptions.SSLError(
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate"
        )

    monkeypatch.setattr(requests, "get", failing_get)
    with pytest.raises(NVDError) as error:
        nvd._requests_get("https://services.nvd.nist.gov/rest/json/cpes/2.0?x=1", {}, 5)
    message = str(error.value)
    assert "CERTIFICATE_VERIFY_FAILED" in message and "REQUESTS_CA_BUNDLE" in message
    assert "--cve-data" in message
    # The OS trust store is used for the request and removed again afterwards.
    assert calls == ["inject", "get", "extract"]


def test_request_works_without_truststore(monkeypatch):
    import sys

    import requests

    monkeypatch.setitem(sys.modules, "truststore", None)  # import fails
    response = type("R", (), {"status_code": 200, "json": lambda self: {"totalResults": 0}})()
    monkeypatch.setattr(requests, "get", lambda *_, **__: response)
    assert nvd._requests_get("https://example.invalid", {}, 5) == {"totalResults": 0}


REAL = CORPUS.parent / "advisories" / "nvd_cve_2024_21762.json"
REAL_CPE = "cpe:2.3:o:fortinet:fortios:6.4.2:*:*:*:*:*:*:*"


def _real_nvd(empty_first=False):
    """Serves the recorded NVD shapes for FortiOS 6.4.2 (retrieved 2026-09-25)."""
    calls = []

    def get(url, headers, timeout):
        calls.append(url)
        query = parse_qs(urlsplit(url).query, keep_blank_values=True)
        assert query["resultsPerPage"] == ["1000"]
        if "/cpes/" in url:
            return {"resultsPerPage": 1, "startIndex": 0, "totalResults": 1, "format": "NVD_CPE",
                    "products": [{"cpe": {"deprecated": False, "cpeName": REAL_CPE}}]}
        if empty_first:
            # What NVD returned for resultsPerPage=2000 or the default page size.
            return {"resultsPerPage": 0, "startIndex": 0, "totalResults": 134, "vulnerabilities": []}
        return json.loads(REAL.read_text(encoding="utf-8"))

    return get, calls


def test_recorded_nvd_record_for_fortios_642():
    get, calls = _real_nvd()
    advisories, status = lookup_software_advisories(
        "FORTIOS", "6.4.2", AdvisoryRequest(online=True),
        client_factory=lambda api_key=None: NVDClient(http_get=get, sleep=lambda _: None),
    )
    assert status["status"] == "completed" and status["cpe-names"] == [REAL_CPE]
    advisory, = advisories
    assert (advisory.cve_id, advisory.cvss, advisory.severity, advisory.kev_date) == (
        "CVE-2024-21762", 9.8, "Critical", "2024-02-09")
    assert not advisory.conditional  # a plain OR node with version ranges


def test_empty_page_with_results_is_an_error_not_zero_cves():
    get, _ = _real_nvd(empty_first=True)
    advisories, status = lookup_software_advisories(
        "FORTIOS", "6.4.2", AdvisoryRequest(online=True),
        client_factory=lambda api_key=None: NVDClient(http_get=get, sleep=lambda _: None),
    )
    assert advisories == [] and status["status"] == "error"
    assert "reported 134 results but returned none" in status["reason"]



def test_aos_s_uses_the_hpe_vendor_name():
    assert product_version("HP_PROCURVE", "WC.16.10.0025").match_string() == "cpe:2.3:o:hpe:arubaos-switch:16.10.0025"


def test_f5_queries_every_provisioned_module():
    from src.advisories.versions import product_versions

    targets = product_versions("F5_BIGIP", "16.1.5", {"ltm": "nominal", "asm": "nominal", "afm": "none", "ilx": "nominal"})
    assert [t.product for t in targets] == [
        "big-ip_local_traffic_manager", "big-ip_application_security_manager"]
    assert "application_security_manager" in targets[0].note and "ilx" in targets[0].note
    only_ltm = product_versions("F5_BIGIP", "16.1.5", None)
    assert [t.product for t in only_ltm] == ["big-ip_local_traffic_manager"]
    assert "no sys provision data" in only_ltm[0].note


def test_f5_module_lookup_merges_and_deduplicates(tmp_path):
    ltm = "cpe:2.3:a:f5:big-ip_local_traffic_manager:16.1.5:*:*:*:*:*:*:*"
    asm = "cpe:2.3:a:f5:big-ip_application_security_manager:16.1.5:*:*:*:*:*:*:*"
    record = {"cve": {"id": "CVE-2023-46747", "descriptions": [{"lang": "en", "value": "x"}], "metrics": {},
                      "configurations": []}}
    only_asm = {"cve": {"id": "CVE-2024-0001", "descriptions": [{"lang": "en", "value": "y"}], "metrics": {},
                        "configurations": []}}

    def get(url, headers, timeout):
        query = parse_qs(urlsplit(url).query, keep_blank_values=True)
        if "/cpes/" in url:
            name = ltm if "local_traffic" in query["cpeMatchString"][0] else asm
            return {"resultsPerPage": 1, "startIndex": 0, "totalResults": 1, "products": [{"cpe": {"cpeName": name}}]}
        items = [record] if query["cpeName"] == [ltm] else [record, only_asm]
        return {"resultsPerPage": len(items), "startIndex": 0, "totalResults": len(items), "vulnerabilities": items}

    bundle = tmp_path / "f5.nvd.json"
    advisories, status = lookup_software_advisories(
        "F5_BIGIP", "16.1.5", AdvisoryRequest(online=True, save_path=str(bundle)),
        client_factory=lambda api_key=None: NVDClient(http_get=get, sleep=lambda _: None),
        modules={"ltm": "nominal", "asm": "nominal"},
    )
    assert status["status"] == "completed" and status["count"] == 2
    shared = next(item for item in advisories if item.cve_id == "CVE-2023-46747")
    assert shared.matched_cpe == (ltm, asm)
    # Replaying needs the same module set.
    replay, replay_status = lookup_software_advisories(
        "F5_BIGIP", "16.1.5", AdvisoryRequest(bundle_path=str(bundle)), modules={"ltm": "nominal", "asm": "nominal"})
    assert [item.cve_id for item in replay] == [item.cve_id for item in advisories]
    _, mismatch = lookup_software_advisories(
        "F5_BIGIP", "16.1.5", AdvisoryRequest(bundle_path=str(bundle)), modules={"ltm": "nominal"})
    assert mismatch["reason-code"] == "bundle-mismatch"


def test_version_1_bundles_are_still_read(tmp_path):
    bundle = tmp_path / "old.nvd.json"
    bundle.write_text(json.dumps({
        "format": "pynipper-nvd-bundle", "format-version": 1, "retrieved-at": "2026-09-25T00:00:00+00:00",
        "product": product_version("FORTIOS", "6.4.2").to_dict(), "cpe-names": [REAL_CPE],
        "cve-pages": {REAL_CPE: [json.loads(REAL.read_text(encoding="utf-8"))]},
    }), encoding="utf-8")
    advisories, status = lookup_software_advisories("FORTIOS", "6.4.2", AdvisoryRequest(bundle_path=str(bundle)))
    assert status["status"] == "completed" and [a.cve_id for a in advisories] == ["CVE-2024-21762"]
