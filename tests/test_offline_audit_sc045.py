"""Public audit paths must not acquire advisory data or resolve network names."""
import json
import socket
from pathlib import Path

import pytest
import requests

from src.main import main
from src.devices import DEVICE_REGISTRY
from src.advisories import AdvisoryRequest, software_advisories

CORPUS = Path(__file__).parent / "test_data" / "regression"
CASES = json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))["cases"]


@pytest.fixture
def prohibit_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Configuration audit attempted network access")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(requests.sessions.Session, "request", forbidden)


@pytest.mark.parametrize("device", list(DEVICE_REGISTRY))
@pytest.mark.parametrize("format", ["JSON", "HTML"])
def test_every_device_audits_offline_by_default(tmp_path, prohibit_network, device, format):
    family = {"IOS_SWITCH": "IOS_ROUTER", "IOS_CATALYST": "IOS_ROUTER", "PIX": "ASA"}.get(device, device)
    case = next(item for item in CASES if item["device"] == family)
    config = tmp_path / "credentials.conf"
    config.write_text("[Cisco]\nCLIENT_ID = fake-id\nCLIENT_SECRET = fake-secret\n", encoding="utf-8")
    output = tmp_path / ("report." + format.lower())
    assert main(["-d", device, "-i", str(CORPUS / case["input"]), "-c", str(config),
                 "-f", str(output), "-o", format]) == 0
    assert output.is_file()
    if format == "JSON":
        assert json.loads(output.read_text(encoding="utf-8"))["software-advisory-lookup"]["status"] == "not-requested"


@pytest.mark.parametrize("body", [None, "[]", "{}", "invalid-json"])
def test_bad_or_missing_local_bundle_still_produces_report(tmp_path, prohibit_network, body):
    bundle = tmp_path / "bundle.json"
    if body is not None:
        bundle.write_text(body, encoding="utf-8")
    output = tmp_path / "report.json"
    assert main(["-d", "fortios", "-i", str(CORPUS / "fortios/vulnerable.conf"),
                 "--cve-data", str(bundle), "-o", "JSON", "-f", str(output), "-x"]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["software-advisory-lookup"]["status"] in {"error", "unavailable"}
    assert report["security-audit"]


def test_analyzer_boundary_rejects_online_request(prohibit_network):
    advisories, status = software_advisories("FORTIOS", object(), AdvisoryRequest(online=True))
    assert advisories == []
    assert status["reason-code"] == "offline-audit"
