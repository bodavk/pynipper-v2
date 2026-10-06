"""SC-050: offline batch audits and assessment-set comparison."""

import json
import os
import shutil
import socket

import pytest

from src.batch import BatchError, compare_batches, load_manifest, main, run_batch

CORPUS = "tests/test_data/regression"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("batch attempted network access")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)


def _manifest(tmp_path, devices, name="batch.json"):
    path = tmp_path / name
    path.write_text(json.dumps({"schema-version": 1, "devices": devices}), encoding="utf-8")
    return str(path)


def _copy(tmp_path, source, target):
    destination = tmp_path / target
    if os.path.isdir(source):
        shutil.copytree(source, destination)
    else:
        shutil.copyfile(source, destination)
    return target


def test_mixed_family_batch_with_directory_artifact(tmp_path):
    inputs = [
        {"id": "fw-forti", "input": _copy(tmp_path, f"{CORPUS}/fortios/vulnerable.conf", "forti.conf")},
        {"id": "pan", "input": _copy(tmp_path, f"{CORPUS}/panos/vulnerable.xml", "pan.xml"), "device": "PAN_OS"},
        {"id": "cp-fw1", "input": _copy(tmp_path, f"{CORPUS}/checkpoint_fw1/vulnerable", "fw1"), "device": "CHECKPOINT_FW1"},
    ]
    index = run_batch(_manifest(tmp_path, inputs), str(tmp_path / "out"))
    statuses = {device["id"]: device for device in index["devices"]}
    assert [device["id"] for device in index["devices"]] == ["cp-fw1", "fw-forti", "pan"]
    assert all(device["status"] == "audited" and device["finding-count"] > 0 for device in statuses.values())
    assert statuses["pan"]["finding-count"] == 24
    assert len(statuses["fw-forti"]["input-sha256"]) == 64 and index["analyzer-fingerprint"]
    assert (tmp_path / "out" / "batch-index.json").exists()
    report = json.loads((tmp_path / "out" / "pan.json").read_text(encoding="utf-8"))
    assert "security-audit" in report and "attack-paths" in report


def test_one_device_failure_is_isolated(tmp_path):
    (tmp_path / "garbage.txt").write_text("not a configuration\n", encoding="utf-8")
    inputs = [
        {"id": "ok", "input": _copy(tmp_path, f"{CORPUS}/cisco_asa/vulnerable.conf", "asa.conf")},
        {"id": "bad", "input": "garbage.txt"},
        {"id": "gone", "input": "missing.conf", "device": "ASA"},
    ]
    index = run_batch(_manifest(tmp_path, inputs), str(tmp_path / "out"))
    status = {d["id"]: d["status"] for d in index["devices"]}
    assert status == {"ok": "audited", "bad": "error", "gone": "error"}


@pytest.mark.parametrize("devices,message", [
    ([{"id": "a", "input": "x"}, {"id": "A", "input": "y"}], "Duplicate device id"),
    ([{"id": "a", "input": "x"}, {"id": "b", "input": "./x"}], "Input used twice"),
    ([{"id": "../evil", "input": "x"}], "needs an \"id\""),
    ([{"id": "a", "input": "x", "password": "p"}], "unknown fields"),
    ([], "non-empty"),
])
def test_malformed_manifest_is_rejected(tmp_path, devices, message):
    with pytest.raises(BatchError, match=message):
        load_manifest(_manifest(tmp_path, devices))


def test_outputs_are_never_overwritten_and_never_inside_inputs(tmp_path):
    inputs = [{"id": "asa", "input": _copy(tmp_path, f"{CORPUS}/cisco_asa/secure.conf", "asa.conf")}]
    manifest = _manifest(tmp_path, inputs)
    run_batch(manifest, str(tmp_path / "out"))
    with pytest.raises(BatchError, match="already exist"):
        run_batch(manifest, str(tmp_path / "out"))
    run_batch(manifest, str(tmp_path / "out"), overwrite=True)
    (tmp_path / "dir").mkdir()
    shutil.copytree(f"{CORPUS}/checkpoint_fw1/secure", tmp_path / "dir" / "fw1")
    with pytest.raises(BatchError, match="must not contain"):
        run_batch(_manifest(tmp_path, [{"id": "c", "input": "dir/fw1", "device": "CHECKPOINT_FW1"}], "m2.json"),
                  str(tmp_path / "dir" / "fw1" / "reports"))


def _two_sets(tmp_path, old_source, new_source, new_policy=None, device="ASA"):
    for label, source in (("old", old_source), ("new", new_source)):
        folder = tmp_path / label
        folder.mkdir()
        shutil.copyfile(source, folder / "dev.conf")
        entry = {"id": "dev", "input": "dev.conf", "device": device}
        if label == "new" and new_policy is not None:
            (folder / "policy.json").write_text(json.dumps(new_policy), encoding="utf-8")
            entry["assessment-policy"] = "policy.json"
        run_batch(_manifest(folder, [entry]), str(folder / "out"))
    return compare_batches(str(tmp_path / "old/out/batch-index.json"), str(tmp_path / "new/out/batch-index.json"))


def test_fixed_findings_are_resolved_only_on_same_rules_and_policy(tmp_path):
    result = _two_sets(tmp_path, f"{CORPUS}/cisco_asa/vulnerable.conf", f"{CORPUS}/cisco_asa/secure.conf")
    assert result["same-analyzer"] is True
    assert result["totals"]["resolved"] == 24 and result["totals"]["new"] == 0
    reverse = compare_batches(str(tmp_path / "new/out/batch-index.json"), str(tmp_path / "old/out/batch-index.json"))
    assert reverse["totals"]["new"] == 24 and reverse["totals"]["resolved"] == 0


def test_changed_policy_or_exclusion_is_not_remediation(tmp_path):
    result = _two_sets(tmp_path, f"{CORPUS}/cisco_asa/vulnerable.conf", f"{CORPUS}/cisco_asa/vulnerable.conf",
                       new_policy={"excluded_categories": ["snmp", "ntp", "logging"]})
    assert result["totals"]["resolved"] == 0
    device = result["devices"][0]
    assert any("assessment policy changed" in note for note in device["notes"])
    assert device["no-longer-assessable"]


def test_missing_or_failed_new_audit_is_not_remediation(tmp_path):
    (tmp_path / "old").mkdir()
    shutil.copyfile(f"{CORPUS}/cisco_asa/vulnerable.conf", tmp_path / "old" / "dev.conf")
    run_batch(_manifest(tmp_path / "old", [{"id": "dev", "input": "dev.conf", "device": "ASA"}]), str(tmp_path / "old/out"))
    (tmp_path / "new").mkdir()
    run_batch(_manifest(tmp_path / "new", [{"id": "dev", "input": "nothing.conf", "device": "ASA"}]), str(tmp_path / "new/out"))
    result = compare_batches(str(tmp_path / "old/out/batch-index.json"), str(tmp_path / "new/out/batch-index.json"))
    assert result["totals"]["resolved"] == 0 and result["totals"]["no-longer-assessable"] == 24


def test_public_cli_run_and_compare(tmp_path, capsys):
    (tmp_path / "set").mkdir()
    shutil.copyfile(f"{CORPUS}/fortios/secure.conf", tmp_path / "set" / "f.conf")
    manifest = _manifest(tmp_path / "set", [{"id": "f", "input": "f.conf"}])
    assert main(["run", "--manifest", manifest, "--output-dir", str(tmp_path / "a")]) == 0
    assert main(["run", "--manifest", manifest, "--output-dir", str(tmp_path / "b"), "--html"]) == 0
    assert (tmp_path / "b" / "f.html").exists()
    output = tmp_path / "cmp.json"
    assert main(["compare", "--old", str(tmp_path / "a/batch-index.json"),
                 "--new", str(tmp_path / "b/batch-index.json"), "--output", str(output)]) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["totals"]["resolved"] == 0
    assert main(["compare", "--old", str(tmp_path / "a/batch-index.json"),
                 "--new", str(tmp_path / "b/batch-index.json"), "--output", str(output)]) == 2


def test_compare_html_output_escapes_values(tmp_path):
    result = _two_sets(tmp_path, f"{CORPUS}/cisco_asa/vulnerable.conf", f"{CORPUS}/cisco_asa/secure.conf")
    from src.batch import comparison_html
    result["devices"][0]["notes"].append("<script>alert(1)</script>")
    html = comparison_html(result)
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "resolved" in html and "cisco.asa." in html
    output = tmp_path / "cmp.html"
    assert main(["compare", "--old", str(tmp_path / "old/out/batch-index.json"),
                 "--new", str(tmp_path / "new/out/batch-index.json"), "--output", str(output)]) == 0
    assert output.read_text(encoding="utf-8").startswith("<!doctype html>")
