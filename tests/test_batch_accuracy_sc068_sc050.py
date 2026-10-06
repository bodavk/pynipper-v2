"""Synthetic offline reproductions; no original export is modified."""
import hashlib
import json
import os
import socket
import subprocess

import pytest

from src.batch import BatchError, compare_batches, comparison_html, main, run_batch


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Network access during an offline audit")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    import requests
    monkeypatch.setattr(requests.sessions.Session, "request", forbidden)


def manifest(folder, devices, name="manifest.json", **extra):
    path = folder / name
    path.write_text(json.dumps({"schema-version": 1, "devices": devices, **extra}), encoding="utf-8")
    return path


def snapshot(folder):
    return {str(p.relative_to(folder)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in folder.rglob("*") if p.is_file()}


@pytest.mark.parametrize("html", [False, True])
@pytest.mark.parametrize("overwrite", [False, True])
def test_exact_export_collision_is_preflight_failure(tmp_path, html, overwrite):
    (tmp_path / "fw.json").write_text("ASA Version 9.22\nhostname synthetic\n", encoding="utf-8")
    m = manifest(tmp_path, [{"id": "fw", "input": "fw.json", "device": "ASA"}])
    before = snapshot(tmp_path)
    with pytest.raises(BatchError):
        run_batch(str(m), str(tmp_path), html=html, overwrite=overwrite)
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize("kind", ["other-input", "manifest", "policy", "bundle", "directory", "index", "input-as-dir"])
def test_all_artifacts_and_duplicate_index_are_protected(tmp_path, kind):
    (tmp_path / "input.conf").write_text("ASA Version 9.22\nhostname synthetic\n", encoding="utf-8")
    devices = [{"id": "fw", "input": "input.conf", "device": "ASA"}]
    extra, name, out = {}, "manifest.json", tmp_path
    if kind == "other-input":
        (tmp_path / "fw.json").write_text("ASA Version 9.22\nhostname other\n", encoding="utf-8")
        devices.append({"id": "other", "input": "fw.json", "device": "ASA"})
    elif kind == "manifest":
        name = "fw.json"
    elif kind == "policy":
        (tmp_path / "fw.json").write_text("{}", encoding="utf-8")
        devices[0]["assessment-policy"] = "fw.json"
    elif kind == "bundle":
        (tmp_path / "fw.json").write_text("{}", encoding="utf-8")
        extra["advisory-bundle"] = "fw.json"
    elif kind == "directory":
        (tmp_path / "export").mkdir()
        (tmp_path / "export/objects.C").write_text("synthetic objects", encoding="utf-8")
        devices[0].update(input="export", device="CHECKPOINT_FW1")
        out = tmp_path / "export/reports"
    elif kind == "index":
        devices[0]["id"] = "batch-index"
        out = tmp_path / "new-reports"
    else:
        out = tmp_path / "input.conf"
    m = manifest(tmp_path, devices, name, **extra)
    before = snapshot(tmp_path)
    with pytest.raises(BatchError):
        run_batch(str(m), str(out), html=True, overwrite=True)
    assert snapshot(tmp_path) == before
    if kind in {"directory", "index"}:
        assert not out.exists()


@pytest.mark.parametrize("alias", ["hardlink", "symlink", "case"])
def test_existing_output_alias_cannot_replace_input(tmp_path, alias):
    source = tmp_path / "INPUT.conf"
    source.write_text("ASA Version 9.22\nhostname synthetic\n", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    target = out / "fw.json"
    if alias == "case":
        if os.name != "nt":
            pytest.skip("Case aliases require a case-insensitive Windows filesystem")
        devices = [{"id": "fw", "input": "out/FW.JSON", "device": "ASA"}]
        target.write_bytes(source.read_bytes())
    else:
        try:
            os.link(source, target) if alias == "hardlink" else target.symlink_to(source)
        except OSError as error:
            pytest.skip(f"Filesystem does not permit {alias} creation: {error.__class__.__name__}")
        devices = [{"id": "fw", "input": source.name, "device": "ASA"}]
    m = manifest(tmp_path, devices)
    (out / "unchanged.json").write_text("existing output", encoding="utf-8")
    before = snapshot(tmp_path)
    with pytest.raises(BatchError):
        run_batch(str(m), str(out), overwrite=True)
    assert snapshot(tmp_path) == before


def test_hardlinked_directory_member_is_protected(tmp_path):
    export = tmp_path / "export"
    export.mkdir()
    source = export / "objects.C"
    source.write_text("synthetic directory member", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    try:
        os.link(source, out / "fw.json")
    except OSError as error:
        pytest.skip(f"Filesystem does not support hard links: {error.__class__.__name__}")
    m = manifest(tmp_path, [{"id": "fw", "input": "export", "device": "CHECKPOINT_FW1"}])
    before = snapshot(tmp_path)
    with pytest.raises(BatchError):
        run_batch(str(m), str(out), overwrite=True)
    assert snapshot(tmp_path) == before


def test_output_directory_symlink_alias_is_protected(tmp_path):
    export = tmp_path / "export"
    export.mkdir()
    try:
        (tmp_path / "alias").symlink_to(export, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"Filesystem does not permit directory symlinks: {error.__class__.__name__}")
    m = manifest(tmp_path, [{"id": "fw", "input": "export", "device": "CHECKPOINT_FW1"}])
    before = snapshot(tmp_path)
    with pytest.raises(BatchError):
        run_batch(str(m), str(tmp_path / "alias/reports"), overwrite=True)
    assert snapshot(tmp_path) == before
    assert not (export / "reports").exists()


@pytest.mark.skipif(os.name != "nt", reason="Directory junctions are Windows filesystem objects")
def test_windows_junction_export_alias_is_protected(tmp_path):
    export = tmp_path / "export"
    export.mkdir()
    alias = tmp_path / "junction"
    created = subprocess.run(["cmd", "/c", "mklink", "/J", str(alias), str(export)],
                             capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    if created.returncode:
        pytest.skip("Windows filesystem does not permit creating a test directory junction")
    m = manifest(tmp_path, [{"id": "fw", "input": "export", "device": "CHECKPOINT_FW1"}])
    before = snapshot(tmp_path)
    with pytest.raises(BatchError):
        run_batch(str(m), str(alias / "reports"), overwrite=True)
    assert snapshot(tmp_path) == before and not (export / "reports").exists()


def test_optional_html_destination_is_also_protected(tmp_path):
    (tmp_path / "fw.html").write_text("ASA Version 9.22\nhostname synthetic\n", encoding="utf-8")
    m = manifest(tmp_path, [{"id": "fw", "input": "fw.html", "device": "ASA"}])
    before = snapshot(tmp_path)
    with pytest.raises(BatchError):
        run_batch(str(m), str(tmp_path), html=True, overwrite=True)
    assert snapshot(tmp_path) == before


def test_uninspectable_identity_fails_before_output_creation(tmp_path, monkeypatch):
    from pathlib import Path
    source = tmp_path / "input.conf"
    source.write_text("ASA Version 9.22\nhostname synthetic\n", encoding="utf-8")
    m = manifest(tmp_path, [{"id": "fw", "input": source.name, "device": "ASA"}])
    before = snapshot(tmp_path)
    original = Path.stat
    with monkeypatch.context() as patch:
        def inaccessible(path, *args, **kwargs):
            if path == source:
                raise PermissionError("do not expose raw details")
            return original(path, *args, **kwargs)
        patch.setattr(Path, "stat", inaccessible)
        with pytest.raises(BatchError, match="safety could not be established"):
            run_batch(str(m), str(tmp_path / "new-reports"), overwrite=True)
    assert snapshot(tmp_path) == before and not (tmp_path / "new-reports").exists()


def test_duplicate_existing_target_identity_is_rejected(tmp_path):
    for name in ("a", "b"):
        (tmp_path / f"{name}.conf").write_text("ASA Version 9.22\nhostname synthetic\n", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    (out / "a.json").write_text("existing report", encoding="utf-8")
    try:
        os.link(out / "a.json", out / "b.json")
    except OSError as error:
        pytest.skip(f"Filesystem does not support hard links: {error.__class__.__name__}")
    m = manifest(tmp_path, [{"id": n, "input": f"{n}.conf", "device": "ASA"} for n in ("a", "b")])
    before = snapshot(tmp_path)
    with pytest.raises(BatchError):
        run_batch(str(m), str(out), overwrite=True)
    assert snapshot(tmp_path) == before


def test_public_collision_error_and_legitimate_same_directory_overwrite(tmp_path, capsys):
    source = tmp_path / "input.conf"
    source.write_text("ASA Version 9.22\nhostname synthetic\n", encoding="utf-8")
    m = manifest(tmp_path, [{"id": "fw", "input": source.name, "device": "ASA"}])
    before = source.read_bytes()
    assert main(["run", "--manifest", str(m), "--output-dir", str(tmp_path), "--html"]) == 0
    assert main(["run", "--manifest", str(m), "--output-dir", str(tmp_path), "--html", "--overwrite"]) == 0
    assert source.read_bytes() == before
    bad = manifest(tmp_path, [{"id": "input", "input": "input.json", "device": "ASA"}], "bad.json")
    saved = snapshot(tmp_path)
    assert main(["run", "--manifest", str(bad), "--output-dir", str(tmp_path), "--overwrite"]) == 2
    assert snapshot(tmp_path) == saved
    assert "hostname synthetic" not in capsys.readouterr().err


def finding(rule="paloalto.panos.policy.security_profiles", evidence="rule A"):
    return {"rule_id": rule, "severity": "High", "title": "<unsafe>", "evidence": [evidence]}


def supplied_sets(folder, old_report, new_report, old_family="PAN_OS", new_family="PAN_OS",
                  fingerprint="a" * 64, policy=None):
    paths = []
    for label, report, family in (("old", old_report, old_family), ("new", new_report, new_family)):
        directory = folder / label
        directory.mkdir()
        (directory / "dev.json").write_text(json.dumps(report), encoding="utf-8")
        record = {"id": "dev", "status": "audited", "device": family, "report": "dev.json"}
        if policy is not None:
            record["assessment-policy"] = policy
        index = directory / "batch-index.json"
        index.write_text(json.dumps({"schema-version": 1, "analyzer-fingerprint": fingerprint,
                                    "devices": [record]}), encoding="utf-8")
        paths.append(index)
    return paths


def report(findings=(), controls=()):
    return {"security-audit": {str(i): f for i, f in enumerate(findings)},
            "coverage": {"controls": {"results": list(controls)}}}


@pytest.mark.parametrize("signal", ["all", "instances", "unassessed-instances", "unassessed-instance-count"])
def test_mixed_instance_unknown_never_resolves_disappeared_finding(tmp_path, signal):
    control = {"control-id": "inspection", "rule-ids": ["paloalto.panos.policy.security_profiles"],
               "outcome": "finding", "instances": [
                   {"instance-key": "A", "outcome": "unknown"},
                   {"instance-key": "B", "outcome": "finding"}],
               "unassessed-instances": [{"instance-key": "A", "reasons": ["Unexported group"]}],
               "unassessed-instance-count": 1}
    if signal != "all":
        for field in ("instances", "unassessed-instances", "unassessed-instance-count"):
            if field != signal:
                control.pop(field)
    old = report([finding(evidence="rule A"), finding(evidence="rule B"), finding("other.control", "unrelated")])
    new = report([finding(evidence="rule B")], [control])
    paths = supplied_sets(tmp_path, old, new)
    result = compare_batches(*(str(p) for p in paths))
    assert result["totals"]["no-longer-assessable"] == 1
    assert result["totals"]["unchanged"] == 1
    assert result["totals"]["resolved"] == 1
    assert result["devices"][0]["resolved"][0]["rule-id"] == "other.control"
    assert any("instance" in n for n in result["devices"][0]["notes"])
    rendered = comparison_html(result)
    assert "no-longer-assessable" in rendered and "&lt;unsafe&gt;" in rendered and "<unsafe>" not in rendered


@pytest.mark.parametrize("old_family,new_family,comparable", [
    ("PAN_OS", "IOS_ROUTER", False), ("PIX", "ASA", False),
    ("CHECKPOINT_FW1", "CHECKPOINT_GAIA", False), ("IOS_XE", "IOS_ROUTER", False),
    ("CISCO_ASA", "ASA", True), ("CISCO_IOS", "IOS_ROUTER", True),
    ("pan-os", "PAN_OS", True), (None, "ASA", False), ("unknown", "unknown", False),
])
def test_comparison_requires_canonical_family(tmp_path, old_family, new_family, comparable):
    paths = supplied_sets(tmp_path, report([finding()]), report([finding("current.rule")]), old_family, new_family)
    result = compare_batches(*(str(p) for p in paths))
    assert result["totals"]["resolved"] == int(comparable)
    assert result["totals"]["not-comparable"] == int(not comparable)
    assert result["totals"]["new"] == 1
    if not comparable:
        assert any("family" in n for n in result["devices"][0]["notes"])


@pytest.mark.parametrize("fingerprint", [None, "", "unknown", "not-a-hash"])
def test_absent_or_invalid_fingerprints_are_not_matching_provenance(tmp_path, fingerprint):
    paths = supplied_sets(tmp_path, report([finding()]), report(), fingerprint=fingerprint)
    result = compare_batches(*(str(p) for p in paths))
    assert result["same-analyzer"] is False
    assert result["totals"]["not-comparable"] == 1 and result["totals"]["resolved"] == 0


@pytest.mark.parametrize("policy", [{}, {"path": "p.json"}, {"sha256": ""}, {"sha256": "unknown"}])
def test_declared_policy_without_digest_is_uncertain(tmp_path, policy):
    paths = supplied_sets(tmp_path, report([finding()]), report(), policy=policy)
    result = compare_batches(*(str(p) for p in paths))
    assert result["totals"]["not-comparable"] == 1 and result["totals"]["resolved"] == 0


@pytest.mark.parametrize("policy", [None, {"sha256": "b" * 64}])
def test_default_and_valid_explicit_policy_comparisons_remain_positive(tmp_path, policy):
    paths = supplied_sets(tmp_path, report([finding()]), report(), policy=policy)
    if policy is None:
        newer = json.loads(paths[1].read_text(encoding="utf-8"))
        newer["devices"][0]["assessment-policy"] = None
        paths[1].write_text(json.dumps(newer), encoding="utf-8")
    assert compare_batches(*(str(p) for p in paths))["totals"]["resolved"] == 1


def test_custom_report_policy_without_index_digest_is_uncertain(tmp_path):
    newer = report()
    newer["data"] = {"assessment-policy": {"policy-version": "custom-v1", "provenance": "policy file: local.json"}}
    paths = supplied_sets(tmp_path, report([finding()]), newer)
    assert compare_batches(*(str(p) for p in paths))["totals"]["not-comparable"] == 1


def test_conflicting_report_family_is_not_comparable(tmp_path):
    newer = report()
    newer["coverage"]["device-type"] = "IOS_ROUTER"
    paths = supplied_sets(tmp_path, report([finding()]), newer)
    assert compare_batches(*(str(p) for p in paths))["totals"]["not-comparable"] == 1


@pytest.mark.parametrize("outcome,expected", [("unknown", "no-longer-assessable"), ("evaluated-no-finding", "resolved")])
def test_legacy_aggregate_fallback_remains_readable(tmp_path, outcome, expected):
    control = {"outcome": outcome, "rule-ids": ["paloalto.panos.policy.security_profiles"]}
    paths = supplied_sets(tmp_path, report([finding()]), report(controls=[control]))
    result = compare_batches(*(str(p) for p in paths))
    assert result["totals"][expected] == 1
    assert any("legacy" in n.casefold() for n in result["devices"][0]["notes"])


def pan_rule(name, attachment=""):
    return (f'<entry name="{name}"><from><member>trust</member></from><to><member>untrust</member></to>'
            '<source><member>any</member></source><destination><member>any</member></destination>'
            '<application><member>any</member></application><service><member>any</member></service>'
            f'<action>allow</action>{attachment}</entry>')


@pytest.mark.parametrize("state", ["unknown", "blocking", "deny"])
def test_actual_pan_mixed_instance_public_comparison(tmp_path, state):
    old = '<config><devices><entry name="fw"><vsys><entry name="vsys1"><rulebase><security><rules>'
    tail = '</rules></security></rulebase></entry></vsys></entry></devices></config>'
    profiles = '<profile-setting><group><member>UNEXPORTED</member></group></profile-setting>'
    if state == "blocking":
        profiles = '<profile-setting><profiles><virus><member>BLOCKING</member></virus></profiles></profile-setting>'
        tail = tail.replace('</rulebase>', '</rulebase><profiles><virus><entry name="BLOCKING"><decoder><entry name="http"><action>reset-both</action></entry></decoder></entry></virus></profiles>')
    for label in ("old", "new"):
        directory = tmp_path / label
        directory.mkdir()
        a = pan_rule("A", profiles if label == "new" and state != "deny" else "")
        if label == "new" and state == "deny":
            a = a.replace("<action>allow</action>", "<action>deny</action>")
        body = old + a + pan_rule("B") + tail
        (directory / "pan.xml").write_text(body, encoding="utf-8")
        m = manifest(directory, [{"id": "pan", "input": "pan.xml", "device": "PAN_OS"}])
        run_batch(str(m), str(directory / "out"), html=True)
    result = compare_batches(str(tmp_path / "old/out/batch-index.json"), str(tmp_path / "new/out/batch-index.json"))
    device = result["devices"][0]
    missing = [f for f in device["resolved"] if f["rule-id"] == "paloalto.panos.policy.security_profiles"]
    uncertain = [f for f in device["no-longer-assessable"] if f["rule-id"] == "paloalto.panos.policy.security_profiles"]
    # A blocking attachment alone still records unknown full-threat coverage.
    # Explicitly denying A is the positive, no-inspection-required case.
    assert len(missing) == int(state == "deny")
    assert len(uncertain) == int(state != "deny")
    assert any(f["rule-id"] == "paloalto.panos.policy.security_profiles" for f in device["unchanged"])
    for format in ("json", "html"):
        output = tmp_path / f"comparison.{format}"
        assert main(["compare", "--old", str(tmp_path / "old/out/batch-index.json"),
                     "--new", str(tmp_path / "new/out/batch-index.json"), "--output", str(output)]) == 0
        if format == "json":
            assert json.loads(output.read_text(encoding="utf-8"))["totals"] == result["totals"]
        else:
            assert comparison_html(result) == output.read_text(encoding="utf-8")
