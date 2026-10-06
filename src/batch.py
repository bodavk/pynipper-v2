"""Offline batch audits and assessment-set comparison (SC-050).

Thin orchestration over the normal per-device pipeline: every manifest entry is
audited exactly as ``python -m src.main`` would audit it, with one JSON report per
device and a consolidated index. Nothing is downloaded, resolved or contacted.

Usage::

    python -m src.batch run --manifest batch.json --output-dir reports/2026-10
    python -m src.batch compare --old reports/2026-09/batch-index.json \
        --new reports/2026-10/batch-index.json --output comparison.json

Manifest (JSON)::

    {"schema-version": 1,
     "devices": [{"id": "edge-fw-1", "input": "exports/fw1.conf",
                  "device": "auto", "assessment-policy": "policy.json",
                  "export-scope": "full running configuration"}],
     "advisory-bundle": "optional/local-bundle.json"}

Relative paths are resolved against the manifest's directory.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

BATCH_SCHEMA_VERSION = 1
COMPARISON_SCHEMA_VERSION = 1
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_SOURCE_ROOT = Path(__file__).resolve().parent


class BatchError(ValueError):
    """Invalid manifest or unsafe output request; nothing is written."""


@dataclass(frozen=True)
class BatchEntry:
    device_id: str
    input_path: Path
    device: str
    assessment_policy: Path | None
    export_scope: str


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    if path.is_dir():
        for item in sorted(p for p in path.rglob("*") if p.is_file()):
            digest.update(item.relative_to(path).as_posix().encode("utf-8") + b"\0")
            digest.update(item.read_bytes())
    else:
        digest.update(path.read_bytes())
    return digest.hexdigest()


def analyzer_fingerprint() -> str:
    """Hash of the parser and rule code, so result sets from different rule versions are not mixed silently."""
    digest = hashlib.sha256()
    for folder in ("analyze", "devices", "common"):
        for item in sorted((_SOURCE_ROOT / folder).rglob("*.py")):
            digest.update(item.relative_to(_SOURCE_ROOT).as_posix().encode("utf-8") + b"\0")
            digest.update(item.read_bytes().replace(b"\r\n", b"\n"))
    return digest.hexdigest()


def tool_version() -> str:
    try:
        from importlib.metadata import version
        return version("pynipper-ng")
    except Exception:  # not installed as a distribution
        return "unknown"


def load_manifest(path: str) -> tuple[list[BatchEntry], Path | None]:
    manifest_path = Path(path).resolve()
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BatchError(f"Manifest could not be read as JSON: {error.__class__.__name__}") from None
    if not isinstance(data, dict) or data.get("schema-version") != BATCH_SCHEMA_VERSION:
        raise BatchError("Manifest must be an object with \"schema-version\": 1")
    devices = data.get("devices")
    if not isinstance(devices, list) or not devices:
        raise BatchError("Manifest \"devices\" must be a non-empty list")
    base = manifest_path.parent
    entries, ids, inputs = [], set(), set()
    for index, item in enumerate(devices, start=1):
        if not isinstance(item, dict):
            raise BatchError(f"Device entry {index} must be an object")
        unknown = set(item) - {"id", "input", "device", "assessment-policy", "export-scope"}
        if unknown:
            raise BatchError(f"Device entry {index} has unknown fields: {', '.join(sorted(unknown))}")
        device_id = item.get("id")
        if not isinstance(device_id, str) or not _ID.fullmatch(device_id):
            raise BatchError(f"Device entry {index} needs an \"id\" of letters, digits, '.', '_' or '-' (max 64)")
        if device_id.casefold() in ids:
            raise BatchError(f"Duplicate device id: {device_id}")
        raw_input = item.get("input")
        if not isinstance(raw_input, str) or not raw_input.strip():
            raise BatchError(f"Device {device_id} needs an \"input\" path")
        input_path = (base / raw_input).resolve()
        if input_path in inputs:
            raise BatchError(f"Input used twice: {raw_input}")
        policy = item.get("assessment-policy")
        if policy is not None and (not isinstance(policy, str) or not policy.strip()):
            raise BatchError(f"Device {device_id}: \"assessment-policy\" must be a path")
        ids.add(device_id.casefold())
        inputs.add(input_path)
        entries.append(BatchEntry(
            device_id=device_id,
            input_path=input_path,
            device=str(item.get("device", "auto")),
            assessment_policy=(base / policy).resolve() if policy else None,
            export_scope=str(item.get("export-scope", "unspecified"))[:200],
        ))
    bundle = data.get("advisory-bundle")
    return entries, ((base / bundle).resolve() if isinstance(bundle, str) and bundle.strip() else None)


def _resolve_device(entry: BatchEntry) -> str:
    from src.devices.detection import detect_device_type
    from src.devices.registry import get_device_definition
    if entry.device.strip().casefold() == "auto":
        return detect_device_type(str(entry.input_path))
    return get_device_definition(entry.device).canonical_id


def _preflight_outputs(entries: list[BatchEntry], bundle: Path | None, manifest: Path,
                       out: Path, targets: list[Path], overwrite: bool) -> None:
    """Protect supplied artifacts and all output identities before creating anything.

    Resolved names catch case/junction/symlink aliases; device/inode identities
    additionally catch existing hard links, including directory-export members.
    This is a preflight, not a guarantee against concurrent filesystem mutation.
    """
    identities = {}

    def identity(path):
        path = path.resolve()
        if path not in identities:
            try:
                info = path.stat()
            except FileNotFoundError:
                identities[path] = None
            else:
                identities[path] = (info.st_dev, info.st_ino, stat.S_ISDIR(info.st_mode))
        return identities[path]

    def same(first, second):
        if first.resolve() == second.resolve():
            return True
        a, b = identity(first), identity(second)
        return a is not None and b is not None and a[:2] == b[:2]

    try:
        protected = [manifest, *(e.input_path for e in entries),
                     *(e.assessment_policy for e in entries if e.assessment_policy)]
        if bundle:
            protected.append(bundle)
        roots = []

        def walk_error(error):
            raise error

        for path in tuple(protected):
            info = identity(path)
            if info is not None and info[2]:
                roots.append(path.resolve())
                for directory, dirs, files in os.walk(path, followlinks=False, onerror=walk_error):
                    protected.extend(Path(directory) / name for name in (*dirs, *files))
        # An exported directory may contain a junction/symlink to another tree.
        # Protect that resolved subtree too, without following recursive links.
        roots.extend(p.resolve() for p in protected if identity(p) is not None and identity(p)[2])
        for destination in (out, *targets):
            resolved = destination.resolve()
            if any(same(destination, artifact) for artifact in protected):
                raise BatchError("Output destinations must not replace or alias supplied artifacts")
            if any(root == resolved or root in resolved.parents for root in roots):
                raise BatchError("Output directory must not contain reports inside a supplied export subtree")
        for position, target in enumerate(targets):
            if any(same(target, earlier) for earlier in targets[:position]):
                raise BatchError("Duplicate output destinations or filesystem aliases")
            info = identity(target)
            if info is not None and info[2]:
                raise BatchError("A report destination is an existing directory")
        if identity(out) is not None and not identity(out)[2]:
            raise BatchError("Output directory is an existing file")
        existing = [t.name for t in targets if identity(t) is not None or t.is_symlink()]
        if existing and not overwrite:
            raise BatchError("Output files already exist (use --overwrite): " + ", ".join(sorted(existing)[:5]))
    except (OSError, RuntimeError):
        raise BatchError("Output safety could not be established from filesystem paths and identities") from None


def run_batch(manifest: str, output_dir: str, *, html: bool = False, overwrite: bool = False) -> dict:
    from src.analyze.analyze_device import analyze_device
    from src.advisories.service import AdvisoryRequest
    from src.common.assessment import AssessmentContext

    entries, bundle = load_manifest(manifest)
    try:
        out = Path(output_dir).resolve()
    except (OSError, RuntimeError):
        raise BatchError("Output safety could not be established from filesystem paths") from None
    targets = [out / "batch-index.json"] + [out / f"{e.device_id}.json" for e in entries]
    if html:
        targets += [out / f"{e.device_id}.html" for e in entries]
    _preflight_outputs(entries, bundle, Path(manifest).resolve(), out, targets, overwrite)
    out.mkdir(parents=True, exist_ok=True)
    default_conf = str(_SOURCE_ROOT / "common" / "default.conf")
    index = {
        "schema-version": BATCH_SCHEMA_VERSION,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool-version": tool_version(),
        "analyzer-fingerprint": analyzer_fingerprint(),
        "advisory-bundle": ({"path": bundle.name, "sha256": _sha256_path(bundle)} if bundle and bundle.is_file() else None),
        "devices": [],
        "scope-note": ("Each report is an offline configuration audit. Index hashes identify the exact inputs, "
                       "assessment policies and analyzer code used; they are not proof of device state."),
    }
    for entry in sorted(entries, key=lambda e: e.device_id.casefold()):
        record = {"id": entry.device_id, "input": entry.input_path.name, "export-scope": entry.export_scope}
        try:
            if not entry.input_path.exists():
                raise FileNotFoundError("input not found")
            record["input-sha256"] = _sha256_path(entry.input_path)
            device = _resolve_device(entry)
            record["device"] = device
            context = AssessmentContext()
            if entry.assessment_policy:
                context = AssessmentContext.from_file(str(entry.assessment_policy))
                record["assessment-policy"] = {"path": entry.assessment_policy.name,
                                               "sha256": _sha256_path(entry.assessment_policy),
                                               "policy-version": context.policy_version}
            request = AdvisoryRequest(online=False, bundle_path=str(bundle) if bundle else None,
                                      save_path=None, software_version=None)
            extra = {"advisory_request": request} if request.requested else {}
            with contextlib.redirect_stdout(io.StringIO()):
                analyze_device(device, str(entry.input_path), str(out / f"{entry.device_id}.json"),
                               "JSON", default_conf, False, context, **extra)
                if html:
                    analyze_device(device, str(entry.input_path), str(out / f"{entry.device_id}.html"),
                                   "HTML", default_conf, False, context, **extra)
            report = json.loads((out / f"{entry.device_id}.json").read_text(encoding="utf-8"))
            record["report"] = f"{entry.device_id}.json"
            record["status"] = "parse-error" if _parse_failed(report) else "audited"
            record["finding-count"] = len(report.get("security-audit") or {})
        except Exception as error:  # isolate one device's failure from the batch
            record["status"] = "error"
            record["error"] = error.__class__.__name__
        index["devices"].append(record)
    (out / "batch-index.json").write_text(json.dumps(index, indent=2, sort_keys=True), encoding="utf-8")
    return index


def _parse_failed(report: dict) -> bool:
    fields = (report.get("coverage") or {}).get("fields") or []
    return bool(fields) and all(field.get("knowledge-state") == "parse_error" for field in fields)


def _finding_keys(report: dict) -> dict[tuple, dict]:
    """Stable keys: rule ID plus evidence text (line numbers and titles excluded)."""
    result = {}
    for record in (report.get("security-audit") or {}).values():
        key = (record.get("rule_id", ""), tuple(sorted(str(item) for item in record.get("evidence") or ())))
        result.setdefault(key, {"rule-id": key[0], "severity": record.get("severity"),
                                "title": record.get("title"), "evidence": list(key[1])[:6]})
    return result


def _excluded(report: dict) -> set[str]:
    policy = (report.get("data") or {}).get("assessment-policy") or {}
    return {str(item).casefold().replace("-", "_") for item in policy.get("excluded-categories") or policy.get("excluded_categories") or ()}


def _unassessable_rules(report: dict) -> set[str]:
    rules = set()
    for control in ((report.get("coverage") or {}).get("controls") or {}).get("results") or ():
        if control.get("outcome") in _UNCERTAIN_OUTCOMES or _scoped_uncertainty(control):
            rules.update(control.get("rule-ids") or ())
    return rules


_UNCERTAIN_OUTCOMES = {"unknown", "unsupported", "excluded", "not-recorded"}


def _scoped_uncertainty(control: dict) -> bool:
    return bool(control.get("unassessed-instances") or control.get("unassessed-instance-count")
                or any(i.get("outcome") in _UNCERTAIN_OUTCOMES for i in control.get("instances") or ()))


def _digest(value) -> str | None:
    return value.casefold() if isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value) else None


def _comparison_family(record: dict, report: dict) -> str | None:
    from src.devices.registry import get_device_definition
    try:
        family = get_device_definition(record.get("device")).canonical_id
        # Optional old-report metadata is not required; when supplied it must
        # agree with the declared family. A manifest ID is not physical identity.
        for value in ((report.get("data") or {}).get("device-type"),
                      (report.get("coverage") or {}).get("device-type")):
            if value is not None and get_device_definition(value).canonical_id != family:
                return None
        return family
    except ValueError:
        return None


def _comparison_policy(record: dict, report: dict) -> tuple[bool, str | None]:
    declared = record.get("assessment-policy")
    if declared is not None:
        digest = _digest(declared.get("sha256")) if isinstance(declared, dict) else None
        return digest is not None, digest
    metadata = (report.get("data") or {}).get("assessment-policy") or {}
    if (metadata.get("policy-version") not in {None, "pynipper-v2/default-v1"}
            or metadata.get("provenance") not in {None, "built-in default"}):
        return False, None
    return True, None  # absent/None default-policy representations are equivalent


def compare_batches(old_index: str, new_index: str) -> dict:
    old_path, new_path = Path(old_index).resolve(), Path(new_index).resolve()
    old, new = (json.loads(p.read_text(encoding="utf-8")) for p in (old_path, new_path))
    for item in (old, new):
        if item.get("schema-version") != BATCH_SCHEMA_VERSION:
            raise BatchError("Both inputs must be batch-index.json files with schema-version 1")
    old_fingerprint, new_fingerprint = (_digest(index.get("analyzer-fingerprint")) for index in (old, new))
    same_rules = old_fingerprint is not None and old_fingerprint == new_fingerprint
    old_devices = {d["id"]: d for d in old.get("devices", ())}
    new_devices = {d["id"]: d for d in new.get("devices", ())}
    devices, totals = [], {"new": 0, "unchanged": 0, "resolved": 0, "no-longer-assessable": 0, "not-comparable": 0}
    for device_id in sorted(set(old_devices) | set(new_devices), key=str.casefold):
        before, after = old_devices.get(device_id), new_devices.get(device_id)
        entry = {"id": device_id, "new": [], "unchanged": [], "resolved": [], "no-longer-assessable": [],
                 "not-comparable": [], "notes": []}

        def load(index_path, record):
            if not record or record.get("status") != "audited":
                return None
            return json.loads((index_path.parent / record["report"]).read_text(encoding="utf-8"))

        old_report, new_report = load(old_path, before), load(new_path, after)
        old_keys = _finding_keys(old_report) if old_report else {}
        new_keys = _finding_keys(new_report) if new_report else {}
        if new_report is None:
            entry["notes"].append("No successful audit in the new set (missing, error or parse failure); earlier findings are not treated as fixed.")
            entry["no-longer-assessable"] = list(old_keys.values())
        elif old_report is None:
            entry["notes"].append("No successful audit in the old set; every current finding is listed as new.")
            entry["new"] = list(new_keys.values())
        else:
            old_family, new_family = _comparison_family(before, old_report), _comparison_family(after, new_report)
            same_family = old_family is not None and old_family == new_family
            old_policy_known, old_policy = _comparison_policy(before, old_report)
            new_policy_known, new_policy = _comparison_policy(after, new_report)
            policy_unknown = not old_policy_known or not new_policy_known
            policy_changed = old_policy != new_policy
            if not same_family:
                entry["notes"].append("Device family is different, unknown or inconsistent with the report; disappeared findings are not comparable.")
            if policy_unknown:
                entry["notes"].append("A declared assessment policy has no valid digest; comparison provenance is unknown.")
            if policy_changed:
                entry["notes"].append("The assessment policy changed; disappeared findings are not counted as resolved.")
            if not same_rules:
                entry["notes"].append("The analyzer fingerprint changed or is missing/invalid; disappeared findings are not comparable.")
            controls = ((new_report.get("coverage") or {}).get("controls") or {}).get("results") or ()
            if any(_scoped_uncertainty(c) for c in controls):
                entry["notes"].append("Scoped instance uncertainty prevents resolution of disappeared findings for the affected control: evidence-only keys have no trusted finding-to-instance binding.")
            if not controls or any(not all(k in c for k in ("instances", "unassessed-instances", "unassessed-instance-count")) for c in controls):
                entry["notes"].append("Legacy aggregate-only coverage fallback is in use for some controls; per-instance uncertainty cannot be recovered from those records.")
            entry["notes"].append("The manifest ID is auditor-declared identity, not verified physical-device identity; finding keys remain evidence-based.")
            if (new_report.get("coverage") or {}).get("input-completeness") == "unrendered-template":
                entry["notes"].append("The new input is an unrendered template; absence-based checks were withheld.")
            excluded, unassessable = _excluded(new_report), _unassessable_rules(new_report)
            template = (new_report.get("coverage") or {}).get("input-completeness") == "unrendered-template"
            for key, finding in old_keys.items():
                if key in new_keys:
                    entry["unchanged"].append(finding)
                elif not same_family or not same_rules or policy_unknown:
                    entry["not-comparable"].append(finding)
                elif (set(key[0].split(".")) & excluded) or key[0] in unassessable or template:
                    entry["no-longer-assessable"].append(finding)
                elif policy_changed:
                    entry["not-comparable"].append(finding)
                else:
                    entry["resolved"].append(finding)
            entry["new"] = [finding for key, finding in new_keys.items() if key not in old_keys]
        for status in totals:
            entry[status] = sorted(entry[status], key=lambda f: (f["rule-id"], f["evidence"]))
            totals[status] += len(entry[status])
        devices.append(entry)
    return {
        "schema-version": COMPARISON_SCHEMA_VERSION,
        "old": {"generated": old.get("generated"), "analyzer-fingerprint": old.get("analyzer-fingerprint")},
        "new": {"generated": new.get("generated"), "analyzer-fingerprint": new.get("analyzer-fingerprint")},
        "same-analyzer": same_rules,
        "totals": totals,
        "devices": devices,
        "scope-note": ("Resolved means the same finding key is absent from a successful audit of the same device with "
                       "the same analyzer code and assessment policy, and its rule was not excluded or unassessable. "
                       "It is a configuration comparison, not proof of remediation on the live device."),
    }


def comparison_html(result: dict) -> str:
    """Self-contained HTML view of a comparison result (values escaped, no scripts)."""
    from html import escape
    labels = ("new", "resolved", "no-longer-assessable", "not-comparable", "unchanged")
    totals = "".join(f"<li><strong>{escape(k)}</strong>: {result['totals'][k]}</li>" for k in labels)
    sections = []
    for device in result["devices"]:
        rows = "".join(
            f"<tr><td>{escape(status)}</td><td>{escape(str(f.get('severity')))}</td><td><code>{escape(f['rule-id'])}</code></td>"
            f"<td>{escape(str(f.get('title') or ''))}</td></tr>"
            for status in labels if status != "unchanged" for f in device[status]
        )
        notes = "".join(f"<li>{escape(note)}</li>" for note in device["notes"])
        sections.append(
            f"<section><h2>{escape(device['id'])}</h2>"
            + (f"<ul>{notes}</ul>" if notes else "")
            + f"<p>{len(device['unchanged'])} unchanged finding(s).</p>"
            + (f"<table><thead><tr><th>Status</th><th>Severity</th><th>Rule</th><th>Title</th></tr></thead><tbody>{rows}</tbody></table>"
               if rows else "<p>No new, resolved or unassessable findings.</p>")
            + "</section>")
    return ("<!doctype html><html><head><meta charset=\"utf-8\"><title>pynipper comparison</title>"
            "<style>body{font-family:sans-serif;margin:2em}table{border-collapse:collapse}td,th{border:1px solid #999;padding:4px 8px;text-align:left}</style>"
            f"</head><body><h1>Assessment comparison</h1><p>{escape(result['scope-note'])}</p><ul>{totals}</ul>"
            + "".join(sections) + "</body></html>")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m src.batch", description="Offline batch audits and comparisons.")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="Audit every device in a manifest")
    run.add_argument("--manifest", required=True)
    run.add_argument("--output-dir", required=True)
    run.add_argument("--html", action="store_true", help="Also write an HTML report per device")
    run.add_argument("--overwrite", action="store_true", help="Replace existing report files in the output directory")
    compare = commands.add_parser("compare", help="Compare two batch-index.json files")
    compare.add_argument("--old", required=True)
    compare.add_argument("--new", required=True)
    compare.add_argument("--output", required=True, help="Comparison file; .html writes an HTML view, otherwise JSON")
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            index = run_batch(args.manifest, args.output_dir, html=args.html, overwrite=args.overwrite)
            for device in index["devices"]:
                print(f"{device['id']}: {device['status']}" + (f", {device['finding-count']} findings" if "finding-count" in device else ""))
            return 1 if any(d["status"] != "audited" for d in index["devices"]) else 0
        output = Path(args.output).resolve()
        if output in {Path(args.old).resolve(), Path(args.new).resolve()} or output.exists():
            raise BatchError("Comparison output must be a new file, different from both indexes")
        result = compare_batches(args.old, args.new)
        output.write_text(comparison_html(result) if output.suffix.casefold() in {".html", ".htm"}
                          else json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        print(", ".join(f"{key}: {value}" for key, value in result["totals"].items()))
        return 0
    except BatchError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
