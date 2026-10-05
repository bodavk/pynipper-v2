from jinja2 import Environment, FileSystemLoader, select_autoescape
import os
import subprocess
import datetime
import array
import csv
import json
import re

from .common.types import ReportType
from .explanations import (
    build_finding_views, coverage_counts, json_security_audit, severity_tiles,
)
from src.advisories.service import not_requested_status
from src.common.assessment import AssessmentContext
from src.analyze.common.attack_paths import empty_attack_path_section

TEMPLATE_FILE = "html_template.html"
_IS_WINDOWS = os.name == "nt"


def _restrict_windows_acl(filename: str) -> bool:
    """Replace inherited Windows ACLs with full control for the process user.

    POSIX mode bits passed to ``os.open`` are ignored on Windows, where a new
    file inherits the directory ACL. ``icacls /inheritance:r`` removes the
    inherited entries. The process token can differ from USERNAME/USERDOMAIN
    (for example under a sandbox or impersonation), so resolve its SID.
    """
    try:
        identity = subprocess.run(
            ["whoami", "/user", "/fo", "csv", "/nh"],
            capture_output=True, text=True, check=False,
        )
        if identity.returncode != 0:
            return False
        rows = [row for row in csv.reader(identity.stdout.splitlines()) if row]
        if (len(rows) != 1 or len(rows[0]) != 2
                or not re.fullmatch(r"S-1-(?:\d+-)+\d+", rows[0][1])):
            return False
        result = subprocess.run(
            ["icacls", filename, "/inheritance:r", "/grant:r", f"*{rows[0][1]}:F"],
            capture_output=True, text=True, check=False,
        )
    except OSError:
        return False
    return result.returncode == 0


def _write_report_file(filename: str, content: str, *, sensitive: bool) -> None:
    if sensitive:
        descriptor = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        if _IS_WINDOWS and not _restrict_windows_acl(filename):
            # Fail closed: never write unmasked secrets into a file other
            # accounts may read through inherited ACLs.
            os.close(descriptor)
            os.remove(filename)
            raise PermissionError(
                "Could not restrict the Windows ACL of the sensitive report; nothing was written. "
                "Choose a directory where icacls can be applied, or run without --show-secrets."
            )
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as report_file:
            report_file.write(content)
    else:
        with open(filename, "w", encoding="utf-8", newline="") as report_file:
            report_file.write(content)


def _sensitive_report(data: dict) -> bool:
    return data.get("assessment-policy", {}).get("report-secret-evidence") is True


def _remediation_summary(issues: dict) -> dict:
    severity_counts: dict[str, int] = {}
    priorities = []
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
    for index, finding in enumerate(issues.values()):
        severity = finding.severity.value
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        priorities.append((rank.get(finding.severity.name, 99), index, {
            "rule-id": finding.rule_id,
            "severity": severity,
            "title": finding.title,
            "recommendation": finding.recommendation,
        }))
    priorities.sort(key=lambda item: (item[0], item[1]))
    return {
        "finding-count": len(issues),
        "severity-counts": severity_counts,
        "priority-actions": [item[2] for item in priorities[:5]],
        "scope-note": (
            "This is a concise prioritization of emitted findings, not a compliance score. "
            "Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope."
        ),
    }


def _attack_paths(data: dict) -> dict:
    """SC-063 section; callers without analysis get an explicit not-assessed placeholder."""
    return data.get("attack-paths") or empty_attack_path_section(
        str(data.get("device-type", "")),
        "Attack-path correlation was not run by this caller; no pattern was assessed.",
    )


def _report_sections(data: dict, issues: dict) -> tuple[dict, dict, dict]:
    coverage = data.get("coverage") or {
        "schema-version": 1,
        "fields": [],
        "diagnostics": [],
        "scope-note": (
            "Coverage metadata was not supplied by this caller. An empty finding list does not imply that controls passed."
        ),
    }
    inventory = data.get("configuration-inventory") or {}
    return coverage, inventory, _remediation_summary(issues)


def generate_report(output_type, output_filename, issues, vulns_array_sorted, data):
    if output_type == ReportType._member_names_[0]:
        _generate_html_report(output_filename,
                              issues, vulns_array_sorted, data)
        print(f"Generated new HTML report file in {output_filename}")
    elif output_type == ReportType._member_names_[1]:
        _generate_json_report(output_filename,
                              issues, vulns_array_sorted, data)
        print(f"Generated new JSON report file in {output_filename}")
    else:
        print("Not a valid file format")


def _generate_html_report(filename: str, issues: dict, vulns: array, data: dict) -> None:
    date = datetime.datetime.now().date()
    device_type = data["device-type"]
    hostname = data["hostname"]
    assessment_policy = data.get("assessment-policy", AssessmentContext().to_dict())
    coverage, inventory, remediation_summary = _report_sections(data, issues)

    template_loader = FileSystemLoader(os.path.dirname(
        os.path.abspath(__file__)) + "/templates")

    env = Environment(
        loader=template_loader,
        autoescape=select_autoescape(['html', 'xml'])
    )

    template = env.get_template(TEMPLATE_FILE)
    findings = build_finding_views(issues)

    text = template.render(
        device_type=device_type,
        hostname=hostname,
        date=date,
        issues=issues,
        findings=findings,
        severity_tiles=severity_tiles(issues),
        coverage_counts=coverage_counts(coverage),
        vulns=vulns,
        advisory_lookup=data.get("software-advisories") or not_requested_status(),
        assessment_policy=assessment_policy,
        coverage=coverage,
        configuration_inventory=inventory,
        remediation_summary=remediation_summary,
        attack_paths=_attack_paths(data),
        secret_evidence=data.get("secret-evidence"),
        report_secret_evidence=_sensitive_report(data),
    )

    _write_report_file(filename, text, sensitive=_sensitive_report(data))


def _generate_json_report(filename: str, issues: dict, vulns: array, data: dict) -> None:
    device_type = data["device-type"]
    hostname = data["hostname"]
    date = datetime.datetime.now()

    report_data = {}
    report_data["device-type"] = device_type
    report_data["hostname"] = hostname
    report_data["date"] = date
    report_data["assessment-policy"] = data.get(
        "assessment-policy", AssessmentContext().to_dict()
    )
    coverage, inventory, remediation_summary = _report_sections(data, issues)

    vulns_dict = {}
    vulns_dict["data"] = report_data
    vulns_dict["vulnerabilities"] = vulns
    vulns_dict["software-advisory-lookup"] = data.get("software-advisories") or not_requested_status()
    vulns_dict["security-audit"] = json_security_audit(issues)
    vulns_dict["coverage"] = coverage
    vulns_dict["configuration-inventory"] = inventory
    vulns_dict["remediation-summary"] = remediation_summary
    vulns_dict["attack-paths"] = _attack_paths(data)
    if _sensitive_report(data):
        vulns_dict["secret-evidence"] = data.get("secret-evidence", {
            "status": "unavailable", "entries": [],
            "scope-note": "Parsing failed before credential source lines could be selected.",
        })
    json_text = json.dumps(
        vulns_dict,
        indent=4,
        sort_keys=True,
        default=lambda x: x.__str__() if isinstance(
            x, datetime.datetime) else x.to_dict()
    )

    _write_report_file(filename, json_text, sensitive=_sensitive_report(data))
