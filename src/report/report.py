from jinja2 import Environment, FileSystemLoader, select_autoescape
import os
import datetime
import array
import json

from .common.types import ReportType
from src.common.assessment import AssessmentContext

TEMPLATE_FILE = "html_template.html"


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

    text = template.render(
        device_type=device_type,
        hostname=hostname,
        date=date,
        issues=issues,
        vulns=vulns,
        assessment_policy=assessment_policy,
        coverage=coverage,
        configuration_inventory=inventory,
        remediation_summary=remediation_summary,
    )

    with open(filename, "w", encoding="utf-8", newline="") as html_file:
        html_file.write(text)


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
    vulns_dict["security-audit"] = issues
    vulns_dict["coverage"] = coverage
    vulns_dict["configuration-inventory"] = inventory
    vulns_dict["remediation-summary"] = remediation_summary
    json_text = json.dumps(
        vulns_dict,
        indent=4,
        sort_keys=True,
        default=lambda x: x.__str__() if isinstance(
            x, datetime.datetime) else x.to_dict()
    )

    with open(filename, "w", encoding="utf-8", newline="") as json_file:
        json_file.write(json_text)
