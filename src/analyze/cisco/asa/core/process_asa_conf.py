from typing import Iterable, List

from src.analyze.common.issue import Finding
from src.devices.common.base_parser import BaseDeviceParser
from ..plugins.asa_checks_plugin import PluginASAChecks
from ..plugins.baseline_plugin import PluginASABaseline


ASA_PLUGINS = (PluginASAChecks, PluginASABaseline)


def process_asa_conf(parser: BaseDeviceParser) -> dict:
    issues = {}
    print(
        "[3/4] Scanning configuration file using the following ASA plugins: "
        f"{[plugin.__name__ for plugin in ASA_PLUGINS]}"
    )

    found_issues: List[Finding] = []
    for plugin_class in ASA_PLUGINS:
        plugin = plugin_class()
        plugin.analyze(parser)
        found_issues.extend(plugin.get_issues())

    issues = _generate_section(_deduplicate_findings(found_issues), issues, 0)

    return issues


def _deduplicate_findings(findings: Iterable[Finding]) -> List[Finding]:
    """Remove repeat emissions while preserving distinct affected objects."""

    unique = []
    seen = set()
    for finding in findings:
        object_identity = finding.evidence or (finding.observation,)
        key = (finding.rule_id, object_identity)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def _generate_section(found_issues: list, issue_dict: dict, index: int) -> dict:
    subindex = 0
    for issue in found_issues:
        title = "2." + str(index) + "." + str(subindex) + ". " + issue.title
        issue_dict[title] = issue
        subindex += 1
    return issue_dict
