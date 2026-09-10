from typing import Iterable

from src.analyze.common.issue import Finding
from src.analyze.cisco.ios.plugins.http_plugin import PluginHTTP
from src.analyze.cisco.ios.plugins.ssh_plugin import PluginSSH
from src.analyze.cisco.ios.plugins.baseline_plugin import PluginIOSBaseline
from src.devices.common.base_parser import BaseDeviceParser
from ..plugins.iosxe_checks_plugin import PluginIOSXEChecks


IOS_XE_PLUGINS = (PluginHTTP, PluginSSH, PluginIOSBaseline, PluginIOSXEChecks)


def _deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    unique = []
    seen = set()
    for finding in findings:
        identity = (finding.rule_id, finding.evidence or (finding.observation,))
        if identity not in seen:
            seen.add(identity)
            unique.append(finding)
    return unique


def process_iosxe_conf(parser: BaseDeviceParser) -> dict:
    findings = []
    for plugin_class in IOS_XE_PLUGINS:
        plugin = plugin_class()
        plugin.analyze(parser)
        findings.extend(plugin.get_issues())
    return _generate_section(_deduplicate(findings), {}, 0)


def _generate_section(issues: list, issue_dict: dict, index: int) -> dict:
    for subindex, issue in enumerate(issues):
        title = f"9.{index}.{subindex}. {issue.title}"
        issue_dict[title] = issue
    return issue_dict
