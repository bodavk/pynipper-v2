"""Deterministic Cisco IOS plugin pipeline."""

from typing import Iterable

from src.analyze.common.issue import Finding
from src.devices.common.base_parser import BaseDeviceParser
from ..plugins.baseline_plugin import PluginIOSBaseline
from ..plugins.http_plugin import PluginHTTP
from ..plugins.ssh_plugin import PluginSSH


IOS_PLUGINS = (PluginHTTP, PluginSSH, PluginIOSBaseline)


def _deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    unique = []
    seen = set()
    for finding in findings:
        identity = (finding.rule_id, finding.evidence or (finding.observation,))
        if identity not in seen:
            seen.add(identity)
            unique.append(finding)
    return unique


def process_cisco_ios_conf(parser: BaseDeviceParser) -> dict:
    findings = []
    print(
        "[3/4] Scanning configuration file using the following IOS plugins: "
        f"{[plugin.__name__ for plugin in IOS_PLUGINS]}"
    )
    for plugin_class in IOS_PLUGINS:
        plugin = plugin_class()
        plugin.analyze(parser)
        findings.extend(plugin.get_issues())
    return _generate_section(_deduplicate(findings), {}, 0)


def _generate_section(findings: list[Finding], issue_dict: dict, index: int) -> dict:
    for subindex, finding in enumerate(findings):
        title = f"2.{index}.{subindex}. {finding.title}"
        issue_dict[title] = finding
    return issue_dict
