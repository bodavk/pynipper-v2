"""Explicit BIG-IP plugin pipeline."""

from src.analyze.common.base_plugin import BasePlugin
from src.devices.common.base_parser import BaseDeviceParser
from src.analyze.f5.plugins.bigip_checks_plugin import PluginF5BIGIPChecks
from src.analyze.common.evidence_lines import attach_source_lines


BIGIP_PLUGINS: tuple[type[BasePlugin], ...] = (PluginF5BIGIPChecks,)


def process_bigip_conf(parser: BaseDeviceParser) -> dict:
    issues = {}
    seen = set()
    for plugin_class in BIGIP_PLUGINS:
        plugin = plugin_class()
        plugin.analyze(parser)
        for issue in parser.assessment_context.filter_findings(attach_source_lines(parser, plugin.get_issues())):
            identity = (issue.rule_id, issue.evidence)
            if identity in seen:
                continue
            seen.add(identity)
            issues[f"12.0.{len(issues)}. {issue.title}"] = issue
    return issues
