"""Explicit Check Point Gaia OS plugin pipeline (SC-023)."""

from src.analyze.checkpoint.plugins.gaia_checks_plugin import PluginCheckPointGaiaChecks
from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.evidence_lines import attach_source_lines
from src.devices.common.base_parser import BaseDeviceParser


GAIA_PLUGINS: tuple[type[BasePlugin], ...] = (PluginCheckPointGaiaChecks,)


def process_checkpoint_gaia_conf(parser: BaseDeviceParser) -> dict:
    issues = {}
    seen = set()
    for plugin_class in GAIA_PLUGINS:
        plugin = plugin_class()
        plugin.analyze(parser)
        for issue in parser.assessment_context.filter_findings(attach_source_lines(parser, plugin.get_issues())):
            identity = (issue.rule_id, issue.evidence)
            if identity in seen:
                continue
            seen.add(identity)
            issues[f"13.0.{len(issues)}. {issue.title}"] = issue
    return issues
