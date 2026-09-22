from src.devices.common.base_parser import BaseDeviceParser
from src.analyze.common.input_scope import select_template_findings
from ..plugins.fortios_checks_plugin import PluginFortiOSChecks
from ..plugins.fortios_baseline_plugin import PluginFortiOSBaseline


def process_fortios_conf(parser: BaseDeviceParser) -> dict:
    issues = {}
    idx = 0

    for plugin_class in (PluginFortiOSChecks, PluginFortiOSBaseline):
        plugin = plugin_class()
        plugin.analyze(parser)
        selected = parser.assessment_context.filter_findings(select_template_findings(parser, plugin.get_issues()))
        issues = _generate_section(selected, issues, idx)
        idx += 1
    
    return issues


def _generate_section(issues: list, issue_dict: dict, index: int) -> dict:
    subindex = 0
    for issue in issues:
        title = "8." + str(index) + "." + str(subindex) + ". " + issue.title
        issue_dict[title] = issue
        subindex += 1
    return issue_dict
