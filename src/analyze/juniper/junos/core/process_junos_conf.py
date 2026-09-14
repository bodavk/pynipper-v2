from src.devices.common.base_parser import BaseDeviceParser
from ..plugins.junos_checks_plugin import PluginJunOSChecks
from ..plugins.baseline_plugin import PluginJunOSBaseline


def process_junos_conf(parser: BaseDeviceParser) -> dict:
    issues = {}
    idx = 0

    for plugin_class in (PluginJunOSChecks, PluginJunOSBaseline):
        plugin = plugin_class()
        plugin.analyze(parser)
        selected = parser.assessment_context.filter_findings(plugin.get_issues())
        issues = _generate_section(selected, issues, idx)
        idx += 1
    
    return issues


def _generate_section(issues: list, issue_dict: dict, index: int) -> dict:
    subindex = 0
    for issue in issues:
        title = "10." + str(index) + "." + str(subindex) + ". " + issue.title
        issue_dict[title] = issue
        subindex += 1
    return issue_dict
