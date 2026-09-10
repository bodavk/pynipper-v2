from src.devices.common.base_parser import BaseDeviceParser
from ..plugins.screenos_checks_plugin import PluginScreenOSChecks
from ..plugins.screenos_baseline_plugin import PluginScreenOSBaseline


def process_screenos_conf(parser: BaseDeviceParser) -> dict:
    issues = {}
    idx = 0

    for plugin_class in (PluginScreenOSChecks, PluginScreenOSBaseline):
        plugin = plugin_class()
        plugin.analyze(parser)
        issues = _generate_section(plugin.get_issues(), issues, idx)
        idx += 1
    
    return issues


def _generate_section(issues: list, issue_dict: dict, index: int) -> dict:
    subindex = 0
    for issue in issues:
        title = "4." + str(index) + "." + str(subindex) + ". " + issue.title
        issue_dict[title] = issue
        subindex += 1
    return issue_dict
