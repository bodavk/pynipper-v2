from src.devices.common.base_parser import BaseDeviceParser
from ..plugins.junos_checks_plugin import PluginJunOSChecks


def process_junos_conf(parser: BaseDeviceParser) -> dict:
    issues = {}
    idx = 0

    plugin = PluginJunOSChecks()
    plugin.analyze(parser)
    
    i = plugin.get_issues()
    issues = _generate_section(i, issues, idx)
    
    return issues


def _generate_section(issues: list, issue_dict: dict, index: int) -> dict:
    subindex = 0
    for issue in issues:
        title = "10." + str(index) + "." + str(subindex) + ". " + issue.title
        issue_dict[title] = issue
        subindex += 1
    return issue_dict
