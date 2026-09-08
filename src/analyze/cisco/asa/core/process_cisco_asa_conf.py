import array
from src.devices.common.base_parser import BaseDeviceParser
from ..plugins.asa_checks_plugin import PluginASAChecks


def process_cisco_asa_conf(parser: BaseDeviceParser) -> dict:
    issues = {}
    idx = 0

    # For ASA, we have a unified plugin checks file
    plugin = PluginASAChecks()
    plugin.analyze(parser)
    
    i = plugin.get_issues()
    issues = _generate_section(i, issues, idx)
    
    return issues


def _generate_section(issues: list, issue_dict: dict, index: int) -> dict:
    subindex = 0
    for issue in issues:
        title = "2." + str(index) + "." + str(subindex) + ". " + issue.title
        issue_dict[title] = issue
        subindex += 1
    return issue_dict
