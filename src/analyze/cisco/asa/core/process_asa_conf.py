import importlib
import pkgutil
from src.devices.common.base_parser import BaseDeviceParser
from .. import plugins as plugs


def _import_modules():
    pkg = plugs.__package__
    modules = []
    module_names = []

    # Get the path to the plugins directory
    plugins_path = plugs.__path__

    for importer, modname, ispkg in pkgutil.iter_modules(plugins_path):
        if modname.endswith("_plugin"):
            module_name = f"{pkg}.{modname}"
            module = importlib.import_module(module_name)
            module_names.append(module.__name__)
            modules.append(module)

    print(f"[3/4] Scanning configuration file using the following ASA plugins: {module_names}")
    return modules


def _classesinmodule(module):
    md = module.__dict__
    return [
        md[c] for c in md if (
            isinstance(md[c], type) and md[c].__module__ == module.__name__
        )
    ]


def process_asa_conf(parser: BaseDeviceParser) -> dict:
    issues = {}
    idx = 0

    for module in _import_modules():
        for module_class in _classesinmodule(module):
            # Check if it's a plugin class (not the base ASAPlugin)
            if module_class.__name__ != "ASAPlugin":
                m = module_class()
                m.analyze(parser)
                found_issues = m.get_issues()
                issues = _generate_section(found_issues, issues, idx)
                idx += 1

    return issues


def _generate_section(found_issues: list, issue_dict: dict, index: int) -> dict:
    subindex = 0
    for issue in found_issues:
        title = "2." + str(index) + "." + str(subindex) + ". " + issue.title
        issue_dict[title] = issue
        subindex += 1
    return issue_dict
