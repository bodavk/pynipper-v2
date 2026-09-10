"""Prevent focused target plugins from emitting findings without citations."""

import ast
from pathlib import Path

import pytest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FOCUSED_PLUGIN_PATHS = (
    "src/analyze/cisco/ios/plugins/http_plugin.py",
    "src/analyze/cisco/ios/plugins/ssh_plugin.py",
    "src/analyze/cisco/iosxe/plugins/iosxe_checks_plugin.py",
    "src/analyze/cisco/asa/plugins/asa_checks_plugin.py",
    "src/analyze/fortinet/plugins/fortios_checks_plugin.py",
    "src/analyze/juniper/junos/plugins/junos_checks_plugin.py",
    "src/analyze/juniper/plugins/screenos_checks_plugin.py",
)
TARGET_PLUGIN_PATHS = FOCUSED_PLUGIN_PATHS + (
    "src/analyze/cisco/ios/plugins/baseline_plugin.py",
    "src/analyze/cisco/asa/plugins/baseline_plugin.py",
    "src/analyze/fortinet/plugins/fortios_baseline_plugin.py",
    "src/analyze/juniper/junos/plugins/baseline_plugin.py",
    "src/analyze/juniper/plugins/screenos_baseline_plugin.py",
    "src/analyze/checkpoint/plugins/fw1_checks_plugin.py",
    "src/analyze/checkpoint/plugins/fw1_baseline_plugin.py",
    "src/analyze/paloalto/plugins/panos_checks_plugin.py",
    "src/analyze/hp/plugins/hp_checks_plugin.py",
    "src/analyze/arista/plugins/arista_checks_plugin.py",
    "src/analyze/sonicwall/plugins/sonicos_checks_plugin.py",
)


@pytest.mark.parametrize("relative_path", TARGET_PLUGIN_PATHS)
def test_every_target_finding_declares_references(relative_path):
    path = REPOSITORY_ROOT / relative_path
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    finding_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "Finding"
    ]

    assert finding_calls, f"{relative_path} contains no Finding construction"
    missing = [
        call.lineno
        for call in finding_calls
        if not any(keyword.arg == "references" for keyword in call.keywords)
    ]
    assert not missing, f"{relative_path} has uncited Finding calls at lines {missing}"


@pytest.mark.parametrize("relative_path", FOCUSED_PLUGIN_PATHS)
def test_focused_reference_constants_are_authoritative_https_urls(relative_path):
    path = REPOSITORY_ROOT / relative_path
    namespace = {}
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or not target.id.endswith(("_GUIDE", "_REFERENCE", "_DOCUMENTATION")):
            continue
        namespace[target.id] = ast.literal_eval(node.value)

    assert namespace, f"{relative_path} declares no reference constants"
    assert all(value.startswith("https://") for value in namespace.values())
    assert all(
        "cisco.com/" in value
        or "fortinet.com/" in value
        or "juniper.net/" in value
        for value in namespace.values()
    )
