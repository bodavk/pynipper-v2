import pytest
from src.devices.juniper.junos import JunOSParser
from src.analyze.juniper.junos.plugins.baseline_plugin import PluginJunOSBaseline
from src.main import main

PREFIX = "system services extension-service request-response grpc"
BOUND = f"set {PREFIX} clear-text address 192.0.2.1\nset {PREFIX} clear-text port 50051\n"


def scan(tmp_path, body):
    source = tmp_path / "grpc.conf"
    source.write_text("set version 22.4R1.10\n" + body, encoding="utf-8")
    parser = JunOSParser(str(source))
    plugin = PluginJunOSBaseline()
    plugin.check_grpc_listener(parser)
    return parser, plugin.get_issues()


def test_explicit_network_listener_with_vrf_and_authentication_metadata(tmp_path):
    parser, findings = scan(tmp_path, BOUND + f"set {PREFIX} routing-instance mgmt_junos\n"
                            f"set {PREFIX} skip-authentication\n")
    state = parser.get_grpc_cleartext_listener()
    assert state.routing_instance == "mgmt_junos" and state.skip_authentication
    assert len(findings) == 1
    assert findings[0].rule_id == "juniper.junos.management.grpc_cleartext"
    assert findings[0].evidence_locations


@pytest.mark.parametrize("body", [
    BOUND.replace("192.0.2.1", "127.0.0.1"),
    BOUND.replace("192.0.2.1", "::1"),
    BOUND.replace("192.0.2.1", "invalid"),
    BOUND.replace("50051", "invalid"),
    BOUND.replace("50051", "9" * 5000),
    BOUND.replace("clear-text", "ssl"),
    BOUND + f"delete {PREFIX} clear-text\n",
    BOUND + f"deactivate {PREFIX}\n",
    BOUND + "set system apply-groups inherited\n",
    f"set {PREFIX} clear-text port 50051\n",
    f"set {PREFIX} skip-authentication\n",
    BOUND + f"set {PREFIX} clear-text address 127.0.0.1\n",
])
def test_unresolved_local_encrypted_or_inactive_bindings_not_reported(tmp_path, body):
    assert scan(tmp_path, body)[1] == []


def test_hierarchical_equivalent(tmp_path):
    source = tmp_path / "hier.conf"
    source.write_text("version 22.4R1.10; system { services { extension-service { "
                      "request-response { grpc { clear-text { address 192.0.2.1; port 50051; } "
                      "skip-authentication; } } } } }", encoding="utf-8")
    state = JunOSParser(str(source)).get_grpc_cleartext_listener()
    assert state.resolution_state == "network" and state.skip_authentication


@pytest.mark.parametrize("format", ["JSON", "HTML"])
def test_public_report(tmp_path, format):
    scan(tmp_path, BOUND)
    output = tmp_path / ("report." + format.lower())
    assert main(["-d", "junos", "-i", str(tmp_path / "grpc.conf"), "-o", format,
                 "-f", str(output)]) == 0
    assert "gRPC service uses clear-text network transport" in output.read_text(encoding="utf-8")
