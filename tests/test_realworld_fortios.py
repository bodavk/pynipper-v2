"""Sanitized reproductions of RV-012, derived from RW-031's command structure.

The deployment template and its credentials are not copied into the fixtures.
"""

import json
import subprocess
import sys

import pytest

from src.devices.fortinet.fortios import FortiOSParser
from src.devices.common.models import ConfigurationState
from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf


def test_end_saves_nested_entry_and_table_without_losing_vdom(tmp_path):
    path = tmp_path / "nested.conf"
    path.write_text("""config vdom
edit root
config firewall policy
edit 1
set action accept
set service ALL
end
config firewall policy
edit 2
set action accept
set status disable
end
end
config vdom
edit root
config firewall policy
edit 1
set service HTTPS
next
end
end
config global
config system global
set admintimeout 60
end
end
config global
config system global
set admintimeout 15
end
end
""", encoding="utf-8")
    parser = FortiOSParser(str(path))
    native = parser.get_native_config()
    policies = native["vdom"]["root"]["firewall policy"]
    assert policies["1"]["service"] == "HTTPS"
    assert policies["2"]["status"] == "disable"
    assert native["global"]["system global"]["admintimeout"] == "15"
    normalized = parser.get_normalized_config().policies.items
    assert [(p.name, p.state, p.scope) for p in normalized] == [
        ("1", ConfigurationState.ENABLED, "root"),
        ("2", ConfigurationState.DISABLED, "root"),
    ]


@pytest.mark.parametrize("output_type", ["JSON", "HTML"])
def test_cli_reports_parse_failure_without_traceback_or_source_values(tmp_path, output_type):
    path = tmp_path / "malformed.conf"
    secret = "synthetic-private-marker"
    path.write_text(f"config table\nset {secret} value\nconfig {secret}\n", encoding="utf-8")
    report = tmp_path / ("report." + output_type.lower())
    result = subprocess.run(
        [sys.executable, "-m", "src.main", "--device", "FORTIOS", "--input", str(path),
         "--output-type", output_type, "--output-filename", str(report), "--offline"],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 2
    text = report.read_text(encoding="utf-8")
    assert secret not in text + result.stdout + result.stderr
    assert "Traceback" not in result.stdout + result.stderr
    assert "line 3" in text
    assert "parse_error" in text
    if output_type == "JSON":
        data = json.loads(text)
        assert data["security-audit"] == {}
        assert data["configuration-inventory"] == {}
        assert len(data["coverage"]["fields"]) == 9
        assert all(f["knowledge-state"] == "parse_error" for f in data["coverage"]["fields"])


@pytest.mark.parametrize("local", ["enable", "disable", "invalid", None])
@pytest.mark.parametrize("remote", ["enable", "disable"])
def test_local_logging_does_not_substitute_for_remote_forwarding(tmp_path, local, remote):
    path = tmp_path / "logging.conf"
    local_line = "" if local is None else f"set status {local}\n"
    path.write_text(
        "config log disk setting\n" + local_line + "end\n"
        "config log syslogd setting\nset server 192.0.2.10\nset status enable\n"
        f"set status {remote}\nend\n", encoding="utf-8",
    )
    parser = FortiOSParser(str(path))
    disk = next(d for d in parser.get_normalized_config().logging_destinations.items
                if d.destination_type == "local-disk")
    assert disk.state == {"enable": ConfigurationState.ENABLED,
                          "disable": ConfigurationState.DISABLED}.get(local, ConfigurationState.UNKNOWN)
    findings = [f for f in process_fortios_conf(parser).values()
                if f.rule_id == "fortinet.fortios.logging.missing"]
    assert bool(findings) == (remote == "disable")
    if findings:
        assert findings[0].title == "Remote security logging is not configured"
        assert ("Local logging is explicitly enabled" in findings[0].observation) == (local == "enable")
