"""Profile-justified snapshot caches preserve the uncached parser semantics."""
import pytest

from src.analyze.paloalto.plugins.panos_checks_plugin import PluginPANOSChecks
from src.devices.paloalto.panos import PaloAltoPANOSParser


OBJECTS = ('<address><entry name="A"><ip-netmask>192.0.2.0/24</ip-netmask></entry>'
           '<entry name="D"><fqdn>do-not-resolve.invalid</fqdn></entry></address>'
           '<address-group><entry name="C"><static><member>C</member><member>A</member></static></entry>'
           '<entry name="G"><static><member>A</member></static></entry></address-group>'
           '<service><entry name="S"><protocol><tcp><port>443</port></tcp></protocol></entry></service>'
           '<service-group><entry name="SC"><members><member>SC</member><member>S</member></members></entry></service-group>')
NAT = ('<nat><rules><entry name="n"><disabled>yes</disabled><source><member>A</member></source>'
       '<destination><member>any</member></destination><service>any</service></entry></rules></nat>')


def parse(tmp_path):
    source = tmp_path / "cache.xml"
    source.write_text('<config><devices><entry name="fw"><vsys><entry name="vsys1">' + OBJECTS
                      + '<rulebase>' + NAT + '</rulebase></entry><entry name="vsys2">'
                      + OBJECTS.replace('192.0.2.0/24', '198.51.100.0/24')
                      + '</entry></vsys></entry></devices></config>', encoding="utf-8")
    return PaloAltoPANOSParser(str(source))


@pytest.mark.parametrize("kind,names,limit", [
    ("network", ("A",), 4096), ("network", ("G",), 1), ("network", ("G",), 2),
    ("network", ("C",), 4096), ("network", ("MISSING",), 4096),
    ("network", ("D",), 4096), ("network", (), 4096), ("network", ("any",), 4096),
    ("service", ("S",), 4096), ("service", ("SC",), 4096),
    ("service", ("SC",), 1), ("service", ("application-default",), 4096),
    ("service", (), 4096),
])
def test_whole_selector_results_match_uncached_cycles_limits_unknowns(tmp_path, kind, names, limit):
    cached = parse(tmp_path)
    uncached = PaloAltoPANOSParser(cached.config_filepath)
    uncached.get_native_config()  # native mutable access deliberately disables caching
    for scope in ("vsys1", "vsys2"):
        method = "resolve_" + kind + "_semantics"
        args = {"device_scope": "fw", "scope": scope, "expansion_limit": limit}
        a = getattr(cached, method)(names, **args)
        assert a == getattr(uncached, method)(names, **args)
        assert getattr(cached, method)(names, **args) is a
    assert not uncached._policy_cache


def test_scope_parser_identity_and_limit_keys_are_independent(tmp_path):
    first = parse(tmp_path)
    kwargs = {"device_scope": "fw", "scope": "vsys1"}
    low = first.resolve_network_semantics(("G",), expansion_limit=1, **kwargs)
    high = first.resolve_network_semantics(("G",), expansion_limit=2, **kwargs)
    assert not low.complete and high.complete
    one = first.resolve_network_semantics(("A",), **kwargs)
    two = first.resolve_network_semantics(("A",), device_scope="fw", scope="vsys2")
    assert one != two
    second = PaloAltoPANOSParser(first.config_filepath)
    assert second.resolve_network_semantics(("A",), **kwargs) == one
    assert second._policy_cache is not first._policy_cache
    assert first.get_nat_rules() == second.get_nat_rules()
    assert first.get_nat_rules() is first.get_nat_rules()


def test_cache_is_bounded_and_reinitialization_invalidates_it(tmp_path):
    parser = parse(tmp_path)
    for number in range(600):
        parser.resolve_network_semantics((f"MISSING-{number}",), device_scope="fw", scope="vsys1")
    assert len(parser._policy_cache) <= 512
    parser.__init__(parser.config_filepath)
    assert not parser._policy_cache and parser._policy_cache_enabled


def test_retained_native_tree_mutation_cannot_reuse_snapshot_cache(tmp_path):
    parser = parse(tmp_path)
    kwargs = {"device_scope": "fw", "scope": "vsys1"}
    before = parser.resolve_network_semantics(("A",), **kwargs)
    native = parser.get_native_config()
    node = native.find("./devices/entry/vsys/entry/address/entry/ip-netmask")
    node.text = "203.0.113.0/24"
    after = parser.resolve_network_semantics(("A",), **kwargs)
    assert before != after
    node.text = "198.18.0.0/15"
    assert parser.resolve_network_semantics(("A",), **kwargs) != after
    assert not parser._policy_cache


def test_cached_and_uncached_findings_and_nat_qualification_are_identical(tmp_path):
    # Reuse the permanent synthetic timing workload's builders, not its timings.
    from test_policy_effectiveness_gap020 import STATIC_OBJECTS, _config, _rule
    source = tmp_path / "policy.xml"
    source.write_text(_config(STATIC_OBJECTS, _rule("P", "WIDE", "HOST", "WEB-RANGE")
                             + _rule("C", "NARROW", "HOST", "WEB-ONE"), nat=NAT), encoding="utf-8")
    cached, uncached = (PaloAltoPANOSParser(str(source)) for _ in range(2))
    uncached.get_native_config()
    outputs = []
    for parser in (cached, uncached):
        plugin = PluginPANOSChecks()
        plugin.check_rule_effectiveness(parser)
        outputs.append([f.to_dict() for f in plugin.get_issues()])
        a, b = parser.get_security_rules()
        assert parser.qualify_nat_comparison(a, b) == cached.qualify_nat_comparison(a, b)
    assert outputs[0] == outputs[1] and outputs[0]
