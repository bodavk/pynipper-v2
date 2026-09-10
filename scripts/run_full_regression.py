"""Run the permanent cross-platform parser/plugin regression corpus.

The manifest stores an exact, duplicate-preserving rule-ID snapshot for each
configuration.  Every case is parsed through the public device factory and
processed through the platform's public plugin pipeline.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from typing import Callable


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from src.analyze.checkpoint.core.process_checkpoint_fw1_conf import (  # noqa: E402
    process_checkpoint_fw1_conf,
)
from src.analyze.cisco.asa.core.process_asa_conf import process_asa_conf  # noqa: E402
from src.analyze.cisco.ios.core.process_cisco_ios_conf import (  # noqa: E402
    process_cisco_ios_conf,
)
from src.analyze.cisco.iosxe.core.process_iosxe_conf import process_iosxe_conf  # noqa: E402
from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf  # noqa: E402
from src.analyze.juniper.core.process_screenos_conf import process_screenos_conf  # noqa: E402
from src.analyze.juniper.junos.core.process_junos_conf import process_junos_conf  # noqa: E402
from src.devices import get_parser  # noqa: E402
from src.devices.registry import validate_device_registry  # noqa: E402


CORPUS_ROOT = REPOSITORY_ROOT / "tests" / "test_data" / "regression"
MANIFEST_PATH = CORPUS_ROOT / "manifest.json"

PROCESSORS: dict[str, Callable] = {
    "IOS_ROUTER": process_cisco_ios_conf,
    "IOS_XE": process_iosxe_conf,
    "ASA": process_asa_conf,
    "FORTIOS": process_fortios_conf,
    "JUNOS": process_junos_conf,
    "SCREENOS": process_screenos_conf,
    "CHECKPOINT_FW1": process_checkpoint_fw1_conf,
}


def _load_cases() -> list[dict]:
    with MANIFEST_PATH.open(encoding="utf-8") as manifest_file:
        manifest = json.load(manifest_file)
    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise AssertionError("Regression manifest must contain a non-empty 'cases' list")
    names = [case.get("name") for case in cases]
    inputs = [case.get("input") for case in cases]
    if len(names) != len(set(names)):
        raise AssertionError("Regression case names must be unique")
    if len(inputs) != len(set(inputs)):
        raise AssertionError("Regression input paths must be unique")
    return cases


def _analyze_case(case: dict) -> tuple[list[str], int]:
    device = case["device"]
    try:
        processor = PROCESSORS[device]
    except KeyError as exc:
        raise AssertionError(f"No public processor registered for corpus device {device}") from exc

    config_path = (CORPUS_ROOT / case["input"]).resolve()
    if CORPUS_ROOT.resolve() not in config_path.parents:
        raise AssertionError(f"Corpus input escapes regression directory: {config_path}")
    if not config_path.exists():
        raise AssertionError(f"Corpus input does not exist: {config_path}")

    parser = get_parser(device, str(config_path))
    parser.get_normalized_config()
    with redirect_stdout(StringIO()):
        findings = list(processor(parser).values())

    identities = [
        (finding.rule_id, tuple(finding.evidence) or (finding.observation,))
        for finding in findings
    ]
    if len(identities) != len(set(identities)):
        raise AssertionError(f"{case['name']}: duplicate rule/evidence identities emitted")

    return sorted(finding.rule_id for finding in findings), len(findings)


def validate_corpus(*, observe: bool = False) -> list[dict]:
    """Validate all cases and return their observed exact snapshots."""

    validate_device_registry()
    results = []
    for case in _load_cases():
        actual_rule_ids, actual_count = _analyze_case(case)
        result = {
            "name": case["name"],
            "device": case["device"],
            "input": case["input"],
            "expected_rule_ids": actual_rule_ids,
            "expected_finding_count": actual_count,
        }
        results.append(result)
        if observe:
            continue

        expected_rule_ids = sorted(case["expected_rule_ids"])
        expected_count = case["expected_finding_count"]
        if actual_rule_ids != expected_rule_ids or actual_count != expected_count:
            raise AssertionError(
                f"{case['name']}: regression mismatch\n"
                f"expected IDs={expected_rule_ids!r}, count={expected_count}\n"
                f"actual IDs={actual_rule_ids!r}, count={actual_count}"
            )
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus-only",
        action="store_true",
        help="Validate the permanent corpus without running the full pytest suite.",
    )
    parser.add_argument(
        "--observe",
        action="store_true",
        help="Print current snapshots without comparing them to the manifest.",
    )
    args = parser.parse_args()

    results = validate_corpus(observe=args.observe)
    if args.observe:
        print(json.dumps({"cases": results}, indent=2))
        return 0

    for result in results:
        print(
            f"PASS {result['name']} ({result['device']}): "
            f"{result['expected_finding_count']} findings"
        )
    print(f"Regression corpus passed: {len(results)} configurations")

    if args.corpus_only:
        return 0
    return subprocess.run(
        [sys.executable, "-m", "pytest", "tests", "-q"],
        cwd=REPOSITORY_ROOT,
        check=False,
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
