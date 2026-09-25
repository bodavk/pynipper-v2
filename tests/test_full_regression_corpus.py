from collections import Counter

from scripts.run_full_regression import PROCESSORS, validate_corpus


def test_permanent_target_platform_regression_corpus():
    results = validate_corpus()

    assert {result["device"] for result in results} == set(PROCESSORS)
    # Check Point FW1 has paired inputs; FortiOS adds the PT-002 multi-line case.
    expected_counts = {device: 3 for device in PROCESSORS}
    expected_counts["CHECKPOINT_FW1"] = 2
    expected_counts["FORTIOS"] = 4
    assert Counter(result["device"] for result in results) == expected_counts
