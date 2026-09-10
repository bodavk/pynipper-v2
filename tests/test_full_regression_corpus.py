from collections import Counter

from scripts.run_full_regression import PROCESSORS, validate_corpus


def test_permanent_target_platform_regression_corpus():
    results = validate_corpus()

    assert {result["device"] for result in results} == set(PROCESSORS)
    assert Counter(result["device"] for result in results) == {
        device: 2 for device in PROCESSORS
    }
