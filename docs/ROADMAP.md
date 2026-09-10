# Roadmap

## Wave 5 — Target quality closure

- Attach vendor/benchmark references to every finding from the older focused IOS, IOS-XE, ASA, FortiOS, Junos, and ScreenOS plugins.
- Add sanitized real-export syntax variants and malformed/truncated cases to the permanent corpus.
- Maintain `scripts/run_full_regression.py` and its cross-platform repository workflow as the target-platform quality gate.

## Wave 6 — Deferred secondary vendors

- Palo Alto PAN-OS: parser scope/reference reconstruction, effective policy checks, and baseline expansion.
- HP ProCurve/ArubaOS-Switch: grammar/default corrections and broader baseline.
- SonicWall SonicOS: identify and enforce an authoritative export dialect before expanding checks.
- Arista EOS: correct eAPI effective state and add EOS-specific baseline coverage.

## Future expansion decisions

Legacy original-Nipper dialects and new platforms should be ranked by observed configuration volume, available authoritative documentation, safe parser feasibility, and maintenance cost. Registry entries are added only with an explicit input format and tested analyzer path; target-baseline status additionally requires paired permanent corpus coverage.
