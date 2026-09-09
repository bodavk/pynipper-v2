# Changelog for Agent

All notable changes made by the autonomous agent to `bodavk/pynipper-v2`.

## [Unreleased]
- Refactored architecture: Implemented `BaseDeviceParser` interface for pluggable parsing.
- Implemented parsers and infrastructure for:
  - Palo Alto PAN-OS
  - Fortinet FortiOS
  - Cisco IOS-XE
  - Juniper JunOS
  - Arista EOS
- Implemented and verified initial security plugins for all above devices.
- Automated testing: Configured `pytest` in CI (`.github/workflows/build-python.yml`) and added comprehensive test suite for all plugins.
- Completed initial parity checks for SonicWALL SonicOS (SW-01) and HP ProCurve (HP-01).
