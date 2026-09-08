# Task: Core Architecture Refactoring — Pluggable Device Parsers

## Status
- [x] Completed (Implemented pluggable BaseDeviceParser, CiscoIOSParser subclass, and refactored core engine/plugins to use it, with full pytest verification)

## Priority
BLOCKING — This refactor must be completed **before** implementing any non-Cisco devices (both Phase 2 and Phase 3).

## Context & Problem
The current codebase assumes that every device config is line-based, uses Cisco IOS style indentation, and is parsed with `ciscoconfparse` inside the standard plugin analyzer loop. This Cisco-centric coupling prevents us from clean scaling:
- Non-Cisco CLI formats (e.g., HP ProCurve, Juniper ScreenOS) have different rules and shouldn't use `ciscoconfparse` directly.
- Modern structured configuration families (XML/JSON for Palo Alto PAN-OS, or curly braces `{ }` for JunOS) cannot be loaded with classic line-based patterns.

## Target Architecture

We need to introduce a pluggable parser/adapter interface to decouple the analysis engine from the configuration format.

```
                  ┌──────────────────────┐
                  │    cli/main loop     │
                  └──────────┬───────────┘
                             │ (Selects Device Type)
                             ▼
                  ┌──────────────────────┐
                  │    DeviceFactory     │
                  └──────────┬───────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │    IDeviceParser     │  ◄── (Interface: get_hostname, get_users, etc.)
                  └─────┬────┬────┬──────┘
                        │    │    │
         ┌──────────────┘    │    └──────────────┐
         ▼                   ▼                   ▼
┌────────────────┐  ┌────────────────┐  ┌────────────────┐
│  CiscoIOSParse │  │  PANOSXMLParse │  │  FortiOSParse  │  ...
└────────────────┘  └────────────────┘  └────────────────┘
```

## Requirements

1.  **Define interface/base class** `BaseDeviceParser` in `src/devices/common/base_parser.py`:
    - `__init__(self, config_filepath)`
    - `get_hostname(self) -> str`
    - `get_version(self) -> str`
    - `get_users(self) -> list[dict]`
    - `get_services(self) -> dict`
    - `get_raw_config(self) -> Any` (to return native representation like dict, XML tree, or CiscoConfParse)

2.  **Define base class** `BasePlugin` in `src/analyze/common/base_plugin.py` which accepts `BaseDeviceParser` as an dependency rather than a raw config file.

3.  **Refactor Device Registration**:
    - Update `DeviceType` enum to match registered parsers.
    - Implement a factory to instantiate the correct `BaseDeviceParser` subclass based on `-d` CLI input.

4.  **Refactor Existing IOS Code**:
    - Port `src/analyze/cisco/ios/cisco_parser/parse_config.py` functions to implement the `CiscoIOSParser` subclass.
    - Update `PluginHTTP` and `PluginSSH` to interact with `CiscoIOSParser` instead of executing raw `CiscoConfParse` inline where possible (or make them use `get_raw_config()` specifically if they rely heavily on `CiscoConfParse` objects).

## Acceptance Criteria
- [x] New `BaseDeviceParser` abstract interface created.
- [x] Existing Cisco IOS parsing encapsulated under a clean `CiscoIOSParser` implementation of that interface.
- [x] No regression on existing Cisco IOS tests or sample outputs.
- [x] Test suite runs successfully.
