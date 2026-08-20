# Architecture & Style Conventions

## 1. Core Architecture

### Base Classes
- **Plugins**: All plugins must inherit from `GenericPlugin` (in `src/analyze/cisco/ios/core/base_plugin.py`).
  - `analyze(self, config_file)`: Must be overridden. It performs the analysis and calls `self.add_issue(issue)`.
  - `self.parse_cisco_ios_config_file(filename)`: Helper in `GenericPlugin` to get a `CiscoConfParse` object.
- **Issues**: All findings must be instances of `CiscoIOSIssue` (in `src/analyze/cisco/ios/issue/cisco_ios_issue.py`).
  - Constructor: `__init__(self, title, observation, impact, ease, recommendation)`.
  - Note: There is currently no `severity` field; `impact` and `ease` are used for descriptive assessment.

### Device Parsers
- Currently, device parsing is implemented as a set of standalone functions in `src/analyze/cisco/ios/cisco_parser/parse_config.py`.
- They typically take a `filename: str` and return a specific value (e.g., `str`, `bool`, `int`).
- They use `CiscoConfParse` for regex-based extraction.

### Registration & Discovery
- Plugins are dynamically discovered in `src/analyze/cisco/ios/core/process_cisco_ios_conf.py`.
- The `_import_modules()` function searches for modules in `src/analyze/cisco/ios/plugins/` that end with `_plugin`.
- It instantiates all classes found in those modules and calls their `analyze()` method.

## 2. Naming Conventions

### Files
- Plugins: `*_plugin.py` (e.g., `http_plugin.py`).
- Core components: snake_case (e.g., `base_plugin.py`, `parse_config.py`).

### Classes
- Plugins: `Plugin<Name>` in PascalCase (e.g., `PluginHTTP`, `PluginSSH`).
- Issues: `CiscoIOSIssue`.

### Methods & Variables
- Standard Python `snake_case`.
- Internal helper methods in plugins are prefixed with an underscore (e.g., `_has_http(self, filename)`).

## 3. Configuration Representation
- **Internal representation**: Uses `ciscoconfparse.CiscoConfParse` for the configuration file.
- **Data shape**: Issues are collected into a dictionary where keys are formatted as `"2.<plugin_index>.<finding_index>. <Title>"` and values are `CiscoIOSIssue` objects.

## 4. Regex Patterns
- Organised within helper methods.
- Use `parser.find_objects("^pattern")` for section/line matching.
- Use `obj.re_match_typed(r'pattern\s+(\S+)', default='')` for value extraction.

## 5. Testing Conventions
- **Current Status**: No automated unit tests exist in the project (as of Phase 0).
- **Test Data**: Sample configurations are stored in `tests/test_data/`.
- **Framework**: `pytest` is the intended framework (per `agent_instructions_pynipper.md`).

## 6. Docstrings & Comments
- Limited use of docstrings in existing code.
- Comments often use `#` for short descriptions.
- `# noqa: E501` is used to suppress long line warnings in issue descriptions.

## 7. Deviations & Proposals
- **BaseDevice Interface**: The `agent_instructions_pynipper.md` mentions a `BaseDevice` interface which is not yet present. This should be implemented when expanding to new vendors to allow for cleaner abstraction.
- **Severity Field**: Nipper-ng traditionally uses severity (Critical, High, etc.). Adding this to `CiscoIOSIssue` would improve report clarity.
