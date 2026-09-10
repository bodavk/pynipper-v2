# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Replaced inherited project documentation with current pynipper-v2 architecture, extension, support, validation, contribution, and security guidance.
- Made Cisco IOS plugin registration explicit and deterministic, matching the other public platform processors.
- Corrected `--offline` so it actually disables external advisory lookup.
- Modernized the generated HTML report language and removed its runtime jQuery dependency.
- Replaced inherited Python 3.6-era automation with a current cross-platform full-regression workflow and supported CodeQL workflow; removed unconfigured third-party service and obsolete lint workflows.

### Removed

- Removed superseded ASA wrapper pipelines, duplicate legacy ASA plugins, unused compatibility parser/issue/registry modules, obsolete generated test-output fixtures, and an unused runtime dependency.

The entries below are retained as historical release notes from the original pynipper-ng project.

## [0.2.0 ALPHA] - 2022-01-27

### Changed
- Changes in code architecture: new package structure and new plugins creation
- Improve CI workflow: security controls, QA analysis, build checks

### Fixed
- HTTP plugin analysis: fix in HTTP rules detection


## [0.1.1 ALPHA] - 2021-05-01

### Added
- PIP install package

### Fixed
- Setup script to install the tool
- Multiple installation errors due to import modules
- Pynipper-ng modules bugs

## [0.1.0 ALPHA] - 2021-04-11

### Added
- CLI basic scan of Cisco IOS missconfigurations
- First scan modules: SSH & HTTP administration vulnerabilities
- Integration with Cisco API to get IOS vulnerabilities of device version
- JSON & HTML report

### Changed

### Deprecated

### Removed

### Fixed

### Security

