# Phase 0: Baseline Documentation

## Commit Hashes
- **origin/main**: 07b5ee7a5cc9a2f77126dbb4d71d783ee6da3886
- **upstream/main**: 58957659205bcf656f1f209b26be51d1d508b9f9

---

## README.md
# pynipper-ng

[![CodeQL](https://github.com/syn-4ck/pynipper-ng/actions/workflows/codeql-analysis.yml/badge.svg?branch=main)](https://github.com/syn-4ck/pynipper-ng/actions/workflows/codeql-analysis.yml)
[![GitGuardian scan](https://github.com/syn-4ck/pynipper-ng/actions/workflows/gitguardian-scan.yml/badge.svg)](https://github.com/syn-4ck/pynipper-ng/actions/workflows/gitguardian-scan.yml)
[![Snyk SCA analysis](https://github.com/syn-4ck/pynipper-ng/actions/workflows/snyk.yml/badge.svg)](https://github.com/syn-4ck/pynipper-ng/actions/workflows/snyk.yml)
[![SonarCloud Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=syn-4ck_pynipper-ng&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=syn-4ck_pynipper-ng)
[![Flake8 CI](https://github.com/syn-4ck/pynipper-ng/actions/workflows/flake8.yml/badge.svg?branch=main)](https://github.com/syn-4ck/pynipper-ng/actions/workflows/flake8.yml)
[![Build pynipper-ng with python3](https://github.com/syn-4ck/pynipper-ng/actions/workflows/build-python.yml/badge.svg)](https://github.com/syn-4ck/pynipper-ng/actions/workflows/build-python.yml)
[![Yaml Lint](https://github.com/syn-4ck/pynipper-ng/actions/workflows/yaml-lint.yml/badge.svg)](https://github.com/syn-4ck/pynipper-ng/actions/workflows/yaml-lint.yml)


## Table of contents
1. [What is pynipper-ng](#what-is-pynipper-ng)
2. [Install](#install)
3. [Quickstart](#quickstart)
4. [More information](#more-information)
5. [References](#references)

## What is pynipper-ng?
pynipper-ng is a **configuration security analyzer for network devices**. The goal of this tool is check the vulnerabilities and misconfigurations of routers, firewalls and switches reporting the issues in a simple way.

This tool is based on [nipper-ng](https://github.com/arpitn30/nipper-ng), updated and translated to Python. The project wants to improve the set of rules that detect security misconfigurations of the network devices using multiple standard benchmarks (like [CIS Benchmark](https://www.cisecurity.org/cis-benchmarks/)) and integrate the tool with APIs (like [PSIRT Cisco API](https://developer.cisco.com/docs/psirt/#!overview/overview)) to scan known vulnerabilities. 

## Install

The requirements are:

* Python 3
* Pip to Python 3

### Python install

You can install pynipper-ng with pip using the wheel package linked in each version of the tool.

```BASH
pip install pynipper_ng-<VERSION>-py3-none-any.whl
```

_It will be in `pypi` registry soon._

### Source code install

Clone this repository and run:

```BASH
python setup.py build install
```

## Quickstart and options

### Quickly demo

```BASH
pynipper-ng -d IOS_ROUTER -i tests\test_data\cisco_ios_example.conf -o HTML -f ./report.html -x
```

### Options

| Flag | OPTION        | DESCRIPTION                                                                                                      | MANDATORY? | DEFAULT VALUE |
|------|---------------|------------------------------------------------------------------------------------------------------------------|------------|--------------|
| -h   | --help        | Display a help message                                                                                           | NO         | N/A             |
| -d   | --device      | Device type to analyze (1)                                                                                       | YES        |             |
| -i   | --input       | Configuration device file to analyze (file contains standard output redirection of `show configuration` command) | YES        |             |
| -o   | --output-type | Report type (HTML or JSON)                                                                                       | NO         | HTML          |
| -f   | --output-filename | Report filename                                                                                              | NO         | report.html
| -x   | --offline         | Disable APIs integration                                                                                     | NO         | True             |
| -c   | --configuration   | Configuration file to pynipper-ng (2)                                                                        | NO         | default.conf    |


(1) Check [here](src/devices/README.md) the devices supported

(2) Check [Pynipper-ng configuration file](#config-file) to know more about it.

## More information

### Pynipper-ng Configuration File

The configuration file is used to define some properties and customize the scans.

#### Pynipper-ng Configuration File: PSIRT Cisco API

To use the PSIRT Cisco API you must provide the API keys. To get it: [https://apiconsole.cisco.com/](https://apiconsole.cisco.com/)

```conf
[Cisco]
CLIENT_ID = <your-client-id>
CLIENT_SECRET = <your-client-secret-token>
```

### Contributing

Contribution are welcome! Please follow the steps defined in CONTRIBUTING file and share your improvements with the community.

### CISCO IOS API integration

Get your credentials and put into the configuration file.

### Pynipper modules

Pynipper-ng detects device configuration weaknesses based on modules. Pynipper modules checks into the network device configuration with regex if a property is set or not, and report it when this is not secure.

#### Pynipper modules summary

Available plugins: [check here](src/analyze/README.md)

#### Implements your modules

You can implements your own modules. You should clone the repository and create the plugins in `src/analyze/cisco/<device_type>/plugins`. To improve the pynipper-ng tool you can contribute adding your work :).

To create your own plugins, follow [this guidelines](src/analyze/README.md)

## References
[nipper-ng](https://github.com/arpitn30/nipper-ng)

---

## CONTRIBUTING.md
# Contributing to pynipper-ng

Welcome developer, thanks for contributing to the project!

Reading and following these guidelines will help me make the contribution process easy and effective for everyone involved. It also communicates that you agree to respect the time of the developers managing and developing these open source projects. In return, we will reciprocate that respect by addressing your issue, assessing changes, and helping you finalize your pull requests.

## Quicklinks

- [Contributing to pynipper-ng](#contributing-to-pynipper-ng)
  - [Quicklinks](#quicklinks)
  - [Code of Conduct](#code-of-conduct)
  - [Getting Started](#getting-started)
    - [Issues](#issues)
    - [Pull Requests](#pull-requests)

## Code of Conduct

We take our open source community seriously and hold ourselves and other contributors to high standards of communication. By participating and contributing to this project, you agree to uphold our [Code of Conduct](https://github.com/syn-4ck/pynipper-ng/blob/master/CODE_OF_CONDUCT.md).

## Getting Started

Contributions are made to this repo via Issues and Pull Requests (PRs). A few general guidelines that cover both:

- To report security vulnerabilities, please check our [Security guide](https://github.com/syn-4ck/pynipper-ng/blob/master/SECURITY.md).
- Search for existing Issues and PRs before creating your own.
- We work hard to makes sure issues are handled in a timely manner but, depending on the impact, it could take a while to investigate the root cause. A friendly ping in the comment thread to the submitter or a contributor can help draw attention if your issue is blocking.

### Issues

Issues should be used to report bugs, request a new feature, or to discuss potential changes before a PR is created. When you create a new Issue, a template will be loaded that will guide you through collecting and providing the information we need to investigate.

Please, fill the template issues with all possible data, attaching screenshots and detailed information. We will review, tag and assign this issues soon.

### Pull Requests

PRs are always welcome and can be a quick way to get your fix or improvement. In general, PRs should:

- Only fix/add the functionality in question.
- Include documentation and a properly description in the repo.
- All actions must be passed.

In general, we follow a fork model:

1. Fork the repository to your own Github account
2. Clone the project to your machine
3. Create a branch locally with a succinct but descriptive name
4. Install pre-commit with `pip install pre-commit` and configure it with `pre-commit install`.
5. Commit changes to the branch
6. Following any formatting and testing guidelines specific to this repo
7. Push changes to your fork
8. Open a PR in our repository. The PR must be merged into the pynipper-ng **develop** branch.

---

## TODO.md

## Core tasks

- [ ] Translate nipper-ng checks to pynipper-ng modules (issue #4)

## Secondary tasks

- [ ] Unit tests and build/testing un CI (issue #42)

---

## src/devices/README.md
# Devices

## Devices supported now

`IOS_SWITCH`: Cisco IOS-based Switch

`IOS_ROUTER`: Cisco IOS-based Router

`IOS_CATALYST`: Cisco IOS-based Catalyst

## Devices in TODO list

`PIX`: Cisco PIX-based Firewall

`ASA`: Cisco ASA-based Firewall

`FWSM`: Cisco FWSM-based Router

`CATOS`: Cisco CatOS-based Catalyst

`NMP`: Cisco NMP-based Catalyst

`CSS`: Cisco Content Services Switch

`SCREENOS`: Juniper NetScreen Firewall

`PASSPORT`: Nortel Passport Device

`SONICOS`: SonicWall SonicOS Firewall

`FW1`: CheckPoint Firewall-1 Firewall

---

## src/analyze/README.md
# Device analysis

## Plugins

To detect misconfigurations in network devices, pynipper-ng uses a regex engine based on plugins.

Plugins are python classes with a `analyze` method that searches in the configuration file and reports vulnerable patterns. This plugins are splitted by protocols, goals or tecnologies.

### Available plugins

**Cisco IOS devices**

| Plugin name          | Scan goal                                        |
|----------------------|--------------------------------------------------|
| http_plugin          | Detect HTTP misconfigurations                    |
| ssh_plugin           | Detect SSH misconfigurations                     |

### Create new plugins

To create your own plugins you need to create a new file in `./<device_type>/plugins` named `<something>_plugin.py` and develop a new class. The class must:

* Extend `./<device_type>/core/base_plugin.py`
* Override the `def analyze(self, config_file):` function

You can see the other plugins to verify your implementation.

---

## CHANGELOG.md
# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
