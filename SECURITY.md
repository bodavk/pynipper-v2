# Security Policy

## Reporting a vulnerability

Please report vulnerabilities in pynipper-v2 privately through [GitHub Security Advisories](https://github.com/bodavk/pynipper-v2/security/advisories/new). Include the affected version or revision, impact, reproduction steps, and any relevant CWE/CVE identifiers. Do not attach real device credentials or unsanitized customer configurations.

Configuration findings produced by the tool are not vulnerabilities in pynipper-v2 itself. Rule false positives, false negatives, parser failures, and missing device syntax may be reported as normal project defects after removing sensitive configuration content.

Normal reports keep credential evidence redacted. The explicit `--show-secrets` option creates a sensitive report with a separate appendix of selected unmasked source lines; it does not recover hashed or unexported values and is not a complete inventory of every possible secret. Supply `-f` with a new output path in an access-controlled directory, review local ACLs before sharing, and never upload such a report to an issue or public artifact store. The CLI refuses to overwrite an existing report in this mode.

## Supported versions

The actively maintained state is the current default branch. Historical upstream alpha releases (`0.1.x` and `0.2.0 ALPHA`) are not maintained by this fork.
