# Validation Results: Cisco IOS Router

## Sample Configuration Used
- **File**: `tests/test_data/cisco_ios_example.conf`
- **Source**: Included in repository.

## Parser Issues Found
- Hostname extraction: **SUCCESS** (`retail`).
- Version extraction: **SUCCESS** (`12.3`).
- Many parsed fields (password encryption, bootp, etc.) are extracted but not utilized by any plugin.

## Plugin Issues Found
- **PluginHTTP**:
    - `HyperText Transport Protocol Service`: Correctly identified HTTP as enabled.
    - `ACL restrict for HTTP service`: Correctly identified missing access-class.
    - `Authentication mode to HTTP service`: Correctly identified missing authentication mode, but the **observation text is incorrect** (copy-pasted from ACL check).
- **PluginSSH**:
    - `SSH Protocol Version`: Correctly identified missing version 2.
    - `SSH retries misconfiguration`: Correctly identified missing config.
    - `SSH timeout misconfiguration`: Correctly identified missing config.
    - `SSH source-interface enabled`: Correctly identified missing config.

## Missing Checks (False Negatives)
- `no service password-encryption` is present but not flagged (needs a plugin).
- Telnet is enabled (`transport input all`) but not flagged (needs a plugin).
- `enable password cisco123` (Type 0) is present but not flagged (needs a plugin).
- SNMP is not checked.
- Logging is not checked.

## Fixes Recommended
- Fix observation text in `PluginHTTP.get_cisco_ios_http_auth`.
- Implement plugins for global configuration gaps (password encryption, etc.).
