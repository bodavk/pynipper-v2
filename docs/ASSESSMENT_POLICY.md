# Assessment policy

The optional assessment policy supplies facts that cannot be established safely from a configuration export alone. It is a JSON object loaded with `--assessment-policy`. Omitting it uses the deterministic `pynipper-v2/default-v1` policy: unknown device/interface roles and no category exclusions.

```json
{
  "policy_version": "organization-network-audit-v1",
  "device_role": "external",
  "interface_roles": {
    "GigabitEthernet0/0": "external",
    "GigabitEthernet0/1": "internal",
    "GigabitEthernet0/2": "voice-fabric"
  },
  "protected_aaa_profiles": ["root:LEGACY-RADIUS"],
  "configuration_backup_scope": "external-managed",
  "minimum_plaintext_credential_length": 15,
  "credential_blocklist_sha256": [
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  ],
  "assessment_time": "2026-09-14T12:00:00Z",
  "management_certificate_identities": {
    "localhost.localdomain": "firewall.example.com",
    "outside": "asa.example.com"
  },
  "trusted_certificate_sha256": [
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  ],
  "report_inventory": ["interfaces", "policies"],
  "excluded_categories": ["discovery"]
}
```

Supported roles are `unknown`, `internal`, `external`, `management`, `access-edge`, `uplink`, and `voice-fabric`. Names are matched case-insensitively but otherwise exactly; there is no wildcard or interface-name guessing. An unknown role never becomes external or trusted automatically.

`protected_aaa_profiles` contains exact, case-insensitive `scope:name` selectors for AAA profiles whose traffic is carried over a separately verified encrypted path, such as an IPsec tunnel. FortiOS administrative RADIUS uses its profile scope/name; Junos administrative RADIUS uses `system:<server-address>`. This declaration records topology evidence that is not present in the device export; it does not validate the tunnel, suppress explicit protocol-integrity failures, or make a legacy protocol intrinsically secure. Omitted profiles retain an unknown path, which is not automatically a finding.

`configuration_backup_scope` accepts `unspecified`, `external-managed`, or `on-device-required`. The default `unspecified` and an explicit `external-managed` value do not turn an absent device-side schedule into a finding, because an exported configuration cannot show an external API, configuration manager, or orchestration backup. `on-device-required` enables the qualified missing-schedule checks for IOS/IOS-XE, Junos, and identified FortiOS 7.x exports. Explicitly insecure or internally incomplete device-side backup configuration is still reported regardless of this scope. The setting never proves backup delivery, retention, storage protection, integrity, or restore success.

Credential property policy remains secret-free at the report boundary. `minimum_plaintext_credential_length` accepts an integer from 1 through 1024 and is evaluated only when the vendor parser proves that the supplied effective value is plaintext; hashes, reversible encodings, malformed values, and opaque/redacted exports never receive an inferred length verdict. `credential_blocklist_sha256` accepts unique 64-character SHA-256 digests of operator-approved blocked plaintext values. The raw configured value is compared only inside the parser, and neither it nor the supplied digest list is serialized into reports; report policy metadata contains only the blocklist entry count. This blocklist is an exact comparison aid, not password cracking or a strength guarantee. The active `policy_version` is attached to the shared credential-property result.

Certificate material assessment is enabled only by explicit inputs:

- `assessment_time` is an ISO-8601 timestamp with a UTC offset. It freezes inclusive not-before/not-after evaluation; the analyzer never substitutes the computer's current clock.
- `management_certificate_identities` maps an exact parser scope to the intended DNS name or IP address. PAN-OS uses its device-entry scope (commonly `localhost.localdomain`); ASA uses the assigned interface name or `default`; FortiOS uses the `system global` scope (usually `root`, or `global` in global-mode exports). Identity matching uses subjectAltName, not an inferred hostname.
- `trusted_certificate_sha256` lists approved 64-character SHA-256 fingerprints. A fingerprint can anchor validation only when that public certificate is also present in the supplied export. Missing anchors remain unknown rather than trusted or failed.

The analyzer parses public DER/PEM material locally. It records public metadata, validity, identity, key/signature policy and supplied-chain verification as independent results. These inputs do not establish revocation status, a client's actual trust store, or which certificate the appliance currently serves. Certificate and private-key payloads are never included in findings or assessment-policy metadata.

`report_inventory` is an optional list containing any of `interfaces`, `management-services`, `policies`, and `logging-destinations`. It is empty by default. Selected sections serialize only the corresponding normalized typed records and omit configuration evidence, local-user/credential records, certificate material, and raw configuration. A selected field is included only when its normalized knowledge state is `known`; unavailable fields remain visible in the coverage ledger instead of becoming empty inventory or implied passes. Inventory entries are configuration data, not security findings or compliance results.

`excluded_categories` accepts rule-ID category tokens such as `discovery`, `routing`, or `snmp`. Exclusions are applied after parsing and rule evaluation. They therefore do not discard configuration evidence, but their findings are omitted from the delivered report. Every HTML and JSON report records the policy version, provenance, roles, exclusions, and the explicit warning that excluded categories were not assessed and are not implied secure.

The policy file is validated before the scan. Unknown fields, unsupported roles, duplicate interface identities, malformed JSON, and invalid category names fail closed. The file should contain no credentials or customer secrets.

## Current boundary

Explicit interface roles currently enable trust-boundary CDP/LLDP analysis on IOS/XE and Junos and access-edge analysis on IOS/XE and AOS-S. Exact protected-AAA declarations qualify path evidence for FortiOS and Junos administrative RADIUS records. Configuration-backup scope controls only the absence decision for qualified device-side schedules. Credential length and blocklist policy applies to secret-free IOS/XE, ASA, Junos, ScreenOS, and EOS metadata. Explicit certificate inputs enable bounded PAN-OS, ASA and FortiOS public-material assessment. Other plugins may use context only after their own vendor grammar, authoritative security requirement, and adversarial tests are added.

CIDR targeting, configuration-section selection, threshold overrides, and overlapping selector precedence are intentionally unsupported. Report inventory selection does not change parsing or finding evaluation. Partial input selection remains a separate design decision because selecting only part of a configuration must not remove referenced objects, alter rule ordering, or suggest that excluded data is secure.
