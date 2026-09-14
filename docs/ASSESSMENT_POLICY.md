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
  "assessment_time": "2026-09-14T12:00:00Z",
  "management_certificate_identities": {
    "localhost.localdomain": "firewall.example.com",
    "outside": "asa.example.com"
  },
  "trusted_certificate_sha256": [
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  ],
  "excluded_categories": ["discovery"]
}
```

Supported roles are `unknown`, `internal`, `external`, `management`, `access-edge`, `uplink`, and `voice-fabric`. Names are matched case-insensitively but otherwise exactly; there is no wildcard or interface-name guessing. An unknown role never becomes external or trusted automatically.

`protected_aaa_profiles` contains exact, case-insensitive `scope:name` selectors for AAA profiles whose traffic is carried over a separately verified encrypted path, such as an IPsec tunnel. The current consumer is FortiOS administrative RADIUS analysis. This declaration records topology evidence that is not present in the device export; it does not validate the tunnel, suppress explicit protocol-integrity failures, or make a legacy protocol intrinsically secure. Omitted profiles retain an unknown path, which is not automatically a finding.

Certificate material assessment is enabled only by explicit inputs:

- `assessment_time` is an ISO-8601 timestamp with a UTC offset. It freezes inclusive not-before/not-after evaluation; the analyzer never substitutes the computer's current clock.
- `management_certificate_identities` maps an exact parser scope to the intended DNS name or IP address. PAN-OS uses its device-entry scope (commonly `localhost.localdomain`); ASA uses the assigned interface name or `default`. Identity matching uses subjectAltName, not an inferred hostname.
- `trusted_certificate_sha256` lists approved 64-character SHA-256 fingerprints. A fingerprint can anchor validation only when that public certificate is also present in the supplied export. Missing anchors remain unknown rather than trusted or failed.

The analyzer parses public DER/PEM material locally. It records public metadata, validity, identity, key/signature policy and supplied-chain verification as independent results. These inputs do not establish revocation status, a client's actual trust store, or which certificate the appliance currently serves. Certificate and private-key payloads are never included in findings or assessment-policy metadata.

`excluded_categories` accepts rule-ID category tokens such as `discovery`, `routing`, or `snmp`. Exclusions are applied after parsing and rule evaluation. They therefore do not discard configuration evidence, but their findings are omitted from the delivered report. Every HTML and JSON report records the policy version, provenance, roles, exclusions, and the explicit warning that excluded categories were not assessed and are not implied secure.

The policy file is validated before the scan. Unknown fields, unsupported roles, duplicate interface identities, malformed JSON, and invalid category names fail closed. The file should contain no credentials or customer secrets.

## Current boundary

Explicit interface roles currently enable trust-boundary CDP/LLDP analysis on IOS/XE and Junos and access-edge analysis on IOS/XE and AOS-S. Exact protected-AAA declarations qualify path evidence for FortiOS RADIUS records. Explicit certificate inputs enable bounded PAN-OS and ASA public-material assessment. Other plugins may use context only after their own vendor grammar, authoritative security requirement, and adversarial tests are added.

CIDR targeting, configuration-section selection, threshold overrides, and overlapping selector precedence are intentionally unsupported. They remain separate design decisions because selecting only part of a configuration must not remove referenced objects, alter rule ordering, or suggest that excluded data is secure.
