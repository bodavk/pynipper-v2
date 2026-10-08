# Configuration anonymization: utility and extension design

Initial implementation: **2026-10-08**. A bounded, standalone utility is available
for **FortiOS, Cisco IOS/IOS-XE and ASA native text exports**. It is not a universal
configuration sanitizer: unsupported commands, sections, payloads or address
proofs block output, so many full production backups will require later adapter
work. Check Point and remaining vendors are planned, not implemented.

The sections below distinguish current behavior from extension requirements.
Only the options shown under current usage are available. Assessment-policy
companions, persistent mapping stores, synthetic PKI, embedded scripts and full
audit-equivalence certification are not implemented.

## Purpose and safety boundary

Create a separate Python utility for preparing customer configuration samples
for offline development and testing. It replaces customer identifiers and all
credential material consistently, while retaining the settings and relationships
needed to reproduce security findings. It is not a device backup/restore tool.
Never import its output into production equipment.

Strictly speaking, this is **pseudonymization**, not a guarantee of anonymity.
Topology, model, release, enabled features and unusual combinations of settings
can still identify an organization. Sharing still requires the owner's approval
and a human review. Preserving network structure improves testing but can weaken
privacy; [RFC 6235, section 4.1.4](https://www.rfc-editor.org/rfc/rfc6235.html#section-4.1.4)
discusses that trade-off for prefix-preserving pseudonymization.

The utility must:

- Read only explicitly supplied local exports and companion files. No device
  connections, DNS, downloads, probes or other network operations.
- Leave originals untouched; never overwrite, delete or silently copy them into
  an output package. Refuse input/output collisions and filesystem aliases.
- Produce new native-format files, not an audit report or normalized inventory.
- Replace inactive, superseded and removed values too, not just effective state.
- Block publication when syntax or sensitive content is unhandled. A successful
  parse or a clean pattern scan is not proof that all private data was removed.
- Keep original values out of console output, exceptions, logs and public
  manifests. Location-only diagnostics identify a field class and line, not its
  value; even original filenames and absolute paths are private by default.

## User experience

One command, strict defaults, a fresh mapping for each independent package.
Current usage from the repository root:

```powershell
python scripts/anonymize_config.py -i fgt400.conf -d fortios --output-dir sanitized\sample-001
python scripts/anonymize_config.py -i router.conf -d cisco-ios --output-dir sanitized\sample-002
python scripts/anonymize_config.py -i asa.conf -d cisco-asa --output-dir sanitized\sample-003
python scripts/anonymize_config.py -i fgt400.conf -d fortios --check-only
```

The utility uses only the Python standard library and the repository's own
modules; Python 3.10+ and the checkout are required, not just a copied entry-point
file. No third-party audit dependencies are needed for sample preparation.
The project's virtual-environment Python also works. `python -m src.anonymize`
runs the same utility.
`--check-only` writes nothing. Exit status 0 means supported grammar/mapping
validation succeeded, 2 means blocked input or unsupported state, and 3 means
I/O or permission failure. A blocked run identifies a generic reason and, where
available, a source line without printing private configuration text. Do not
remove security-bearing content simply to bypass a gate.

On success, review `config.conf` and `sanitization-summary.json` before sharing.
Never send the original export, a reverse map or an unsanitized assessment policy.
Input is bounded to 8 MiB, 100,000 physical lines/rewrites and 4,096 distinct
address-proof operands, plus 200,000 source tokens and 100,000 domain-suffix
allocations. Existing output directories are refused. On Windows,
directory ACLs are restricted before file contents are written. A write failure
can leave an incomplete directory; it is not an approved package and is never
deleted automatically.

Device selection reuses the existing friendly selectors, aliases and
canonical registry. Unambiguous detection may select a family; ambiguous input
must require `-d`, without an interactive prompt in unattended runs. Audit support
does not imply anonymization support. Register each qualified rewrite adapter
explicitly against existing canonical IDs, without a second device catalogue.

The output package contains neutral filenames such as `config.conf`, or the
required Check Point filenames, plus `sanitization-summary.json`. The summary
lists adapter version, transformed category counts, deliberately retained
structural constants and validation limitations. It contains no reverse map,
original digest, source identifier or raw audit output. Status must distinguish
`blocked`, `privacy-checked-within-supported-scope`, and the independently
qualified test-equivalence result; never label output universally anonymous.

In a future companion-file stage, supplied assessment policies must be transformed
with the export. The initial utility does not accept them.
Publish a package only after validation. Until then, transformed buffers remain
in memory, with explicit size limits; avoid raw-content temporary files. A write
failure must leave an incomplete package clearly unapproved, never a success
marker. Output requires a new destination; no overwrite option in the first
version. Exit codes should separate successful qualified output, blocked
unsupported/privacy state, and I/O failure.

## What changes and what stays

The table is the extension target. Current adapters cover selected FortiOS
global/admin/API-user/interface/zone/address/group/policy/service/VPN/logging
and related fields, including scoped references, UUIDs, credential slots,
IPv4 masks/ranges, IPv6 prefixes and FQDNs. Cisco covers selected hostname/domain,
account/credential, interface/VRF/VLAN, AAA, ACL, logging, SNMP community, NTP,
route and ASA object/group/source-admission commands. These are explicit
grammars, not complete vendor exports: unsupported fields within even a listed
section still block. MACs, general URLs/DNs, certificate payloads, embedded
scripts, ASA NAT and broader routing/VPN grammar remain gates.

Credential substitutes retain the supported parser's representation/storage
classification where qualified; they are not guaranteed valid device ciphertext
or cryptographic hashes. Empty values and native `*****`/`<redacted>` markers
stay empty/masked. Structural numeric IDs, native ports and the reserved FortiOS
root VDOM remain unchanged. Address translations preserve containing-block
offsets and allocate nonoverlapping outputs; class-crossing or unrelocatable
blocks, conflicts with retained special addresses and noncontiguous wildcards
block instead of being approximated.

Exported factory objects such as the FortiOS `all` address retain their public
native identity, including when an explicit definition is present; otherwise a
broad policy could turn into an unresolved custom reference. Built-ins are
namespace-qualified, so an address called `HTTP` is still renamed rather than
confused with the service `HTTP`. Ambiguous case-variant custom references are
blocked until their native case/override behavior is qualified. Empty banners
remain empty; neutral text is never inserted as missing protection.

The exact FortiOS field/section registrations are the constants in
[`src/devices/fortinet/anonymization.py`](../src/devices/fortinet/anonymization.py).
The explicit Cisco statement grammar is
[`src/devices/cisco/anonymization.py`](../src/devices/cisco/anonymization.py).
New syntax requires adapter tests; it must not be added through generic
"unknown values are safe" handling.

| Data | Proposed handling |
|---|---|
| IPv4/IPv6 hosts, subnets, ranges and IP-bearing URLs | Consistent, relation-checked address mapping; distinguish addresses from masks |
| Hostnames, domains, server identities, email addresses | Synthetic labels, preserving qualified matching relationships |
| Custom objects, groups, zones, segments, VDOMs, VRFs, accounts and profiles | Scoped names such as `addr_001`, `zone_001`, `user_001`, and updated references |
| Passwords, hashes, encrypted blobs, communities, PSKs, API keys and tokens | Synthetic replacements; never retain originals, including hashes |
| Serial numbers, UUIDs, MAC addresses, contact details and source filenames | Synthetic identifiers with required syntax and relationship preservation |
| Comments, descriptions, banners and free-form labels | Neutral text; preserve syntactic delimiters, not customer prose |
| Embedded scripts, regexes, certificate/key material and opaque payloads | Dedicated qualified transformation, or block; no generic pass-through |
| Release/model, commands, algorithms, ports, masks, policy order and actions | Retain where security semantics depend on them; disclose residual fingerprinting |
| Built-in identifiers and special constants | Retain only through a vendor/context-qualified allowlist |

Examples of structural constants include FortiOS `all`, `ALL`, `super_admin`
and the reserved `root` scope, or Cisco native interface syntax. A custom address
object called `HTTP` is not automatically a built-in service. Numeric policy IDs,
VLAN tags and autonomous-system numbers remain structural in the initial scope;
renumbering them is a separate relationship-preserving feature, not an assumed
privacy guarantee. Customer-defined interface aliases change; native physical
port identifiers are retained unless a qualified adapter proves safe renaming.

## Architecture: rewrite source, not effective inventory

Follow [Architecture](ARCHITECTURE.md), [Extending](EXTENDING.md) and
[Export evidence](EXPORT_EVIDENCE.md). Vendor syntax and reference semantics stay
in vendor-owned code. The separate utility does not add detection plugins,
finding IDs, report modes or network dependencies to audits.

Implemented separation:

```text
scripts/anonymize_config.py             thin command-line wrapper
src/anonymize/                         offline orchestration, mapping, validation
src/devices/common/anonymization.py     typed source-span/namespace contracts
src/devices/<vendor>/...                explicit vendor rewrite adapters
tests/test_anonymize_*.py               synthetic fixtures and public CLI tests
```

Existing evidence-redaction APIs are not whole-file sanitizers. For example,
FortiOS `_SECRET_FIELDS` and `get_report_secret_evidence()` serve selected report
and effective-state use cases; IOS masks banner bodies for parsing; Check Point
tokens retain locations but are not a lossless rewrite interface. Reuse qualified
lexing helpers, not their completeness assumptions. Existing
`group_double_quoted_lines()` reports unterminated strings; sanitization must
block them rather than process their bodies as independent commands.

Adapters expose immutable typed records describing:

- exact source spans, token category and native quote/escape rules;
- family, tenant and identifier namespace;
- definitions, references, removals and built-in identity;
- IP roles: host, network, mask, wildcard, range endpoint and embedded address;
- credential representation and known semantic restrictions;
- unsupported constructs and location-only blocking reasons.

Source buffers and original tokens stay inside the private rewrite boundary.
They must not enter Findings, normalized records, public summaries or debug
representations. Retain byte/character-offset conversion explicitly; decoding
errors block rather than silently replacing characters. Reject overlapping spans
and uncontrolled input size, nesting, expansion or reference cycles.

Process in two passes: collect all occurrences and relationships, then allocate
collision-free replacements and rewrite spans. Definitions may appear after
references. Never regenerate an export from effective state: that would lose
ordered edits, unsupported settings and the very evidence being tested.

## Consistency and scope

Use one address map across the supplied package. Equal normalized IP literals
map equally even when written differently; IPv4 and IPv6 remain separate.
Address class and native contextual meanings must not change accidentally.

Names are different: key them by native namespace and scope, not just text. An
address object and an administrator with the same spelling need not be the same
entity. Identical names in different VDOMs must not collapse. Resolve shared,
global and inherited references exactly as the vendor does; preserve unresolved
references as unresolved, rather than accidentally creating a definition.
Rename forward references, `no`/`unset`/`delete`, rename/clone operations and
inactive declarations consistently. Preserve case-sensitive identity where the
dialect requires it, and avoid collisions with all retained built-ins.

Use fresh cryptographic randomness per package and an in-memory mapping by
default. Do not use unsalted hashes of original names or addresses as public
pseudonyms. Multi-file processing shares the same session. A later optional
private mapping store may enable incremental samples, but requires restrictive
permissions, schema validation and explicit opt-in; it must live outside the
shareable directory and must never be committed or uploaded.

## Addresses: preserve the bug, not merely valid syntax

Arbitrary replacement of individual IPs can turn a restrictive ACL into a broad
one, break NAT relationships or change shadowing. Preserve equality, family,
prefix lengths, subnet membership, relevant intersections, range ordering and
the modeled match sets. Keep masks and wildcard masks as masks. Do not transform
an IP-looking version string or a subnet mask as though it were a host.

The initial implementation supports **bounded CIDR-block translation**:
allocate disjoint replacement blocks of the same size, map hosts by offset,
and verify every modeled network/range relationship. Support a range only where
its entire transformation is proven contiguous and ordered. Cross-block ranges,
noncontiguous Cisco wildcards or unsupported embedded selectors block until a
qualified transformation exists. Do not assume prefix-preserving permutations
preserve arbitrary numerical ranges.

Allocation avoids retained constants and collisions with other mapped blocks.
Ordinary target blocks also avoid source blocks. The three IPv4 documentation
blocks are instead cyclically permuted together, preserving offsets and avoiding
collisions even when all three are supplied. Public target addresses may belong
to real networks: the output is exclusively for offline tests, not live use.
Preserve private/public, loopback, link-local and multicast classification where
a consumer depends on it. If a block cannot be relocated under those constraints,
block or explicitly qualify a narrower sample; do not silently change its class.
Do not promise that every export can fit inside documentation address space.
Hosts within translated blocks retain relative offsets, which is useful for
testing but leaks topology; document that limitation.

Unrestricted selectors (`0.0.0.0/0`, `::/0`, vendor `any`), unspecified listener
addresses, and context-qualified special addresses remain special. Subnet
broadcast/network addresses transform with their containing network. Retaining
a special constant is not permission to retain all ordinary addresses in its
class. Malformed IP evidence must never become valid accidentally: provide a
synthetic invalid token preserving the invalid state only where grammar and
privacy handling are qualified; otherwise block.

## Domains, free text and payloads

The utility uses synthetic domains beneath `.invalid`, reserved as nonexistent by
[RFC 6761, section 6.4](https://www.rfc-editor.org/rfc/rfc6761.html#section-6.4).
Never resolve either original or replacement names. Preserve modeled domain
suffix relationships and wildcard meaning; `*.domain-001.invalid` and
`server-001.domain-001.invalid` must stay related. Generated hostname labels must
use valid hostname syntax and respect label and total-name length limits;
underscores are not ordinary hostname characters. Account identifiers, FQDNs,
LDAP distinguished names and URLs need separate grammar handling, not a global
substring replacement. URLs preserve relevant scheme/port but replace private
hosts, userinfo, paths and query tokens under a qualified adapter.

Neutralize customer prose, including addresses embedded in comments and banner
bodies. Preserve multiline delimiters without allowing placeholder text to
become commands. Scripts, regexes, encoded content and nested XML/JSON cannot
be passed through because they did not match an IP or password pattern.
Unqualified payloads block publication. Do not remove a security-bearing block
just to make the file look sanitized.

MAC rewriting must preserve equality and required unicast/multicast semantics,
avoid broadcast constants and update embedded IPv6 identity relationships where
present; otherwise gate those cases. Synthetic UUIDs preserve required syntax
and cross-file links, not the original bytes.

## Credentials and certificates: explicit equivalence limits

Replacing every secret with `<redacted>` makes samples less useful and can
change parser knowledge states. Prefer synthetic, valid representations retaining
the proven storage class: Cisco type markers, hash-family prefixes, FortiOS
`ENC` syntax and empty/masked/malformed distinctions. Where qualified, plaintext
substitutes preserve length/composition categories without retaining the value.
Never decode or crack supplied credentials. Opaque proprietary encrypted formats
remain gated unless a non-sensitive replacement preserves the relevant parser
state. A matching prefix alone is not proof of a valid vendor ciphertext.

Equal secrets in the same qualified representation should map consistently.
Equality across different encrypted/hash representations is generally not known
and must not be inferred. Synthetic placeholders must never coincidentally
match a known default unless that is an explicitly qualified test case.

Some checks cannot survive replacement unchanged. Exact factory-password and
operator-blocklist matches depend on the original representation. An unsalted
default hash cannot both change and retain an exact-match result. Built-in
account names can also affect default detection. Do not retain a supplied secret
to preserve a finding, or introduce a sidecar that makes the auditor trust a
claimed vulnerability. Mark those controls as non-equivalent; strict reproduction
of that issue needs a separately authored synthetic fixture. A same-length
plaintext substitute is not evidence of equivalent credential strength.

Certificates contain customer identities even when public. Replacing PEM with a
placeholder loses key-size, signature, validity, identity and chain checks.
Full certificate support requires a qualified synthetic PKI generator preserving
the properties under test and rewriting all trustpoint/profile/SAN/anchor
references. Private keys must always be replaced; generator limitations and
unsupported algorithms remain gates. Until then, block certificate-bearing
samples requiring those transformations, rather than leaving originals intact.

## Companion files and validation

Check Point packages must rewrite object names and UIDs together across the
supplied rulebase and object files. Read an explicit supported-file allowlist;
do not recursively copy directories, hidden files, logs or backups. Controller
references outside the package remain outside it. Gaia is a separate export,
not evidence of FW1 OS settings.

Assessment-policy scope keys, interface roles, usernames, intended identities,
addresses and any supported certificate anchors must track transformed entities.
If a policy field cannot be mapped correctly, block policy publication. Never
infer an external interface from its name. Local advisory bundles ordinarily
depend on unchanged family/release metadata, but must be schema-reviewed before
including them; do not copy arbitrary companion metadata or free text.

The following are the target validation contracts. The initial runtime validates
registered source grammar, namespace resolution and bounded address allocation,
then revalidates the transformed grammar and physical line count. Tests exercise
native parser bindings and public offline reports for selected controls. It does
**not** run a comprehensive residual scanner, native reference-graph comparator
or per-control equivalence comparison at runtime. The summary therefore declares
`test-equivalence: not-certified`; it cannot be used to claim unchanged findings.

Two independent validations are required for later qualified-equivalence support:

1. **Privacy coverage:** every source span is classified as transformed,
   vendor-qualified structural syntax, or blocking unknown. Scan for residual
   original sensitive tokens and encoded variants as a second defense, not a
   completeness proof. Do not use fuzzy substring matching for short structural
   words or leak originals in scanner messages.
2. **Test equivalence:** reparse both inputs locally; compare mapped reference
   graphs, scoped settings, ordered edits, interval relationships and explicit
   knowledge states. Exercise processors for supported controls, exclusions and
   attack paths. No invented defaults, filled missing fields or repaired bindings.

Current batch finding identity is evidence-based, so exact report text or equal
finding counts cannot prove equivalence. Use typed entity mappings and only
qualified rule/control/path comparisons; unavailable subject identity must stay
a stated limitation. Reports and private comparison data remain local, outside
the shareable package. A credential-related difference must not silently allow
unrelated policy or coverage differences. Record limitations by affected control
and scope; do not alter the audit ledger to pretend replacement data is original.

## Delivery order and acceptance gates

### Open plan-refinement tasks (2026-10-08)

These refinements remain tracked with their original scope. The initial utility
implements parts of them, described above, but broader acceptance must not be
inferred from the implemented vendor IDs. Checked scope below is explicitly
limited; unverified extensions stay open.

- [ ] **Bound the first FortiOS milestone.** Publish an explicit supported-field
  and syntax matrix for ordinary objects, groups, policies, addresses and
  administrator settings. Support only qualified credential representations.
  Detect and block certificates/private-key payloads, embedded scripts and opaque
  encrypted content that cannot be safely replaced. Unknown syntax must block
  publication rather than be copied through. Keep later payload/certificate
  support separate and sample-dependent qualification open as an evidence gate.
  **Current scope:** explicit section/field registration, unknown/payload gates
  and parser-only synthetic credential slots are implemented and tested. Broader
  field coverage and vendor-valid encrypted/certificate material stay gated.
- [ ] **Specify overlapping-network translation.** Nested and overlapping
  networks must use a consistent mapping rather than independent block
  allocations. Define allocation precedence and collision handling across hosts,
  prefixes and ranges. Test IPv4/IPv6 equality, membership, intersections,
  containment, range ordering, address classes and qualified NAT relationships.
  Block allocations that cannot preserve the required relationships; do not
  silently broaden selectors or change their security meaning.
  **Current scope:** containing-block precedence, nested-prefix membership,
  range ordering, separate address families/classes, retained-special conflicts
  and documentation-block collision handling are tested. Broader NAT selectors
  and native operational equivalence are not certified.
- [ ] **Define measurable per-adapter equivalence.** List the rules, controls,
  scoped knowledge states and attack-path relationships each adapter promises
  to preserve, with positive/negative acceptance fixtures. Identify credential
  replacements that make specific controls non-equivalent, including exact
  default and blocklist comparisons. Compare mapped entities and bindings;
  equal finding counts alone are insufficient. Differences outside the declared
  exceptions must block a qualified-equivalence result.
  **Current scope:** no equivalence result is certified; selected policy findings
  and typed credential storage/binding behavior have positive pipeline tests.
- [ ] **Specify protected output and failure behavior.** Establish restrictive
  directory/file permissions before publishing content, including explicit
  Windows ACL handling. Test permission failures, interrupted writes and
  input/output aliases. Publish the success summary only after all required
  files and validations succeed; incomplete packages must be clearly unapproved
  and never reported as successful. Give actionable field-class/location-only
  diagnostics without original values, filenames or private paths. Preserve
  originals and do not delete files.
  **Current scope:** private directories/files, Windows ACL checks, new-path
  preflight, interrupted-write tests and final-marker publication are implemented.
  Filesystem-alias and concurrent-write hardening need continued adversarial review.
- [x] **Validate synthetic hostname syntax (initial ordinary-host scope).** Use labels such as
  `domain-001.invalid` and `server-001.domain-001.invalid`. Test label lengths,
  valid characters, wildcard/suffix relationships and collision-free allocation
  without DNS or other network access. Treat native underscore-bearing DNS
  service labels separately from ordinary hostnames.
  **Verified scope:** hostname labels use hyphens rather than underscores;
  generated domain length, label boundaries, wildcard/suffix relationships and
  allocation are tested offline. Underscore-bearing DNS service labels are
  explicitly blocked, not silently rewritten as ordinary hostnames.

### Vendor delivery stages

These are extension stages, not promises of complete vendor support or new
security backlog priorities. Stages 1 and 2 have the bounded initial subsets
described above; stages 3 and 4 are not implemented.

1. **Shared engine + FortiOS:** native `.conf` grammar, nested scopes, objects and
   references, IPv4/IPv6, administrators, policy/profile attachments, credentials,
   descriptions, URLs, scripts and payload gates. Preserve `config/edit/next/end`,
   rename/clone/move/unset behavior and both address families.
2. **Cisco:** IOS/IOS-XE first, then a separately qualified ASA adapter. Cover
   ACLs/masks, interfaces and aliases, VRFs, object/service groups, AAA identities,
   named servers, routing/VPN keys, banners, ordered removals and NAT. PIX remains
   independently gated until its dialect is demonstrated; IOS support does not
   imply NX-OS or Firepower support.
3. **Check Point:** FW1 `rules.C`/`objects.C` and qualified legacy rulebase formats,
   then Gaia Clish independently. Verify cross-file UIDs, layers, install targets,
   groups, object topology and ordered references.
4. **Remaining registered formats:** Junos set/hierarchical, PAN-OS XML, EOS,
   F5 saved tmsh/SCF, ScreenOS, ArubaOS-S and supported SonicOS 7 E-CLI. Qualify
   each adapter independently. Unsupported encrypted/compressed exports and
   missing controller inheritance remain gates.

Each adapter needs synthetic tests for repeated identifiers, forward references,
tenant/namespace collisions, group cycles, ranges/prefixes, masks, IPv6, override
and removal, inactive/unbound objects, malformed syntax, unsupported payloads,
all secret classes, quoted Unicode and escaping, and no original data in errors.
Test originals unchanged, output collisions/symlinks/hardlinks, Windows permission
failures, bounded resource use and network access prohibited. Compare public
JSON/HTML findings, scoped coverage and paths for qualified preserved controls.

Validate the first supported adapters on secure/vulnerable synthetic exports and
the applicable permanent corpus cases. Run the full regression after source
changes; review intentional differences, never regenerate expectations to hide
them. A vendor is ready only when supported input is privacy-covered and its
declared preserved semantics are tested. Unknown syntax must not turn an early
adapter into a universal sanitizer.
