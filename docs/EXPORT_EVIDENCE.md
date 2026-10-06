# Export evidence and offline assessment boundaries

This is the maintenance contract for incomplete exports, not a claim that every
legacy check has been migrated. The execution register is
[SC-064–SC-067](agent_notes/SECURITY_COVERAGE_TASKS.md#sc-064).

## Omitted settings versus missing evidence (maintainer rule, 2026-10-06)

This rule takes precedence over everything below; see [AGENTS.md](../AGENTS.md).
A setting omitted **inside an object or section that is in the export** is known
configuration state, not missing evidence. Apply a cited, release-gated vendor
default (`DOCUMENTED_DEFAULT`), or report a feature that is simply not configured
(`REQUIRED_SETTING_MISSING`; `MISSING_EXPLICIT_SETTING` when the default matters but
is unverified). The observation states that the setting is omitted / not
configured, and the report's basis note says that nothing is set to a wrong value
and that the setting may be applied elsewhere. Unknown is reserved for: a whole
containing section absent from the export, malformed or unsupported values,
references to objects outside the export (unresolved, Panorama/template/controller
inheritance), and defaults not verified for the release. Exports omit defaults, so
never require them to be restated (FortiOS backups omit `set status up`).

The 2026-10-06 correction restored these findings after the first SC-064 pass had
turned them into unknowns: PAN-OS `policy.security_profiles` (allow rule without
profiles), `updates.threat_content` (no threat schedule while the management
configuration is exported), `admin.ssh_profile_missing` and omitted algorithm lists,
`management.tls_profile_missing`, an omitted TLS minimum (`MISSING_EXPLICIT_SETTING`),
`credentials.password_complexity` for an omitted section or `<enabled>`; ASA
`aaa.management_authentication`/`management_accounting` for an exported management
grant without a binding; FortiOS omitted interface `status` (default `up`) and
omitted policy `utm-status` (default `disable`) on 7.x. PAN-OS treats the management
configuration as exported when `mgt-config` administrator entries and a
`deviceconfig/system` section are present (`PaloAltoPANOSParser.management_exported`);
a hostname-only fragment stays unknown.

## Scoped knowledge

Parsers expose `ExportScopeKnowledge(domain, scope, state, reason)` through
`get_export_scope_knowledge()` and `get_export_scopes()`. The base implementation
is unknown. A recognized platform/version header, valid XML, successful parse,
known hostname or populated inventory collection cannot establish completeness
of authentication, policy, logging, certificates or unrelated sections.

`KNOWN` may establish that the explicit fields required by one check are present
and valid. It does **not** certify a whole section or device export. PAN-OS
password-complexity knowledge covers its enabled flag and five explicit minimum
fields, not password profiles or roles. Management SSH knowledge covers the
applied profile and exported algorithm lists. Omitted fields within exported
objects follow the maintainer rule above; duplicate, malformed, unsupported,
inherited or absent-domain evidence remains unknown.

An explicit unsafe setting can still produce a finding in a partial export;
unknown fields must remain visible. Release-qualified defaults are a separate
evidence basis with independent vendor/release requirements. This cleanup does
not extend the insecure-defaults register. There is no assessment-policy flag
that declares an arbitrary file complete. Future completeness provenance must
qualify an export procedure and its exact device/tenant/domain, not infer it from
inventory or override unresolved inheritance.

## Report contract

The version-1 aggregate control outcome remains compatible. Additive `instances`,
`unassessed-instances` and `unassessed-instance-count` preserve uncertainty when
a finding coexists with unknown fields or another unknown instance. Exclusions
remain explicit; unrendered templates downgrade no-finding instances to unknown.
HTML displays scoped reasons. The original eight controls remain registered;
new controls are explicitly registered, never discovered from findings.

`coverage.export-scopes` carries parser knowledge. `coverage.limitations` states
rule-hit, live reachability, exploitability, advisory and dialect/module limits.
A configuration alone cannot establish observed zero hits, revocation, currently
served certificates or actual exploitation. Local advisory release matching
does not establish affected-feature applicability. Empty finding/path lists are
not passes; non-migrated rules remain findings-only.

PAN-OS threat-update knowledge currently qualifies single explicit hourly,
daily or weekly recurrence/action records with valid exported timing, and explicit
manual (`none`) selection. Unsupported recurrence dialects remain unknown rather
than being guessed from a familiar action string.

## High/Critical absence-check inventory

Registered analyzer negative branches and parser missing/unresolved/default
states were reviewed. Rows are grouped by semantics: explicit nonblocking actions,
factory-hash matches and policy-qualified certificate failures are not absent
section claims. Low/Medium absence hygiene is not claimed migrated here.

| Family / rule groups | Verified cleanup or remaining evidence gate |
|---|---|
| PAN-OS `credentials.password_complexity` | Fragment without exported management configuration: unknown. Omitted section or `<enabled>` in an exported management configuration: not configured (finding). Malformed values: unknown. Explicit disablement and weak minima: findings. |
| PAN-OS `admin.ssh_profile_missing`, `ssh_profile_unresolved`, `ssh_profile_algorithms`; `management.tls_profile_missing`, `tls_minimum_version` | Enabled service without a profile, or an applied profile with omitted lists/minimum: not configured (finding). Unresolved/inherited references: unknown. Explicit weak algorithms/legacy minimum: findings. Certificate assessment is separate. |
| PAN-OS `admin.role_assignment`, `authentication_profile_unresolved` | Migrated: absent/ambiguous/unexported roles/authentication objects unknown per identity/binding; local authentication inferred from omission is not an explicit-binding pass. |
| PAN-OS `policy.security_profiles`, `security_profile_unresolved`, `security_profile_ineffective`, `updates.threat_content` | Exported allow rule without profiles: not configured (finding). No threat schedule while the management configuration is exported: not configured (finding); fragment: unknown. Unexported group members/content: unknown. Explicit nonblocking actions/download-only schedules: findings. Full threat coverage and content freshness are unassessed. |
| ASA `aaa.management_authentication`, `management_accounting` | Exported management grant without a binding (or with the binding removed): not configured (finding). Binding to a server group that is not in the export: unknown per protocol. |
| FortiOS `policy.security_profiles`, `security_profile_unresolved`, `security_profile_ineffective` and Medium `policy.logging` | Native IPv4 `policy` and IPv6 `policy6`: qualify permission, VDOM/family and boundary roles. Omitted interface `status` is the documented default `up` and omitted `utm-status` the documented default `disable` on 7.x (finding with `DOCUMENTED_DEFAULT`). Explicit UTM/logging disablement and nonblocking content: findings. Omitted `logtraffic` is not "disabled". Unresolved attachments/content: unknown. |
| IOS/XE AAA/login, VTY authentication/authorization/group usability, console/auxiliary authentication, `aaa.tacacs_key_missing` | Open: qualify per-line/method/group completeness and fallback applicability, not an IOS header. Explicit bypasses are distinct. |
| IOS/XE control-plane policy/class references and empty policy; `routing.bgp.authentication` | Open: separate unexported definitions from explicit no enforcement or effective unauthenticated sessions. |
| ASA `failover.authentication`, `aaa.tacacs_key_missing`, routing-authentication and bound crypto-reference branches | Open: qualify domain/attachment completeness and unexported authentication/crypto objects. Explicit legacy crypto and client-certificate policy violations are separate. |
| FortiOS `admin.remote_group`, `snmp.secure_user_missing`, incomplete `snmp.v3_security`, `vpn.unresolved` | Open: model account/group/profile/credential completeness per VDOM. Admin MFA/trusted-host/password-policy omissions also consume independently maintained release defaults; do not bulk rewrite that database. |
| Junos super-user authentication/login-class/accounting bindings, lo0/filter/policer references, BGP authentication, RadSec trust/client certificate, unresolved VPN | Open: qualify hierarchy, logical systems, groups and referenced domains. Explicit no-enforcement and documented routing defaults are separate. |
| EOS role/command-authorization bindings, eAPI TLS profile/certificate, control-plane ACL/CoPP references and empty selectors | Open: qualify role/AAA/TLS/filter/class domains and attachments. Explicit bypasses and documented OSPF defaults are separate. |
| Check Point FW1 layer cleanup/stealth absence | Open: prove complete ordered layer and gateway/object inventory; policy-only exports do not establish OS administration or absent gateway objects. Gaia is a separate dialect. |
| ScreenOS manager sources/authentication-server references; HP/AOS-S manager/password/SNMP protection; SonicOS SNMP protection | Open or independently default-qualified: establish dialect/release, domain and same-object field knowledge. SonicOS custom E-CLI does not certify legacy preference formats. |
| F5 module/default branches | Existing explicit/module/release qualifications retained. Missing NTP configuration is already ungraded. Provisioning a module is not proof of complete AFM/APM/ASM rule content; UCS/F5OS are separate inputs. |

Review 2026-10-06 (SC-064, after the omitted-setting correction): the remaining
rows already follow the maintainer rule. Their absence checks report settings
omitted from exported configuration as not configured or by a cited default, and
explicit values are judged as such. Dangling references in self-contained exports
(IOS/XE AAA groups and CoPP classes, ASA crypto and AAA objects, Junos filters and
policers, EOS ACLs, FortiOS VPN objects) remain findings; references managed
outside the export (Panorama, FortiManager, Junos apply-groups, controller state)
stay unknown. A whole-file "fragment" heuristic (for example no `interface` or
`line` section in an IOS file) was prototyped and rejected: it also suppressed
findings about objects present in the file whose evidence is redacted or
summarized, and complete exports always contain those sections anyway. Fragment
handling therefore stays per domain (PAN-OS `management_exported`). Control
outcomes for these rules continue under SC-049.

## Effective permission is not shadowing

`TrafficMatch` and `EffectivePermissionProof` implement bounded exact
source/destination/protocol/service-selector subtraction. Parsers qualify scope,
terminal order, interfaces/zones, schedules and selectors. Every preceding
terminal action, including an earlier allow, removes traffic from the candidate
rule's own permission. Results are proven nonempty, proven empty or unknown;
only a complete nonempty proof returns a concrete range witness.

Bounds are 64 earlier rules, 2,048 fragments and 100,000 subtraction work units.
Unsupported protocol identity and exhausted budgets return unknown. IP protocols
use their finite 0–255 identity, not a fictitious "other" protocol. No packets are
generated. Ordinary shadow/redundancy hygiene findings remain independent.
`protective-deny-defeated` additionally requires nonempty permission intersecting
the later deny. Two earlier IPv4 half-space denies can empty an apparent allow;
partial-deny paths describe only the proven remainder, not every denied flow.

Repeated identical ASA ACE commands do not get silently moved to the end of a
bound ACL. Their exported effective order remains unqualified, so ordered shadow
and path conclusions are withheld with an explicit reason. Independent explicit
configuration-value hygiene remains available.

FortiOS logging/inspection consumes this same API. Boundary claims require
explicit assessment roles and uniquely resolved same-VDOM interfaces that are up
(explicit `status up`, or an omitted status on 7.x, whose documented default is
`up`), not names such as `wan1`. Routing, Internet reachability and runtime
traffic remain unproved. Unsupported schedules, negation, ISDB, identities,
selectors or interface overlap stay unknown. Modern unified IPv6 `firewall policy`
selectors (`ip-version`/`srcaddr6`/`dstaddr6`) are not silently treated as legacy
`policy6`; their unqualified syntax remains gated.

## NAT and family qualification

PAN-OS NAT relevance is shared by findings and paths for an exact
device/vsys/security-rulebase comparison. All supplied active/unresolved NAT
entries across local/pre/post tables are considered (64-entry bound); later NAT
entries are not assumed unreachable. Inactive/other-vsys rules, disjoint original
source zones, or resolved disjoint original address/service selectors can prove
irrelevance. Relevant, unlocated, malformed, reverse/bidirectional or unresolved
interactions stay unknown. A translated destination or different NAT destination
zone cannot prove irrelevance: security matches original pre-NAT addresses and
post-NAT zones ([vendor NAT semantics](https://docs.paloaltonetworks.com/ngfw/networking/nat/nat-policy-rules)).
Panorama/application/user/category/schedule/dynamic-object gates are retained.

PAN-OS `any` covers both families and IPv4 can match IPv6 low-prefix ranges.
The remainder API currently establishes bounded IPv4 witnesses for PAN-OS;
explicit IPv6/mapped-prefix interactions remain unknown. Empty IPv4 remainder
for universal selectors is disclosed as unknown IPv6 permission, not a dual-stack
pass or a High risk path.

FortiOS parser predicates validate IPv6 family, static addressing and trusted
host syntax. Family instance IDs remain stable; summaries/remediation use
`ip6-trusthost`, `ip6-allowaccess` and `source-address6`. Cross-VDOM user/group
fallback is forbidden. Listener-name collisions and unqualified global admin
ownership are unknown. SSL-VPN identities bind to the exact local auth rule,
interfaces and family source filters; later overlapping rules, realms and
unsupported source/cipher predicates remain gated. Configured IPv4 admission is
not proof of an assigned address or public reachability.

`dual-stack-mode` concerns tunnel addressing, not an inferred IPv6 listener switch
([vendor SSL-VPN settings](https://docs.fortinet.com/document/fortigate/7.4.6/cli-reference/114404382/config-vpn-ssl-settings)).
The five active patterns and five gated expansion patterns are retained.
Research links are maintenance references only: audits never retrieve them,
query devices/DNS, check revocation or contact update servers.

## Baseline trusted-host syntax

`FortiAdminTrustedHosts` contains scoped, secret-free `FortiTrustedHostSelector`
records (native field, family, explicit/malformed/unsupported origin, knowledge,
broadness, reason and located evidence). Baseline and path predicates share the
validator, not eligibility. Every supplied selector must validate its address,
netmask/prefix, family and supported index; IPv4 wildcard masks are not netmasks.
Unknown selectors cannot establish a restriction. Known broad selectors remain
findings alongside scoped unknown reasons. A wholly omitted required restriction
inside an exported administrator remains a not-configured finding. Valid
IPv4-only/IPv6-only baseline restrictions do not imply protection of the omitted
family. Account privileges, remote/MFA behavior and path listener/role/local-in/
VDOM/release gates are unchanged; a baseline finding never completes a path.

## Batch safety and comparison

`src.batch` checks the complete output set before creating even the output
directory. It protects manifest, every input, policies, local advisory bundle and
directory-export subtrees. Resolved names detect case/symlink/junction aliases;
existing device/inode identities also detect hard links and duplicate outputs.
Failure to inspect a suspect identity fails closed. Safe report overwrite and
noncolliding output beside a flat configuration remain allowed. This preflight
does not promise atomic safety against another process changing paths concurrently.

Comparison keeps schema 1 and evidence-based finding keys. It consumes aggregate
and scoped SC-049 outcomes, unassessed lists and counts. Until parser-owned subject
bindings exist, scoped uncertainty blocks resolution of disappeared findings for
the affected control, without altering unchanged findings or unrelated controls.
Legacy aggregate-only reports use their prior fallback with a limitation note;
unmigrated checks are not blanket-marked unknown.

Remediation conclusions require matching canonical registry families and valid,
nonempty matching analyzer SHA-256 fingerprints. True aliases resolve normally;
PIX/ASA, FW1/Gaia and IOS-XE/IOS remain distinct. Missing and `None` default-policy
representations are equivalent; an explicitly declared policy needs a valid
digest. Unknown/mismatched provenance or family is not comparable. Exclusion,
template and unsuccessful-audit handling is preserved. The manifest ID is an
auditor's declared identity, not a verified physical identity. Current findings
remain visible in both JSON and escaped HTML comparison views. Stable scoped
subject metadata is separately planned under SC-050, not implemented here.

## PAN-OS snapshot cache boundary

Profiling the unchanged 200-rule workload found 5,362 address inventory rebuilds
and about 72% of profiled analysis time spent collecting those objects. The
conditional SC-066 gate justified parser-local caches of immutable address/service
inventory, whole top-level selector results and typed NAT inventory. A combined
512-entry LRU and maximum 4,096 retained items per result bound retention. Selector
keys include device/vsys scope, ordered selectors and expansion limit. Empty,
unresolved and cyclic final results are preserved; ancestor-dependent intermediate
recursion is never cached. Proof budgets and eligibility are unchanged.

Reinitialization and root replacement invalidate cached snapshots. Handing out
mutable native XML clears and disables caches for that parser instance, so later
changes through a retained native reference cannot reuse stale results. Direct
internal XML mutation must call `invalidate_policy_cache()`; there is no hidden
file reload, process-wide cache or audit-network dependency. Cached/uncached
equivalence, scope/parser isolation, cycles, limits and native mutation are tested.
