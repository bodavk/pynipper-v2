# pynipper-v2 Architecture

## Design goals

The project is organized around five rules:

1. One registry defines every CLI-visible device and its parser/analyzer pair.
2. Parsers own syntax and effective-state reconstruction; plugins do not reopen files.
3. Shared analysis uses typed normalized records with explicit unknown state.
4. Public processors register plugins explicitly and return vendor-neutral findings.
5. Target-platform behavior is locked by exact permanent regression snapshots.

## End-to-end flow

```text
CLI arguments
    |
    v
src.main
    |
    v
analyze_device -> device registry -> platform analyzer
                                      |
                                      v
                              parser from get_parser
                                      |
                         +------------+-------------+
                         |                          |
                         v                          v
                vendor-native model         NormalizedConfig
                         |                          |
                         +------------+-------------+
                                      |
                                      v
                         explicit platform processor
                                      |
                                      v
                           ordered plugin classes
                                      |
                                      v
                          Finding objects + advisories
                                      |
                                      v
                              HTML or JSON report
```

## Major components

### CLI and dispatch

`src/main.py` validates command-line values and resolves every explicit family name through the authoritative registry. The registry also supplies a short recommended-name list; historical IDs remain compatibility aliases. With `-d auto` (the default), `src/devices/detection.py` reads a bounded input sample and selects a family only from distinctive export markers. Ambiguous or unrecognized inputs stop before analysis, without echoing source content. Format detection never infers device or interface role. The analyzer receives the canonical family ID, which is recorded in the report.

`src/analyze/analyze_device.py` validates the input path, resolves a `DeviceDefinition`, lazily imports its analyzer, and delegates the scan. Lazy import paths prevent registry/parser/analyzer import cycles.

### Authoritative device registry

`src/devices/registry.py` is the only device catalogue. Each immutable `DeviceDefinition` contains:

- canonical ID and legacy numeric value;
- accepted aliases;
- parser import path;
- analyzer import path;
- display name.

The registry builds `DeviceType`, recommended CLI names, accepted compatibility aliases, parser construction, and analyzer dispatch. Alias uniqueness and registry reachability are enforced in `tests/test_architecture.py`.

### Parser layer

Every parser extends `BaseDeviceParser` and implements hostname, software version, local-user, management-service, and native-configuration accessors. `get_native_config()` exposes the vendor-specific representation when a rule genuinely requires it.

`get_normalized_config()` returns a `NormalizedConfig` containing typed values for:

- hostname, model, and software version;
- management services and permitted sources;
- local users;
- interfaces and zones;
- security policies;
- logging destinations;
- cryptographic settings.

Every normalized value or collection has a `KnowledgeState`: `KNOWN`, `UNKNOWN`, `UNSUPPORTED`, or `PARSE_ERROR`. An empty known collection means the parser established that no matching objects exist. An unknown collection means the parser cannot make that claim. Plugins must preserve this distinction.

`get_normalized_config()` is the vendor-neutral snapshot contract for shared detection. Its scalar and collection fields must always carry a knowledge state: `KNOWN` is authoritative for the supported input, `UNKNOWN` contains no asserted value or items, `UNSUPPORTED` explains the input/platform limit, and `PARSE_ERROR` identifies a failed supported parse. Configuration records separately use `ConfigurationState` (`enabled`, `disabled`, `configured`, or `unknown`) so a defined object is not mistaken for an active attachment. The base parser returns an explicit-unknown snapshot; vendor parsers promote fields to known only after their grammar, scope, ordered mutations, and references are tested. New shared checks use the normalized snapshot. Vendor-specific checks may use `get_native_config()` for constructs the common model does not represent; `get_raw_config()` is a compatibility alias, not a new-code API.

Known records should carry `ConfigEvidence` with source path, exact sanitized source text, and a positive line number where the format provides one. Secrets are redacted before evidence leaves the parser. Finding `references` are independent of configuration evidence and identify the vendor or benchmark source for the evaluated behavior.

Normalized adapters remain bounded by native evidence. IOS/IOS-XE, for example, reports explicit VTY and HTTP(S) endpoints, redacted local-user metadata, ordered interface state, effectively attached interface ACL/control-plane policy, syslog destinations and configured SSH cryptography. Unattached ACL definitions are excluded from effective policy inventory; device-model metadata and omitted service defaults remain unknown. FortiOS retains VDOM scope and includes both IPv4 and IPv6 transit-policy sections with explicit logging state. Junos keeps stateless firewall terms distinct from SRX zone-pair policies while exposing both through the common policy inventory. These reporting adapters do not replace the richer native records used by security checks.

Vendor parsers also reconstruct effective state where syntax is ordered. Examples include IOS `no` commands, Junos `delete`/`deactivate`, ScreenOS `unset`, FortiOS nested global/VDOM edits, and Check Point ordered layers and object references.

FortiOS `end` closes an active edited entry and its enclosing table while preserving any outer scope. Direct parser callers receive `FortiOSParseError` for malformed structure. The FortiOS analyzer converts that typed exception into a failed-parse coverage report and returns exit status 2 through dispatch and the CLI. Error reports contain a line number and generic diagnostic, never the raw exception or source command. Local disk/memory logging records retain explicit enabled/disabled/unknown state separately from remote forwarding; local storage cannot satisfy a centralized-logging check. Remote syslog transport is a separate per-sink typed record: an enabled destination, delivery mode, explicit encryption setting and TLS minimum are evaluated independently. Reliable TCP alone is not TLS; omitted or conflicting transport state and inactive VDOM overrides remain unknown, and delivery or server trust is never claimed from static configuration.

Documented defaults and legacy syntax are release-gated, not inferred from a vendor label. The ScreenOS parser, for example, exposes its documented unmatched-policy default and timeout defaults only when the export identifies the verified 6.3 family. It keeps console/Telnet, Web administration, administrator AAA, and policy/user authentication-server controls separate, resolves only active named bindings, and returns unsupported or unresolved state when the release or referenced object is not established. This pattern prevents a modern Junos control—or even a different ScreenOS release—from being silently applied to a legacy export.

Authentication relationships are parser-owned records, not plugin substring tests. A time association, for example, retains its server/peer role, address, VRF or device scope, key or NTS-profile reference, algorithm, effective resolution state, and sanitized evidence. A configured secret field may be known present, known missing, or redacted/unexported; those states must not be collapsed. Plugins evaluate every active association independently so one protected peer cannot mask another insecure peer.

The CLI-only `--show-secrets` path is a narrow report exception to the secret-free evidence contract. Normal parsers, normalized records, plugins, findings and inventory stay sanitized. For supported families, the report adapter uses effective parser-owned credential metadata and its source line numbers; FortiOS uses effective secret fields, F5 TMOS uses explicit `auth user` password directives, and SonicOS 7 uses explicit built-in/local administrator password directives, each with a verified input snapshot. The adapter adds a separate sensitive appendix. Unsupported families are rejected; no generic raw-config dump or heuristic evidence substitution is performed. Sensitive reports are created only at a new path with exclusive creation and restrictive creation mode where the OS supports it. The user must still control directory permissions and distribution, especially on Windows where inherited ACLs govern access.

IOS/IOS-XE VTY AAA follows physical line numbers when overlapping `line vty` ranges are edited in source order. The parser resolves login, EXEC/privilege-15 authorization and accounting bindings separately, plus effective global accounting declarations and explicit named server-group members. A named accounting list is not effective merely because it exists; the default list is automatically selected unless an explicit line binding overrides it. An empty named server group is known unusable, while a configured group member is not proof of a reachable server. `none` and `if-authenticated` authorization methods are graded as configured bypass paths without describing the login as unauthenticated.

IOS/XE endpoint admission is evaluated only on active switchports explicitly classified `access-edge` by the assessment policy. A separate typed record resolves ordered global 802.1X enablement, default dot1x AAA declaration, per-port control mode and explicit open access. `force-authorized` is a configured admission bypass even if a global authenticator is enabled; `auto` with an explicit global disable and `auto` with active open access are distinct causes. Omitted commands, AAA server reachability, MAB/guest/critical authorization, dynamic policy and independent port ACL restrictions remain ungraded. This narrow slice does not assert that every access-edge port must use 802.1X.

IOS/XE spanning-tree edge protection uses a separate parser-owned record. Global BPDU guard is effective only when the eligible port is PortFast/edge-enabled; a per-port `spanning-tree bpduguard disable` overrides global inheritance, while `no spanning-tree bpduguard` returns to it. Local BPDU filtering is evaluated separately because it can prevent guard from receiving BPDUs. Only active, assessed access switchports outside a channel group are graded. Omitted global/port defaults, uncertain operational PortFast state and non-edge topology remain unknown rather than a blanket missing-guard finding.

FortiOS administrator privilege follows the same binding rule. The parser resolves enabled accounts to built-in or scoped custom access profiles and records explicitly writable permission groups. Existing privileged-account source and MFA checks apply to proven write-capable custom roles as well as `super_admin`. Unresolved profiles and unexported permission defaults remain unknown; whether a log-writing role exceeds an organization's authorized duties requires explicit assessment policy.

Administrative policy uses the same relationship boundary. On Junos, the parser binds each named user to its predefined or locally declared login class, resolves class-specific idle timeout before the supported global fallback, and keeps unresolved classes distinct from missing bindings. Pre-authentication messages and post-login announcements are separate facts. Accounting events, selected RADIUS/TACACS+ destinations and their effective server fallback are resolved together, while J-Web idle and concurrent-session controls remain separate from whether HTTP or HTTPS is enabled. Unexpanded `apply-groups`, malformed values, disputed defaults and runtime delivery/session state remain unknown; plugins do not convert them into absence findings.

PAN-OS administrative policy follows local reference scope in the same way. The parser resolves each local administrator's dynamic or custom role and authentication profile or sequence, plus the global external-administrator authentication reference, retaining explicit MFA state without treating a RADIUS or SAML declaration as proof that an upstream factor ran. Global idle, failed-attempt, lockout and concurrent-session fields remain independent typed values. PAN-OS 10+ SSH analysis begins with enabled management SSH, follows the applied server profile, and evaluates only that profile's cipher, KEX and MAC lists. Unmerged Panorama templates, malformed or FIPS-dependent absent values, pre-10 grammar and the runtime SSH service-restart state remain unknown.

PAN-OS default-security-rule overrides are separate from named security rules. The parser resolves an explicit local-vsys `interzone-default` action before an exported shared action; a shared-only override in an unmerged Panorama export remains unknown. Only a proven explicit interzone allow produces the unmatched-transit finding. The normal `intrazone-default` allow and omitted implicit defaults are not recast as broad named rules.

EOS logging severity uses ordered parser-owned trap and buffer state. The remote trap threshold is assessed only with an effective default- or named-VRF syslog host and no explicit global logging disablement; the buffer threshold is a separate local-evidence question. Syslog numbers are inverted from common "higher number means more severe" intuition: a threshold below error level 3 excludes level-3 events. Reset, malformed, conflicting general/system trap settings and omitted thresholds are unknown; a local buffer never substitutes for remote delivery. Broader warning/notification requirements need an approved assessment policy.

ArubaOS-S administrative policy is modeled in its native manager/operator and login/enable terms. Ordered password commands preserve removal and `all` expansion, but an absent credential is known missing only when `include-credentials` or an explicit removal makes that conclusion valid. Each console, Telnet, SSH, and WebAgent authentication level retains its primary and secondary method and channel applicability; the documented `authorized` method is represented as unauthenticated rather than folded into a generic fallback. Remote CLI, serial/USB, and WebAgent idle timeouts are separate records, including general-to-serial override behavior and malformed-value uncertainty. MOTD and WebAgent plaintext/TLS state are also independent. These defaults are gated to verified AOS-S 16.10/16.11 exports and are never imported from AOS-CX.

AOS-S remote logging separates configured syslog servers from effective destination enablement and Event Log forwarding. A saved `no debug destination logging` can leave server addresses configured but inactive; `no debug event` can leave debug delivery active while excluding normal switch events. The parser resolves these commands and severity filters in order. Only a verified 16.10/16.11 export with an active server and explicit `logging severity major` is reported as excluding error-level events. This remote filter does not change the local Event Log, and no transport encryption is inferred from a server address.

SonicOS administrative policy is modeled from the SonicOS 7 custom E-CLI export. The parser resolves the built-in administrator separately from local users, follows inline or nested user/group membership through bounded cycles, applies the documented full/limited/read-only/guest precedence, and discards credential values at the parser boundary. Authentication method/local fallback, password constraints, login/session controls, CLI connection banners, and active HTTPS TLS/certificate selection remain separate records. Because custom exports omit factory values, documented SonicOS 7.0-7.2 defaults are applied only to those identified releases. SonicOS 7.3 changed new-install security defaults while upgrades retain prior behavior, so absent 7.3+ fields remain unknown; explicit 7.x commands are still evaluated.

Arista EOS administrative policy preserves the platform's distinct authentication, EXEC authorization, all-command authorization, and EXEC/command-accounting lists, including ordered `no`/`default` behavior and the documented meaning of `none`. Local users resolve through built-in, custom, or configured default roles without treating privilege rank as an RBAC role. Console, SSH, and Telnet applicability and idle/absolute timers remain independent; the absolute timer is release-gated to EOS 4.36.0F and later. Login and MOTD banners are separate. Active eAPI endpoints retain VRF evidence and follow their attached SSL profile to certificate and explicit TLS-version state. Undefined or removed roles/profiles stay unresolved, inactive services suppress exposure findings, and runtime AAA results, live sessions, served certificates, trust/revocation, and implicit TLS defaults remain outside static claims.

ASA local-administrator policy is evaluated only when an active management protocol binds to the local database or an explicit local fallback. The parser retains ordered local max-fail and password-minimum mutations independently of external identity-provider policy. Explicit ASDM idle settings are separate from SSH timeout, and the supported connection-wide HTTP timeout takes precedence over the ASDM-specific setting; unsupported releases and multiple-context no-effect cases are not graded. EOS global local-password minimum is separate from named password profiles: an explicit one-character minimum or explicit disablement is reportable on qualified releases with a local-login path, while exported named profiles make effective global inheritance unknown until bindings are modeled. Neither parser infers current password strength from a policy declaration.

F5 BIG-IP TMOS currently has a basic saved tmsh/SCF text adapter. It tokenizes balanced object blocks, retains only selected sanitized management and audit properties, and applies last-explicit-property precedence. `sys sshd allow none` means unrestricted sources, while `sys httpd allow none` means no permitted clients; these native meanings stay separate. An explicit `auth password-policy max-login-failures 0` establishes disabled local lockout; `minimum-length 0` is assessed only with explicitly enabled policy enforcement. Explicit `auth user password` is distinct from `encrypted-password`: the former produces a secret-free plaintext-storage finding, while masked values remain unknown and the latter is not assumed strong. User role/AAA semantics remain unmodeled. Omitted values and organization-specific finite thresholds remain ungraded. A narrow LTM adapter follows an explicitly enabled virtual server's partition-scoped clientside Client SSL reference to an enabled exported profile before assessing `allow-non-ssl enabled`. Missing properties, unresolved/inactive attachments and unverified defaults remain unknown or ungraded. Malformed or unrelated input produces a controlled parse-error report. Broader LTM traffic and module-specific APM/AFM/WAF semantics are not inferred from this slice.

AAA transport follows that relationship rule. FortiOS records resolve named RADIUS profiles through user groups to enabled remote administrators and retain transport, server identity/CA settings, TLS minimum, source interface/address and VRF. Junos separately resolves effective `system radius-server` and explicit accounting-destination servers only when administrative authentication/accounting uses them; RadSec trusted-CA and client-certificate bindings are distinct from UDP Message-Authenticator state. Shared-secret fields are excluded from both typed records and evidence. Release capability, binding, unexpanded Junos groups, explicit protected-path context and unknown topology remain separate facts; a configured UDP endpoint alone is not proof of an unsafe path.

SNMP access follows the same relationship boundary. Vendor parsers resolve effective users to their groups, security levels, read/write views, source ACLs or manager attachments, and active agent scope before a plugin grades protection. Authentication/privacy material is reduced immediately to present, missing, hidden/redacted, or unknown state. A secure identity never substitutes for assessment of another active identity, while an explicitly inactive agent or unbound ASA user is not reported as exposed access.

Routing trust is also relationship-scoped. Native IOS/XE and Junos records retain process/peer or interface identity, VRF/routing-instance, address family, inherited authentication/key-chain state, passive/shutdown state, directional policy attachment and prefix-limit presence. Plugins grade only active relationships. Route-policy absence is reportable only when the peer's external role is explicit; unknown inheritance, role or algorithm remains unknown. Static configuration never proves which routes were accepted at runtime.

For external IOS/XE IPv4 BGP peers, the bounded filter adapter retains each effective neighbor/peer-group policy reference by direction and type. A missing referenced prefix list, route map or AS-path filter list is an unresolved configuration boundary, not proof of a route leak. A standalone prefix list is provably nonrestrictive only when its sole exported rule is `permit 0.0.0.0/0 le 32`; a route map only when its sole exported sequence is an empty `permit` clause; and an AS-path filter list only when its sole rule permits `.*` or `^.*$`. Each conclusion additionally requires no other policy type attached in that direction. Other sequence patterns, unsupported predicates, address families and distribute-list effects remain unknown; the adapter does not claim runtime route acceptance.

IOS/XE boot-configuration retrieval is a separate, assessment-gated relationship. Only an explicitly commissioned device on a qualified 15.x-or-later saved export is assessed for active `boot host/network tftp:` configuration retrieval. Ordered `no boot` removals are honored, while `no service config` is not treated as disabling the explicit boot fetch on those releases. The parser emits protocol and retrieval kind but redacts endpoint and file path. CNS, PnP, unqualified release defaults and actual network retrieval are outside this adapter.

IOS/XE HTTPS certificate assessment starts only at an explicitly enabled `ip http secure-server` and effective `ip http secure-trustpoint` selection. The parser reads exported public X.509 hexadecimal DER from the selected `crypto pki certificate chain`; CA-only, missing, malformed or multiply ambiguous identity material remains ungraded. The shared certificate evaluator checks public key/signature properties independently of optional assessment-time validity, declared `ios-https` identity and approved exported trust-anchor fingerprints. Implicit primary/self-signed selection, filesystem-referenced material, private keys, runtime served certificates and revocation are not inferred.

ASA's opt-in IKE policy adapter keeps enabled IKEv1 and IKEv2 interface families separate, resolves explicit DH alternatives within each policy, and compares only exact group identities against `approved_asa_ike_dh_groups`. Existing legacy group 1/2/5/14 findings are not duplicated by the profile rule. Unenabled policies, unspecified group defaults, peer negotiation, and IPsec phase-2 PFS are outside this increment; no numeric DH-group strength ordering is inferred.

ASA remote-access authentication has a separate, 9.16+-qualified, policy-gated WebVPN slice. It follows an enabled listener to a remote-access tunnel group with an enabled group URL and explicit webvpn-attribute authentication mode. Only an explicit AAA-only path violates an opted-in client-certificate requirement; certificate-containing modes are separate from SAML and unknown external identity-provider policy. Group URLs are retained only for internal effective-state/removal ordering and redacted from records and findings. Earlier releases, default groups, alias-only selection, group-policy authorization filters, IPsec entry points, operational MFA and live reachability remain outside this slice.

The first additional IOS/XE routing adapter is deliberately limited to classic default-VRF IPv4 RIPv2. It binds an explicit classful `router rip network` to a configured interface address, follows ordered removals, receive-version and key-chain/mode commands, and excludes shut or unmatched interfaces. RIP passive mode suppresses sending but not inbound update processing, so it does not suppress an authentication finding. A configured MD5 chain with no explicit receive-version-2 boundary remains unknown because version-1 acceptance cannot be ruled out. Named/VRF address-family RIP, unsupported/malformed commands, key lifetimes, peer identity and runtime exchange require separate evidence; key-string values never leave the parser.

The companion IOS/XE EIGRP adapter is limited to classic numeric-AS, default-VRF IPv4 processes. It binds effective `network` selectors to configured interface addresses, resolves per-AS interface MD5 mode and key-chain bindings, and excludes shut, unmatched or passive interfaces. Unlike RIP, passive EIGRP does not exchange hellos or updates and cannot form an adjacency. Missing mode is unauthenticated; enabled MD5 without an exported effective key is unresolved; unsupported mode syntax is unknown. Named/address-family EIGRP, VRF and IPv6 activation, and operational neighbor state require separate adapters or evidence. Shared key-chain parsing retains only key presence and redacted evidence.

The first key-lifetime adapter compares exported IOS/XE key-chain send and accept windows for active OSPF, classic RIPv2 and classic EIGRP bindings. It requires both an assessment-policy timestamp and an explicit UTC-zero device timezone without daylight saving. Each key's absent lifetime uses the documented forever default; malformed or unsupported syntax remains unknown. A finding requires proof that every material-bearing key is outside either the send or receive-valid window. Rollover keys are assessed together, no local clock or runtime neighbor state is inferred, and key strings never enter the evidence.

Inspection policy follows attachment scope rather than object inventory. PAN-OS records retain enabled allow-rule profile mode, resolve groups and individual profiles in same-vsys/shared precedence, and classify exported actions. Anti-spyware and vulnerability profiles additionally retain ordered severity/action selectors: only the first broad, explicit critical/high selector is assessed for an active attachment, so a later blocking rule cannot mask an earlier nonblocking action. FortiOS records retain enabled accept-policy UTM mode, expand profile groups in VDOM/global/root precedence, and resolve each member independently. IPS sensors additionally retain ordered entries; only an explicitly enabled first broad critical/high selector with an explicit pass/monitor action is reported. Narrow predicates, omitted severity/action/status, signature exceptions without provable severity, built-in definitions and unexpanded inheritance remain unknown rather than proof of protection or exposure. Custom empty and explicitly non-blocking attached profiles are distinct from unresolved references; disabled rules and unbound definitions are ignored. Static profile resolution never asserts subscription health, signature freshness or runtime inspection.

Traffic domains must also remain separate. FortiOS transit policies and IPv4/IPv6 local-in policies have different typed records and checks. Junos stateless firewall filters and SRX zone-pair security policies likewise use different records: the SRX model resolves static zone/global address books and applications while preserving order, deletion, deactivation and apply-groups uncertainty. A wildcard finding requires complete positive resolution; a dynamic or inherited unknown is never treated as `any`.

Policy-effectiveness proof uses small shared set-containment primitives, not a universal ACL parser. `src/devices/common/policy_semantics.py` represents bounded IPv4/IPv6 address intervals, protocol/port intervals and explicit proof outcomes (`PROVEN`, `DISPROVEN`, `UNKNOWN`). Eight adapter families retain native boundaries: Check Point layer/time/VPN/through/install targets; ASA bindings and configured line order; IOS/IOS-XE effective interface attachment, direction, family and sequence order; PAN-OS device/vsys/rulebase and management/NAT uncertainty; FortiOS VDOM/global scope and separate IPv4/IPv6 policy; Junos SRX zone pairs, address books, application sets and inheritance uncertainty; ScreenOS zone pairs, policy order and authentication behavior; and SonicOS E-CLI address family, zone pair, rule order, schedule, logging and extra-predicate state. Each adapter resolves only documented, statically complete address and protocol/port forms, including bounded nested groups where the platform supports them. Dynamic/FQDN/wildcard objects, cycles, missing references, source-port constraints, schedules, negation, identity/application predicates and unexpanded inheritance remain unknown wherever the native adapter cannot prove equivalence. IOS noncontiguous wildcards and extended clauses such as TCP flags, fragments and time ranges also block proof. Redundancy requires identical terminal action and modeled non-match behavior so logging, inspection, NAT or authentication differences are not erased. Stateful transit policies, self-traffic policies and stateless filters remain separate models, and a shared containment result is never evidence of runtime rule usage.

Control-plane protection is attachment-driven and platform-native. IOS/IOS-XE begins at each active control-plane input service policy and follows policy maps into classes, ACL selectors and explicit policing/drop actions. Junos begins only at `lo0` family input/input-list attachments and resolves the matching-family stateless filter, ordered terms and referenced policers; an ordinary interface filter is not Routing Engine protection. EOS models its optional direct control-plane ACL separately from the always-attached system-owned `copp-system-policy`, resolving only exported custom class/ACL and shape/bandwidth overrides. FortiOS DoS records remain transit/edge policy rather than router CoPP and preserve every enabled anomaly's action, logging and threshold state independently. ASA MPF analysis follows attached policy maps to class-level connection limits; explicit zero is unlimited, while an unattached policy does not count. Undefined, empty, removed, disabled, wrong-family and unreferenced objects cannot establish protection. Omitted generated policy content, live counters/hardware programming and finite-rate suitability remain platform-managed, unknown or human-reviewed.

Configuration-management evidence is also native rather than reduced to a generic backup flag. IOS/IOS-XE separates archive destination and write/time triggers from `archive log config`, including secret suppression and syslog notification. Junos retains every ordered archive site, transfer-on-commit/interval state, routing instance, and independent accounting or syslog change-audit selector. FortiOS recognizes exported `system auto-script` entries that invoke supported backup commands and resolves their start, interval, repeat, destination, and transport without retaining command credentials. The assessment context determines whether an absent on-box schedule is required; external backup processes remain unknown. These records establish configured intent only—not transfer success, retained copies, storage integrity, or recoverability.

VPN analysis begins at an active attachment, not at an inventory of proposal objects. FortiOS resolves an enabled phase2 binding to phase1 only inside its VDOM scope. Junos resolves an active policy tunnel or interface-bound VPN through gateway, IKE policy/proposal and IPsec policy/proposal relationships. Unreferenced weak objects and disabled tunnels are ignored, while broken active chains are reported separately from explicit weak algorithms. Static configuration cannot establish negotiated transforms, peer identity, policy installation or security-association health.

Credential-bearing parsers expose `CredentialMetadata` rather than raw values. The record keeps storage format and storage assessment separate from exact known-default and optional operator-blocklist comparisons: a `NO_MATCH` result only means that the supplied representation did not equal that list, never that the credential is strong. A shared versioned evaluator now consumes the secret-free IOS/XE, ASA, Junos, ScreenOS, and EOS records and returns independent storage, known-default, blocklist, and plaintext-length property states. Plaintext length is retained only as an integer when the parser proves plaintext storage. Optional blocklist SHA-256 values are compared inside the parser and are represented only as match/no-match/not-evaluated; the verifier list is not serialized. `UNKNOWN` and `MALFORMED` formats cannot be promoted to approved storage or receive plaintext verdicts. Secret values remain inside the parser boundary; evidence contains only redacted command structure. Reversible decoding, cross-account reuse, and cracking-tool export are not performed by this layer.

Management-certificate assessment uses the same separation. PAN-OS resolves an active management TLS/profile reference to a shared or device-scoped certificate object; ASA resolves effective SSL trustpoint assignments to trustpoint and certificate-chain declarations. FortiOS evaluates a selected `admin-server-cert` only when HTTPS management is enabled, resolving supplied local public certificate objects and CA objects; an export without certificate inventory remains unknown. A shared X.509 layer parses public DER/PEM and exposes only fingerprint, subject/issuer, SAN, validity interval, public-key/signature properties and CA/self-issued state. Private-key and certificate payloads are never stored in typed records or finding evidence. Validity requires an explicit timestamp, identity requires an exact scope mapping, and chain validation requires an approved SHA-256 anchor that is also present in the export. Missing inputs remain unknown. Static validation never claims revocation state, client trust, or which certificate is currently served.

### Analyzer layer

An analyzer is the CLI-facing orchestration function for one platform. It:

1. obtains the registered parser through `get_parser()`;
2. optionally obtains external advisory data where supported;
3. calls the platform processor;
4. gathers hostname/device metadata;
5. calls the report generator.

Analyzer modules remain thin by design. Detection logic belongs in plugins and syntax logic belongs in parsers.

An optional immutable `AssessmentContext` is created at the CLI boundary and attached to the parser before processing. It carries policy identity/provenance, explicit device and interface roles, exact protected-AAA profile declarations, configuration-backup scope, credential length/blocklist policy, and category exclusions. Processors filter excluded rule categories only after plugins finish, preserving parser coverage and effective-state reconstruction. Reports always serialize the non-sensitive active policy metadata and warn that exclusions are not evidence of compliance. Role/path consumers must require an exact explicit declaration; names, addresses and routes are not topology inference.

### Processors and plugin registration

Each platform processor exposes a `process_*_conf()` function and an explicit ordered tuple of plugin classes. Explicit registration makes the public scan surface deterministic and prevents an unrelated file placed in a plugin directory from silently becoming executable analysis.

Processors instantiate each plugin once, call `analyze(parser)`, combine its findings, and may deduplicate by `(rule_id, evidence)` while preserving findings for distinct affected objects.

### Plugins

Every plugin extends `BasePlugin` and receives a constructed parser. Plugins may consume the normalized model or a typed vendor-specific parser API. Direct file I/O and independent reparsing are not allowed.

A plugin emits `Finding` instances. Each finding requires:

- stable namespaced `rule_id`;
- canonical device ID;
- title, observation, impact, and recommendation;
- typed severity;
- exploitability narrative;
- sanitized configuration evidence;
- vendor/benchmark references for new or modified checks.

One finding should describe one root cause. Multiple affected objects may share a rule ID when their evidence differs.

### Reporting

`src/report/report.py` renders findings and optional software advisories as HTML or JSON. The neutral `Finding.to_dict()` contract remains the issue JSON boundary. `src/report/coverage.py` separately derives an additive, versioned ledger from `NormalizedConfig`: parser/input provenance, every normalized field's knowledge state and known item count, exclusion selection, and sanitized parser diagnostics. It never serializes normalized evidence.

Configuration inventory is explicit and off by default. The assessment policy may select normalized `interfaces`, `management-services`, `policies`, and `logging-destinations`; only `KNOWN` collections and fixed allowlisted record fields are serialized. Users, credential metadata, evidence, certificate payload/material, and raw native configuration are outside this path. Both formats label inventory as configuration data, not passed controls, and include a concise finding-derived remediation priority list that is not a compliance score. Callers that omit coverage metadata receive an explicit unavailable notice rather than an implied complete assessment. All report text is UTF-8 and HTML autoescaping applies to findings, inventory and advisory summaries.

### Validation

Unit tests cover parser semantics, individual rules, finding validation, registry reachability, CLI behavior, and reports.

`tests/test_data/regression/manifest.json` defines the permanent target corpus. `scripts/run_full_regression.py` constructs parsers through the public factory, requests normalized state, executes public processors, rejects duplicate rule/evidence identities, compares exact finding snapshots, and then runs the entire test suite.

`.github/workflows/build-python.yml` runs the same gate across the supported Python and operating-system matrix. CodeQL remains as the repository's built-in static security workflow; unconfigured inherited third-party service workflows are intentionally not part of the current architecture.

## Supported-depth boundary

The registry contains both target-baseline and partial devices. Registration guarantees that the CLI can construct and dispatch the implementation; it does not guarantee equal detection depth. [Supported devices](SUPPORTED_DEVICES.md) is the user-facing authority for current maturity and input-dialect limits. Original-Nipper lineage does not imply dialect or check-category parity.

## Architectural invariants

- Do not add a second device list or dispatch chain.
- Do not treat absence as a known secure or insecure state unless the relevant platform/version default is established.
- Do not use unanchored positive substring matching where a negated command can match.
- Do not coerce untrusted tokens without parse-error handling.
- Do not expose secrets in evidence.
- Do not dynamically discover executable plugins.
- Do not add a public rule without true-positive, true-negative, edge/override, and pipeline tests.
- Do not describe a partial parser as target-baseline support.

## Durable engineering decisions

These decisions apply to future checks, parser work, and device additions:

- Reconstruct effective configuration state in parsers, preserving source order, scope, negation, removal, disablement, and inheritance where the format supports them.
- Evaluate related fields from the same policy, object, interface, or management profile; resolve attachments before reporting exposure.
- Treat missing, unsupported, malformed, and version-dependent state as explicit unknowns rather than silently secure or insecure values.
- Keep vendor-specific grammar in typed parser APIs. Extend the normalized model only for concepts that have stable meaning across platforms.
- Redact passwords, keys, communities, tokens, and other secrets before storing evidence or serializing findings.
- Require every new or materially changed finding to have a stable namespaced rule ID, one root cause, sanitized evidence, an authoritative reference, and positive/negative edge-case coverage through the public processor.
- Keep the permanent regression corpus exact and duplicate-free; snapshot changes require semantic review rather than automatic acceptance.
- Separate static configuration analysis from live operational checks such as certificate validity, licensing, runtime authorization, controller-inherited state, and current firmware support.

See [Extending pynipper-v2](EXTENDING.md) for the implementation workflow.
