# Report usability and evidence review

Reviewed 2026-10-07 at commit `0a15ded`. This is a design proposal; it does not change detection, rule IDs, finding bases, snapshots, or the task backlog.

## Findings from the review

The current FortiOS implementation is a useful foundation. Coverage is the last HTML chapter and collapsed by default. Optional inventory and credential sections remain ahead of it, and parse-error notices remain visible. Evidence context is additive, parser-owned and bounded. Other vendors need selective context migration rather than a blanket object dump.

I inspected the shared models, finding serialization, report template and scripts, FortiOS context producer, cross-vendor evidence producers, audit CLI, advisory command and batch workflow. I also inventoried emitted findings from all 39 permanent sanitized regression exports, through their public parsers and processors. The companion `report-evidence-inventory.md` groups 322 family/rule pairs with representative current evidence.

Across those fixtures:

- 367 finding instances were emitted; 39 have richer context, all FortiOS.
- 114 finding instances have evidence but no located statement. Many describe omissions or documented defaults; these are not automatically defects.
- 41 context occurrences remain after deduplication within each finding. Median size is five statements, maximum 14, and 12 exceed eight statements.
- The context occurrences include 75 rows with values omitted by the context allowlist. This includes repeated contexts across findings, not 75 distinct settings.

These figures describe the regression fixtures, not production prevalence. They do not establish how the interface performs on large real exports. Tests exercise the 200-statement limit, but production usability at that limit remains an evidence gate.

## Choose the smallest useful proof

Use three presentations, selected by the parser's existing typed records:

1. **Specific settings:** show the relevant two to six statements for a listener, account, service, timeout or crypto option. A finding with a complete single command does not need an object excerpt.
2. **Bounded object context:** show a policy's relevant selectors and behavior, or an administrator's role, authentication and trusted-host configuration. Select supported fields; do not expose arbitrary object content.
3. **Related objects:** show separately titled contexts for the attachment and its referenced target. A user and privilege class, listener and AAA binding, policy and address group, or virtual server and TLS profile require relationship evidence, not adjacent lines.

Missing protection should be explained next to the owning object: “No trusted-host settings are configured in this administrator object.” Do not invent a line number for absence. Documented defaults need their release qualification and vendor citation. Undefined local references remain broken-binding findings under AGENTS.md; only externally managed or inherited references are described as outside the export. Presentation must preserve those distinctions without recalculating detection.

## Vendor migration plan

| Family | Observed gap or current strength | Proposed parser-owned context |
|---|---|---|
| FortiOS | Object context is present, but account context does not automatically show the referenced privilege profile; policy context can name groups without their definitions. | Add separate, bounded account/profile and policy/group/interface contexts using existing same-VDOM/global resolution. Put the decisive settings before secondary or masked settings. |
| Cisco IOS / IOS-XE | `cisco.ios.ssh.vty_access_restriction` can cite only `line vty 0 4`; some AAA and default findings are summaries. | Show the effective VTY range, input protocols, access-class and AAA bindings. Attach the selected ACL or method list as a separate context. Include the assessed time and key-chain binding for routing-key findings where relevant. Keep overlapping ranges and ordered `no` commands resolved by the parser. |
| Cisco ASA / PIX | Management grant commands are often already sufficient. AAA findings can be unlocated summaries, and ACL issues may need an access-group attachment or referenced object group. | Pair management grant with applicable authentication/accounting binding; pair ACL entry with interface attachment and only the relevant network/service group expansion. Preserve PIX versus ASA release qualification. |
| Junos | A super-user finding can show only the user class statement; group inheritance and policy attachments require additional proof. | Separate user/login-class, zone/interface/screen, policy/address-book and protocol/key contexts. Preserve logical-system/routing-instance scope and active/deleted/deactivated state. Label unexpanded apply-groups explicitly; do not present inherited content as locally resolved. |
| PAN-OS | `policy.broad_allow` and `policy.security_profiles` cite a rule identity and line, without the rule selectors or profile contents. | First migrate security rules: from/to, source/destination, application/service, action, logging and profile attachment. Add separate profile-group/profile and administrator/authentication contexts. Label device/vsys/shared/pre/post-rule scope and unresolved Panorama inheritance. Render selected XML leaves, not a complete XML subtree. |
| Check Point FW1 | Broad/shadowed rule evidence identifies layer, rule and position, but does not display selectors or referenced object definitions. | Present the rule's action, source/destination/service, tracking, install-on and layer. For shadowing, show earlier and later rules separately. Add bounded referenced objects from objects.C with their own filenames and lines; distinguish policy exports from Gaia administration. |
| Check Point Gaia | Many service and SNMP commands are already readable; omitted timeout/default evidence can be a summary. | Show the relevant effective Clish commands for web sessions, password policy, user privileges and permitted networks. Keep secret hashes redacted; attach default/release notes without fabricating source statements. |
| Arista EOS | eAPI findings already include the management block and protocol statements. Role, command authorization and TLS references are harder to verify. | Preserve compact eAPI evidence; add scoped account/role, listener/AAA and listener/TLS contexts. Produce them from EOS records rather than borrowing IOS meaning solely through inheritance. |
| HP ProCurve / ArubaOS-Switch | SNMP findings can show only `credential configured`; that hides the command and access mode even though the credential itself must stay secret. | Show a redacted SNMP directive plus manager/operator access and any source restriction. For management authentication, show channel-specific login/enable methods and timeout. Keep release-default and include-credentials qualifications visible. |
| ScreenOS | Broad/unlogged policy evidence currently includes unrelated IKE commands in the vulnerable fixture. | Correct evidence membership before migration. `_parse_policy_continuation` appends a line before validating its relevance. Select recognized policy statements only, then add separate address/service group and policy-authentication contexts. Any semantic parser repair needs its own review, not an incidental UI change. |
| SonicOS | Access-rule evidence already includes selectors, enablement and logging, so a large excerpt adds little. | Preserve concise rule statements; expand only zone/address/service references and account privilege/authentication relationships. Stay within the supported SonicOS 7 E-CLI dialect. |
| F5 BIG-IP | Existing evidence can already show a virtual server and TLS profile, but omits the virtual's destination/profile attachment in some findings. | Pair virtual destination and selected profile attachment with the relevant TLS fields; pair self IP with lockdown, VLAN and address. Preserve partition paths, module qualification and tmsh inheritance/default distinctions. Do not dump full SCF blocks. |

Prioritize PAN-OS policy, Check Point FW1 policy and IOS VTY/AAA contexts because the current evidence often does not expose the decisive fields. F5, EOS eAPI, SonicOS rules and simple ASA grants need smaller targeted additions.

## Shared context contract

Keep the existing EvidenceContext and additive JSON serialization. Multiple related contexts can already be represented by attaching separate contexts to the relevant evidence records; avoid a new generic raw-file extraction service.

Each producer should consume resolved native records and their evidence map, accept a specific entity or binding, and return sanitized selected statements. It must preserve original source locations and clearly label effective values reconstructed from multiple edits. Do not reparse command text in the report or infer relationships from object names.

For cross-object context, use headings such as “VTY listener”, “Selected login method”, and “Referenced server group”, each including its scope. Show the source filename alongside context line numbers: the current HTML context rows show only “Line N”, which is insufficient once rules.C and objects.C appear together. Keep source-qualified identities in deduplication.

Introduce a presentation-origin enum only if several producers need it. Today the template labels every unlocated context line “Derived”; future defaults, omissions and unresolved references need their own labels rather than sharing that label. Keep these annotations separate from FindingBasis and detection state.

## Compact presentation

- Retain eight statements as the initial disclosure threshold, but measure meaningful settings separately from container headers, masked placeholders and long wrapped lines. Prefer a visible decisive-settings preview with the longer context collapsed underneath.
- Keep the 200-statement ceiling as a safety bound. It is too large to serve as the default excerpt target. Select the cited field and proof-bearing settings first, then a small bounded set of supporting statements. Large groups should show relevant members and an explicit omitted count, not silently sample a proof.
- Distinguish “setting not configured”, “value withheld”, “value redacted”, “derived effective value”, and “additional statements truncated”. For irrelevant unapproved fields, prefer one count in a note over many placeholder rows. Essential omitted/default notes must remain visible even when the excerpt is collapsed.
- Collapse long legacy evidence tables too. At present only EvidenceContext length triggers the new disclosure; large existing evidence lists can still dominate a finding.
- Keep observation, decisive proof and remediation visible. Generic abuse examples and “Also check” lists are candidates for secondary disclosure when they repeat the finding's impact or link to many unrelated issues.
- Preserve coverage at the bottom. Add a compact top-level indication of parse failure, unresolved templates and material unassessed scope with a link to coverage, without adding another large coverage table or implying a score.
- Make navigation reveal its disclosure target. The current coverage anchor can land on a collapsed chapter; findings linked while a severity filter hides them should be revealed. Restore prior disclosure/filter state after printing; current beforeprint expands everything and resets the filter without afterprint restoration.

## CLI and optional workflow improvements

Provide one discoverable command surface for audit, batch and advisory preparation while retaining existing entry points and compatibility flags. For example, a future `pynipper-ng advisories prepare --manifest batch.json --output-dir bundles` can acquire public metadata as an explicitly separate operation. A subsequent audit command only reads those bundles.

Manifest advisory preparation should deduplicate exact product/version/module requests, reuse compatible cached bundles with visible acquisition dates, list ambiguous versions needing an explicit override, and record success/failure per requested product. Network access must be limited to the advisory acquisition operation and must send only product/version/module metadata, never configuration content or customer object names. Provide a plan-only mode to show the requests before acquisition; do not make approval mandatory for an explicitly requested fetch.

The current batch manifest supplies one advisory bundle while heterogeneous devices can require different bundles. Propose optional per-device bundle paths and a preparation index that maps requests to bundle files. Keep failed/missing advisory preparation independent of configuration audit success.

Improve ordinary CLI feedback: use “Reading local advisory data” consistently, clearly show the selected family, report path and skipped optional work, and explain ambiguous device/version choices with a usable next command. Choose report.json as the default name for JSON output instead of retaining report.html. Summarize malformed policies and parser failures without exposing source values.

Batch HTML+JSON currently runs the full analyzer twice. A later orchestration change can produce one assessment result and render both outputs, preserving a single parsed snapshot and avoiding duplicate work. Treat that as an independent architectural change with output-equivalence tests.

## Staged delivery and acceptance

1. Evidence selection and compact HTML improvements: review ScreenOS membership separately; display filenames in context; keep omission notes visible; improve disclosure navigation/print restoration and legacy evidence limits.
2. Cross-vendor context: PAN-OS and Check Point policy pilots, then IOS/ASA management bindings and Junos accounts; follow with the remaining targeted cases in the table. Keep parser producers vendor-specific and migrate one finding family at a time.
3. Related-object contexts and large-export trials: FortiOS privilege/address groups, F5 attachments and remaining vendor relationships. Obtain sanitized representative exports, including groups, repeated edits, inheritance and multiple domains. Keep unsupported/sample-dependent items open as evidence gates.
4. Advisory preparation and command discoverability: separate explicit acquisition, compatible per-device bundles and useful cache/status reporting. Consolidate batch rendering only after the reusable result boundary is designed.

For each context migration, require existing detection identities and finding counts to remain unchanged, additive JSON context, HTML escaping, absence/default labels, active-object selection, source locations, tenant/partition isolation, repeated edits/removal, broken local bindings, external inheritance, secret exclusion, bounds and offline operation. Validate print and keyboard behavior in a browser when changing interaction. Run the full regression gate for implementation changes without regenerating snapshots merely to pass.

Validation performed for this review: 97 focused evidence, report, redaction and batch tests passed; all 39 exact permanent corpus configurations passed. The handoff reports an earlier full 3,880-test pass; I did not rerun the full suite for this design-only review. No parsers, plugins, findings, report code or backlog files were changed.
