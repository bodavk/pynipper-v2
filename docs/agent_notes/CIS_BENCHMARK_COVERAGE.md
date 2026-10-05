# CIS benchmark coverage review

Reviewed 2026-10-05 (rule IDs verified against the code the same day) from CIS benchmark PDFs supplied by the maintainer (kept outside the repository; CIS text is licensed and is not reproduced here). Recommendation numbers are cited; descriptions below are our own paraphrases. The full per-recommendation catalogue with CIS titles lives in the git-ignored `Claude outputs/cis/` folder.

Mapping status: **C** covered by an existing rule, **P** partially covered, **V** believed covered but the rule ID must be verified against the code, **G** configuration-assessable gap, **M** organisational/manual (not provable from a configuration), **R** needs runtime or companion data (advisories, hit counters), **N** not a security control for this tool or a policy-specific variant.

CIS mapping is cross-reference metadata, not a compliance claim (see SC-049 and the standards note in `SECURITY_COVERAGE_TASKS.md`). The tool's evidence rules still apply: an absent setting is a finding only with a vendor-documented default; a CIS recommendation alone is not a source for a default.

## Benchmarks reviewed

| Benchmark (version) | pynipper family | Recs | C | P | V | G | M | R | N |
|---|---|---|---|---|---|---|---|---|---|
| FortiGate 7.4.x v1.0.1 | FORTIOS | 64 | 22 | 7 | 0 | 28 | 4 | 2 | 1 |
| Cisco IOS XE 17.x v2.2.1 | IOS_XE / IOS family | 84 | 55 | 6 | 0 | 20 | 3 | 0 | 0 |
| Cisco ASA 9.x Firewall v1.1.0 | ASA | 78 | 36 | 2 | 0 | 30 | 5 | 2 | 3 |
| Juniper OS v2.1.0 | JUNOS | 178 | 52 | 17 | 15 | 66 | 17 | 2 | 9 |
| Arista EOS v1.0.0 | ARISTA_EOS | 33 | 21 | 3 | 0 | 6 | 1 | 0 | 2 |
| F5 Networks v1.0.0 (archived) | F5_BIGIP | 29 | 16 | 1 | 0 | 10 | 2 | 0 | 0 |
| Palo Alto Firewall 11 v1.2.0 | PANOS | 78 | 27 | 7 | 0 | 39 | 4 | 0 | 1 |
| Check Point Firewall v1.1.0 | CHECKPOINT_FW1 / GAIA | 60 | 10 | 0 | 11 | 30 | 3 | 1 | 5 |

Older or sibling benchmarks were compared with the newest one for the same family; only recommendations without an equivalent are listed in the tasks below: FortiGate 7.0.x v1.4.0 and FortiGate v1.1.0; Cisco IOS XE 16.x v2.2.0, IOS 17.x v2.0.0, IOS 16 v2.0.0, IOS 15 v4.1.1 (archived), IOS XE v1.0.0; Cisco Firewall 8.x v4.2.0 (archived, ASA 8.x/PIX); Palo Alto Firewall 10 v1.3.0. Cisco IOS XR 7.x v1.0.1 and NX-OS v1.2.0 were supplied but cover platforms the tool does not support; they are not mapped.

## New tasks

Priorities follow the existing scheme (P1 direct administrative/authentication/route-injection risk, P2 hardening depth, P3 hygiene). Each task still needs a vendor source for any default it relies on.

### SC-055 — FortiOS CIS gaps

- **P2 management hardening:** post-login banner (7.4 2.1.2); hostname shown on the GUI login page (2.1.13); SNMPv3 per-user query (2.3.3); built-in `admin` account name still in use (2.4.1; 7.0 2.4.1 factory password is not provable); default HTTPS/SSH admin ports (2.4.7); local-in virtual patching (2.4.8); intra-zone traffic allowed (1.2); DNS servers set (1.1); unique policy names (FortiGate v1.1.0 3.3).
- **P2 security-profile depth:** botnet detection in IPS (4.1.1); antivirus push updates, outbreak prevention, AI/heuristic detection, grayware, inline sandbox, CDR (4.2.1, 4.2.3–4.2.7); DNS-filter botnet blocking and query logging (4.3.1, 4.3.2); application control high-risk categories, non-default ports and logging (4.5.1–4.5.3); ISDB-based deny of Tor/malicious sources (3.3); compromised-host quarantine (5.1.1).
- **P3 monitoring/HA:** SNMP memory traps (2.3.4); single-CPU-core overload event (2.1.12); HA monitored interfaces, reserved management interface and group ID when HA is configured (2.5.2–2.5.4).
- Partial items to deepen: management services on WAN (1.3), SNMPv3 trusted hosts (2.3.2), local-in policies (2.4.6), `ALL` service in policies (3.2), DNS-filter/web-filter/app-control attachment (4.3.3, 4.4.1, 4.5.4).

### SC-056 — Cisco IOS / IOS-XE CIS gaps

- **P2:** login block-for/lockout (IOS 17.x 1.6.1; IOS XE v1.0.0 1.2.11; IOS XE warns on `no login block-for`); HTTP secure-server session limit and idle timeout (1.2.9, 1.2.10); TTY line authentication and timeout (IOS 15 1.1.5, 1.2.8); zero-touch/autoinstall features (IOS XE v1.0.0 2.1.7).
- **P3:** AAA accounting network/system (1.1.9, 1.1.10); exec and webauth banners (1.3.1, 1.3.4); SNMP trap host/traps (1.5.7, 1.5.8); hostname and domain name (2.1.1.1.1–2.1.1.1.2); `no service dhcp` (2.1.4, partial); logging buffer size, console level, debug timestamps, source interface, login success/failure logging (2.2.2, 2.2.3, 2.2.6–2.2.8); loopback and management source interfaces for AAA/NTP/TFTP (2.4.1–2.4.4); CEF and gratuitous ARP (IOS XE v1.0.0 2.1.8, 3.1.5).
- Also: `aaa authentication enable default` method list (1.1.3); deepen connection accounting (1.1.7), CDP (2.1.2) and aux transport (XE16 1.2.9). The 2026-10-05 verification against rule IDs resolved the earlier verify items (SSH timeout/retries, TCP keepalives, aux/console timeouts, RSA key size and logging trap level are covered).
- Note: XE17 1.4.2 recommends `service password-encryption`; Cisco's IOS XE security-warnings reference now marks it insecure in favour of AES (type 6). The tool should keep preferring AES storage and say so in guidance.

### SC-057 — Cisco ASA CIS gaps

- **P2:** password recovery enabled (1.1.4); secure HTTP client authentication (1.4.3.3); RSA key size (1.6.3); AAA command and exec authorization (1.4.4.1, 1.4.4.2); OSPF/EIGRP/BGP authentication (2.1.1–2.1.3); untrusted-interface protections: DNS guard, DHCP, fragment limits, IPS, botnet traffic filter, security level 0 on the Internet interface (2.3, 2.4, 3.1–3.3, 3.8, 3.9); proxy-ARP on untrusted interfaces (2.2); RIP authentication and serial-console authentication (Firewall 8.x 2.1.1, 1.4.3.4).
- **P3:** host/domain name (1.2.1, 1.2.2); unused interfaces shut down (1.2.4); ASDM, EXEC, LOGIN and MOTD banners (1.5.1–1.5.4); logging to monitor/serial console, device ID, history level, timestamps, buffer size and level (1.10.2, 1.10.4–1.10.8, Firewall 8.x 1.10.2); SNMP traps (1.11.4).
- Already covered after verification: management authentication and accounting, logging trap level, ICMP restriction (2.5) and basic threat detection (3.6).

### SC-058 — Junos CIS gaps

- **P1 (extends SC-005):** IS-IS loose authentication check and suppressed hello/PSNP/CSNP authentication (4.2.4–4.2.7); RIP, OSPFv3, BFD, LDP, MSDP, RSVP authentication and BFD loose check (4.4.1–4.11.1); EBGP GTSM (4.1.3).
- **P1/P2 management plane:** REST API depth: HTTPS certificate and mutual auth, cipher list, API explorer, allowed sources, connection limits, service address (6.10.5.2–6.10.5.11; REST over HTTP is already `juniper.junos.management.rest_http`); XNM-SSL/NETCONF/SSH connection and rate limits, XNM-SSL SSLv3 (6.10.1.3, 6.10.1.4, 6.10.3.2–6.10.4.2); web-management PKI certificate (6.10.2.3); local accounts usable only on AAA loss (6.3.2); user and root SSH-key login (6.6.13, 6.9.3); RADIUS MS-CHAPv2 and AAA source address (6.8.4, 6.8.5); reverse telnet and unused DHCP service (6.10.7, 6.10.10).
- **P2:** routing-engine filter completeness: explicit terms per service/protocol, rate limits, flood protection, explicit deny-and-log (2.2–2.6); internet-options ICMP rate limits, source quench, TCP SYN/FIN drop, RST (6.5.1–6.5.5); console/aux port disable, insecure flag and log-out-on-disconnect (6.11.1–6.11.5); diagnostic and PIC console passwords (6.4.1, 6.23); autoinstallation (6.13); configuration file encryption (6.14); proxy ARP, router discovery, SEND (3.5, 4.10.1, 4.9.1).
- **P3:** local log files for firewall, authentication and interactive-command events (6.12.3–6.12.6); multicast echo, ping record-route and timestamps (6.15–6.17); NTP boot server and version (6.7.3, 6.7.4); unused interfaces disabled (3.3); dial-in caller ID/CHAP (3.1.x).
- Verify (V, 15 left after the 2026-10-05 check): SNMP client lists and v3 algorithms, password complexity/changes, AAA shared secret, SSH algorithms (see catalogue). Accounting, archive, lockout, login classes, idle timeout, password hashing, web-management timeouts, NTP, syslog, ICMP redirects and legacy services were confirmed covered.

### SC-059 — Arista EOS CIS gaps

- **P2:** enable secret (2.1.2); AES-GCM encryption of stored secrets (1.2); syslog over TLS (1.1.9).
- **P3:** DNS configuration (1.1.6); management VRF (1.1.1.1); Telnet management (2.8).
- Partial: IS-IS absence stays ungraded until Arista documents the default (3.1.2); SNMP VRF/ACL restriction (2.7.1); server groups (2.5.2). BGP authentication (3.2.1) is covered by the SC-005 EOS BGP stage.

### SC-060 — F5 BIG-IP CIS gaps

- **P2:** remote-auth fallback to local (2.3); RADIUS used for authentication only (2.1); remote-user partition access and terminal access (2.5, 2.6); SSH ciphers, MAC and key-exchange algorithms (4.5–4.7).
- **P3:** pre-login banner (4.1); ETag inode exposure (5.2); access-log restriction to administrative roles (6.3); NTP authentication depth (5.1, partial).
- Covered after verification: SSH, tmsh and console idle timeouts and SNMP allowed addresses (4.2–4.4, 6.1).

### SC-061 — PAN-OS CIS gaps

- **P1:** update server identity verification disabled (1.6.1; analogous to `cisco.asa.update.server_unverified`).
- **P2:** User-ID scope: probing, untrusted interfaces, include/exclude networks, agent traffic (2.1–2.4, 2.8); application allow rules from untrusted zones and trusted-IP deny rules (7.1, 7.3); decryption policy (8.1, 8.2); DNS sinkhole (6.4); URL filtering profile, actions and logging (6.8–6.12); credential submission (6.19); data filtering (6.13, 6.14).
- **P3:** SNMPv3 traps (1.1.1.2); high dataplane-load logging (1.1.3); password profiles (1.3.10); HA monitoring (3.1–3.3); content update schedules (4.1, 4.2; partial via `updates.threat_content`); WildFire settings (5.1, 5.4–5.6, 5.8; PAN-10 5.3); inline cloud/ML features (6.20–6.25).
- Note: 1.5.1 (SNMPv3 polling) conflicts with the maintainer decision not to schedule SNMPv1/v2c for PAN-OS; left as N.
- Covered after verification: syslog forwarding, banner, permitted IPs, HTTP/Telnet, management certificate, password complexity/history, idle timeout, lockout, NTP, zone flood/recon protection, service `any`; default-rule logging is partial.

### Check Point (no new task)

Global Properties, implied rules and anti-spoofing gaps (3.9–3.20) join **SC-017**; Gaia password-policy depth, MOTD, DNS/hostname, DHCP, SNMP traps, web UI TLS and audit-log settings (1.x, 2.1.x, 2.2.3–2.2.4, 2.5.3, 2.6.x) join **SC-023**. Both remain sample-gated.

### SC-062 — CIS cross-reference metadata (P3)

Resolve every **V** entry against the code; add CIS recommendation numbers to rule references and SC-049 control metadata where a rule fully implements a recommendation; keep the catalogue's benchmark versions current.

## Implementation status (2026-10-05)

Implemented (rule IDs; hygiene items are grouped into one informational `<vendor>.hardening.cis_hygiene` finding per device so the report stays short):

- **FortiOS (SC-055):** `policy.intrazone_allow`, `updates.schedule_disabled`, `policy.antivirus_detection_weakened`, `banner.post_login_disabled`, `management.login_hostname_disclosed`, `management.default_admin_ports`, `admin.default_account_name`; hygiene: 2.1.12, 2.4.8, 2.5.2–2.5.4, 4.5.2, 5.1.1, v1.1 3.3 (releases 6.4.14+ only).
- **IOS/IOS-XE (SC-056):** `authentication.login_lockout`; hygiene: 1.1.3, 1.1.9, 1.1.10, 1.2.9, 1.2.10, 1.3.1, 1.5.7, 1.5.8, 2.1.1.1.1, 2.1.1.1.2, 2.2.2, 2.2.3, 2.2.6–2.2.8, 2.4.2, 2.4.3, XE v1.0 2.1.8. TTY timeouts were already covered (`tty.session_timeout`).
- **ASA (SC-057):** `aaa.management_authorization`, `routing.{ospf,eigrp,rip,bgp}.authentication`, `interface.external_security_level`, `services.external_dhcp_server`, `services.dns_guard_disabled`, `platform.password_recovery`; hygiene: 1.2.1, 1.2.4, 1.5.1–1.5.4, 1.10.2, 1.10.4–1.10.8, 1.11.4.
- **Junos (SC-058):** `routing.isis.suppressed_authentication`, `routing.rip.authentication`, `routing.rip.cleartext_authentication`, `routing.ospf3.authentication`, `routing.bfd.authentication`, `routing.bfd.loose_authentication`, `management.unrestricted_rest`, `management.rest_explorer`, `services.autoinstallation`, `routing.router_discovery`; hygiene: 6.4.1, 6.5.1–6.5.5, 6.7.4, 6.8.4, 6.8.5, 6.10.1.3, 6.10.1.4, 6.10.2.3, 6.10.5.4, 6.10.5.5, 6.10.5.9, 6.11.1, 6.11.5, 6.12.5, 6.15–6.17.
- **Arista EOS (SC-059):** `logging.remote_cleartext`, `management.insecure_protocol` (telnet); hygiene: 1.1.1.1, 1.1.6, 1.2, 2.1.2.
- **F5 (SC-060):** `auth.remote_fallback_local`, `auth.remote_console_access`, `ssh.weak_algorithms` (from `sys sshd include`).
- **PAN-OS (SC-061):** `update.server_unverified`, `user_id.untrusted_zone`; hygiene: 1.1.1.2, 1.1.3, 1.3.10, 3.2, 4.1, 5.6.

Not implemented, with reason:

- **No vendor default or syntax source yet:** Junos LDP/MSDP/RSVP authentication (no default statement), EBGP GTSM (filter + TTL design), Junos authentication-order fallback semantics (6.3.2), SEND (4.9.1); PAN-OS URL filtering, data filtering, DNS sinkhole, credential submission, decryption, WildFire session/upload settings, inline cloud features (XML paths not verified against a vendor schema); FortiOS DNS-filter botnet/logging, application-control categories and logging, ISDB Tor deny, inline sandbox, CDR (profile semantics need vendor CLI references); ASA IPS/botnet/fragment items (module-dependent).
- **Not provable from configuration:** ASA RSA key size (keys are not in the running configuration), image integrity, organisational items (M/R in the catalogue).
- **Deliberately dropped:** F5 SSH banner and ETag hygiene (default banner state and ETag syntax not verified; would add a finding to nearly every export).
- **Sample-gated:** Check Point Global Properties, implied rules, anti-spoofing (SC-017) and Gaia items (SC-023).
- **Still to verify:** 15 Junos and 11 Check Point catalogue mappings (SC-062).
