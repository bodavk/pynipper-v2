"""Reader-oriented explanations for findings (PT-006) and related areas (PT-007).

A finding's own observation, impact and recommendation describe the exact
configuration state on this device. This catalogue adds vendor-neutral
context for readers who do not administer the platform every day:

* ``summary``: what the weakness means, in plain language;
* ``example``: a concrete way it could be abused;
* ``technical``: more precise background for technical readers;
* ``verify``: what to confirm manually, including compensating controls.

Entries are chosen by an ordered, explicit list of rule-ID patterns. The
patterns match the part of the rule ID after ``<vendor>.<os>.`` and group the
same weakness across vendors (for example every ``*.snmp.default_community``).
Each entry belongs to an *area*; areas define which other parts of the
report a reader should look at next. The text must not claim more than a
static configuration export can prove.
"""

from dataclasses import dataclass
import re
from typing import Optional, Tuple


@dataclass(frozen=True)
class Area:
    key: str
    title: str
    related: Tuple[str, ...]


@dataclass(frozen=True)
class Guidance:
    key: str
    area: str
    summary: str
    example: str
    technical: str
    verify: str

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "area": self.area,
            "area-title": AREAS[self.area].title,
            "summary": self.summary,
            "example": self.example,
            "technical": self.technical,
            "verify": self.verify,
        }


_AREA_LIST = (
    Area("traffic-policy", "Firewall and access policy",
         ("logging-audit", "threat-inspection", "control-plane")),
    Area("policy-hygiene", "Rule-base hygiene", ("traffic-policy", "logging-audit")),
    Area("threat-inspection", "Threat inspection and security updates",
         ("traffic-policy", "logging-audit", "platform")),
    Area("management-access", "Management access exposure",
         ("authentication", "session-control", "management-crypto", "logging-audit")),
    Area("management-crypto", "Management encryption and certificates",
         ("management-access", "authentication")),
    Area("authentication", "Administrator authentication",
         ("management-access", "session-control", "credentials", "logging-audit")),
    Area("authorization", "Administrator privileges", ("authentication", "logging-audit")),
    Area("session-control", "Login lockout and session limits",
         ("authentication", "logging-audit")),
    Area("credentials", "Stored credentials and password policy",
         ("authentication", "management-access", "backup")),
    Area("snmp", "SNMP monitoring access", ("management-access", "credentials", "logging-audit")),
    Area("time", "Time synchronization", ("logging-audit", "management-crypto")),
    Area("logging-audit", "Logging, accounting and change audit", ("time", "traffic-policy")),
    Area("backup", "Configuration backup and provisioning", ("logging-audit", "credentials")),
    Area("routing", "Routing protocol trust", ("control-plane", "logging-audit", "traffic-policy")),
    Area("control-plane", "Device self-protection and DoS controls",
         ("management-access", "routing", "logging-audit")),
    Area("access-edge", "Switch access-port protections", ("traffic-policy", "logging-audit")),
    Area("vpn", "VPN cryptography", ("traffic-policy", "logging-audit", "management-crypto")),
    Area("platform", "Platform lifecycle and general hygiene",
         ("threat-inspection", "management-access")),
)
AREAS = {area.key: area for area in _AREA_LIST}


_G = Guidance
_CATALOGUE = (
    # Firewall and access policy -------------------------------------------------
    (r"^((policy|filter|acl)\.(broad_\w+|overly_broad_accept|default_permit\w*|interzone_default_allow|negated_accept|risky_service_exposure)|afm\.default_accept)$", _G(
        "policy-broad", "traffic-policy",
        "A traffic rule (or the default action for unmatched traffic) allows much more than a "
        "business need usually requires, such as any source to any destination on any service. "
        "The firewall then no longer separates the networks on either side of it.",
        "Malware on one laptop in a user network scans the network and reaches a database or "
        "management interface in a server network, because the broad rule lets that traffic "
        "through. The attacker never has to defeat the firewall itself.",
        "Broad rules defeat segmentation and least privilege. They are especially dangerous when "
        "they sit early in an ordered rule base, because every later, more specific rule is then "
        "never reached. The tool reports a rule as broad only when its fields resolve completely; "
        "dynamic objects and inherited policy stay unknown.",
        "Confirm who owns the rule and which flows it must carry, then replace it with explicit "
        "sources, destinations and services. Until then, make sure the traffic it matches is "
        "logged and inspected (see the related areas), so misuse would at least be visible.",
    )),
    (r"^(policy|acl|layer)\.(\w*unlogged\w*|\w*untracked|logging|session_logging|log_forwarding)$", _G(
        "policy-logging", "logging-audit",
        "Traffic allowed by this rule is not logged, or its logs never reach a central log "
        "server. If the rule is misused, there is no record of it.",
        "An attacker uses an allowed path to copy data out of the network over several days. "
        "During incident response nobody can tell which hosts talked to each other, when, or how "
        "much data left, because the firewall kept no session records for that rule.",
        "Session logs are a primary source for detection and forensics. Logging at session end "
        "records duration and byte counts; forwarding to a central collector protects the records "
        "if the firewall itself is compromised or its local disk rotates.",
        "Check that the rule's traffic is logged elsewhere (for example on a downstream proxy or "
        "flow collector) and that the central log destination is configured and reachable.",
    )),
    (r"^(policy|acl|layer|object)\.(shadowed_rule|redundant_rule|disabled_permissive_rule|inactive_permissive_rule|expired_rule|install_scope_any|explicit_cleanup_missing|cleanup_untracked|unresolved_\w+)$", _G(
        "policy-hygiene", "policy-hygiene",
        "The rule base contains rules that never take effect, duplicate each other, are disabled "
        "but still present, or reference objects that do not exist. That does not open access by "
        "itself, but it makes the policy hard to read and easy to get wrong.",
        "An administrator adds a deny rule for a compromised host, but places it below an earlier "
        "rule that already allows the traffic. The new rule is shadowed, and the host stays "
        "reachable while everyone believes it is blocked. Similarly, a disabled \"allow any\" "
        "rule can be re-enabled by mistake during a change.",
        "Shadowed means an earlier rule fully covers this rule's traffic with a different "
        "action; redundant means the same action is already applied earlier. The tool proves "
        "this only for statically resolvable addresses and services in the same rule scope. It "
        "does not use hit counts, so unused rules at runtime are not claimed.",
        "Review the listed rules with the policy owner, remove or reorder them, and confirm with "
        "hit counters on the device before deleting anything.",
    )),
    # Threat inspection -----------------------------------------------------------
    (r"^(policy\.(security_profile\w*|ips_selector_\w+|threat_selector_nonblocking|idp_\w+)|security_services\.\w+|zone\.security_service_disabled|asm\.\w+|capture_atp\.\w+|updates\.\w+|fortiguard\.\w+|firmware\.automatic_updates|threat_detection\.\w+)$", _G(
        "threat-inspection", "threat-inspection",
        "Traffic that the firewall allows is not fully checked for known attacks or malware, or "
        "the signatures used for that check are not kept up to date.",
        "An allowed web or file-transfer connection carries a known exploit or malware sample. "
        "Because intrusion prevention or antivirus is not attached to the rule (or only alerts "
        "instead of blocking, or runs on old signatures), the attack passes through unchanged.",
        "Next-generation firewalls inspect allowed sessions with profiles such as IPS, "
        "antivirus, anti-spyware and URL filtering. A profile must be attached to the allowing "
        "rule, set to block high-severity threats, and fed with current content updates. The tool "
        "evaluates configuration only; it cannot see licence status or whether updates succeed.",
        "Confirm the subscriptions are licensed and current on the device, and check whether "
        "another control (proxy, endpoint protection, upstream IPS) inspects the same traffic.",
    )),
    # Management access -----------------------------------------------------------
    (r"^(management\.(telnet|http|insecure_protocol)|vty\.(telnet|insecure_output_transport)|eapi\.(insecure_http|https_disabled)|http\.(cleartext_service|redirect_disabled))$", _G(
        "management-cleartext", "management-access",
        "The device can be managed over an unencrypted protocol such as Telnet or plain HTTP. "
        "Everything typed or sent in such a session, including administrator passwords, crosses "
        "the network readable by anyone on the path.",
        "An attacker who has compromised any host on the same network segment (or a switch or "
        "Wi-Fi link on the way) captures traffic while an administrator logs in, reads the "
        "password from the capture, and later logs in as that administrator.",
        "Telnet and HTTP provide no confidentiality or server authentication. SSH and HTTPS with "
        "current algorithms protect both the credentials and the session contents. Leaving the "
        "clear-text service enabled keeps it available even if administrators normally use the "
        "encrypted one.",
        "Check whether management traffic is confined to an isolated management network or VPN, "
        "and whether the clear-text service is additionally restricted to specific source "
        "addresses. Those reduce, but do not remove, the exposure.",
    )),
    (r"^services\.smart_install$", _G(
        "unauthenticated-provisioning", "management-access",
        "A zero-touch provisioning service that needs no password is listening on the device "
        "(Cisco Smart Install).",
        "An attacker who can reach TCP port 4786 tells the switch to download a new "
        "configuration or software image from a server the attacker controls, taking over the "
        "switch without ever logging in.",
        "Smart Install was designed for first-time deployment and has no authentication. "
        "Cisco recommends disabling it with 'no vstack' after deployment; exposed clients are "
        "scanned for on the internet.",
        "Check whether TCP 4786 is blocked towards this device and whether Smart Install is "
        "still used for deployment.",
    )),
    (r"^ltm\.clientssl_cleartext_enabled$", _G(
        "service-cleartext", "traffic-policy",
        "An application service that is meant to use TLS also accepts unencrypted connections, "
        "so clients may send their data in clear text.",
        "A misconfigured or downgraded client connects without TLS and submits a login form. An "
        "attacker on the network path reads the credentials and session cookies.",
        "Allowing non-SSL traffic on a TLS virtual server removes the guarantee that client data "
        "is encrypted in transit. The tool follows the virtual server to its attached profile but "
        "cannot see iRules or client behaviour.",
        "Check whether an iRule or upstream component redirects or rejects clear-text requests.",
    )),
    (r"^(management\.(unrestricted_\w+|source_restriction|external_interface|auxiliary_services|http_sources|self_ip_port_lockdown)|http\.(access_restriction|unrestricted_sources)|ssh\.(source_restriction|unrestricted_sources|vty_access_restriction)|eapi\.source_restriction|admin\.trusted_hosts|administration\.manager_sources|local_in\.unrestricted_management|layer\.stealth_rule_missing|auxiliary\.enabled)$", _G(
        "management-exposure", "management-access",
        "The device's management interfaces (SSH, web GUI, API) accept connections from any "
        "address, or from an untrusted/external network, instead of only from administrator "
        "workstations or a management network.",
        "The login page of the firewall is reachable from the internet. Attackers try common and "
        "leaked passwords against it around the clock, and when a new vulnerability in the "
        "management service is published, they can exploit it before the device is patched.",
        "Management services are high-value targets: a successful login or exploit gives control "
        "of the device and everything it protects. Source restrictions (ACLs, trusted hosts, "
        "permitted IPs) shrink the set of systems that can even try. Most serious network-device "
        "compromises start with an exposed management interface.",
        "Check for an upstream control that already limits access (management VLAN, VPN, "
        "separate out-of-band network), and confirm that strong authentication, lockout and "
        "logging are in place for the exposed service.",
    )),
    (r"^(ssh\.(weak_\w+|protocol_version)|tls\.\w+|management\.(legacy_tls|tls_\w+)|eapi\.(legacy_tls|tls_profile\w*)|admin\.ssh_profile_\w+|crypto\.(strong_crypto|admin_ssh_v1|ssl_static_key_ciphers|ssh_cbc_cipher|dh_parameters)|https\.(legacy_cipher|global_activation)|http\.(legacy_tls_protocol|weak_cipher_suite)|sslvpn\.(legacy_tls|weak_algorithm))$", _G(
        "management-crypto", "management-crypto",
        "The encrypted management connection (SSH or HTTPS) still allows outdated protocol "
        "versions or algorithms that are known to be weak.",
        "An attacker positioned on the network path forces or waits for a connection that uses "
        "the weak option, then attacks it offline or tampers with it. Old options also widen "
        "exposure to published protocol attacks.",
        "Examples include SSH version 1, 3DES/CBC ciphers, SHA-1/MD5 MACs, small Diffie-Hellman "
        "groups, TLS 1.0/1.1 and static-RSA key exchange. Modern clients do not need these; "
        "keeping them only helps an attacker. The tool reports explicitly configured weak "
        "options and does not guess vendor defaults.",
        "Confirm which clients (old monitoring or automation tools) still need legacy options, "
        "and plan to upgrade them rather than keep weak algorithms enabled.",
    )),
    (r"^(management\.\w*certificate\w*|management\.self_signed_certificate|https\.\w*certificate\w*|eapi\.tls_certificate|sslvpn\.factory_certificate)$", _G(
        "management-certificate", "management-crypto",
        "The certificate that proves the device's identity to administrators is missing, "
        "self-signed or factory default, weak, expired, for another name, or not trusted.",
        "Administrators are used to clicking through browser certificate warnings for the "
        "firewall. An attacker on the network impersonates the device with their own "
        "certificate, nobody notices the (usual) warning, and the attacker captures the "
        "administrator's login.",
        "TLS protects a session only if the client can verify the server certificate. Factory or "
        "self-signed certificates cannot be verified, which trains users to ignore warnings. The "
        "tool evaluates only certificate material present in the export, against an assessment "
        "time, identity and trust anchors that you supply.",
        "Check whether administrators connect through a jump host that pins the certificate, and "
        "replace the certificate with one issued by your internal CA for the correct name.",
    )),
    # Authentication and authorization -----------------------------------------------
    (r"^(ssh\.(empty_passwords|root_login)|(vty|console|auxiliary|http)\.authentication|authentication\.(super_user|unauthenticated_method)|admin\.unauthenticated_method|vty\.(authorization_bypass|aaa_server_group_unusable)|aaa\.(new_model|login_authentication|management_authentication)|admin\.authentication_profile_unresolved|auth\.active_remote_servers_none|authentication\.server_reference|remote_access\.client_certificate_missing)$", _G(
        "authentication-missing", "authentication",
        "A way to log in to the device is not protected by a proper authentication method: it "
        "may allow an empty password, a direct root login, a method that always succeeds, or "
        "point to an authentication server that is not actually defined.",
        "Someone with network (or physical console) access connects to the line or service and "
        "gets a management prompt without knowing a valid personal password, or by using a "
        "shared built-in account that is never locked or audited per person.",
        "Every management entry point (console, AUX, VTY/SSH, web, API) needs its own effective "
        "authentication binding. A bypass method such as 'none', an empty password, or a missing "
        "server group can silently turn into open access or a shared-secret fallback.",
        "Check whether physical access to the console is controlled and whether the path is "
        "reachable at all, and confirm with a test login that the intended authentication "
        "method is actually used.",
    )),
    (r"^(admin\.(centralized_authentication|mfa\w*|remote_group)|authentication\.centralized)$", _G(
        "authentication-central", "authentication",
        "Administrators log in with accounts stored only on this device, instead of a central "
        "identity service (RADIUS/TACACS+/SAML) with multi-factor authentication.",
        "An administrator leaves the company, but their local account on this firewall is "
        "forgotten and still works. Or a password reused elsewhere leaks, and with no second "
        "factor it is enough to log in.",
        "Central authentication gives per-person accounts, immediate revocation, one password "
        "policy and MFA. Local accounts should be limited to a documented break-glass fallback. "
        "The tool cannot see whether an external identity provider enforces MFA.",
        "Confirm how local accounts are reviewed and removed, whether MFA is enforced upstream, "
        "and that logins are logged centrally.",
    )),
    (r"^(aaa\.(radius_\w+|radsec_\w+|ldap_\w+|tacacs_\w+)|auth\.ldap_\w+)$", _G(
        "authentication-transport", "authentication",
        "The connection between the device and its authentication server (RADIUS, RadSec or "
        "LDAP) is not protected as intended: validation, encryption or server identity checks "
        "are disabled or weak.",
        "An attacker on the path between the firewall and the authentication server spoofs or "
        "tampers with the server's replies, making the firewall accept a login it should reject, "
        "or reads administrator credentials sent to LDAP without TLS.",
        "Classic RADIUS relies on a shared secret and the Message-Authenticator attribute "
        "(see the BlastRADIUS attack); RadSec and LDAPS add TLS, which only helps if the "
        "server certificate and name are verified. The tool cannot prove whether the path "
        "is already protected by a VPN unless you declare it in the assessment policy.",
        "Check whether the authentication traffic runs over a separately protected path, and "
        "enable certificate and server-identity validation.",
    )),
    (r"^(admin\.(role_\w+|conflicting_roles)|authorization\.\w+|vty\.authorization|authentication\.login_class_binding|password\.admin_scope)$", _G(
        "authorization", "authorization",
        "Administrator accounts have more privilege than they need, or their privilege level "
        "cannot be determined because it points to an undefined role.",
        "A monitoring or helpdesk account that only needs to read the configuration can also "
        "change firewall rules. When that account's password leaks, the attacker gets full "
        "control instead of read-only access.",
        "Role-based access and command authorization limit what each account can do and make "
        "misuse visible. An unresolved role may fall back to a default level that the tool "
        "cannot predict, so it is reported instead of assumed safe.",
        "Review each account's role against its job, and check that command accounting records "
        "privileged changes.",
    )),
    (r"^(aaa\.(accounting|management_accounting)|authentication\.accounting\w*|vty\.accounting_\w+)$", _G(
        "accounting", "logging-audit",
        "Administrator logins and commands are not recorded on a central accounting server, so "
        "there is no reliable audit trail of who changed what on the device.",
        "A rule allowing an attacker in is added late at night. Without command accounting, "
        "nobody can tell which account made the change, from where, or what else it did.",
        "AAA accounting (TACACS+/RADIUS) or equivalent audit logging sends start/stop and "
        "command records off the device, where an intruder with device access cannot erase them.",
        "Check whether configuration changes are captured another way (syslog change "
        "notifications, a configuration-management tool) and reviewed.",
    )),
    # Session control ------------------------------------------------------------------
    (r"^\w+\.(\w*lockout\w*|\w*login_attempts|authentication_retries|log_without_lockout)$", _G(
        "lockout", "session-control",
        "The device does not slow down or block repeated failed logins, so an attacker can keep "
        "guessing passwords.",
        "An automated tool tries thousands of common passwords against the SSH or web login. "
        "With no lockout or retry limit, it eventually finds a weak administrator password.",
        "Lockout thresholds and delays turn online guessing from fast to impractical. Very "
        "aggressive lockout can be abused to lock out real administrators, so a moderate "
        "threshold with a timed lockout is usual.",
        "Check whether the service is reachable only from trusted sources and whether failed "
        "logins are logged and alerted on.",
    )),
    (r"^\w+\.(\w*idle_timeout\w*|\w*session_timeout\w*|web_session_limit|concurrent_sessions|negotiation_timeout)$", _G(
        "session-timeout", "session-control",
        "Administrative sessions stay open indefinitely (or for a long time) when unattended, "
        "or the number of simultaneous sessions is not limited.",
        "An administrator walks away from an unlocked workstation with an open SSH or console "
        "session to the firewall. Someone else sits down and has full access without logging in.",
        "Idle timeouts close forgotten sessions and free resources. Session limits reduce the "
        "effect of stolen session tokens and resource-exhaustion attempts against the "
        "management plane.",
        "Check workstation lock policies and whether console access is physically controlled.",
    )),
    # Credentials ------------------------------------------------------------------------
    (r"^credentials\.(default_or_empty|known_default_value)$", _G(
        "credentials-default", "credentials",
        "An account uses an empty password or a well-known default value that appears in "
        "vendor documentation and public password lists.",
        "An attacker who can reach any login prompt simply tries the vendor default "
        "(for example admin/admin) and is in on the first attempt.",
        "Default credentials are among the first things automated attack tools try. The tool "
        "compares values only inside the parser and never prints them in the normal report.",
        "Change the password immediately and check logs for past logins with that account.",
    )),
    (r"^(credentials\.(\w+_storage|local_plaintext|terminattr_literal|weak_enable_password)|authentication\.weak_storage|configuration\.change_logging_secrets)$", _G(
        "credentials-storage", "credentials",
        "A password or key is stored in the configuration in plain text or with a weak, easily "
        "reversible encoding (for example Cisco type 7 or MD5-based hashes).",
        "A configuration backup is copied to a file share, ticket or email. Anyone who gets that "
        "file can read or quickly crack the password and log in to this device, and to any other "
        "system where the same password is reused.",
        "Configuration files travel: backups, support cases, change tickets. Strong one-way "
        "hashes (for example type 8/9 scrypt or PBKDF2, SHA-512 crypt) make a leaked file far less "
        "useful. Reversible encodings are obfuscation, not protection.",
        "Check where configuration backups are stored and who can read them, and rotate any "
        "credential that has been stored weakly.",
    )),
    (r"^(credentials\.(password_complexity|password_history_disabled|username_inclusion_allowed)|password\.(complexity|minimum_length)|password_policy\.\w+|admin\.(local_password_minimum\w*|manager_credential_missing))$", _G(
        "password-policy", "credentials",
        "The device does not enforce a reasonable password policy for local accounts (length, "
        "complexity, reuse), or a local credential is missing.",
        "An administrator sets a short or reused password because the device accepts it. The "
        "password is guessed or appears in a breach list and gives direct access.",
        "Password policy on the device applies to local accounts only. Length matters most; "
        "history and username checks stop the most common weak choices.",
        "Check whether local accounts are only break-glass accounts managed through a password "
        "vault, and whether central authentication is used for daily work.",
    )),
    # SNMP ---------------------------------------------------------------------------------
    (r"^snmp\.(default_community|legacy_community|community_access|write_community|legacy_version)$", _G(
        "snmp-community", "snmp",
        "SNMP versions 1/2c are enabled. They use a shared \"community\" string that works like "
        "a password but is sent in clear text; sometimes it is also a well-known default such as "
        "'public' or 'private', or grants write access.",
        "An attacker sniffs the community string (or just guesses 'public') and reads the full "
        "device inventory, interfaces, routes and sometimes configuration. With a write "
        "community, they can change settings or download the configuration.",
        "SNMPv1/v2c has no per-user authentication and no encryption. SNMPv3 with "
        "authentication and privacy (authPriv) replaces it. Source ACLs on the SNMP agent "
        "reduce exposure but do not protect the community string on the wire.",
        "Check whether SNMP is limited to monitoring hosts by ACL and whether the monitoring "
        "system supports SNMPv3 so the community can be removed.",
    )),
    (r"^snmp\.(v3_\w+|secure_user_missing)$", _G(
        "snmp-v3", "snmp",
        "SNMP is in use, but no SNMPv3 user is configured with both authentication and "
        "encryption, or an SNMPv3 user uses weak algorithms or broad access.",
        "Monitoring traffic crosses the network. Without SNMPv3 privacy, an attacker on the path "
        "reads device data; with weak or missing authentication, they can impersonate the "
        "monitoring server.",
        "SNMPv3 security level authPriv with SHA-2 authentication and AES privacy is the current "
        "baseline. Each user is evaluated separately, so one secure user does not hide a weak one.",
        "Check what the monitoring platform supports and restrict SNMP to its addresses.",
    )),
    # Time ----------------------------------------------------------------------------------
    (r"^ntp\.(authentication\w*|key_resolution|weak_algorithm|associations|unauthenticated_server)$", _G(
        "ntp-authentication", "time",
        "The device synchronizes its clock with time servers without verifying that the replies "
        "really come from those servers.",
        "An attacker spoofs time-server replies and shifts the device clock. Log timestamps no "
        "longer line up with other systems, certificate validity checks go wrong, and "
        "time-based rules or key lifetimes misbehave.",
        "NTP authentication (symmetric keys or NTS) lets the client reject forged time. Each "
        "server association is checked separately, because one authenticated server does not "
        "protect against another unauthenticated one.",
        "Check whether the time servers are internal and reached only over trusted networks.",
    )),
    (r"^ntp\.(servers|synchronization|custom_server_missing)$", _G(
        "ntp-missing", "time",
        "No time source is configured, so the device clock may drift.",
        "During an investigation, the firewall's log entries are minutes or hours off from the "
        "server and endpoint logs, making it hard or impossible to reconstruct what happened.",
        "Accurate time is required for correlating logs, validating certificates and "
        "time-limited rules. Some platforms use a vendor default time source that the export "
        "does not show.",
        "Check whether the device gets time from another source (controller, hypervisor, "
        "vendor default) and whether logs from it correlate correctly.",
    )),
    # Logging and configuration management ---------------------------------------------------
    (r"^(logging\.\w+|dos\.logging|cli\.audit_disabled)$", _G(
        "logging", "logging-audit",
        "Security-relevant events are not sent to a central log server, some important events "
        "are filtered out, or the log transport is not protected.",
        "An attacker logs in, changes a rule and later deletes the local log buffer. Because "
        "nothing was forwarded, there is no trace of the intrusion on any other system.",
        "Central logging protects records from tampering on the device and enables alerting. "
        "Severity filters that exclude error or warning events, or clear-text syslog over "
        "untrusted networks, reduce the value of the logs.",
        "Check whether the device is covered by another log collection method (API polling, "
        "controller) and whether someone actually reviews or alerts on these logs.",
    )),
    (r"^configuration\.(change_\w+)$", _G(
        "change-audit", "logging-audit",
        "Changes to the device configuration are not logged or reported, so unauthorized or "
        "accidental changes can go unnoticed.",
        "Someone quietly adds an 'allow' rule or a new local account. Without change logging, "
        "the change is discovered only when it is exploited, if at all.",
        "Configuration-change logging records each command with the user and time, ideally sent "
        "to syslog so it is kept off the device.",
        "Check whether a configuration-management system detects drift between backups.",
    )),
    (r"^(configuration\.(archive_\w+|backup_\w+)|services\.(tftp_boot_config|cns_config_cleartext))$", _G(
        "backup", "backup",
        "Configuration backups are missing, incomplete or sent over an unencrypted protocol "
        "(FTP/TFTP), or the device loads its configuration over TFTP at boot.",
        "After a failure, the device must be rebuilt without a recent backup, prolonging an "
        "outage. Or an attacker intercepts an FTP/TFTP transfer and obtains the configuration, "
        "including stored credentials, or feeds the device a modified configuration at boot.",
        "Backups should be regular, stored securely and transferred over SCP/SFTP/HTTPS. Whether "
        "an external system already takes backups cannot be seen in the export; set "
        "configuration_backup_scope in the assessment policy.",
        "Check whether an external tool backs up this device and test a restore.",
    )),
    # Routing -----------------------------------------------------------------------------------
    (r"^routing\.(\w+\.)?(\w*authentication|key_resolution|key_lifetime_unusable|version1_receive)$", _G(
        "routing-authentication", "routing",
        "A routing protocol session (BGP, OSPF, RIP, EIGRP) accepts neighbors or updates "
        "without proper authentication, or its keys are missing, weak or expired.",
        "A device an attacker controls on the same link starts speaking OSPF or RIP and "
        "announces better routes. Traffic for other networks is redirected through the attacker "
        "or dropped.",
        "Routing authentication (MD5/SHA keys, TCP-AO, key chains) ensures only configured "
        "neighbors can inject routes. Clear-text or legacy authentication gives little "
        "protection. Passive interfaces and link isolation reduce exposure.",
        "Check whether the routing links are point-to-point or otherwise isolated, and whether "
        "neighbors are restricted by ACLs.",
    )),
    (r"^routing\.bgp\.(inbound_policy|outbound_policy|prefix_limit\w*|missing_\w+|permit_all_\w+)$", _G(
        "bgp-policy", "routing",
        "An external BGP neighbor has no effective route filter or prefix limit, so the device "
        "accepts or announces whatever routes are exchanged.",
        "A peer (or an attacker who hijacks it) announces your own prefixes or a full routing "
        "table by mistake. Your traffic is diverted, or the router runs out of memory. Without an "
        "outbound filter, you might leak routes to a provider and attract unexpected traffic.",
        "Inbound and outbound route policies and maximum-prefix limits are standard safeguards "
        "for external BGP (see MANRS). The tool reports only neighbors explicitly classified as "
        "external and filters it can fully resolve.",
        "Check whether the provider filters your announcements and whether RPKI validation is "
        "in place.",
    )),
    # Device self-protection -----------------------------------------------------------------------
    (r"^(control_plane\.\w+|dos\.\w+|zone\.\w+|screen\.\w+)$", _G(
        "control-plane", "control-plane",
        "The device's own CPU and management plane are not protected from floods, or "
        "denial-of-service protections are disabled on an exposed interface or zone.",
        "An attacker floods the firewall or router with traffic addressed to the device itself "
        "(or with SYN/UDP/ICMP floods). The CPU saturates, routing sessions drop, management "
        "becomes unreachable, and the network goes down.",
        "Control-plane policing, loopback filters and zone/DoS protection limit what traffic "
        "can reach the processor and at what rate. The right thresholds depend on the "
        "environment, so the tool reports only missing, empty or explicitly disabled "
        "protection.",
        "Check for upstream DDoS protection and whether management and routing traffic are "
        "prioritized.",
    )),
    (r"^(interface\.(ip_hardening|reverse_path|unused_enabled)|interfaces\.redirects|ip\.source_route|services\.(unnecessary|legacy))$", _G(
        "service-hardening", "control-plane",
        "Legacy IP features or services that are rarely needed are still enabled (for example "
        "source routing, ICMP redirects, proxy ARP, small servers), or anti-spoofing is missing.",
        "An attacker uses source routing or redirects to steer traffic around a filter, or "
        "sends spoofed packets that the missing reverse-path check would have dropped.",
        "Each enabled service is extra attack surface. Hardening guides recommend disabling "
        "these features and enabling unicast reverse-path forwarding on untrusted interfaces.",
        "Check whether any application genuinely depends on the feature before disabling it.",
    )),
    # Access edge ---------------------------------------------------------------------------------
    (r"^(layer2\.[\w.]+|discovery\.[\w.]+|macsec\.\w+)$", _G(
        "access-edge", "access-edge",
        "A switch port that connects end devices lacks a standard protection (DHCP snooping, "
        "ARP inspection, BPDU guard, 802.1X, port security), or leaks discovery information to "
        "an untrusted side.",
        "A user plugs a small router or laptop into an office port. It hands out fake DHCP "
        "addresses, poisons ARP tables to intercept colleagues' traffic, or disrupts the "
        "spanning tree and takes the network down.",
        "Access-layer protections stop rogue devices at the first switch port. The tool applies "
        "them only to ports you classify as access-edge in the assessment policy.",
        "Check which ports are really user-facing and whether network access control is "
        "enforced elsewhere.",
    )),
    # VPN -----------------------------------------------------------------------------------------
    (r"^(crypto\.(legacy_\w+|ike_dh_policy|unresolved_transform)|vpn\.\w+)$", _G(
        "vpn-crypto", "vpn",
        "An active VPN tunnel can negotiate outdated encryption, hashing or key-exchange "
        "settings (such as DES/3DES, MD5/SHA-1, or small Diffie-Hellman groups), or references "
        "a proposal that cannot be resolved.",
        "A well-resourced attacker records VPN traffic between sites for months, then breaks the "
        "weak key exchange or cipher and decrypts it. Weak settings also let a man-in-the-middle "
        "downgrade the negotiation.",
        "Current guidance is AES-GCM or AES-CBC with SHA-2, and DH group 14 or higher (ECDH "
        "groups 19/20/21 preferred). The tool evaluates proposals attached to active tunnels, "
        "not what a peer actually negotiated.",
        "Check what the remote peers support, and move both sides to the modern proposal.",
    )),
    # Platform ----------------------------------------------------------------------------------------
    (r"^lifecycle\.\w+$", _G(
        "end-of-life", "platform",
        "The device's software is end-of-life, so the vendor no longer publishes security fixes.",
        "A vulnerability is found in the firewall's management or VPN service. Supported "
        "platforms receive a patch; this one never will, so the hole stays open permanently.",
        "Running unsupported software means every future vulnerability is permanent. "
        "Compensating controls can only reduce exposure.",
        "Plan replacement. Until then, restrict management access tightly and monitor the device "
        "closely.",
    )),
    (r"^(banner\.\w+|\w+\.(login_banner\w*|connection_banner))$", _G(
        "login-banner", "platform",
        "No warning notice is shown before login.",
        "This rarely enables an attack by itself. In some jurisdictions, a missing notice can "
        "make legal action against unauthorized users harder.",
        "Many policies require a pre-login notice that access is restricted and monitored. The "
        "exact wording should come from your legal or security team.",
        "Check your organization's policy for required banner text.",
    )),
    (r"^failover\.\w+$", _G(
        "failover", "platform",
        "Traffic between the two members of a high-availability pair is not authenticated or "
        "encrypted.",
        "An attacker with access to the failover link injects state or configuration messages, "
        "or reads synchronized data such as keys and passwords.",
        "Failover links carry configuration and session state. A shared key protects them when "
        "the link is not physically isolated.",
        "Check whether the failover link is a direct cable or a dedicated, isolated VLAN.",
    )),
    (r"^dns\.\w+$", _G(
        "dns", "platform",
        "No DNS servers are configured on the device.",
        "Functions that depend on name resolution, such as update downloads, FQDN objects and "
        "threat feeds, fail silently, which can leave protections outdated.",
        "DNS is an operational dependency rather than a direct vulnerability.",
        "Check whether DNS is inherited from a management system.",
    )),
    (r"^analysis\.\w+$", _G(
        "assessment-scope", "platform",
        "Part of the configuration is inherited from a central manager and is not included in "
        "this file, so some settings could not be assessed.",
        "A rule or setting pushed from Panorama could be weak, but it is not visible in the "
        "local export, so no finding appears for it.",
        "Findings based on missing settings are suppressed when inheritance is unknown.",
        "Assess the merged running configuration or the central manager's templates as well.",
    )),
)

_COMPILED = tuple((re.compile(pattern), guidance) for pattern, guidance in _CATALOGUE)


def _rule_suffix(rule_id: str) -> str:
    parts = rule_id.split(".", 2)
    return parts[2] if len(parts) == 3 else rule_id


def guidance_for(rule_id: str) -> Optional[Guidance]:
    """Return the first catalogue entry matching ``rule_id``, or ``None``."""

    suffix = _rule_suffix(rule_id)
    for pattern, guidance in _COMPILED:
        if pattern.match(suffix):
            return guidance
    return None


__all__ = ["AREAS", "Area", "Guidance", "guidance_for"]
