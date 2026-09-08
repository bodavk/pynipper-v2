# Phase 3: New Device Support Candidates

This document evaluates modern (current as of 2026) network and security devices that were never supported by the original `nipper-ng` but are highly prevalent in enterprise production networks today.

## Feasibility & Value Assessment

### 1. Palo Alto Networks (PAN-OS)
- **Market Relevance**: **CRITICAL** (Industry leader in next-generation enterprise firewalls).
- **Configuration Format**: XML (running config) or JSON/CLI `set` commands.
- **Feasibility**: **HIGH** (XML/JSON is structured and easy to parse in Python natively without complex regex engines).
- **Standards Availability**: CIS Benchmark for PAN-OS, DISA STIG, and Palo Alto Best Practice Assessment (BPA) guidelines are widely available.
- **Score (Relevance x Feasibility x Standards)**: **9/10**

### 2. Fortinet FortiGate (FortiOS)
- **Market Relevance**: **CRITICAL** (Highest market share in volume of firewall shipments; widely used in enterprise and SMB).
- **Configuration Format**: Block-based flat CLI syntax (e.g., `config system global` ... `set hostname ...` ... `end`).
- **Feasibility**: **HIGH** (Easily parsed using line-by-line block state machines or indentation-based parsers).
- **Standards Availability**: CIS Benchmark for FortiOS and DISA STIG are readily available.
- **Score (Relevance x Feasibility x Standards)**: **9/10**

### 3. Juniper JunOS
- **Market Relevance**: **HIGH** (Extremely common in enterprise backbone routing and service providers).
- **Configuration Format**: Hierarchical curly braces `{ }` or flat `set` commands.
- **Feasibility**: **HIGH** (Can be parsed using standard braces-balancing parsers, or by parsing the `set` command format which is extremely linear).
- **Standards Availability**: CIS Benchmark for Juniper JunOS and DISA STIG exist.
- **Score (Relevance x Feasibility x Standards)**: **8/10**

### 4. Cisco IOS-XE
- **Market Relevance**: **CRITICAL** (The modern standard operating system for all enterprise-grade Cisco routers and Catalyst switches).
- **Configuration Format**: Cisco IOS-like flat syntax.
- **Feasibility**: **VERY HIGH** (Can directly reuse the existing classic Cisco IOS parser `ciscoconfparse` with minimal adjustments for modern security commands like MACsec or CTS).
- **Standards Availability**: CIS Cisco IOS-XE Benchmark and DISA STIG exist.
- **Score (Relevance x Feasibility x Standards)**: **9/10**

### 5. Cisco NX-OS
- **Market Relevance**: **HIGH** (Standard for Cisco Nexus data center switches).
- **Configuration Format**: Cisco-like CLI syntax but with modular features (e.g., `feature tacacs+`).
- **Feasibility**: **HIGH** (Very similar to classic IOS, easily parsed with minor syntax extensions).
- **Standards Availability**: CIS Cisco NX-OS Benchmark exists.
- **Score (Relevance x Feasibility x Standards)**: **8/10**

### 6. Arista EOS
- **Market Relevance**: **MEDIUM-HIGH** (Dominant in major cloud datacenters and high-frequency trading environments).
- **Configuration Format**: Virtually identical to Cisco IOS CLI.
- **Feasibility**: **VERY HIGH** (Can be parsed natively by `ciscoconfparse` with zero configuration syntax changes).
- **Standards Availability**: CIS Arista EOS Benchmark is available.
- **Score (Relevance x Feasibility x Standards)**: **7.5/10**

---

## Approved Expansion Candidates Rank

Based on modern security value and feasibility of parsing, the recommended expansion candidates are ranked as follows:

| Rank | Candidate | Platform | Format | Priority | Target Task File |
| :---: | :--- | :--- | :--- | :--- | :--- |
| 1 | Palo Alto Networks | PAN-OS | XML/JSON | **CRITICAL** | `01_paloalto_panos.md` |
| 2 | Fortinet FortiGate | FortiOS | CLI Blocks | **CRITICAL** | `02_fortinet_fortios.md` |
| 3 | Cisco IOS-XE | IOS-XE | CLI Flat | **HIGH** | `03_cisco_iosxe.md` |
| 4 | Juniper Networks | JunOS | `{ }` or `set` | **HIGH** | `04_juniper_junos.md` |
| 5 | Arista Networks | EOS | CLI Flat | **MEDIUM** | `05_arista_eos.md` |
