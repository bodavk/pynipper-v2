# Task: Cisco IOS-XE Parser & Checks

## Status
- [x] Completed (Parser implemented, inheriting from IOS; plugin checks implemented)

## Priority
HIGH — Standard corporate router/switch platform today.

## Source of Truth
- Cisco IOS-XE Security Configuration Guide
- CIS Cisco IOS-XE Benchmark v2.0.0
- DISA Cisco IOS-XE STIG

## Architecture Notes
- Which existing parser(s)/plugin(s) most closely resemble this one: `CiscoIOSParser` (classic IOS).
- Expected deviation: Extremely low deviation. Classic IOS rules and parser can be inherited/reused, but IOS-XE supports modern security commands that classic IOS does not.

## Scope
- Device/vendor: Cisco
- OS version to support: IOS-XE 17.x

## Parser Requirements
1. File location: `src/devices/cisco/iosxe.py` (subclasses `CiscoIOSParser` for maximum code reuse).
2. Must extract:
   - [x] Classic IOS sections
   - [x] MACsec configuration (`mka policy ...`)
   - [x] Modern AAA and crypto configuration (`crypto ikev2 ...`)

## Plugin/Check Requirements
- [x] XE-01: Lack of MACsec — Flag interfaces connected to peer network devices that do not have MACsec encryption configured.
- [x] XE-02: Legacy Crypto Ciphers — Scan IKEv2 policies for weak parameters (e.g. 3DES, MD5, DH Groups 1/2/5).
- [x] XE-03: Classic IOS rules run as standard.

## Acceptance Criteria
- [x] Registered in CLI as `IOS_XE`.
- [x] Reuses existing `CiscoIOSParser` code seamlessly.
