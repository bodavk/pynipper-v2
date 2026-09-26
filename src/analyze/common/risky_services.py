"""Shared catalogue of services that are risky to allow from broad sources (SC-043).

Clear-text logins, file sharing, remote administration and data stores that are
commonly attacked when reachable from untrusted networks. Firewall plugins use this
catalogue only for active allow rules whose source is "any"; the rule's own vendor
parser resolves objects and ports first.
"""

from __future__ import annotations

# (protocol, port) -> label. "any" protocol entries apply to TCP and UDP.
RISKY_PORTS: dict[tuple[str, int], str] = {
    ("tcp", 21): "FTP",
    ("tcp", 23): "Telnet",
    ("udp", 69): "TFTP",
    ("tcp", 110): "POP3",
    ("tcp", 135): "MS-RPC",
    ("udp", 135): "MS-RPC",
    ("udp", 137): "NetBIOS",
    ("udp", 138): "NetBIOS",
    ("tcp", 139): "NetBIOS/SMB",
    ("tcp", 143): "IMAP",
    ("udp", 161): "SNMP",
    ("udp", 162): "SNMP trap",
    ("tcp", 389): "LDAP",
    ("udp", 389): "LDAP",
    ("tcp", 445): "SMB",
    ("tcp", 512): "rexec",
    ("tcp", 513): "rlogin",
    ("tcp", 514): "rsh",
    ("tcp", 1433): "MS SQL",
    ("tcp", 1521): "Oracle",
    ("tcp", 2375): "Docker API",
    ("tcp", 3306): "MySQL",
    ("tcp", 3389): "RDP",
    ("tcp", 5432): "PostgreSQL",
    ("tcp", 6379): "Redis",
    ("tcp", 27017): "MongoDB",
}
RISKY_PORT_RANGES: tuple[tuple[str, int, int, str], ...] = (
    ("tcp", 5900, 5999, "VNC"),
    ("tcp", 6000, 6063, "X11"),
)
# Service names used by vendors for the same protocols (case-insensitive).
RISKY_SERVICE_NAMES = frozenset({
    "ftp", "telnet", "tftp", "rlogin", "rsh", "rexec", "exec", "login", "cmd",
    "netbios-ns", "netbios-dgm", "netbios-ssn", "microsoft-ds", "smb", "samba",
    "ms-wbt-server", "rdp", "vnc", "x11", "snmp", "pop3", "imap", "imap4", "ldap",
    "ms-sql", "mysql", "sqlnet", "redis",
})
# Named ports used in Cisco ASA/IOS access lists.
CISCO_PORT_NAMES: dict[str, int] = {
    "ftp": 21, "telnet": 23, "tftp": 69, "pop3": 110, "netbios-ns": 137, "netbios-dgm": 138,
    "netbios-ssn": 139, "imap4": 143, "snmp": 161, "snmptrap": 162, "ldap": 389, "exec": 512,
    "login": 513, "rsh": 514, "cmd": 514, "sqlnet": 1521,
}
# Wider ranges are already "broad service" findings; do not label every port inside them.
_MAX_RANGE = 1024


def risky_labels(protocol: str, first_port: int, last_port: int) -> set[str]:
    """Labels of catalogued services inside a TCP/UDP port interval."""
    protocol = protocol.casefold()
    protocols = {"tcp", "udp"} if protocol in {"any", "ip", "tcp-udp"} else {protocol}
    if last_port - first_port > _MAX_RANGE:
        return set()
    labels = {
        label for (proto, port), label in RISKY_PORTS.items()
        if proto in protocols and first_port <= port <= last_port
    }
    labels.update(
        label for proto, low, high, label in RISKY_PORT_RANGES
        if proto in protocols and first_port <= high and low <= last_port
    )
    return labels


def is_risky_port(port: int) -> bool:
    """Protocol-agnostic check used where only a port number is known."""
    return any(item_port == port for (_, item_port) in RISKY_PORTS) or any(
        low <= port <= high for _, low, high, _ in RISKY_PORT_RANGES
    )
