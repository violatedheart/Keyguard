"""Read socket metadata without traffic capture or new network connections."""

import ipaddress
from typing import Any

import psutil

from keyguard.models import Detection, Finding


def remote_connection(connection: Any) -> dict[str, Any] | None:
    """Return connected non-loopback peers; direction cannot be proven by psutil."""
    if connection.status != psutil.CONN_ESTABLISHED or not connection.raddr:
        return None
    host, port = connection.raddr[0], connection.raddr[1]
    try:
        if ipaddress.ip_address(host.split("%", 1)[0]).is_loopback:
            return None
    except ValueError:
        return None
    local = list(connection.laddr) if connection.laddr else []
    return {"local": local, "remote": [host, port], "status": connection.status,
            "direction": "unknown (possible outbound)"}


def collect_connections() -> tuple[dict[int, list[dict[str, Any]]], list[str]]:
    """Collect one TCP snapshot; access failure is a coverage issue, never safe evidence."""
    peers: dict[int, list[dict[str, Any]]] = {}
    issues: list[str] = []
    try:
        for connection in psutil.net_connections(kind="tcp"):
            item = remote_connection(connection)
            if item and connection.pid is not None:
                peers.setdefault(connection.pid, []).append(item)
    except (psutil.Error, OSError) as exc:
        issues.append(f"Network enumeration incomplete: {exc}. Run as administrator for more coverage.")
    return peers, issues


def analyze_network(connections: list[dict[str, Any]], keyboard: bool, known: bool) -> Detection:
    """Raise risk only when an unknown process combines keyboard imports and peers."""
    result = Detection(data={"connections": connections})
    if connections and keyboard and not known:
        result.findings.append(Finding("keyboard_network", "network",
                                       f"Unknown process imports keyboard APIs and has {len(connections)} established non-loopback TCP peer(s); possible outbound/exfiltration"))
    return result
