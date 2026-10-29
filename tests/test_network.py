"""Socket metadata tests with no traffic capture or external connections."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import psutil
import pytest

from keyguard import network


@pytest.mark.parametrize(("host", "status", "expected"), [("127.0.0.1", "ESTABLISHED", False),
                                                            ("::1", "ESTABLISHED", False),
                                                            ("192.0.2.10", "ESTABLISHED", True),
                                                            ("192.0.2.10", "LISTEN", False)])
def test_peer_filter(host: str, status: str, expected: bool) -> None:
    """Include private/public remote peers but exclude loopback and listeners."""
    connection = SimpleNamespace(raddr=(host, 443), laddr=("192.0.2.2", 50000), status=status)
    assert bool(network.remote_connection(connection)) == expected


def test_network_requires_combination() -> None:
    """Network use alone and known keyboard utilities are not exfiltration signals."""
    peers = [{"remote": ["192.0.2.10", 443]}]
    assert network.analyze_network(peers, True, False).findings
    assert not network.analyze_network(peers, False, False).findings
    assert not network.analyze_network(peers, True, True).findings


def test_access_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep a useful reduced-coverage result when socket enumeration is denied."""
    monkeypatch.setattr(psutil, "net_connections", MagicMock(side_effect=psutil.AccessDenied()))
    peers, issues = network.collect_connections()
    assert peers == {} and "administrator" in issues[0]
