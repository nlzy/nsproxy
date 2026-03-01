"""
SOCKS5 Proxy Tests
==================

These tests verify nsproxy's SOCKS5 proxy support, including both TCP and UDP
connections, with and without authentication.

Tests:
------
test_socks5_tcp
    Tests SOCKS5 TCP connection without authentication.
    - Uses SOCKS5 proxy on port 31080 (no auth)
    - Runs tcp_pingpong test through the proxy
    - Verifies 100KB bidirectional data transfer

test_socks5_udp
    Tests SOCKS5 UDP connection without authentication (UDP associate).
    - Uses SOCKS5 proxy on port 31080 (no auth)
    - Runs udp_pingpong test through the proxy
    - Verifies 1KB bidirectional data transfer via UDP

test_socks5_auth_tcp
    Tests SOCKS5 TCP connection with username/password authentication.
    - Uses SOCKS5 proxy on port 31081 (auth required)
    - Credentials: testuser:testpass
    - Runs tcp_pingpong test through the proxy

test_socks5_auth_udp
    Tests SOCKS5 UDP connection with authentication.
    - Uses SOCKS5 proxy on port 31081 (auth required)
    - Runs udp_pingpong test through the proxy

Usage:
------
    pytest -v tests/test_socks5.py
    pytest -v -k "socks5" tests/
"""

from .conftest import SOCKS_NOAUTH_PORT, SOCKS_AUTH_PORT
from .test_direct import _run_pingpong_test


def test_socks5_tcp(proxy_server, nsproxy_runner):
    """Test SOCKS5 TCP connection"""
    _run_pingpong_test(
        nsproxy_runner, ["-s", "127.0.0.1", "-p", str(SOCKS_NOAUTH_PORT)], is_udp=False
    )


def test_socks5_udp(proxy_server, nsproxy_runner):
    """Test SOCKS5 UDP connection"""
    _run_pingpong_test(
        nsproxy_runner, ["-s", "127.0.0.1", "-p", str(SOCKS_NOAUTH_PORT)], is_udp=True
    )


def test_socks5_auth_tcp(proxy_server, nsproxy_runner):
    """Test SOCKS5 TCP connection with authentication"""
    _run_pingpong_test(
        nsproxy_runner,
        ["-a", "testuser:testpass", "-s", "127.0.0.1", "-p", str(SOCKS_AUTH_PORT)],
        is_udp=False,
    )


def test_socks5_auth_udp(proxy_server, nsproxy_runner):
    """Test SOCKS5 UDP connection with authentication"""
    _run_pingpong_test(
        nsproxy_runner,
        ["-a", "testuser:testpass", "-s", "127.0.0.1", "-p", str(SOCKS_AUTH_PORT)],
        is_udp=True,
    )
