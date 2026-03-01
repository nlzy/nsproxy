"""
HTTP Proxy Tests
================

These tests verify nsproxy's HTTP proxy support. Note that HTTP proxy protocol
does not support UDP, so only TCP tests are included.

Tests:
------
test_http_tcp
    Tests HTTP proxy TCP connection without authentication.
    - Uses HTTP proxy on port 38080 (no auth)
    - Uses -H flag to enable HTTP proxy mode
    - Runs tcp_pingpong test through the proxy
    - Verifies 100KB bidirectional data transfer

test_http_tcp_auth
    Tests HTTP proxy TCP connection with username/password authentication.
    - Uses HTTP proxy on port 38081 (auth required)
    - Credentials: testuser:testpass
    - Runs tcp_pingpong test through the proxy

Usage:
------
    pytest -v tests/test_http.py
    pytest -v -k "http" tests/
"""

from .conftest import HTTP_NOAUTH_PORT, HTTP_AUTH_PORT
from .test_direct import _run_pingpong_test


def test_http_tcp(proxy_server, nsproxy_runner):
    """Test HTTP proxy TCP connection (HTTP proxy does not support UDP)"""
    _run_pingpong_test(
        nsproxy_runner,
        ["-H", "-s", "127.0.0.1", "-p", str(HTTP_NOAUTH_PORT)],
        is_udp=False,
    )


def test_http_tcp_auth(proxy_server, nsproxy_runner):
    """Test HTTP proxy TCP connection with authentication"""
    _run_pingpong_test(
        nsproxy_runner,
        ["-H", "-a", "testuser:testpass", "-s", "127.0.0.1", "-p", str(HTTP_AUTH_PORT)],
        is_udp=False,
    )
