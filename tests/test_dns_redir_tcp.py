"""
DNS Redirection TCP Tests
=========================

These tests verify nsproxy's DNS redirection to a TCP nameserver.

Tests:
------
test_dns_redir_tcp_direct
    Tests DNS redirection to TCP nameserver in direct mode (-D flag).

test_dns_redir_tcp_socks5
    Tests DNS redirection to TCP nameserver through SOCKS5 proxy.

test_dns_redir_tcp_http
    Tests DNS redirection to TCP nameserver through HTTP proxy.

Usage:
------
    pytest -v tests/test_dns_redir_tcp.py
    pytest -v -k "dns_redir_tcp" tests/
"""

import subprocess
import time
from .conftest import (
    HTTP_NOAUTH_PORT,
    SOCKS_NOAUTH_PORT,
    managed_proc,
)

COREDNS_CONFIG = "tests/conf/coredns.conf"
COREDNS_PORT = 30053


def _run_dns_redir_tcp_test(nsproxy_runner, extra_args):
    """Run DNS redirection TCP test through nsproxy"""
    with managed_proc(subprocess.Popen(
        ["coredns", "-conf", COREDNS_CONFIG],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )):
        # Wait for server to start listening
        time.sleep(0.5)

        # Run the dig client through nsproxy
        with managed_proc(nsproxy_runner(extra_args + [
            "-d",
            f"tcp://127.0.0.1:{COREDNS_PORT}",
            "dig",
            "+short",
            "+time=1",
            "+tries=2",
            "example.com",
        ])) as client:
            stdout, stderr = client.communicate(timeout=3)

        # Get outputs
        stdout_str = stdout.decode(errors="replace")
        stderr_str = stderr.decode(errors="replace")

        # Assertions
        assert "120.0.0.1" in stdout_str, (
            f"DNS query did not return expected IP. stdout: {stdout_str}, stderr: {stderr_str}"
        )
        assert client.returncode == 0, (
            f"Client exited with error code {client.returncode}. stderr: {stderr_str}"
        )


def test_dns_redir_tcp_direct(nsproxy_runner):
    """Test DNS redirection to TCP nameserver in direct mode"""
    _run_dns_redir_tcp_test(nsproxy_runner, ["-D"])


def test_dns_redir_tcp_socks5(proxy_server, nsproxy_runner):
    """Test DNS redirection to TCP nameserver through SOCKS5 proxy"""
    _run_dns_redir_tcp_test(
        nsproxy_runner,
        ["-s", "127.0.0.1", "-p", str(SOCKS_NOAUTH_PORT)],
    )


def test_dns_redir_tcp_http(proxy_server, nsproxy_runner):
    """Test DNS redirection to TCP nameserver through HTTP proxy"""
    _run_dns_redir_tcp_test(
        nsproxy_runner,
        ["-H", "-s", "127.0.0.1", "-p", str(HTTP_NOAUTH_PORT)],
    )
