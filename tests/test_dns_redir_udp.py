"""
DNS Redirection UDP Tests
=========================

These tests verify nsproxy's DNS redirection to a UDP nameserver.

Tests:
------
test_dns_redir_udp_direct
    Tests DNS redirection to UDP nameserver in direct mode (-D flag).

test_dns_redir_udp_socks5
    Tests DNS redirection to UDP nameserver through SOCKS5 proxy.

Usage:
------
    pytest -v tests/test_dns_redir_udp.py
    pytest -v -k "dns_redir_udp" tests/
"""

import subprocess
import time
from .conftest import SOCKS_NOAUTH_PORT

COREDNS_CONFIG = "tests/conf/coredns.conf"
COREDNS_PORT = 30053


def _run_dns_redir_udp_test(nsproxy_runner, extra_args):
    """Run DNS redirection UDP test through nsproxy"""
    # Start the CoreDNS server
    server_proc = subprocess.Popen(
        ["coredns", "-conf", COREDNS_CONFIG],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for server to start listening
    time.sleep(0.5)

    try:
        # Run the dig client through nsproxy
        client_args = extra_args + [
            "-d",
            f"udp://127.0.0.1:{COREDNS_PORT}",
            "dig",
            "+short",
            "example.com",
        ]
        client = nsproxy_runner(client_args)
        stdout, stderr = client.communicate(timeout=30)

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

    finally:
        if server_proc.poll() is None:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                server_proc.kill()


def test_dns_redir_udp_direct(nsproxy_runner):
    """Test DNS redirection to UDP nameserver in direct mode"""
    _run_dns_redir_udp_test(nsproxy_runner, ["-D"])


def test_dns_redir_udp_socks5(proxy_server, nsproxy_runner):
    """Test DNS redirection to UDP nameserver through SOCKS5 proxy"""
    _run_dns_redir_udp_test(
        nsproxy_runner,
        ["-s", "127.0.0.1", "-p", str(SOCKS_NOAUTH_PORT)],
    )
