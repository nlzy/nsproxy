"""
Basic IPv6 Tests
==================

These tests verify nsproxy's IPv6 connection support through different modes:
direct mode, HTTP proxy, and SOCKS5 proxy.

Tests:
------
test_basic_ipv6_tcp_direct
    Tests IPv6 TCP connection in direct mode without proxy.

test_basic_ipv6_udp_direct
    Tests IPv6 UDP connection in direct mode without proxy.

test_basic_ipv6_tcp_socks5
    Tests IPv6 TCP connection through SOCKS5 proxy.

test_basic_ipv6_udp_socks5
    Tests IPv6 UDP connection through SOCKS5 proxy.

test_basic_ipv6_tcp_http
    Tests IPv6 TCP connection through HTTP proxy.

Usage:
------
    pytest -v tests/test_basic_ipv6.py
    pytest -v -k "ipv6" tests/
"""

import subprocess
import time
from .conftest import (
    LOCAL_IPV6,
    HTTP_NOAUTH_PORT,
    SOCKS_NOAUTH_PORT,
    wait_server,
    managed_proc,
)


def _run_pingpong_test(nsproxy_runner, extra_args, is_udp=False):
    """Run TCP/UDP pingpong test through nsproxy over IPv6"""
    pingpong_script = (
        "tests/tools/udp_pingpong.py" if is_udp else "tests/tools/tcp_pingpong.py"
    )
    pingpong_marker = (
        "Server bind on" if is_udp else "Server listened on"
    )
    pingpong_port = 37777

    with managed_proc(subprocess.Popen(
        [
            "python3",
            pingpong_script,
            "-s",
            "::",
            "-p",
            str(pingpong_port),
            "-6",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )) as server:
        wait_server(server, pingpong_marker)

        with managed_proc(nsproxy_runner(extra_args + [
            "python3",
            pingpong_script,
            "-c",
            LOCAL_IPV6,
            "-p",
            str(pingpong_port),
            "-6",
        ])) as client:
            cl_stdout, cl_stderr = client.communicate(timeout=3)

        # Get outputs
        cl_out = cl_stdout.decode(errors="replace")
        cl_err = cl_stderr.decode(errors="replace")

        # Immediately kill server after client finishes
        if server.poll() is None:
            server.kill()

        sv_stdout, sv_stderr = server.communicate(timeout=3)
        sv_out = sv_stdout.decode(errors="replace")
        sv_err = sv_stderr.decode(errors="replace")

        # Assertions
        assert "SERVER-RECV-OK" in sv_out, (
            f"Server did not receive data. stderr: {sv_err}"
        )
        assert "CLIENT-RECV-OK" in cl_out, (
            f"Client did not receive data. stderr: {cl_err}"
        )
        assert server.returncode == 0, (
            f"Server exited with error code {server.returncode}. stderr: {sv_err}"
        )
        assert client.returncode == 0, (
            f"Client exited with error code {client.returncode}. stderr: {cl_err}"
        )


def test_basic_ipv6_tcp_direct(nsproxy_runner):
    """Test direct IPv6 TCP connection through nsproxy (no proxy)"""
    _run_pingpong_test(nsproxy_runner, ["-D", "-6"])


def test_basic_ipv6_udp_direct(nsproxy_runner):
    """Test direct IPv6 UDP connection through nsproxy (no proxy)"""
    _run_pingpong_test(nsproxy_runner, ["-D", "-6"], is_udp=True)


def test_basic_ipv6_tcp_socks5(proxy_server, nsproxy_runner):
    """Test SOCKS5 IPv6 TCP connection"""
    _run_pingpong_test(
        nsproxy_runner,
        ["-6", "-s", "127.0.0.1", "-p", str(SOCKS_NOAUTH_PORT)],
    )


def test_basic_ipv6_udp_socks5(proxy_server, nsproxy_runner):
    """Test SOCKS5 IPv6 UDP connection"""
    _run_pingpong_test(
        nsproxy_runner,
        ["-6", "-s", "127.0.0.1", "-p", str(SOCKS_NOAUTH_PORT)],
        is_udp=True,
    )


def test_basic_ipv6_tcp_http(proxy_server, nsproxy_runner):
    """Test HTTP proxy IPv6 TCP connection"""
    _run_pingpong_test(
        nsproxy_runner,
        ["-6", "-H", "-s", "127.0.0.1", "-p", str(HTTP_NOAUTH_PORT)],
    )
