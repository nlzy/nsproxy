"""
Basic TCP Tests
==================

These tests verify nsproxy's TCP connection support through different modes:
direct mode, HTTP proxy, and SOCKS5 proxy.

Tests:
------
test_basic_tcp_direct
    Tests TCP connection in direct mode (-D flag) without proxy.

test_basic_tcp_http
    Tests HTTP proxy TCP connection without authentication.

test_basic_tcp_socks5
    Tests SOCKS5 TCP connection without authentication.

Usage:
------
    pytest -v tests/test_tcp_pingpong.py
    pytest -v -k "tcp" tests/
"""

import subprocess
import time
from .conftest import (
    LOCAL_IP,
    HTTP_NOAUTH_PORT,
    SOCKS_NOAUTH_PORT,
    wait_server,
    managed_proc,
)


def _run_tcp_pingpong_test(nsproxy_runner, extra_args):
    """Run TCP pingpong test through nsproxy"""
    pingpong_script = "tests/tools/tcp_pingpong.py"
    pingpong_port = 37777

    with managed_proc(subprocess.Popen(
        [
            "python3",
            pingpong_script,
            "-s",
            "0.0.0.0",
            "-p",
            str(pingpong_port),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )) as server:
        wait_server(server, "Server listened on")

        with managed_proc(nsproxy_runner(extra_args + [
            "python3",
            pingpong_script,
            "-c",
            LOCAL_IP,
            "-p",
            str(pingpong_port),
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


def test_basic_tcp_direct(nsproxy_runner):
    """Test direct TCP connection through nsproxy (no proxy)"""
    _run_tcp_pingpong_test(nsproxy_runner, ["-D"])


def test_basic_tcp_http(proxy_server, nsproxy_runner):
    """Test HTTP proxy TCP connection (HTTP proxy does not support UDP)"""
    _run_tcp_pingpong_test(
        nsproxy_runner,
        ["-H", "-s", "127.0.0.1", "-p", str(HTTP_NOAUTH_PORT)],
    )


def test_basic_tcp_socks5(proxy_server, nsproxy_runner):
    """Test SOCKS5 TCP connection"""
    _run_tcp_pingpong_test(
        nsproxy_runner, ["-s", "127.0.0.1", "-p", str(SOCKS_NOAUTH_PORT)]
    )
