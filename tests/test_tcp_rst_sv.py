"""
TCP Server RST Tests
====================

These tests verify nsproxy's handling of TCP RST (reset) scenarios where
server closes the connection using RST instead of FIN.

This is a specialized test for proper RST handling in the TCP stack.

Data flow
-------------
See tools/tcp_rst_sv.py

Verification:
-------------
- SERVER-RECV-OK: Server received data from client
- SERVER-RST: Client detected that server closed connection with RST

Usage:
------
    pytest -v tests/test_tcp_rst_sv.py
    pytest -v -k "sv_rst" tests/
"""

import pytest
import subprocess
import time
from .conftest import SOCKS_NOAUTH_PORT, HTTP_NOAUTH_PORT, LOCAL_IP, wait_server, managed_proc


def _run_sv_rst_test(nsproxy_runner, extra_args):
    """Helper function to run TCP server RST test with given nsproxy args."""
    RST_PORT = 37777

    with managed_proc(subprocess.Popen(
        [
            "python3",
            "tests/tools/tcp_rst_sv.py",
            "-s",
            "0.0.0.0",
            "-p",
            str(RST_PORT),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )) as server:
        wait_server(server, "Server listened on")

        with managed_proc(nsproxy_runner(extra_args + [
            "python3",
            "tests/tools/tcp_rst_sv.py",
            "-c",
            LOCAL_IP,
            "-p",
            str(RST_PORT),
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

        # Assertions in order of data exchange:
        # 1. Client sends data -> Server receives
        assert "SERVER-RECV-OK" in sv_out, (
            f"Server did not receive data. stderr: {sv_err}"
        )

        # 2. Server sends RST -> Client detects RST
        assert "SERVER-RST" in cl_out, (
            f"Client did not detect RST. stderr: {cl_err}"
        )

        # 3. Both processes exit successfully
        assert server.returncode == 0, (
            f"Server exited with error code {server.returncode}. stderr: {sv_err}"
        )
        assert client.returncode == 0, (
            f"Client exited with error code {client.returncode}. stderr: {cl_err}"
        )


def test_tcp_rst_sv_direct(nsproxy_runner):
    """Test TCP server RST functionality through nsproxy in direct mode."""
    _run_sv_rst_test(nsproxy_runner, ["-D"])


@pytest.mark.skip_proxy("*", reason="No proxy supports transparent RST forwarding")
def test_tcp_rst_sv_socks(proxy_server, nsproxy_runner):
    """Test TCP server RST functionality through SOCKS proxy."""
    _run_sv_rst_test(
        nsproxy_runner, ["-s", "127.0.0.1", "-p", str(SOCKS_NOAUTH_PORT)]
    )


@pytest.mark.skip_proxy("*", reason="No proxy supports transparent RST forwarding")
def test_tcp_rst_sv_http(proxy_server, nsproxy_runner):
    """Test TCP server RST functionality through HTTP proxy."""
    _run_sv_rst_test(
        nsproxy_runner, ["-H", "-s", "127.0.0.1", "-p", str(HTTP_NOAUTH_PORT)]
    )
