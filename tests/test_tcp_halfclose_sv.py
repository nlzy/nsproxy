"""
TCP Half-Close Tests (Server-initiated)
========================================

These tests verify nsproxy's handling of TCP half-close scenarios where
the server initiates the half-close by shutting down its write end while
keeping the read end open.

This is a specialized test for proper FIN/RST handling in the TCP stack.

Data flow
-------------
See tools/tcp_halfclose_sv.py

Verification:
-------------
- SERVER-FIRST-RECV-OK: Server received first chunk
- CLIENT-FINAL-RECV-OK: Client received data and detected server half-close (FIN)
- SERVER-FINAL-RECV-OK: Server received second chunk and detected client close (FIN)

Usage:
------
    pytest -v tests/test_tcp_halfclose_sv.py
    pytest -v -k "halfclose_sv" tests/
"""

import pytest
import subprocess
import time
from .conftest import SOCKS_NOAUTH_PORT, HTTP_NOAUTH_PORT, LOCAL_IP, wait_server, managed_proc


def _run_halfclose_sv_test(nsproxy_runner, extra_args):
    """Helper function to run TCP half-close (server-initiated) test with given nsproxy args."""
    HALFCLOSE_PORT = 37777

    with managed_proc(subprocess.Popen(
        [
            "python3",
            "tests/tools/tcp_halfclose_sv.py",
            "-s",
            "0.0.0.0",
            "-p",
            str(HALFCLOSE_PORT),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )) as server:
        wait_server(server, "Server listened on")

        with managed_proc(nsproxy_runner(extra_args + [
            "python3",
            "tests/tools/tcp_halfclose_sv.py",
            "-c",
            LOCAL_IP,
            "-p",
            str(HALFCLOSE_PORT),
        ])) as client:
            stdout, stderr = client.communicate(timeout=3)

        # Get outputs
        stdout_str = stdout.decode(errors="replace")
        stderr_str = stderr.decode(errors="replace")

        # Immediately kill server after client finishes
        if server.poll() is None:
            server.kill()

        server_stdout, server_stderr = server.communicate(timeout=3)
        server_stdout_str = server_stdout.decode(errors="replace")
        server_stderr_str = server_stderr.decode(errors="replace")

        # Assertions in order of data exchange:
        # 1. Client sends 'c' -> Server receives -> Server sends 's' and shutdown WR
        assert "SERVER-FIRST-RECV-OK" in server_stdout_str, (
            f"Server did not receive first chunk. stderr: {server_stderr_str}"
        )

        # 2. Client receives 's' and must detect server's FIN (half-close)
        assert "CLIENT-FINAL-RECV-OK" in stdout_str, (
            f"Client did not receive data or detect server half-close (FIN). stderr: {stderr_str}"
        )

        # 3. Client sends 'C' and closes (sends FIN)
        #    Server receives 'C' and must detect FIN (not RST) to confirm close
        assert "SERVER-FINAL-RECV-OK" in server_stdout_str, (
            f"Server did not receive second chunk or detect close (FIN). stderr: {server_stderr_str}"
        )

        # 4. Both processes exit successfully
        assert server.returncode == 0, (
            f"Server exited with error code {server.returncode}. stderr: {server_stderr_str}"
        )
        assert client.returncode == 0, (
            f"Client exited with error code {client.returncode}. stderr: {stderr_str}"
        )


def test_tcp_halfclose_sv_direct(nsproxy_runner):
    """Test TCP half-close (server-initiated) functionality through nsproxy in direct mode."""
    _run_halfclose_sv_test(nsproxy_runner, ["-D"])


@pytest.mark.skip_proxy("v2ray", reason="v2ray not supports half-close")
def test_tcp_halfclose_sv_socks(proxy_server, nsproxy_runner):
    """Test TCP half-close (server-initiated) functionality through SOCKS proxy."""
    _run_halfclose_sv_test(
        nsproxy_runner, ["-s", "127.0.0.1", "-p", str(SOCKS_NOAUTH_PORT)]
    )


@pytest.mark.skip_proxy("v2ray", reason="v2ray not supports half-close")
def test_tcp_halfclose_sv_http(proxy_server, nsproxy_runner):
    """Test TCP half-close (server-initiated) functionality through HTTP proxy."""
    _run_halfclose_sv_test(
        nsproxy_runner, ["-H", "-s", "127.0.0.1", "-p", str(HTTP_NOAUTH_PORT)]
    )
