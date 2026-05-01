"""
TCP Half-Close Tests
====================

These tests verify nsproxy's handling of TCP half-close scenarios, where
one side shuts down its write end while keeping the read end open.

This is a specialized test for proper FIN/RST handling in the TCP stack.

Data flow
-------------
See tools/tcp_halfclose_cl.py

Verification:
-------------
- SERVER-FIRST-RECV-OK: Server received first chunk
- CLIENT-FIRST-RECV-OK: Client received first chunk
- SERVER-FINAL-RECV-OK: Server received second chunk and detected half-close
- CLIENT-FINAL-RECV-OK: Client received final chunk and detected close

Usage:
------
    pytest -v tests/test_tcp_halfclose_cl.py
    pytest -v -k "halfclose" tests/
"""

import pytest
import subprocess
import time
from .conftest import SOCKS_NOAUTH_PORT, HTTP_NOAUTH_PORT, LOCAL_IP, wait_server, managed_proc


def _run_halfclose_cl_test(nsproxy_runner, extra_args):
    """Helper function to run TCP half-close test with given nsproxy args."""
    HALFCLOSE_PORT = 37777

    with managed_proc(subprocess.Popen(
        [
            "python3",
            "tests/tools/tcp_halfclose_cl.py",
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
            "tests/tools/tcp_halfclose_cl.py",
            "-c",
            LOCAL_IP,
            "-p",
            str(HALFCLOSE_PORT),
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
        # 1. Client sends 'c' -> Server receives -> Server sends 's'
        assert "SERVER-FIRST-RECV-OK" in sv_out, (
            f"Server did not receive first chunk. stderr: {sv_err}"
        )

        # 2. Client receives 's'
        assert "CLIENT-FIRST-RECV-OK" in cl_out, (
            f"Client did not receive first chunk. stderr: {cl_err}"
        )

        # 3. Client sends 'C' and shutdown WR (sends FIN)
        #    Server receives 'C' and must detect FIN (not RST) to confirm half-close
        assert "SERVER-FINAL-RECV-OK" in sv_out, (
            f"Server did not receive second chunk or detect half-close (FIN). stderr: {sv_err}"
        )

        # 4. Client receives 'S' and must detect server's FIN (not RST) to confirm full-close
        assert "CLIENT-FINAL-RECV-OK" in cl_out, (
            f"Client did not receive second chunk or detect close (FIN). stderr: {cl_err}"
        )

        # 5. Both processes exit successfully
        assert server.returncode == 0, (
            f"Server exited with error code {server.returncode}. stderr: {sv_err}"
        )
        assert client.returncode == 0, (
            f"Client exited with error code {client.returncode}. stderr: {cl_err}"
        )


def test_tcp_halfclose_cl_direct(nsproxy_runner):
    """Test TCP half-close functionality through nsproxy in direct mode."""
    _run_halfclose_cl_test(nsproxy_runner, ["-D"])


@pytest.mark.skip_proxy("v2ray", reason="v2ray not supports half-close")
def test_tcp_halfclose_cl_socks(proxy_server, nsproxy_runner):
    """Test TCP half-close functionality through SOCKS proxy."""
    _run_halfclose_cl_test(
        nsproxy_runner, ["-s", "127.0.0.1", "-p", str(SOCKS_NOAUTH_PORT)]
    )


@pytest.mark.skip_proxy("v2ray", reason="v2ray not supports half-close")
def test_tcp_halfclose_cl_http(proxy_server, nsproxy_runner):
    """Test TCP half-close functionality through HTTP proxy."""
    _run_halfclose_cl_test(
        nsproxy_runner, ["-H", "-s", "127.0.0.1", "-p", str(HTTP_NOAUTH_PORT)]
    )
