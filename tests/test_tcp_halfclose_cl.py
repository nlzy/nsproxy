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
from .conftest import SOCKS_NOAUTH_PORT, HTTP_NOAUTH_PORT, LOCAL_IP


def _run_halfclose_cl_test(nsproxy_runner, extra_args):
    """Helper function to run TCP half-close test with given nsproxy args."""
    HALFCLOSE_PORT = 37777

    # Start the half-close server
    server_proc = subprocess.Popen(
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
    )

    # Wait for server to start listening
    time.sleep(0.5)

    try:
        client_args = extra_args + [
            "python3",
            "tests/tools/tcp_halfclose_cl.py",
            "-c",
            LOCAL_IP,
            "-p",
            str(HALFCLOSE_PORT),
        ]
        client = nsproxy_runner(client_args)
        stdout, stderr = client.communicate(timeout=30)

        # Get outputs
        stdout_str = stdout.decode(errors="replace")
        stderr_str = stderr.decode(errors="replace")

        server_stdout, server_stderr = server_proc.communicate(timeout=5)
        server_stdout_str = server_stdout.decode(errors="replace")
        server_stderr_str = server_stderr.decode(errors="replace")

        # Assertions in order of data exchange:
        # 1. Client sends 'c' -> Server receives -> Server sends 's'
        assert "SERVER-FIRST-RECV-OK" in server_stdout_str, (
            f"Server did not receive first chunk. stderr: {server_stderr_str}"
        )

        # 2. Client receives 's'
        assert "CLIENT-FIRST-RECV-OK" in stdout_str, (
            f"Client did not receive first chunk. stderr: {stderr_str}"
        )

        # 3. Client sends 'C' and shutdown WR (sends FIN)
        #    Server receives 'C' and must detect FIN (not RST) to confirm half-close
        assert "SERVER-FINAL-RECV-OK" in server_stdout_str, (
            f"Server did not receive second chunk or detect half-close (FIN). stderr: {server_stderr_str}"
        )

        # 4. Client receives 'S' and must detect server's FIN (not RST) to confirm full-close
        assert "CLIENT-FINAL-RECV-OK" in stdout_str, (
            f"Client did not receive second chunk or detect close (FIN). stderr: {stderr_str}"
        )

        # 5. Both processes exit successfully
        assert server_proc.returncode == 0, (
            f"Server exited with error code {server_proc.returncode}. stderr: {server_stderr_str}"
        )
        assert client.returncode == 0, (
            f"Client exited with error code {client.returncode}. stderr: {stderr_str}"
        )

    finally:
        # Cleanup
        if server_proc.poll() is None:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                server_proc.kill()


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
