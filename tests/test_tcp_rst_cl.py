"""
TCP Client RST Tests
====================

These tests verify nsproxy's handling of TCP RST (reset) scenarios where
client closes the connection using RST instead of FIN.

This is a specialized test for proper RST handling in the TCP stack.

Data flow
-------------
See tools/tcp_rst_cl.py

Verification:
-------------
- SERVER-RECV-OK: Server received data from client
- CLIENT-RECV-OK: Client received data from server
- CLIENT-RST: Server detected that client closed connection with RST

Usage:
------
    pytest -v tests/test_tcp_rst_cl.py
    pytest -v -k "cl_rst" tests/
"""

import subprocess
import time
from .conftest import SOCKS_NOAUTH_PORT, HTTP_NOAUTH_PORT, LOCAL_IP


def _run_cl_rst_test(nsproxy_runner, extra_args):
    """Helper function to run TCP client RST test with given nsproxy args."""
    RST_PORT = 37777

    # Start the RST server
    server_proc = subprocess.Popen(
        [
            "python3",
            "tests/tools/tcp_rst_cl.py",
            "-s",
            "0.0.0.0",
            "-p",
            str(RST_PORT),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for server to start listening
    time.sleep(0.5)

    try:
        client_args = extra_args + [
            "python3",
            "tests/tools/tcp_rst_cl.py",
            "-c",
            LOCAL_IP,
            "-p",
            str(RST_PORT),
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
        # 1. Client sends data -> Server receives
        assert "SERVER-RECV-OK" in server_stdout_str, (
            f"Server did not receive data. stderr: {server_stderr_str}"
        )

        # 2. Server sends data -> Client receives
        assert "CLIENT-RECV-OK" in stdout_str, (
            f"Client did not receive data. stderr: {stderr_str}"
        )

        # 3. Client sends RST -> Server detects RST
        assert "CLIENT-RST" in server_stdout_str, (
            f"Server did not detect RST. stderr: {server_stderr_str}"
        )

        # 4. Both processes exit successfully
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


def test_tcp_rst_cl_direct(nsproxy_runner):
    """Test TCP client RST functionality through nsproxy in direct mode."""
    _run_cl_rst_test(nsproxy_runner, ["-D"])


def test_tcp_rst_cl_socks(proxy_server, nsproxy_runner):
    """Test TCP client RST functionality through SOCKS proxy."""
    _run_cl_rst_test(nsproxy_runner, ["-s", "127.0.0.1", "-p", str(SOCKS_NOAUTH_PORT)])


def test_tcp_rst_cl_http(proxy_server, nsproxy_runner):
    """Test TCP client RST functionality through HTTP proxy."""
    _run_cl_rst_test(
        nsproxy_runner, ["-H", "-s", "127.0.0.1", "-p", str(HTTP_NOAUTH_PORT)]
    )
