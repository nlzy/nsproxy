"""
Authentication Success Tests
============================

These tests verify that nsproxy can successfully authenticate with proxies
that require username/password authentication.

Tests:
------
test_http_auth_ok
    Tests HTTP proxy TCP connection with authentication.

test_socks5_auth_ok
    Tests SOCKS5 TCP connection with authentication.

Usage:
------
    pytest -v tests/test_auth_ok.py
    pytest -v -k "auth" tests/
"""

import subprocess
import time
from .conftest import LOCAL_IP, HTTP_AUTH_PORT, SOCKS_AUTH_PORT


def _run_tcp_pingpong_test(nsproxy_runner, extra_args):
    """Run TCP pingpong test through nsproxy"""
    pingpong_script = "tests/tools/tcp_pingpong.py"
    pingpong_port = 37777

    # Start the pingpong server
    server_proc = subprocess.Popen(
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
    )

    # Wait for server to start listening
    time.sleep(0.5)

    try:
        # Run the pingpong client through nsproxy
        client_args = extra_args + [
            "python3",
            pingpong_script,
            "-c",
            LOCAL_IP,
            "-p",
            str(pingpong_port),
        ]
        client = nsproxy_runner(client_args)
        stdout, stderr = client.communicate(timeout=30)

        # Get outputs
        stdout_str = stdout.decode(errors="replace")
        stderr_str = stderr.decode(errors="replace")

        server_stdout, server_stderr = server_proc.communicate(timeout=5)
        server_stdout_str = server_stdout.decode(errors="replace")
        server_stderr_str = server_stderr.decode(errors="replace")

        # Assertions
        assert "SERVER-RECV-OK" in server_stdout_str, (
            f"Server did not receive data. stderr: {server_stderr_str}"
        )
        assert "CLIENT-RECV-OK" in stdout_str, (
            f"Client did not receive data. stderr: {stderr_str}"
        )
        assert server_proc.returncode == 0, (
            f"Server exited with error code {server_proc.returncode}. stderr: {server_stderr_str}"
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


def test_http_auth_ok(proxy_server, nsproxy_runner):
    """Test HTTP proxy TCP connection with authentication"""
    _run_tcp_pingpong_test(
        nsproxy_runner,
        ["-H", "-a", "testuser:testpass", "-s", "127.0.0.1", "-p", str(HTTP_AUTH_PORT)],
    )


def test_socks5_auth_ok(proxy_server, nsproxy_runner):
    """Test SOCKS5 TCP connection with authentication"""
    _run_tcp_pingpong_test(
        nsproxy_runner,
        ["-a", "testuser:testpass", "-s", "127.0.0.1", "-p", str(SOCKS_AUTH_PORT)],
    )
