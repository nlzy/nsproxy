"""
Authentication Failure Tests
============================

These tests verify that nsproxy properly handles authentication failures
when connecting to proxies that require authentication.

Tests:
------
test_http_auth_fail
    Tests connection to HTTP proxy with wrong password.
    - Uses HTTP proxy on port 38081 (auth required)
    - Provides wrong credentials: testuser:wrongpass
    - Expects error message in stderr
    - Verifies server does not receive any data

test_http_auth_missing
    Tests connection to HTTP proxy without providing credentials.
    - Uses HTTP proxy on port 38081 (auth required)
    - No -a flag provided
    - Expects error message in stderr
    - Verifies server does not receive any data

test_socks5_auth_fail
    Tests connection to SOCKS5 proxy with wrong password.
    - Uses SOCKS5 proxy on port 31081 (auth required)
    - Provides wrong credentials: testuser:wrongpass
    - Expects error message in stderr

test_socks5_auth_missing
    Tests connection to SOCKS5 proxy without providing credentials.
    - Uses SOCKS5 proxy on port 31081 (auth required)
    - No -a flag provided
    - Expects error message in stderr

Usage:
------
    pytest -v tests/test_auth_fail.py
    pytest -v -k "auth_fail" tests/
"""

import subprocess
import time
import pytest
from .conftest import HTTP_AUTH_PORT, SOCKS_AUTH_PORT, LOCAL_IP


def _test_auth_failure(nsproxy_runner, extra_args, is_udp=False):
    """Test authentication failure using pingpong"""
    pingpong_script = (
        "tests/tools/udp_pingpong.py" if is_udp else "tests/tools/tcp_pingpong.py"
    )
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
        # Run the pingpong client through nsproxy with wrong auth
        client_args = extra_args + [
            "python3",
            pingpong_script,
            "-c",
            LOCAL_IP,
            "-p",
            str(pingpong_port),
        ]
        client = nsproxy_runner(client_args)
        stdout, stderr = client.communicate(timeout=10)

        # Get outputs
        stdout_str = stdout.decode(errors="replace")
        stderr_str = stderr.decode(errors="replace")

        # Client should fail with auth error
        assert "Please check your username and password." in stderr_str, (
            f"Expected auth error message not found. stderr: {stderr_str}"
        )

    finally:
        # Terminate server (it may still be waiting for connection)
        if server_proc.poll() is None:
            server_proc.terminate()
            try:
                server_stdout, server_stderr = server_proc.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                server_proc.kill()
                server_stdout, server_stderr = b"", b""
        else:
            server_stdout, server_stderr = (
                server_proc.stdout.read() if server_proc.stdout else b"",
                server_proc.stderr.read() if server_proc.stderr else b"",
            )

        # Check server output - it should not have received any data
        server_stdout_str = (
            server_stdout.decode(errors="replace") if server_stdout else ""
        )
        assert "SERVER-RECV-OK" not in server_stdout_str, (
            "Server should not have received data when auth failed"
        )


def test_http_auth_fail(proxy_server, nsproxy_runner):
    """Try to connect with wrong password through HTTP proxy"""
    _test_auth_failure(
        nsproxy_runner,
        [
            "-H",
            "-a",
            "testuser:wrongpass",
            "-s",
            "127.0.0.1",
            "-p",
            str(HTTP_AUTH_PORT),
        ],
        is_udp=False,
    )


def test_http_auth_missing(proxy_server, nsproxy_runner):
    """Try to connect without auth to HTTP proxy that requires it"""
    _test_auth_failure(
        nsproxy_runner,
        [
            "-H",
            "-s",
            "127.0.0.1",
            "-p",
            str(HTTP_AUTH_PORT),
        ],
        is_udp=False,
    )


def test_socks5_auth_fail(proxy_server, nsproxy_runner):
    """Try to connect with wrong password through SOCKS5 proxy"""
    _test_auth_failure(
        nsproxy_runner,
        [
            "-a",
            "testuser:wrongpass",
            "-s",
            "127.0.0.1",
            "-p",
            str(SOCKS_AUTH_PORT),
        ],
        is_udp=False,
    )


def test_socks5_auth_missing(proxy_server, nsproxy_runner):
    """Try to connect without auth to SOCKS5 proxy that requires it"""
    _test_auth_failure(
        nsproxy_runner,
        [
            "-s",
            "127.0.0.1",
            "-p",
            str(SOCKS_AUTH_PORT),
        ],
        is_udp=False,
    )
