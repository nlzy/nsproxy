"""
Authentication Failure Tests
============================

These tests verify that nsproxy properly handles authentication failures
when connecting to proxies that require authentication.

Tests:
------
test_http_auth_fail
    Tests connection to HTTP proxy with wrong password.

test_http_auth_missing
    Tests connection to HTTP proxy without providing credentials.

test_socks5_auth_fail
    Tests connection to SOCKS5 proxy with wrong password.

test_socks5_auth_missing
    Tests connection to SOCKS5 proxy without providing credentials.

Usage:
------
    pytest -v tests/test_auth_fail.py
    pytest -v -k "auth_fail" tests/
"""

import subprocess
import time
import pytest
from .conftest import HTTP_AUTH_PORT, SOCKS_AUTH_PORT, LOCAL_IP, wait_server, managed_proc


def _test_auth_failure(nsproxy_runner, extra_args, is_udp=False):
    """Test authentication failure using pingpong"""
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
            "0.0.0.0",
            "-p",
            str(pingpong_port),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )) as server:
        wait_server(server, pingpong_marker)

        with managed_proc(nsproxy_runner(extra_args + [
            "python3",
            pingpong_script,
            "-c",
            LOCAL_IP,
            "-p",
            str(pingpong_port),
        ])) as client:
            stdout, stderr = client.communicate(timeout=3)

        # Get outputs
        stdout_str = stdout.decode(errors="replace")
        stderr_str = stderr.decode(errors="replace")

        # Client should fail with auth error
        assert "Please check your username and password." in stderr_str, (
            f"Expected auth error message not found. stderr: {stderr_str}"
        )


def test_http_auth_fail(proxy_server, nsproxy_runner):
    """Try to connect with wrong password through HTTP proxy"""
    _test_auth_failure(
        nsproxy_runner,
        [ "-H", "-a", "testuser:wrongpass", "-s", "127.0.0.1", "-p", str(HTTP_AUTH_PORT) ]
    )


def test_http_auth_missing(proxy_server, nsproxy_runner):
    """Try to connect without auth to HTTP proxy that requires it"""
    _test_auth_failure(
        nsproxy_runner,
        [ "-H", "-s", "127.0.0.1", "-p", str(HTTP_AUTH_PORT) ]
    )


def test_socks5_auth_fail(proxy_server, nsproxy_runner):
    """Try to connect with wrong password through SOCKS5 proxy"""
    _test_auth_failure(
        nsproxy_runner,
        [ "-a", "testuser:wrongpass", "-s", "127.0.0.1", "-p", str(SOCKS_AUTH_PORT) ]
    )


def test_socks5_auth_missing(proxy_server, nsproxy_runner):
    """Try to connect without auth to SOCKS5 proxy that requires it"""
    _test_auth_failure(
        nsproxy_runner,
        [ "-s", "127.0.0.1", "-p", str(SOCKS_AUTH_PORT) ]
    )
