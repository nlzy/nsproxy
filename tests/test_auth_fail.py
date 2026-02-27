import subprocess
import time
import pytest
from .conftest import HTTP_AUTH_PORT, SOCKS_AUTH_PORT, TCP_PORT, LOCAL_IP


def test_http_auth_fail(proxy_server, nsproxy_runner):
    # Try to connect with wrong password
    client = nsproxy_runner(
        [
            "-H",
            "-a",
            "testuser:wrongpass",
            "-s",
            "127.0.0.1",
            "-p",
            str(HTTP_AUTH_PORT),
            "nc",
            "-v",
            "-z",
            LOCAL_IP,
            str(TCP_PORT),
        ]
    )

    stdout, stderr = client.communicate(timeout=5)
    stderr_output = stderr.decode() if stderr else ""

    assert "Please check your username and password." in stderr_output


def test_http_auth_missing(proxy_server, nsproxy_runner):
    # Try to connect without auth to a proxy that requires it
    client = nsproxy_runner(
        [
            "-H",
            "-s",
            "127.0.0.1",
            "-p",
            str(HTTP_AUTH_PORT),
            "nc",
            "-v",
            "-z",
            LOCAL_IP,
            str(TCP_PORT),
        ]
    )

    stdout, stderr = client.communicate(timeout=5)
    stderr_output = stderr.decode() if stderr else ""

    assert "Please check your username and password." in stderr_output


def test_socks5_auth_fail(proxy_server, nsproxy_runner):
    # Try to connect with wrong password
    client = nsproxy_runner(
        [
            "-a",
            "testuser:wrongpass",
            "-s",
            "127.0.0.1",
            "-p",
            str(SOCKS_AUTH_PORT),
            "nc",
            "-v",
            "-z",
            LOCAL_IP,
            str(TCP_PORT),
        ]
    )

    stdout, stderr = client.communicate(timeout=5)
    stderr_output = stderr.decode() if stderr else ""

    assert "Please check your username and password." in stderr_output


def test_socks5_auth_missing(proxy_server, nsproxy_runner):
    # Try to connect without auth to a proxy that requires it
    client = nsproxy_runner(
        [
            "-s",
            "127.0.0.1",
            "-p",
            str(SOCKS_AUTH_PORT),
            "nc",
            "-v",
            "-z",
            LOCAL_IP,
            str(TCP_PORT),
        ]
    )

    stdout, stderr = client.communicate(timeout=5)
    stderr_output = stderr.decode() if stderr else ""

    assert "Please check your username and password." in stderr_output
