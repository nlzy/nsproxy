"""
Proxy Connection Failure Tests
==============================

These tests verify that nsproxy properly handles proxy connection failures
when the proxy server is unreachable. In these tests, unreachable proxy server
is port 0 on localhost.

Tests:
------
test_tcp_proxy_fail_socks5
    Tests TCP connection failure through SOCKS5 proxy on port 0.

test_tcp_proxy_fail_http
    Tests TCP connection failure through HTTP proxy on port 0.

test_udp_proxy_fail_socks5
    Tests UDP connection failure through SOCKS5 proxy on port 0.

test_dns_proxy_fail_socks5
    Tests DNS over TCP query failure through SOCKS5 proxy on port 0.

test_dns_proxy_fail_http
    Tests DNS over TCP query failure through HTTP proxy on port 0.

Usage:
------
    pytest -v tests/test_proxy_fail.py
    pytest -v -k "proxy_fail" tests/
"""

import subprocess
from .conftest import LOCAL_IP, managed_proc, COMMUNICATE_TIMEOUT


def _test_proxy_fail(nsproxy_runner, extra_args, is_udp=False):
    """Test client fails when proxy is unreachable (port 0)"""
    pingpong_script = (
        "tests/tools/udp_pingpong.py" if is_udp else "tests/tools/tcp_pingpong.py"
    )
    error_string = (
        "TimeoutError" if is_udp else "ConnectionRefusedError"
    )
    pingpong_port = 37777

    with managed_proc(
        nsproxy_runner(
            extra_args
            + [
                "python3",
                pingpong_script,
                "-c",
                LOCAL_IP,
                "-p",
                str(pingpong_port),
            ]
        )
    ) as client:
        cl_stdout, cl_stderr = client.communicate(timeout=COMMUNICATE_TIMEOUT)

    cl_out = cl_stdout.decode(errors="replace")
    cl_err = cl_stderr.decode(errors="replace")

    assert error_string in cl_err, (
        f"Client didn't got {error_string}."
        f"stdout: {cl_out}, stderr: {cl_err}"
    )
    assert client.returncode == 1, (
        f"Expected client exited with status 1."
        f"stdout: {cl_out}, stderr: {cl_err}"
    )


def _test_dns_proxy_fail(nsproxy_runner, extra_args):
    """Test DNS query fails when proxy is unreachable (port 0)"""
    dig_noreply_returncode = 9

    with managed_proc(
        nsproxy_runner(
            extra_args
            + [
                "dig",
                "+short",
                "+time=1",
                "+tries=1",
                "example.com",
            ]
        )
    ) as client:
        cl_stdout, cl_stderr = client.communicate(timeout=COMMUNICATE_TIMEOUT)

    cl_out = cl_stdout.decode(errors="replace")
    cl_err = cl_stderr.decode(errors="replace")

    assert client.returncode == dig_noreply_returncode, (
        f"Expected DNS query to fail when proxy is unreachable. "
        f"stdout: {cl_out}, stderr: {cl_err}"
    )


def test_tcp_proxy_fail_socks5(nsproxy_runner):
    """Test TCP connection fails when SOCKS5 proxy is unreachable"""
    _test_proxy_fail(nsproxy_runner, ["-s", "127.0.0.1", "-p", "0"])


def test_tcp_proxy_fail_http(nsproxy_runner):
    """Test TCP connection fails when HTTP proxy is unreachable"""
    _test_proxy_fail(nsproxy_runner, ["-H", "-s", "127.0.0.1", "-p", "0"])


def test_udp_proxy_fail_socks5(nsproxy_runner):
    """Test UDP connection fails when SOCKS5 proxy is unreachable"""
    _test_proxy_fail(nsproxy_runner, ["-s", "127.0.0.1", "-p", "0"], is_udp=True)


def test_dns_proxy_fail_socks5(nsproxy_runner):
    """Test DNS over TCP fails when SOCKS5 proxy is unreachable"""
    _test_dns_proxy_fail(nsproxy_runner, ["-s", "127.0.0.1", "-p", "0"])


def test_dns_proxy_fail_http(nsproxy_runner):
    """Test DNS over TCP fails when HTTP proxy is unreachable"""
    _test_dns_proxy_fail(nsproxy_runner, ["-H", "-s", "127.0.0.1", "-p", "0"])
