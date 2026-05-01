"""
iperf3 Tests
============================

These tests verify nsproxy's TCP performance and scalability with iperf3,
in both upload and download directions.

Tests:
------
test_iperf3_direct_upload
    Tests upload in direct mode (-D flag) without proxy.

test_iperf3_direct_download
    Tests download in direct mode (-D flag) without proxy.

test_iperf3_http_upload
    Tests upload through HTTP proxy without authentication.

test_iperf3_http_download
    Tests download through HTTP proxy without authentication.

test_iperf3_socks5_upload
    Tests upload through SOCKS5 proxy without authentication.

test_iperf3_socks5_download
    Tests download through SOCKS5 proxy without authentication.

Usage:
------
    pytest -v tests/test_iperf3.py
    pytest -v -k "iperf3" tests/
"""

import subprocess
import time
from .conftest import (
    LOCAL_IP,
    HTTP_NOAUTH_PORT,
    SOCKS_NOAUTH_PORT,
    wait_server,
    managed_proc,
)

IPERF3_PORT = 37778
IPERF3_DURATION = 3
IPERF3_CONNECTIONS = 128
TEST_TIMEOUT = 5


def _run_iperf3_test(nsproxy_runner, extra_args, reverse=False):
    """Run iperf3 test through nsproxy"""
    server_args = [
        "iperf3",
        "-i", "0",
        "--forceflush",
        "-s",
        "-p", str(IPERF3_PORT)
    ]
    client_args = [
        "iperf3",
        "-i", "0",
        "--forceflush",
        "-c", LOCAL_IP,
        "-p", str(IPERF3_PORT),
        "-P", str(IPERF3_CONNECTIONS),
        "-t", str(IPERF3_DURATION),
    ]
    if reverse:
        client_args.append("-R")

    with managed_proc(subprocess.Popen(
        server_args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )) as server:
        wait_server(server, "Server listening on")

        with managed_proc(nsproxy_runner(extra_args + client_args)) as client:
            cl_stdout, cl_stderr = client.communicate(timeout=TEST_TIMEOUT)

        if server.poll() is None:
            server.kill()

        sv_stdout, sv_stderr = server.communicate(timeout=TEST_TIMEOUT)

        cl_out, cl_err, sv_out, sv_err = [
            s.decode(errors="replace") for s in [cl_stdout, cl_stderr, sv_stdout, sv_stderr]
        ]

        assert client.returncode == 0, (
            f"iperf3 client exited with error code {client.returncode}. "
            f"stderr: {cl_err}"
        )
        assert "Done" in cl_out, (
            f"iperf3 client did not complete successfully. "
            f"stdout: {cl_out}, stderr: {cl_err}"
        )


# Direct mode tests

def test_iperf3_direct_upload(nsproxy_runner):
    """Test TCP upload through nsproxy direct mode"""
    _run_iperf3_test(nsproxy_runner, ["-q", "-D"], reverse=False)


def test_iperf3_direct_download(nsproxy_runner):
    """Test TCP download through nsproxy direct mode"""
    _run_iperf3_test(nsproxy_runner, ["-q", "-D"], reverse=True)


# HTTP proxy tests

def test_iperf3_http_upload(proxy_server, nsproxy_runner):
    """Test TCP upload through HTTP proxy"""
    _run_iperf3_test(
        nsproxy_runner,
        ["-q", "-H", "-s", "127.0.0.1", "-p", str(HTTP_NOAUTH_PORT)],
        reverse=False,
    )


def test_iperf3_http_download(proxy_server, nsproxy_runner):
    """Test TCP download through HTTP proxy"""
    _run_iperf3_test(
        nsproxy_runner,
        ["-q", "-H", "-s", "127.0.0.1", "-p", str(HTTP_NOAUTH_PORT)],
        reverse=True,
    )


# SOCKS5 proxy tests

def test_iperf3_socks5_upload(proxy_server, nsproxy_runner):
    """Test TCP upload through SOCKS5 proxy"""
    _run_iperf3_test(
        nsproxy_runner,
        ["-q", "-s", "127.0.0.1", "-p", str(SOCKS_NOAUTH_PORT)],
        reverse=False,
    )


def test_iperf3_socks5_download(proxy_server, nsproxy_runner):
    """Test TCP download through SOCKS5 proxy"""
    _run_iperf3_test(
        nsproxy_runner,
        ["-q", "-s", "127.0.0.1", "-p", str(SOCKS_NOAUTH_PORT)],
        reverse=True,
    )
