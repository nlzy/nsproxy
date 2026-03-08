"""
Basic UDP Tests
==================

These tests verify nsproxy's UDP connection support through different modes:
direct mode and SOCKS5 proxy (HTTP proxy does not support UDP).

Tests:
------
test_basic_udp_direct
    Tests UDP connection in direct mode (-D flag) without proxy.

test_basic_udp_socks5
    Tests SOCKS5 UDP connection without authentication (UDP associate).

Usage:
------
    pytest -v tests/test_udp_pingpong.py
    pytest -v -k "udp" tests/
"""

import subprocess
import time
from .conftest import LOCAL_IP, SOCKS_NOAUTH_PORT


def _run_udp_pingpong_test(nsproxy_runner, extra_args):
    """Run UDP pingpong test through nsproxy"""
    pingpong_script = "tests/tools/udp_pingpong.py"
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


def test_basic_udp_direct(nsproxy_runner):
    """Test direct UDP connection through nsproxy (no proxy)"""
    _run_udp_pingpong_test(nsproxy_runner, ["-D"])


def test_basic_udp_socks5(proxy_server, nsproxy_runner):
    """Test SOCKS5 UDP connection"""
    _run_udp_pingpong_test(
        nsproxy_runner, ["-s", "127.0.0.1", "-p", str(SOCKS_NOAUTH_PORT)]
    )
