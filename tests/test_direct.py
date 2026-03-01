"""
Direct Connection Tests
=======================

These tests verify that nsproxy can work in direct mode (-D flag) without
requiring a proxy server. The traffic is forwarded directly to the target
server.

Tests:
------
test_direct_tcp
    Tests TCP connection in direct mode using tcp_pingpong tool.
    - Starts tcp_pingpong server on port 37777
    - Runs tcp_pingpong client through nsproxy with -D flag
    - Verifies bidirectional data transfer (100KB each way)
    - Client sends 'c' * 100000, server sends 's' * 100000
    - Checks for SERVER-RECV-OK and CLIENT-RECV-OK output

test_direct_udp
    Tests UDP connection in direct mode using udp_pingpong tool.
    - Starts udp_pingpong server on port 37777
    - Runs udp_pingpong client through nsproxy with -D flag
    - Verifies bidirectional data transfer (1KB each way)
    - Client sends 'c' * 1000, server sends 's' * 1000
    - Checks for SERVER-RECV-OK and CLIENT-RECV-OK output

Usage:
------
    pytest -v tests/test_direct.py
    pytest -v -k "direct" tests/
"""

import subprocess
import time
from .conftest import LOCAL_IP


def _run_pingpong_test(nsproxy_runner, extra_args, is_udp=False):
    """Run pingpong test (TCP or UDP) through nsproxy"""
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


def test_direct_tcp(nsproxy_runner):
    """Test direct TCP connection through nsproxy (no proxy)"""
    _run_pingpong_test(nsproxy_runner, ["-D"], is_udp=False)


def test_direct_udp(nsproxy_runner):
    """Test direct UDP connection through nsproxy (no proxy)"""
    _run_pingpong_test(nsproxy_runner, ["-D"], is_udp=True)
