"""
Smoke Test
==========

A minimal smoke test to ensure nsproxy binary can start and execute
a simple command in direct mode (-D).

Tests:
------
test_000smoke
    Run 'nsproxy -D true' and verify it exits with code 0.

Usage:
------
    pytest -v tests/test_000smoke.py
"""

from .conftest import managed_proc, COMMUNICATE_TIMEOUT


def test_000smoke(nsproxy_runner):
    """Run nsproxy -D true and verify it exits with code 0"""
    with managed_proc(nsproxy_runner(["-D", "true"])) as client:
        cl_stdout, cl_stderr = client.communicate(timeout=COMMUNICATE_TIMEOUT)

    cl_out = cl_stdout.decode(errors="replace")
    cl_err = cl_stderr.decode(errors="replace")

    assert client.returncode == 0, (
        f"Client exited with error code {client.returncode}. "
        f"stdout: {cl_out}, stderr: {cl_err}"
    )
