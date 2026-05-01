import os
import select
import socket
import subprocess
import time
from contextlib import contextmanager

import pytest

# Configuration
NSPROXY_PATH = "./build/nsproxy"

# v2ray Configuration
PROXY_V2RAY_PATH = "v2ray"
PROXY_V2RAY_CONFIG = "tests/conf/v2ray.json"

# singbox Configuration
PROXY_SINGBOX_PATH = "sing-box"
PROXY_SINGBOX_CONFIG = "tests/conf/singbox.json"

# shadowsocks-rust Configuration
PROXY_SS_SERVER_PATH = "ssserver"
PROXY_SS_LOCAL_PATH = "sslocal"
PROXY_SS_SERVER_CONFIG = "tests/conf/shadowsocks_server.json"
PROXY_SS_LOCAL_CONFIG = "tests/conf/shadowsocks_local.json"

SOCKS_NOAUTH_PORT = 31080
SOCKS_AUTH_PORT = 31081
HTTP_NOAUTH_PORT = 38080
HTTP_AUTH_PORT = 38081


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = "127.0.0.1"
    finally:
        s.close()
    return IP


def get_local_ipv6():
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        s.connect(("2001:db8::1", 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = "::1"
    finally:
        s.close()
    return IP


LOCAL_IP = get_local_ip()
LOCAL_IPV6 = get_local_ipv6()


def wait_server(proc, marker, timeout=2):
    """Wait for one of the startup marker to appear in proc.stdout."""
    end_time = time.time() + timeout
    buf = b""
    fd = proc.stdout.fileno()
    while time.time() < end_time:
        remaining = end_time - time.time()
        if remaining <= 0:
            break
        ready, _, _ = select.select([fd], [], [], remaining)
        if ready:
            try:
                chunk = os.read(fd, 1024)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            if marker.encode() in buf:
                return
        if proc.poll() is not None:
            stdout, stderr = proc.communicate()
            raise RuntimeError(
                f"Server exited early with code {proc.returncode}. stdout: {stdout.decode(errors='replace')}, stderr: {stderr.decode(errors='replace')}"
            )
    raise TimeoutError(
        f"Server did not print startup marker within {timeout}s. stdout so far: {buf.decode(errors='replace')}"
    )


@contextmanager
def managed_proc(proc):
    """Ensure a subprocess is terminated/killed when exiting the context."""
    try:
        yield proc
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


@pytest.fixture(
    scope="module",
    params=["v2ray", "singbox", "shadowsocks"],
    ids=["v2ray", "singbox", "shadowsocks"],
)
def proxy_server(request):
    proxy_type = request.param
    procs = []

    if proxy_type == "v2ray":
        if not os.path.exists(PROXY_V2RAY_CONFIG):
            pytest.fail(f"v2ray config file not found at {PROXY_V2RAY_CONFIG}")

        proc = subprocess.Popen(
            [PROXY_V2RAY_PATH, "run", "-c", PROXY_V2RAY_CONFIG],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(proc)

    elif proxy_type == "singbox":
        if not os.path.exists(PROXY_SINGBOX_CONFIG):
            pytest.fail(f"singbox config file not found at {PROXY_SINGBOX_CONFIG}")

        proc = subprocess.Popen(
            [PROXY_SINGBOX_PATH, "run", "-c", PROXY_SINGBOX_CONFIG],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(proc)

    else:  # shadowsocks
        # Check config files
        if not os.path.exists(PROXY_SS_SERVER_CONFIG):
            pytest.fail(
                f"shadowsocks server config not found at {PROXY_SS_SERVER_CONFIG}"
            )
        if not os.path.exists(PROXY_SS_LOCAL_CONFIG):
            pytest.fail(
                f"shadowsocks local config not found at {PROXY_SS_LOCAL_CONFIG}"
            )

        # Start ssserver first
        proc_server = subprocess.Popen(
            [PROXY_SS_SERVER_PATH, "-c", PROXY_SS_SERVER_CONFIG],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(proc_server)

        # Start sslocal
        proc_local = subprocess.Popen(
            [PROXY_SS_LOCAL_PATH, "-c", PROXY_SS_LOCAL_CONFIG],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(proc_local)

    time.sleep(0.5)
    yield procs
    for proc in procs:
        proc.kill()
        proc.wait()


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "skip_proxy(name, reason=None): skip test for specific proxy"
    )


def pytest_runtest_setup(item):
    for mark in item.iter_markers(name="skip_proxy"):
        skip_name = mark.args[0]
        skip_reason = mark.kwargs.get("reason", "")
        current_proxy = item.callspec.params.get("proxy_server") if hasattr(item, "callspec") else None
        if skip_name in (current_proxy, "*"):
            pytest.skip(skip_reason)


def pytest_addoption(parser):
    parser.addoption(
        "--valgrind",
        action="store_true",
        default=False,
        help="Run tests with valgrind memory checker",
    )


@pytest.fixture
def execution_mode(request):
    if request.config.getoption("--valgrind"):
        return "valgrind"
    return "normal"


@pytest.fixture
def nsproxy_runner(request, execution_mode):
    verbose = request.config.getoption("verbose")
    use_valgrind = execution_mode == "valgrind"

    def _run(args):
        cmd = []
        if use_valgrind:
            cmd.extend(
                [
                    "valgrind",
                    "--leak-check=full",
                    "--show-leak-kinds=all",
                    "--error-exitcode=100",
                    "--trace-children=no",
                ]
            )
            if verbose == 0:
                cmd.append("--quiet")

        cmd.append(NSPROXY_PATH)

        if verbose > 0:
            cmd.append("-vvv")
        cmd.extend(args)

        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        original_communicate = proc.communicate

        def communicate_with_check(*args, **kwargs):
            stdout, stderr = original_communicate(*args, **kwargs)
            if verbose > 0:
                if stdout:
                    print(stdout.decode(errors="replace"), end="")
                if stderr:
                    print(stderr.decode(errors="replace"), end="")
            if use_valgrind and proc.returncode == 100:
                if stderr:
                    err_msg = stderr.decode(errors="replace")
                    pytest.fail(f"Valgrind detected memory leaks or errors:\n{err_msg}")
                else:
                    pytest.fail(
                        "Valgrind detected memory leaks or errors (check console output)"
                    )
            return stdout, stderr

        proc.communicate = communicate_with_check
        return proc

    return _run
