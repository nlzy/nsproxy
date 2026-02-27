import subprocess
import time
import pytest
import socket
import os
import random
import threading
import string

# Configuration
NSPROXY_PATH = "./build/nsproxy"

# 3proxy Configuration
PROXY_3PROXY_PATH = "3proxy"
PROXY_3PROXY_NOAUTH_CONFIG = "tests/conf/3proxy_noauth.cfg"
PROXY_3PROXY_AUTH_CONFIG = "tests/conf/3proxy_auth.cfg"

# v2ray Configuration
PROXY_V2RAY_PATH = "v2ray"
PROXY_V2RAY_NOAUTH_CONFIG = "tests/conf/v2ray_noauth.json"
PROXY_V2RAY_AUTH_CONFIG = "tests/conf/v2ray_auth.json"

SOCKS_NOAUTH_PORT = 31080
SOCKS_AUTH_PORT = 31081
HTTP_NOAUTH_PORT = 38080
HTTP_AUTH_PORT = 38081

TCP_PORT = 39000  # Target server port
UDP_PORT = 39001  # Target server port


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


LOCAL_IP = get_local_ip()


def tcp_bi_transfer(nsproxy_runner, extra_args, data_size=100 * 1024):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("0.0.0.0", TCP_PORT))
    server_sock.listen(1)

    client_send_data = "".join(
        random.choices(string.ascii_letters, k=data_size)
    ).encode("ascii")
    server_send_data = "".join(
        random.choices(string.ascii_letters, k=data_size)
    ).encode("ascii")

    received_by_server = bytearray()

    def server_thread():
        try:
            server_sock.settimeout(10)
            conn, addr = server_sock.accept()
            conn.settimeout(5)
            # Read all
            while len(received_by_server) < data_size:
                chunk = conn.recv(min(4096, data_size - len(received_by_server)))
                if not chunk:
                    break
                received_by_server.extend(chunk)
            # Send all
            conn.sendall(server_send_data)
            conn.close()
        except Exception as e:
            pass  # Error will be caught by assertions in main thread
        finally:
            server_sock.close()

    t = threading.Thread(target=server_thread)
    t.start()

    try:
        client_args = extra_args + ["nc", "-w", "2", LOCAL_IP, str(TCP_PORT)]
        client = nsproxy_runner(client_args)
        stdout, stderr = client.communicate(input=client_send_data, timeout=20)

        t.join(timeout=10)

        assert len(received_by_server) == data_size, (
            f"Server only received {len(received_by_server)} bytes"
        )
        assert received_by_server == client_send_data
        assert len(stdout) == data_size, f"Client only received {len(stdout)} bytes"
        assert stdout == server_send_data
        assert client.returncode == 0
    finally:
        server_sock.close()


def udp_bi_transfer(nsproxy_runner, extra_args, data_size=1024):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("0.0.0.0", UDP_PORT))

    client_send_data = os.urandom(data_size)
    server_send_data = os.urandom(data_size)

    received_by_server = []

    def server_thread():
        try:
            server_sock.settimeout(10)
            data, addr = server_sock.recvfrom(data_size + 100)
            received_by_server.append(data)
            server_sock.sendto(server_send_data, addr)
        except Exception as e:
            pass
        finally:
            server_sock.close()

    t = threading.Thread(target=server_thread)
    t.start()

    try:
        client_args = extra_args + ["nc", "-u", "-w", "2", LOCAL_IP, str(UDP_PORT)]
        client = nsproxy_runner(client_args)
        stdout, stderr = client.communicate(input=client_send_data, timeout=20)

        t.join(timeout=10)

        assert len(received_by_server) > 0, "Server received no data"
        assert received_by_server[0] == client_send_data
        assert stdout == server_send_data
        assert client.returncode == 0
    finally:
        server_sock.close()


@pytest.fixture(scope="module", params=["3proxy", "v2ray"], ids=["3proxy", "v2ray"])
def proxy_server(request):
    proxy_type = request.param

    if proxy_type == "3proxy":
        # Check 3proxy config files
        if not os.path.exists(PROXY_3PROXY_NOAUTH_CONFIG):
            pytest.fail(
                f"3proxy noauth config file not found at {PROXY_3PROXY_NOAUTH_CONFIG}"
            )
        if not os.path.exists(PROXY_3PROXY_AUTH_CONFIG):
            pytest.fail(
                f"3proxy auth config file not found at {PROXY_3PROXY_AUTH_CONFIG}"
            )

        # Start 3proxy noauth
        proc_noauth = subprocess.Popen(
            [PROXY_3PROXY_PATH, PROXY_3PROXY_NOAUTH_CONFIG],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # Start 3proxy auth
        proc_auth = subprocess.Popen(
            [PROXY_3PROXY_PATH, PROXY_3PROXY_AUTH_CONFIG],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    else:  # v2ray
        # Check v2ray config files
        if not os.path.exists(PROXY_V2RAY_NOAUTH_CONFIG):
            pytest.fail(
                f"v2ray noauth config file not found at {PROXY_V2RAY_NOAUTH_CONFIG}"
            )
        if not os.path.exists(PROXY_V2RAY_AUTH_CONFIG):
            pytest.fail(
                f"v2ray auth config file not found at {PROXY_V2RAY_AUTH_CONFIG}"
            )

        # Start v2ray noauth
        proc_noauth = subprocess.Popen(
            [PROXY_V2RAY_PATH, "run", "-c", PROXY_V2RAY_NOAUTH_CONFIG],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # Start v2ray auth
        proc_auth = subprocess.Popen(
            [PROXY_V2RAY_PATH, "run", "-c", PROXY_V2RAY_AUTH_CONFIG],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    time.sleep(0.5)
    yield (proc_noauth, proc_auth)
    proc_noauth.terminate()
    proc_noauth.wait()
    proc_auth.terminate()
    proc_auth.wait()


@pytest.fixture(params=["normal", "valgrind"], ids=["normal", "valgrind"])
def execution_mode(request):
    return request.param


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

        # When verbose is enabled, we don't want to capture stdout/stderr
        # so they can be seen in real-time or via pytest -s
        # However, subprocess.Popen with PIPE is still needed if we want to
        # manipulate them or use .communicate() like existing tests do.

        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        # If not capturing, communicate() will return (None, None)
        original_communicate = proc.communicate

        def communicate_with_check(*args, **kwargs):
            stdout, stderr = original_communicate(*args, **kwargs)
            if verbose > 0:
                if stdout:
                    print(stdout.decode(errors="replace"), end="")
                if stderr:
                    print(stderr.decode(errors="replace"), end="")
            if use_valgrind and proc.returncode == 100:
                # If we were capturing, we can show the error
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
