import subprocess
import time
from .conftest import HTTP_NOAUTH_PORT, HTTP_AUTH_PORT, tcp_bi_transfer


def test_http_tcp(proxy_server, nsproxy_runner):
    tcp_bi_transfer(
        nsproxy_runner, ["-H", "-s", "127.0.0.1", "-p", str(HTTP_NOAUTH_PORT)]
    )


def test_http_tcp_auth(proxy_server, nsproxy_runner):
    tcp_bi_transfer(
        nsproxy_runner,
        ["-H", "-a", "testuser:testpass", "-s", "127.0.0.1", "-p", str(HTTP_AUTH_PORT)],
    )
