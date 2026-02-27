import subprocess
import time
from .conftest import (
    SOCKS_NOAUTH_PORT,
    SOCKS_AUTH_PORT,
    tcp_bi_transfer,
    udp_bi_transfer,
)


def test_socks5_tcp(proxy_server, nsproxy_runner):
    tcp_bi_transfer(nsproxy_runner, ["-s", "127.0.0.1", "-p", str(SOCKS_NOAUTH_PORT)])


def test_socks5_udp(proxy_server, nsproxy_runner):
    udp_bi_transfer(nsproxy_runner, ["-s", "127.0.0.1", "-p", str(SOCKS_NOAUTH_PORT)])


def test_socks5_auth_tcp(proxy_server, nsproxy_runner):
    tcp_bi_transfer(
        nsproxy_runner,
        ["-a", "testuser:testpass", "-s", "127.0.0.1", "-p", str(SOCKS_AUTH_PORT)],
    )


def test_socks5_auth_udp(proxy_server, nsproxy_runner):
    udp_bi_transfer(
        nsproxy_runner,
        ["-a", "testuser:testpass", "-s", "127.0.0.1", "-p", str(SOCKS_AUTH_PORT)],
    )
