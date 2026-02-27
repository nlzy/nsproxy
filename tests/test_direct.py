import subprocess
import time
from .conftest import tcp_bi_transfer, udp_bi_transfer


def test_direct_tcp(nsproxy_runner):
    # test_direct_tcp verifies that nsproxy can connect directly to a TCP server
    # when using the -D (direct) flag, without requiring a proxy server.
    tcp_bi_transfer(nsproxy_runner, ["-D"])


def test_direct_udp(nsproxy_runner):
    # test_direct_udp verifies that nsproxy can connect directly to a UDP server
    # when using the -D (direct) flag, without requiring a proxy server.
    udp_bi_transfer(nsproxy_runner, ["-D"])
