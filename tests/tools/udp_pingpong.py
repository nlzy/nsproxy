#!/usr/bin/env python3
"""
UDP Ping-Pong Test Tool
=======================

This script implements a simple UDP ping-pong test where client and server
take turns sending fixed-size data chunks.

Usage:
    python3 udp_pingpong.py -s <bind_addr> -p <port>    # Run as server
    python3 udp_pingpong.py -c <server_addr> -p <port>  # Run as client

Arguments:
    -s, --server <bind_addr>    Run in server mode, binding to specified address
    -c, --client <server_addr>  Run in client mode, connecting to specified server
    -p, --port <port>           Port number to use (default: 37777)

Test Flow:
                      Client                              Server
                        |                                    |
                        |-------- 1. send 'c' -------------->|
                        |         (DATA_SIZE bytes)          |
                        |                                    |-- 2. recv 'c'
                        |                                    |      print SERVER-RECV-OK
                        |<------- 3. send 's' ---------------|
                        |         (DATA_SIZE bytes)          |
                        |                                    |-- 4. exit()
         5. recv 's'  --|                                    |
print CLIENT-RECV-OK    |                                    |
              exit()    |                                    |

Output Messages:
    SERVER-RECV-OK    - Server successfully received data from client
    CLIENT-RECV-OK    - Client successfully received data from server

Exit Codes:
    0 - Success
    1 - Error (with details printed to stderr)
"""

import socket
import sys
import argparse

DATA_SIZE = 1000  # 1,000 bytes for UDP


def run_server(bind_addr, port, ipv6=False):
    """Run as server"""
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    server_sock = socket.socket(family, socket.SOCK_DGRAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((bind_addr, port))
    print(f"Server bind on {bind_addr}:{port}", flush=True)

    # diagram.2: Receive 'c' from client
    server_sock.settimeout(10)
    data, client_addr = server_sock.recvfrom(DATA_SIZE + 100)

    if len(data) != DATA_SIZE:
        print(
            f"ERROR: Failed to receive data, got {len(data)} bytes, expected {DATA_SIZE}",
            file=sys.stderr,
        )
        sys.exit(1)

    # Verify data content
    if data != b"c" * DATA_SIZE:
        print("ERROR: Data mismatch", file=sys.stderr)
        sys.exit(1)

    print("SERVER-RECV-OK", flush=True)

    # diagram.3: Send 's' to client
    server_sock.sendto(b"s" * DATA_SIZE, client_addr)

    # Close socket
    server_sock.close()


def run_client(server_addr, port, ipv6=False):
    """Run as client"""
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    client_sock = socket.socket(family, socket.SOCK_DGRAM)
    client_sock.settimeout(1.0)

    # diagram.1: Send 'c' to server
    client_sock.sendto(b"c" * DATA_SIZE, (server_addr, port))

    # diagram.5: Receive 's' from server
    data, server_addr_received = client_sock.recvfrom(DATA_SIZE + 100)

    if len(data) != DATA_SIZE:
        print(
            f"ERROR: Failed to receive data, got {len(data)} bytes, expected {DATA_SIZE}",
            file=sys.stderr,
        )
        sys.exit(1)

    # Verify data content
    if data != b"s" * DATA_SIZE:
        print("ERROR: Data mismatch", file=sys.stderr)
        sys.exit(1)

    print("CLIENT-RECV-OK", flush=True)

    # diagram.6: Close socket
    client_sock.close()


def main():
    parser = argparse.ArgumentParser(
        description="UDP ping-pong test tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -s 0.0.0.0 -p 37777          # Start server
  %(prog)s -c 127.0.0.1 -p 37777        # Start client
        """,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-s",
        "--server",
        metavar="BIND_ADDR",
        help="Run as server, binding to specified address",
    )
    group.add_argument(
        "-c",
        "--client",
        metavar="SERVER_ADDR",
        help="Run as client, connecting to specified server",
    )
    parser.add_argument(
        "-p", "--port", type=int, default=37777, help="Port number (default: 37777)"
    )
    parser.add_argument(
        "-6", "--ipv6", action="store_true", help="Use IPv6"
    )

    args = parser.parse_args()

    if args.server:
        run_server(args.server, args.port, args.ipv6)
    else:
        run_client(args.client, args.port, args.ipv6)


if __name__ == "__main__":
    main()
