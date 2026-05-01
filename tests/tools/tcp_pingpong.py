#!/usr/bin/env python3
"""
TCP Ping-Pong Test Tool
=======================

This script implements a simple TCP ping-pong test where client and server
take turns sending fixed-size data chunks.

Usage:
    python3 tcp_pingpong.py -s <bind_addr> -p <port>    # Run as server
    python3 tcp_pingpong.py -c <server_addr> -p <port>  # Run as client

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
                        |         close()                    |
                        |         (TCP FIN)                  |
4. recv 's' until EOF --|                                    |
 print CLIENT-RECV-OK   |                                    |
                        |-------- 5. close() --------------->|
                        |         (TCP FIN)                  |

Output Messages:
    SERVER-RECV-OK    - Server successfully received data from client
    CLIENT-RECV-OK    - Client successfully received data from server

Exit Codes:
    0 - Success
    1 - Error (with details printed to stderr)
"""

import socket
import struct
import sys
import argparse

DATA_SIZE = 100000  # 100,000 bytes


def recv_exact(sock, size):
    """Receive exactly `size` bytes from socket."""
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(min(4096, size - len(data)))
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)


def recv_exact_eof(sock):
    """Receive data from socket until EOF."""
    data = bytearray()
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def run_server(bind_addr, port):
    """Run as server"""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.setsockopt(
        socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 10)
    )
    server_sock.bind((bind_addr, port))
    server_sock.listen(1)
    print(f"Server listened on {bind_addr}:{port}", flush=True)

    conn, addr = server_sock.accept()
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 10))

    # diagram.2: Receive 'c' from client
    data = recv_exact(conn, DATA_SIZE)
    if data is None:
        print(f"ERROR: Failed to receive data, connection closed", file=sys.stderr)
        sys.exit(1)
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

    # diagram.3: Send 's' to client, then close
    conn.sendall(b"s" * DATA_SIZE)
    conn.close()

    # Close connection
    server_sock.close()


def run_client(server_addr, port):
    """Run as client"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 10))
    sock.settimeout(1.0)
    sock.connect((server_addr, port))

    # diagram.1: Send 'c' to server
    sock.sendall(b"c" * DATA_SIZE)

    # diagram.4: Receive 's' from server until EOF
    data = recv_exact_eof(sock)
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

    # diagram.5: Close connection
    sock.close()


def main():
    parser = argparse.ArgumentParser(
        description="TCP ping-pong test tool",
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

    args = parser.parse_args()

    if args.server:
        run_server(args.server, args.port)
    else:
        run_client(args.client, args.port)


if __name__ == "__main__":
    main()
