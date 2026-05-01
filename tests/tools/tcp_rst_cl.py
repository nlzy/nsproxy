#!/usr/bin/env python3
"""
TCP Client RST Test Tool
========================

This script implements a TCP RST test where the client closes the connection
using RST (reset) instead of FIN after receiving data from server.

Usage:
    python3 tcp_rst_cl.py -s <bind_addr> -p <port>    # Run as server
    python3 tcp_rst_cl.py -c <server_addr> -p <port>  # Run as client

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
                          |                                    |
                          |<------- 3. send 's' ---------------|
                          |         (DATA_SIZE bytes)          |
            4. recv 's' --|                                    |
   print CLIENT-RECV-OK   |                                    |
                          |                                    |
                          |-------- 5. RST ------------------->|
                          |         (SO_LINGER with 0)         |
                          |                                    |-- 6. detect RST
                          |                                    |      print CLIENT-RST

Output Messages:
    SERVER-RECV-OK  - Server successfully received data from client
    CLIENT-RECV-OK  - Client successfully received data from server
    CLIENT-RST      - Server detected that client closed connection with RST

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


def run_server(bind_addr, port):
    """Run as server"""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((bind_addr, port))
    server_sock.listen(1)
    print(f"Server listened on {bind_addr}:{port}", flush=True)

    conn, addr = server_sock.accept()

    # diagram.2: Receive 'c' from client
    data1 = recv_exact(conn, DATA_SIZE)
    if data1 is None:
        print(f"ERROR: Failed to receive data, connection closed", file=sys.stderr)
        sys.exit(1)
    if len(data1) != DATA_SIZE:
        print(
            f"ERROR: Failed to receive data, got {len(data1)} bytes, expected {DATA_SIZE}",
            file=sys.stderr,
        )
        sys.exit(1)

    # Verify data content
    if data1 != b"c" * DATA_SIZE:
        print("ERROR: Data mismatch", file=sys.stderr)
        sys.exit(1)

    print("SERVER-RECV-OK", flush=True)

    # diagram.3: Send 's' to client
    conn.sendall(b"s" * DATA_SIZE)

    # diagram.6: Wait for client to close connection
    # When client sends RST, recv() will raise ConnectionResetError
    try:
        conn.settimeout(5)
        data = conn.recv(4096)
        if data == b"":
            # Got EOF (FIN) instead of RST - this is unexpected
            print("ERROR: Got FIN instead of RST", file=sys.stderr)
            sys.exit(1)
        elif data:
            print(f"ERROR: Got unexpected data: {len(data)} bytes", file=sys.stderr)
            sys.exit(1)
    except socket.timeout:
        print("ERROR: Timeout waiting for RST", file=sys.stderr)
        sys.exit(1)
    except (ConnectionResetError, BrokenPipeError, OSError):
        # RST received - this is expected
        print("CLIENT-RST", flush=True)

    conn.close()
    server_sock.close()


def run_client(server_addr, port):
    """Run as client"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    sock.connect((server_addr, port))

    # diagram.1: Send 'c' to server
    sock.sendall(b"c" * DATA_SIZE)

    # diagram.4: Receive 's' from server
    data = recv_exact(sock, DATA_SIZE)
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
    if data != b"s" * DATA_SIZE:
        print("ERROR: Data mismatch", file=sys.stderr)
        sys.exit(1)

    print("CLIENT-RECV-OK", flush=True)

    # diagram.5: Send RST to server using SO_LINGER with 0 timeout
    # This causes an abortive close (RST) instead of graceful close (FIN)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    sock.close()


def main():
    parser = argparse.ArgumentParser(
        description="TCP client RST test tool",
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
