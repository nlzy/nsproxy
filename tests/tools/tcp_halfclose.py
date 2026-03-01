#!/usr/bin/env python3
"""
TCP Half-Close Test Tool
========================

This script implements a TCP half-close test that verifies proper handling
of TCP half-close scenarios where one side shuts down its write end while
keeping the read end open.

Usage:
    python3 tcp_halfclose.py -s <bind_addr> -p <port>    # Run as server
    python3 tcp_halfclose.py -c <server_addr> -p <port>  # Run as client

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
                              |                                    |      print SERVER-FIRST-RECV-OK
                              |                                    |
                              |<------- 3. send 's' ---------------|
                              |         (DATA_SIZE bytes)          |
                4. recv 's' --|                                    |
 print CLIENT-FIRST-RECV-OK   |                                    |
                              |                                    |
                              |-------- 5. send 'C' -------------->|
                              |         (DATA_SIZE bytes)          |
                              |         shutdown(SHUT_WR)          |
                              |                                    |-- 6. recv 'C' until EOF
                              |                                    |      print SERVER-FINAL-RECV-OK
                              |<------- 7. send 'S' ---------------|
                              |         (DATA_SIZE bytes)          |
                              |         close()                    |
      8. recv 'S' until EOF --|                                    |
 print CLIENT-FINAL-RECV-OK   |                                    |
                              |                                    |

Output Messages:
    SERVER-FIRST-RECV-OK    - Server successfully received first data chunk
    CLIENT-FIRST-RECV-OK    - Client successfully received first data chunk
    SERVER-FINAL-RECV-OK    - Server received second chunk and detected half-close
    CLIENT-FINAL-RECV-OK    - Client received final chunk and detected close

Exit Codes:
    0 - Success
    1 - Error (with details printed to stderr)
"""

import socket
import sys
import argparse

DATA_SIZE = 100000  # 100,000 bytes


def recv_exact(sock, size):
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
    print(f"Server listening on {bind_addr}:{port}", flush=True)
    server_sock.listen(1)

    conn, addr = server_sock.accept()

    # diagram.2: Receive 'c' from client
    data1 = recv_exact(conn, DATA_SIZE)
    if data1 is None:
        print(
            f"ERROR: Failed to receive first data, connection closed", file=sys.stderr
        )
        sys.exit(1)
    if len(data1) != DATA_SIZE:
        print(
            f"ERROR: Failed to receive first data, got {len(data1)} bytes, expected {DATA_SIZE}",
            file=sys.stderr,
        )
        sys.exit(1)

    # Verify data content
    if data1 != b"c" * DATA_SIZE:
        print("ERROR: First data mismatch", file=sys.stderr)
        sys.exit(1)

    print("SERVER-FIRST-RECV-OK", flush=True)

    # diagram.3: Send 's' to client
    conn.sendall(b"s" * DATA_SIZE)

    # diagram.6: Receive 'C' from client and detect half-close
    data2 = recv_exact(conn, DATA_SIZE)
    if data2 is None:
        print(
            f"ERROR: Failed to receive second data, connection closed", file=sys.stderr
        )
        sys.exit(1)
    if len(data2) != DATA_SIZE:
        print(
            f"ERROR: Failed to receive second data, got {len(data2)} bytes, expected {DATA_SIZE}",
            file=sys.stderr,
        )
        sys.exit(1)

    # Verify data content
    if data2 != b"C" * DATA_SIZE:
        print("ERROR: Second data mismatch", file=sys.stderr)
        sys.exit(1)

    # Confirm client has stopped sending (must receive FIN, not RST)
    # Keep reading until EOF (empty bytes) which indicates FIN received
    conn.settimeout(5)
    while True:
        chunk = conn.recv(4096)
        if chunk == b"":
            # EOF received - this is the expected FIN
            break
        if chunk:
            print(
                f"ERROR: Received unexpected extra data: {len(chunk)} bytes",
                file=sys.stderr,
            )
            sys.exit(1)

    print("SERVER-FINAL-RECV-OK", flush=True)

    # diagram.7: Send 'S' to client, then close
    conn.sendall(b"S" * DATA_SIZE)

    # Close connection
    conn.close()
    server_sock.close()


def run_client(server_addr, port):
    """Run as client"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server_addr, port))

    # diagram.1: Send 'c' to server
    sock.sendall(b"c" * DATA_SIZE)

    # diagram.4: Receive 's' from server
    data1 = recv_exact(sock, DATA_SIZE)
    if data1 is None:
        print(
            f"ERROR: Failed to receive first data, connection closed", file=sys.stderr
        )
        sys.exit(1)
    if len(data1) != DATA_SIZE:
        print(
            f"ERROR: Failed to receive first data, got {len(data1)} bytes, expected {DATA_SIZE}",
            file=sys.stderr,
        )
        sys.exit(1)

    # Verify data content
    if data1 != b"s" * DATA_SIZE:
        print("ERROR: First data mismatch", file=sys.stderr)
        sys.exit(1)

    print("CLIENT-FIRST-RECV-OK", flush=True)

    # diagram.5: Send 'C' to server and shutdown write end
    sock.sendall(b"C" * DATA_SIZE)
    sock.shutdown(socket.SHUT_WR)

    # diagram.8: Receive 'S' from server and detect server closed
    data2 = recv_exact(sock, DATA_SIZE)
    if data2 is None:
        print(
            f"ERROR: Failed to receive second data, connection closed", file=sys.stderr
        )
        sys.exit(1)
    if len(data2) != DATA_SIZE:
        print(
            f"ERROR: Failed to receive second data, got {len(data2)} bytes, expected {DATA_SIZE}",
            file=sys.stderr,
        )
        sys.exit(1)

    # Verify data content
    if data2 != b"S" * DATA_SIZE:
        print("ERROR: Second data mismatch", file=sys.stderr)
        sys.exit(1)

    # Confirm server has stopped sending (must receive FIN, not RST)
    # Keep reading until EOF (empty bytes) which indicates FIN received
    sock.settimeout(5)
    while True:
        chunk = sock.recv(4096)
        if chunk == b"":
            # EOF received - this is the expected FIN
            break
        if chunk:
            print(
                f"ERROR: Received unexpected extra data: {len(chunk)} bytes",
                file=sys.stderr,
            )
            sys.exit(1)

    print("CLIENT-FINAL-RECV-OK", flush=True)

    # Close connection
    sock.close()


def main():
    parser = argparse.ArgumentParser(
        description="TCP half-close test tool",
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
