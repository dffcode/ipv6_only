#!/usr/bin/env python3
"""
SOCKS5 proxy server — IPv6 only.

Accepts SOCKS5 connections over IPv6 and forwards traffic exclusively
over IPv6.  IPv4 addresses are rejected.

Compatible with Windows 11 and Linux.
"""

from __future__ import annotations

import argparse
import asyncio
import errno
import logging
import socket
import struct
import sys

logger = logging.getLogger("ipv6proxy")

# SOCKS5 constants
SOCKS_VERSION = 0x05
AUTH_NONE = 0x00
AUTH_NO_ACCEPTABLE = 0xFF
CMD_CONNECT = 0x01
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04
REP_SUCCESS = 0x00
REP_GENERAL_FAILURE = 0x01
REP_NOT_ALLOWED = 0x02
REP_NETWORK_UNREACHABLE = 0x03
REP_HOST_UNREACHABLE = 0x04
REP_CONNECTION_REFUSED = 0x05
REP_TTL_EXPIRED = 0x06
REP_ADDR_TYPE_NOT_SUPPORTED = 0x08

# Build errno-to-SOCKS reply map portably (some errnos are missing on Windows)
ERRNO_TO_SOCKS_REP: dict[int, int] = {}
if hasattr(errno, "ENETUNREACH"):
    ERRNO_TO_SOCKS_REP[errno.ENETUNREACH] = REP_NETWORK_UNREACHABLE
if hasattr(errno, "EHOSTUNREACH"):
    ERRNO_TO_SOCKS_REP[errno.EHOSTUNREACH] = REP_HOST_UNREACHABLE
if hasattr(errno, "ECONNREFUSED"):
    ERRNO_TO_SOCKS_REP[errno.ECONNREFUSED] = REP_CONNECTION_REFUSED
if hasattr(errno, "ETIMEDOUT"):
    ERRNO_TO_SOCKS_REP[errno.ETIMEDOUT] = REP_TTL_EXPIRED

# Windows winerror codes for the same conditions
if sys.platform == "win32":
    WINERROR_TO_SOCKS_REP: dict[int, int] = {
        10051: REP_NETWORK_UNREACHABLE,   # WSAENETUNREACH
        10065: REP_HOST_UNREACHABLE,      # WSAEHOSTUNREACH
        10061: REP_CONNECTION_REFUSED,    # WSAECONNREFUSED
        10060: REP_TTL_EXPIRED,           # WSAETIMEDOUT
    }


async def read_exact(reader: asyncio.StreamReader, n: int) -> bytes:
    data = await reader.readexactly(n)
    return data


async def resolve_host_ipv6(hostname: str) -> list[str]:
    """Resolve a hostname to IPv6 addresses only (AAAA records)."""
    loop = asyncio.get_running_loop()
    seen: set[str] = set()
    addrs: list[str] = []

    try:
        results = await loop.getaddrinfo(
            hostname, None, family=socket.AF_INET6, type=socket.SOCK_STREAM
        )
        for r in results:
            addr = r[4][0]
            if addr not in seen:
                seen.add(addr)
                addrs.append(addr)
    except (socket.gaierror, OSError):
        pass

    return addrs


async def send_reply(
    writer: asyncio.StreamWriter,
    rep: int,
    bind_addr: str = "::",
    bind_port: int = 0,
) -> None:
    """Send a SOCKS5 reply with an IPv6 address."""
    addr_bytes = socket.inet_pton(socket.AF_INET6, bind_addr)
    reply = struct.pack("!BBxB", SOCKS_VERSION, rep, ATYP_IPV6)
    reply += addr_bytes + struct.pack("!H", bind_port)
    writer.write(reply)
    await writer.drain()


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Forward data from reader to writer until EOF."""
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError,
            ConnectionAbortedError):
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except OSError:
            pass


def oserror_to_socks_rep(exc: OSError) -> int:
    """Map an OSError to the appropriate SOCKS5 reply code, cross-platform."""
    if exc.errno is not None:
        rep = ERRNO_TO_SOCKS_REP.get(exc.errno)
        if rep is not None:
            return rep

    if sys.platform == "win32":
        winerr = getattr(exc, "winerror", None)
        if winerr is not None:
            rep = WINERROR_TO_SOCKS_REP.get(winerr)
            if rep is not None:
                return rep

    return REP_GENERAL_FAILURE


async def handle_client(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
) -> None:
    peer = client_writer.get_extra_info("peername")
    logger.info("New connection from %s", peer)

    try:
        # --- Authentication negotiation ---
        header = await read_exact(client_reader, 2)
        version, n_methods = struct.unpack("!BB", header)

        if version != SOCKS_VERSION:
            logger.warning("Unsupported SOCKS version %d from %s", version, peer)
            client_writer.close()
            return

        methods = await read_exact(client_reader, n_methods)

        if AUTH_NONE not in methods:
            client_writer.write(struct.pack("!BB", SOCKS_VERSION, AUTH_NO_ACCEPTABLE))
            await client_writer.drain()
            client_writer.close()
            return

        # Select no-auth
        client_writer.write(struct.pack("!BB", SOCKS_VERSION, AUTH_NONE))
        await client_writer.drain()

        # --- Request ---
        req_header = await read_exact(client_reader, 4)
        ver, cmd, _, atyp = struct.unpack("!BBBB", req_header)

        if ver != SOCKS_VERSION:
            await send_reply(client_writer, REP_GENERAL_FAILURE)
            client_writer.close()
            return

        if cmd != CMD_CONNECT:
            logger.warning("Unsupported command %d from %s", cmd, peer)
            await send_reply(client_writer, REP_NOT_ALLOWED)
            client_writer.close()
            return

        # Parse destination address — IPv6 only
        addrs_to_try: list[str] = []

        if atyp == ATYP_IPV4:
            # Read and discard the IPv4 address + port so the stream stays aligned
            await read_exact(client_reader, 4)
            await read_exact(client_reader, 2)
            logger.warning("Rejected IPv4 destination from %s (IPv6 only)", peer)
            await send_reply(client_writer, REP_ADDR_TYPE_NOT_SUPPORTED)
            client_writer.close()
            return

        elif atyp == ATYP_DOMAIN:
            length = (await read_exact(client_reader, 1))[0]
            domain = (await read_exact(client_reader, length)).decode("ascii")
            port = struct.unpack("!H", await read_exact(client_reader, 2))[0]
            addrs_to_try = await resolve_host_ipv6(domain)
            if not addrs_to_try:
                logger.warning(
                    "No AAAA records for %s, rejecting (%s)", domain, peer
                )
                await send_reply(client_writer, REP_HOST_UNREACHABLE)
                client_writer.close()
                return
            logger.info(
                "Resolved %s -> %s", domain, ", ".join(addrs_to_try),
            )

        elif atyp == ATYP_IPV6:
            raw = await read_exact(client_reader, 16)
            port = struct.unpack("!H", await read_exact(client_reader, 2))[0]
            ipv6_addr = socket.inet_ntop(socket.AF_INET6, raw)
            addrs_to_try = [ipv6_addr]

        else:
            logger.warning("Unknown address type %d from %s", atyp, peer)
            await send_reply(client_writer, REP_ADDR_TYPE_NOT_SUPPORTED)
            client_writer.close()
            return

        # --- Connect to remote via IPv6, trying each address in order ---
        remote_reader = None
        remote_writer = None
        last_exc: Exception | None = None

        for addr in addrs_to_try:
            logger.info("Connecting to [%s]:%d for %s", addr, port, peer)
            try:
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(addr, port, family=socket.AF_INET6),
                    timeout=10,
                )
                dst_addr = addr
                break
            except asyncio.TimeoutError:
                logger.warning("Timed out connecting to [%s]:%d", addr, port)
                last_exc = None
                continue
            except OSError as exc:
                logger.warning("Failed to connect to [%s]:%d: %s", addr, port, exc)
                last_exc = exc
                continue

        if remote_writer is None:
            if last_exc is not None and isinstance(last_exc, OSError):
                rep = oserror_to_socks_rep(last_exc)
            else:
                rep = REP_TTL_EXPIRED
            await send_reply(client_writer, rep)
            client_writer.close()
            return

        # Get the local bound address for the reply
        sock = remote_writer.get_extra_info("socket")
        bind_host, bind_port = sock.getsockname()[:2]

        await send_reply(client_writer, REP_SUCCESS, bind_host, bind_port)
        logger.info("Tunnel established: %s <-> [%s]:%d", peer, dst_addr, port)

        # --- Bidirectional forwarding ---
        await asyncio.gather(
            pipe(client_reader, remote_writer),
            pipe(remote_reader, client_writer),
        )

    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError,
            ConnectionAbortedError):
        pass
    except Exception:
        logger.exception("Error handling client %s", peer)
    finally:
        try:
            client_writer.close()
            await client_writer.wait_closed()
        except OSError:
            pass
        logger.info("Connection closed: %s", peer)


async def run_server(host: str, port: int) -> None:
    server = await asyncio.start_server(
        handle_client,
        host=host,
        port=port,
        family=socket.AF_INET6,
    )

    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    logger.info("SOCKS5 proxy listening on %s", addrs)

    async with server:
        await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SOCKS5 proxy server (IPv6 only)"
    )
    parser.add_argument(
        "--host",
        default="::1",
        help="Listen address (default: ::1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=1080,
        help="Listen port (default: 1080)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    logger.info("Starting SOCKS5 proxy (IPv6 only) on %s:%d", args.host, args.port)

    try:
        asyncio.run(run_server(args.host, args.port))
    except KeyboardInterrupt:
        logger.info("Shutting down.")
        sys.exit(0)


if __name__ == "__main__":
    main()
