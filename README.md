IPv6-Only SOCKS5 Proxy
======================

A lightweight SOCKS5 proxy that transmits traffic exclusively over IPv6.
IPv4 destinations are rejected outright.


REQUIREMENTS
------------
- Python 3.10+
- No external dependencies (uses only the standard library)
- The host machine must have working IPv6 connectivity


HOW IT WORKS
------------
The proxy implements the SOCKS5 protocol (RFC 1928) and enforces IPv6-only
traffic at three levels:

1. IPv4 address targets (ATYP 0x01) are immediately rejected with
   "address type not supported".

2. Domain name targets (ATYP 0x03) are resolved using AAAA DNS lookups only.
   If a domain has no AAAA record the connection is refused.

3. IPv6 address targets (ATYP 0x04) are connected directly.

The proxy itself listens on an IPv6 socket (default ::1 port 1080).


USAGE
-----
Start the proxy:

    python3 proxy.py

With options:

    python3 proxy.py --host ::1 --port 1080 --log-level DEBUG

Options:
    --host       Listen address. Default: ::1 (IPv6 loopback).
    --port       Listen port. Default: 1080.
    --log-level  DEBUG, INFO, WARNING, or ERROR. Default: INFO.

Stop the proxy with Ctrl+C.


FIREFOX CONFIGURATION
---------------------
1. Open Firefox and go to Settings (about:preferences).
2. Scroll down to "Network Settings" and click "Settings...".
3. Select "Manual proxy configuration".
4. In the "SOCKS Host" field enter:   ::1
   In the "Port" field enter:          1080
5. Select "SOCKS v5".
6. Check "Proxy DNS when using SOCKS v5" so that domain resolution
   also goes through the proxy (ensuring AAAA-only lookups).
7. Leave HTTP/HTTPS/FTP proxy fields empty.
8. Click OK.

Alternatively, set the following in about:config:

    network.proxy.type            = 1
    network.proxy.socks           = ::1
    network.proxy.socks_port      = 1080
    network.proxy.socks_version   = 5
    network.proxy.socks_remote_dns = true


TESTING
-------
Verify the proxy is running:

    curl -6 --socks5-hostname [::1]:1080 https://ipv6.google.com

This should succeed. An IPv4-only site will be refused:

    curl --socks5-hostname [::1]:1080 https://ipv4only.example.com
    # Expected: connection refused / address type not supported


LOGGING
-------
All connections are logged to stderr with timestamps:

    2026-03-14 12:00:00 [INFO] New connection from ('::1', 54321, 0, 0)
    2026-03-14 12:00:00 [INFO] Resolved example.com -> 2606:2800:21f:cb07:6820:80da:af6b:8b2c
    2026-03-14 12:00:00 [INFO] Tunnel established: ('::1', 54321, 0, 0) <-> [2606:...]:443
    2026-03-14 12:00:00 [WARNING] Rejected IPv4 destination 93.184.216.34 from ('::1', 54322, 0, 0)
    2026-03-14 12:00:00 [WARNING] No IPv6 (AAAA) record for v4only.example.com, rejecting


ARCHITECTURE
------------
- Built with Python asyncio for efficient concurrent connection handling.
- Each client connection spawns two tasks for bidirectional data piping.
- No threads, no external dependencies.
- Authentication: only "no auth" (0x00) is supported, which is standard
  for local/trusted-network usage.


LIMITATIONS
-----------
- Only the CONNECT command is supported (no BIND or UDP ASSOCIATE).
- No authentication methods beyond "no auth".
- The proxy must run on a host with IPv6 connectivity to the internet.
- Sites that only have A (IPv4) DNS records will be unreachable by design
