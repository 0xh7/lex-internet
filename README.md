# lex-internet

A networking playground in **Go** and **C**. The repository contains protocol packages, small servers and clients, and low-level packet code for experimenting with the stack from Ethernet up to application protocols.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Applications (cmd/)                │
│  dns-server  http-server  ftp-server  smtp-server   │
│  ping  traceroute  proxy  firewall  nat-gateway     │
├─────────────────────────────────────────────────────┤
│              Service Packages (pkg/)                │
│  dns  http  ftp  smtp  dhcp  tls  proxy  firewall   │
├─────────────────────────────────────────────────────┤
│             Protocol Packages (pkg/)                │
│  tcp  udp  icmp  ip  ethernet  arp  nat  routing    │
├─────────────────────────────────────────────────────┤
│            C Low-Level Library (c/)                 │
│  raw_socket  packet_parser  checksum  arp           │
└─────────────────────────────────────────────────────┘
```

## Project Layout

```
lex-internet/
├── c/                      # C static library (libnetstack.a)
│   ├── arp/                # ARP request/reply + cache
│   ├── checksum/           # RFC 1071 checksums (IP, TCP, UDP)
│   ├── packet_parser/      # Ethernet/IPv4/TCP/UDP/ICMP/ARP parser
│   ├── raw_socket/         # Cross-platform raw socket abstraction
│   └── Makefile
├── cmd/                    # Runnable binaries
│   ├── arp-tool/           # ARP scanner and resolver
│   ├── dhcp-server/        # DHCP server with IP pool management
│   ├── dns-client/         # DNS lookup client (dig-like)
│   ├── dns-server/         # Authoritative + recursive DNS server
│   ├── firewall/           # Stateful packet filtering proxy
│   ├── ftp-server/         # Full FTP server (PASV, PORT, auth)
│   ├── http-client/        # HTTP/1.1 client with redirects
│   ├── http-server/        # HTTP/1.1 server with REST API demo
│   ├── nat-gateway/        # Userland NAT relay
│   ├── ping/               # ICMP ping with statistics
│   ├── proxy/              # HTTP + SOCKS5 proxy server
│   ├── smtp-server/        # SMTP server (EHLO, PIPELINING)
│   ├── tcp-client/         # TCP echo client
│   ├── tcp-server/         # TCP echo server (concurrent)
│   ├── tls-server/         # TLS-wrapped TCP server
│   ├── traceroute/         # ICMP/UDP traceroute
│   ├── udp-client/         # UDP client
│   └── udp-server/         # UDP echo server
├── pkg/                    # Reusable Go packages
│   ├── arp/                # ARP packet marshal/parse
│   ├── dhcp/               # DHCP message + server
│   ├── dns/                # Full DNS: message, zone, cache, resolver, server
│   ├── ethernet/           # Ethernet frame handling
│   ├── firewall/           # Rule engine + stateful connection tracking
│   ├── ftp/                # FTP client + server
│   ├── http/               # HTTP/1.1 client, server, router, middleware
│   ├── icmp/               # ICMP message handling
│   ├── ip/                 # IPv4 packet + checksum
│   ├── nat/                # NAT translation table
│   ├── proxy/              # HTTP proxy + SOCKS5 proxy
│   ├── routing/            # Routing table + longest-prefix match
│   ├── smtp/               # SMTP client, server, email parser
│   ├── tcp/                # TCP segment handling
│   ├── tls/                # TLS record/handshake parser + Go crypto/tls wrapper
│   └── udp/                # UDP datagram handling
├── examples/               # Example configuration files
│   ├── zones/              # DNS zone files
│   └── firewall.rules      # Firewall rule file
├── scripts/                # Build helper scripts
├── .github/workflows/      # CI pipeline
├── go.mod
└── Makefile
```

## Requirements

- **Go 1.22+**
- **C toolchain** (`gcc` + `make`) for the C library
- Raw socket tools (`ping`, `traceroute`, `arp-tool`) require **elevated privileges**

## Build

Build everything:
```bash
make verify
```

Go binaries only:
```bash
make build
```

C library only:
```bash
make c
```

Cross-compile:
```bash
make build-linux    # linux/amd64
make build-windows  # windows/amd64
```

Format Go code:
```bash
make fmt
```

Run tests only:
```bash
make test
```

## Usage Examples

### DNS Server
```bash
# Start with local zones and Google upstream
go run ./cmd/dns-server -listen :5353 -zones ./examples/zones -upstream 8.8.8.8:53

# Query it
go run ./cmd/dns-client -server 127.0.0.1:5353 -type A example.com
```

### HTTP Server
```bash
# Start with REST API and static file serving
go run ./cmd/http-server -port 8080 -dir ./examples

# Test the API
go run ./cmd/http-client -v POST http://127.0.0.1:8080/api/items '{"name":"test"}'
go run ./cmd/http-client http://127.0.0.1:8080/api/items
```

### FTP Server
```bash
go run ./cmd/ftp-server -listen :2121 -root ./data -user demo -pass secret
```

### SMTP Server
```bash
go run ./cmd/smtp-server -listen :2525 -domain mail.example.com
```

### DHCP Server
```bash
go run ./cmd/dhcp-server -listen :67 -start 192.168.1.100 -end 192.168.1.200 \
    -subnet 255.255.255.0 -gateway 192.168.1.1 -dns 8.8.8.8
```

### Proxy (HTTP or SOCKS5)
```bash
# HTTP proxy
go run ./cmd/proxy -mode http -listen :8080

# SOCKS5 with auth
go run ./cmd/proxy -mode socks5 -listen :1080 -auth user:pass
```

### Firewall
```bash
go run ./cmd/firewall -rules ./examples/firewall.rules -listen :9090 -upstream 127.0.0.1:8080
```

### NAT Gateway
```bash
go run ./cmd/nat-gateway -listen :9000 -internal 127.0.0.1:8080 -external 203.0.113.10
```

### Ping & Traceroute
```bash
# Requires admin/root
go run ./cmd/ping -c 4 google.com
go run ./cmd/traceroute -m 20 google.com
```

### TCP/UDP Echo
```bash
# Terminal 1: Start server
go run ./cmd/tcp-server -listen :9999

# Terminal 2: Connect client
go run ./cmd/tcp-client -addr 127.0.0.1:9999
```

### TLS Server
```bash
go run ./cmd/tls-server -listen :8443 -hosts localhost
```

## Protocol Implementation Details

| Layer | Package | Description |
|-------|---------|-------------|
| L2 | `pkg/ethernet` | Ethernet II frame parse/serialize, MAC address handling |
| L2 | `pkg/arp` | ARP request/reply construction |
| L3 | `pkg/ip` | IPv4 header with checksum, pseudo-header for TCP/UDP |
| L3 | `pkg/icmp` | ICMP echo request/reply, unreachable, time exceeded |
| L3 | `pkg/routing` | Routing table with longest-prefix match, metric support |
| L4 | `pkg/tcp` | TCP segment with flags, options, padding |
| L4 | `pkg/udp` | UDP datagram with auto length |
| L7 | `pkg/dns` | Full DNS: wire format, compression, zones, caching, recursive resolver |
| L7 | `pkg/http` | HTTP/1.1 with trie router, connection pooling, chunked encoding, middleware |
| L7 | `pkg/tls` | TLS 1.2 record/handshake parsing + self-signed cert generation |
| L7 | `pkg/ftp` | FTP client + server (PASV, PORT, AUTH, file ops) |
| L7 | `pkg/smtp` | SMTP client + server (EHLO, PIPELINING, 8BITMIME) |
| L7 | `pkg/dhcp` | DHCP message format + server with lease management |
| Infra | `pkg/firewall` | Stateful firewall with connection tracking, rule files |
| Infra | `pkg/nat` | NAT translation table with port allocation |
| Infra | `pkg/proxy` | HTTP CONNECT proxy + SOCKS5 proxy with auth |

## C Library

The `c/` directory builds `libnetstack.a` with:

- **checksum**: RFC 1071 one's complement sum for IP, TCP, UDP headers
- **packet_parser**: Zero-copy parsing of Ethernet, IPv4, TCP, UDP, ICMP, ARP
- **raw_socket**: Cross-platform raw socket abstraction (Linux `SO_BINDTODEVICE`, Windows Winsock2)
- **arp**: ARP request/reply over raw Ethernet with LRU cache (64 entries, 5-min TTL)

```bash
make -C c          # Build with system compiler
make -C c clean    # Clean build artifacts
```

## Contributing

If you want to contribute, read these first:

- Read `CONTRIBUTING.md` for setup, expectations, and validation steps
- Read `CODE_OF_CONDUCT.md` before opening issues or pull requests
- Read `SECURITY.md` before reporting vulnerabilities

Recommended contributor workflow:

```bash
make fmt
make test
go vet ./...
make verify
```

High-value areas for contribution:

- Add `*_test.go` coverage across `pkg/`
- Expand protocol compliance and edge-case handling
- Improve examples, docs, and cross-platform behavior

## Notes

- All Go packages use only the standard library
- The C library builds with `-Wall -Wextra -pedantic -O2`
- Raw socket tools need `CAP_NET_RAW` on Linux or Administrator on Windows
- The TLS wrapper uses Go's `crypto/tls` while exposing simplified handshake helpers
- The NAT gateway runs as a userland TCP relay without kernel packet forwarding
