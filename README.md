# mdns-scanner

<p align="left">
  <b>English</b> |
  <b><a href="README_zh.md">简体中文</a></b>
</p>

[![Go Report Card](https://goreportcard.com/badge/github.com/S-zhi/mdns-scanner)](https://goreportcard.com/report/github.com/S-zhi/mdns-scanner)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> A high-performance, concurrent mDNS (Multicast/Unicast DNS-SD) protocol reconnaissance & asset mapping CLI tool written in Go.

---

## What We Are Building

In modern network environments (LANs, cloud VPCs, and enterprise perimeters), devices such as Network Attached Storage (QNAP, Synology), smart workstations, printers, and IoT gateways advertise rich metadata about themselves via **mDNS / DNS-SD (RFC 6762 / RFC 6763)**. 

`mdns-scanner` is designed for **network surveying and asset discovery**. Given a target IP address, CIDR network block (e.g. `192.168.1.0/24`), and port specifications, it dispatches unicast mDNS discovery probes to uncover active nodes and extract deep banner fingerprints—including:
- **Service Bindings**: Service names, transport protocols, and exposed ports (`workstation:9/tcp`, `http:5000/tcp`, `smb:445/tcp`, `afpovertcp:548/tcp`, etc.).
- **Host Identifiers**: Hostnames (`*.local`), hardware MAC addresses, and resolved IPv4 / IPv6 addresses.
- **Deep Banner Fingerprints**: Complete TXT record metadata parsing (hardware model, firmware version, display model, access URLs, and web paths).
- **DNS-SD Service Catalog**: Enumerated `PTR` query answers.

---

## Key Features

- **CIDR & Multi-Port Scanning**: Support for individual IPs, CIDR blocks (e.g. `192.168.1.0/24`), and flexible port ranges (e.g. `5353`, `5000-5005`).
- **Deep Metadata & Banner Extraction**: Comprehensive parsing of `PTR`, `SRV`, `TXT`, `A`, and `AAAA` records without crashing on malformed or empty payloads.
- **Concurrent Worker Pool**: Bounded goroutine worker pool with configurable concurrency (default 100 workers) to prevent socket exhaustion and packet drops.
- **Robust Edge-Case Handling**: Built-in defensive measures for silent UDP drops, missing A records (fallback to probe IP), and multi-service aggregation.
- **Standardized Terminal & JSON Output**: Human-readable hierarchical text output matching industry survey standards, with optional JSON output support.

---

## Architecture Overview

```
 [ CLI Arguments ] -> ( CIDR & Port Parser )
                              │
                              ▼
                     [ Job Dispatcher ]
                              │
       ┌──────────────────────┼──────────────────────┐
       ▼                      ▼                      ▼
  [ Worker 1 ]           [ Worker 2 ]          [ Worker N ] (Worker Pool)
  (Unicast Probe)        (Unicast Probe)       (Unicast Probe)
       │                      │                      │
       └──────────────────────┼──────────────────────┘
                              │ (DNS Responses)
                              ▼
                     [ Aggregator & Parser ]
                  (SRV / TXT / PTR / A / AAAA)
                              │
                              ▼
                     [ Formatted Output ]
```

---

## Quick Start

### Prerequisites
- **Go**: Version 1.21 or higher installed.

### 1. Clone the Repository
```bash
git clone https://github.com/S-zhi/mdns-scanner.git
cd mdns-scanner
```

### 2. Build the Binary
```bash
go build -o mdns-scanner main.go
```

### 3. Run a Quick Scan

#### Scan a Single Host on mDNS Default Port (5353)
```bash
./mdns-scanner -i 192.168.1.120 -p 5353
```

#### Scan an Entire CIDR Subnet
```bash
./mdns-scanner -t 192.168.1.0/24 -p 5353
```

#### Scan Subnet with Custom Port Range & Concurrency
```bash
./mdns-scanner -t 192.168.1.0/24 -p 5353,5000-5005 -c 150 --timeout 3
```

---

## Command-Line Usage

```text
Usage: mdns-scanner -t <target> [-p <port>] [-c <concurrency>] [--timeout <seconds>] [--json]

Options:
  -t, --target, -i    Target IP or CIDR network block (e.g. 192.168.1.0/24 or 192.168.1.120) [Required]
  -p, --port          Target port or port range (e.g. 5353, 5000-5005) [Default: 5353]
  -c, --concurrency   Number of concurrent workers [Default: 100]
      --timeout       Probe timeout in seconds [Default: 2]
      --json          Output scan results in JSON format [Default: false]
```

---

## Output Example

When a target device (e.g., a QNAP NAS) is detected, `mdns-scanner` formats the gathered intelligence into a structured hierarchy:

```text
services:
9/tcp workstation:
Name=slw-nas [24:5e:be:69:a3:13]
IPv4=192.168.1.120
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
5000/tcp http:
Name=slw-nas
IPv4=192.168.1.120
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
path=/
445/tcp smb:
Name=slw-nas
IPv4=192.168.1.120
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
5000/tcp qdiscover:
Name=slw-nas
IPv4=192.168.1.120
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9,fwBuildNum=20260214
device-info:
Name=slw-nas(AFP)
IPv4=192.168.1.120
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
model=Xserve
548/tcp afpovertcp:
Name=slw-nas(AFP)
IPv4=192.168.1.120
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
answers:
PTR:
_workstation._tcp.local
_http._tcp.local
_smb._tcp.local
_qdiscover._tcp.local
_device-info._tcp.local
_afpovertcp._tcp.local
```

---

## Testing & Quality Assurance

The test suite incorporates data-driven, table-driven unit tests specifically targeting boundary conditions, defensive parsing, fallback mechanics, and format consistency.

### Run All Unit Tests with Coverage
```bash
go test -v -cover ./...
```

### Test Matrix & Coverage Summary

| Package | Test Scope & Edge Cases Covered | Coverage | Status |
| :--- | :--- | :---: | :---: |
| **`pkg/target`** | CIDR streaming, single IP parsing, port ranges (`5000-5005`), invalid IP/mask bounds check (`/33`), out-of-range port rejection (`70000`). | **80.7%** | `PASS` |
| **`pkg/parser`** | TXT banner parsing (QNAP metadata), zero-length/empty TXT defense, missing equals sign tags (no index out of range panic), complex query preserving, and missing A record fallback. | **78.6%** | `PASS` |
| **`pkg/output`** | Full mock QNAP NAS template validation (verifying exact fidelity of `services:`, ports, banners, `answers: PTR:`), nil-pointer defense. | **80.9%** | `PASS` |
| **`pkg/probe`** | Mock UDP mDNS engine lifecycle, non-blocking response streaming, timeout cancellation. | **79.4%** | `PASS` |

For in-depth boundary condition analysis and technical resolutions, refer to [DOCS/TEST_PLAN.md](DOCS/TEST_PLAN.md).

---

## License

This project is licensed under the MIT License.

