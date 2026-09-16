# mdns-scanner

High-performance mDNS Protocol Asset Reconnaissance & Mapping CLI Tool.

## Overview
A lightweight and high-concurrency CLI tool built with Go for scanning and mapping mDNS (Multicast DNS / Unicast DNS-SD) assets across specified CIDR network ranges and port lists.

## Features
- **CIDR & Multi-Port Scanning**: Support for single IPs, CIDR blocks (e.g. `192.168.1.0/24`), and custom port ranges.
- **Deep Banner & Metadata Extraction**: Parses PTR, SRV, TXT, A, AAAA records to extract device models, firmware versions, hostnames, TTL, and exposed services.
- **High Concurrency & Low Latency**: Worker-pool architecture with adaptive timeout handling.
- **Structured Output**: Clean terminal representation aligned with asset mapping standards.
