# foxsniff

> A minimal, dependency-free IPv4 packet sniffer for Linux, built directly on Python raw sockets.

[![Python](https://img.shields.io/badge/Python-%3E%3D3.8-blue?logo=python)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange?logo=linux)](https://www.kernel.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**foxsniff** is a small educational packet sniffer that captures Ethernet frames using Linux raw sockets and manually parses Ethernet and IPv4 headers using only Python's standard library.

It intentionally avoids `libpcap`, Scapy, and other packet-capture frameworks so that the mechanics of packet capture and protocol parsing remain visible and easy to understand.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [How It Works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
  - [Install from PyPI](#install-from-pypi)
  - [Install from Source](#install-from-source)
  - [Development Installation](#development-installation)
- [Usage](#usage)
- [Example Output](#example-output)
- [Packet Parsing](#packet-parsing)
  - [Ethernet](#ethernet)
  - [IPv4](#ipv4)
  - [Protocol Numbers](#protocol-numbers)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [Architecture](#architecture)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [Security and Responsible Use](#security-and-responsible-use)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

Traditional packet-analysis tools often hide low-level packet handling behind mature libraries.

foxsniff takes the opposite approach.

It opens a Linux `AF_PACKET` raw socket, receives raw Ethernet frames, parses the Ethernet header, filters for IPv4 traffic, and then parses the IPv4 header directly with `struct.unpack()`.

The result is a compact codebase that is useful for:

- Learning how Ethernet frames are structured
- Understanding IPv4 header fields
- Learning Python's `socket` and `struct` modules
- Experimenting with raw sockets
- Building a foundation for a more capable packet analyzer
- Exploring networking concepts without external dependencies

### What foxsniff currently captures

```text
Ethernet frame
    │
    ├── Destination MAC
    ├── Source MAC
    └── EtherType
             │
             └── IPv4 (0x0800)
                    │
                    ├── Version
                    ├── Header Length
                    ├── TTL
                    ├── Protocol
                    ├── Source IP
                    └── Destination IP
```

foxsniff currently reports IPv4 packet metadata rather than attempting to fully decode the transport-layer payload.

---

## Features

- **Raw packet capture** using Linux `AF_PACKET`
- **Ethernet header parsing**
- **IPv4 header parsing**
- **Variable-length IPv4 header support** through the IHL field
- **MAC address formatting**
- **IPv4 address formatting**
- **Protocol number reporting**
- **TTL reporting**
- **Zero third-party runtime dependencies**
- **Small, readable implementation**
- **Command-line entry point**
- **Python 3.8+ support**
- **MIT licensed**

---

## How It Works

foxsniff operates at the Ethernet layer and works upward through the IPv4 header.

### 1. Create a raw socket

The program creates a Linux packet socket:

```python
socket.socket(
    socket.AF_PACKET,
    socket.SOCK_RAW,
    socket.ntohs(3)
)
```

`AF_PACKET` provides access to packets at the link layer and is specific to Linux.

Because raw packet sockets require elevated privileges, foxsniff normally needs to be executed with `sudo`.

### 2. Receive a frame

The sniffer waits for incoming frames:

```python
raw_data, addr = conn.recvfrom(65536)
```

The returned data contains the raw bytes of the captured frame.

### 3. Parse the Ethernet header

The first 14 bytes are interpreted as:

```text
6 bytes   Destination MAC
6 bytes   Source MAC
2 bytes   EtherType
```

foxsniff uses network byte order (`!`) with Python's `struct` module.

IPv4 frames have an EtherType of:

```text
0x0800
```

Only frames with this EtherType are passed to the IPv4 parser.

### 4. Parse the IPv4 header

The IPv4 parser extracts:

- IP version
- Internet Header Length (IHL)
- TTL
- Protocol
- Source address
- Destination address

The IHL value is used to determine where the IPv4 payload begins, allowing the parser to account for IPv4 header options.

### 5. Display the result

The extracted information is printed to the terminal in a compact, human-readable format.

---

## Requirements

### Operating system

**Linux is required.**

foxsniff relies on:

```python
socket.AF_PACKET
```

which is a Linux-specific packet-capture interface.

It is not currently a portable Windows or macOS packet sniffer.

### Python

Python **3.8 or newer** is required.

### Runtime dependencies

None.

foxsniff uses Python standard-library modules such as:

- `socket`
- `struct`
- `sys`

### Privileges

Raw packet sockets generally require elevated privileges.

Run the program with:

```bash
sudo foxsniff
```

---

## Installation

### Install from PyPI

If a published package is available:

```bash
python3 -m pip install foxsniff
```

Then run:

```bash
sudo foxsniff
```

### Install from Source

Clone the repository:

```bash
git clone https://github.com/foxhackerzdevs/foxsniff.git
cd foxsniff
```

Install it:

```bash
python3 -m pip install .
```

Run:

```bash
sudo foxsniff
```

### Development Installation

For local development, install the package in editable mode:

```bash
python3 -m pip install -e .
```

This allows changes to the source tree to be reflected without reinstalling the package.

---

## Usage

Start the sniffer with:

```bash
sudo foxsniff
```

You should see:

```text
Listening for incoming packets...
```

foxsniff then waits for IPv4 packets.

Press:

```text
Ctrl+C
```

to stop the sniffer.

---

## Example Output

A typical capture looks like:

```text
Listening for incoming packets...

[+] IPv4 Packet: 192.0.2.1 -> 192.0.2.2
    |- Ethernet Frame: MAC Src: 02:FC:00:00:00:05 | MAC Dst: 02:FC:00:00:00:01
    |- Protocol: 6 | TTL: 60
```

### Reading the output

```text
192.0.2.1 -> 192.0.2.2
```

The source and destination IPv4 addresses.

```text
MAC Src: 02:FC:00:00:00:05
```

The Ethernet source address.

```text
MAC Dst: 02:FC:00:00:00:01
```

The Ethernet destination address.

```text
Protocol: 6
```

The IPv4 protocol field. `6` represents TCP.

```text
TTL: 60
```

The IPv4 Time To Live value.

---

## Packet Parsing

### Ethernet

foxsniff reads the standard Ethernet II header:

| Field | Size | Description |
|---|---:|---|
| Destination MAC | 6 bytes | Receiving interface MAC address |
| Source MAC | 6 bytes | Sending interface MAC address |
| EtherType | 2 bytes | Identifies the encapsulated protocol |

The parser uses:

```python
struct.unpack('! 6s 6s H', data[:14])
```

The `!` specifies network byte order.

IPv4 is identified with:

```python
0x0800
```

### IPv4

foxsniff reads the beginning of the IPv4 header and extracts:

| Field | Description |
|---|---|
| Version | IP version |
| IHL | IPv4 header length |
| TTL | Time To Live |
| Protocol | Encapsulated transport/network protocol |
| Source IP | Packet origin |
| Destination IP | Packet destination |

The IPv4 header is not always exactly 20 bytes. The IHL field specifies its length in 32-bit words.

foxsniff converts that value to bytes:

```python
header_length = (version_and_header_length & 15) * 4
```

This allows the parser to locate the IPv4 payload correctly when optional IPv4 header fields are present.

---

## Protocol Numbers

The IPv4 `Protocol` field identifies the next protocol.

Common values include:

| Number | Protocol |
|---:|---|
| `1` | ICMP |
| `6` | TCP |
| `17` | UDP |
| `41` | IPv6 |
| `47` | GRE |
| `50` | ESP |
| `51` | AH |
| `89` | OSPF |

foxsniff currently prints the numeric protocol value rather than decoding it into a protocol name.

For example:

```text
Protocol: 6
```

means TCP.

---

## Project Structure

```text
foxsniff/
├── src/
│   └── sniffer/
│       ├── __init__.py
│       └── sniffer.py
├── tests/
│   └── test_sniffer.py
├── .gitignore
├── LICENSE
├── README.md
└── pyproject.toml
```

### `src/sniffer/sniffer.py`

Contains the packet-sniffing implementation, including:

- Raw socket creation
- Ethernet frame parsing
- IPv4 packet parsing
- MAC formatting
- IP formatting
- Main capture loop

### `tests/test_sniffer.py`

Contains tests for the sniffer's parsing functionality.

### `pyproject.toml`

Defines the Python package metadata, build configuration, dependencies, and the `foxsniff` command-line entry point.

The package exposes:

```text
foxsniff -> sniffer.sniffer:main
```

### `LICENSE`

Contains the project's MIT license.

---

## Testing

Run the test suite with:

```bash
python3 -m pytest
```

If pytest is not installed in your development environment:

```bash
python3 -m pip install pytest
```

The tests are separate from the runtime package, so pytest is not required simply to run foxsniff.

---

## Architecture

foxsniff follows a deliberately simple processing pipeline:

```text
                Linux Network Interface
                          │
                          ▼
                 AF_PACKET raw socket
                          │
                          ▼
                    Raw Ethernet
                       frame
                          │
                          ▼
              ┌───────────────────────┐
              │ Ethernet parser       │
              │                       │
              │ Src MAC               │
              │ Dst MAC               │
              │ EtherType             │
              └───────────┬───────────┘
                          │
                    EtherType
                    == 0x0800
                          │
                          ▼
              ┌───────────────────────┐
              │ IPv4 parser           │
              │                       │
              │ Version               │
              │ IHL                   │
              │ TTL                   │
              │ Protocol              │
              │ Source IP             │
              │ Destination IP        │
              └───────────┬───────────┘
                          │
                          ▼
                    Terminal output
```

The design intentionally keeps protocol parsing explicit instead of delegating it to a packet-analysis library.

---

## Limitations

foxsniff is intentionally minimal and should not be considered a replacement for mature packet-analysis tools.

Current limitations include:

- Linux only
- Requires elevated privileges
- IPv4-focused
- Does not currently decode TCP headers
- Does not currently decode UDP headers
- Does not currently decode ICMP messages
- Does not display TCP/UDP ports
- Does not decode TCP flags
- Does not save packets to PCAP
- Does not provide BPF-style filtering
- Does not provide interface-selection CLI options
- Does not reconstruct connections or flows
- Does not inspect application-layer protocols
- Does not provide a graphical interface
- Does not provide packet statistics or summaries

For advanced packet analysis, tools such as Wireshark or Scapy are more appropriate.

The goal of foxsniff is simplicity and education.

---

## Troubleshooting

### `PermissionError`

If you see:

```text
Error: You must run this script with root/administrator privileges.
```

run:

```bash
sudo foxsniff
```

Raw packet sockets generally require elevated privileges.

### `AF_PACKET` is unavailable

If the socket creation fails because `AF_PACKET` is unavailable, verify that you are running Linux.

foxsniff is not currently designed for Windows or macOS.

### No packets appear

Try generating some network traffic from another terminal:

```bash
ping 1.1.1.1
```

or:

```bash
curl https://example.com
```

Then watch the foxsniff terminal for IPv4 packets.

Also verify that your system and network configuration allow the interface to expose the traffic you expect to capture.

### Stopping the sniffer

Press:

```text
Ctrl+C
```

The program catches `KeyboardInterrupt` and exits the capture loop.

---

## Security and Responsible Use

Packet sniffing provides visibility into network traffic and should be used responsibly.

Only capture traffic on systems and networks that you own or have explicit authorization to monitor.

Do not use foxsniff to intercept traffic belonging to other people, organizations, or networks without permission.

Remember that packet captures can potentially expose sensitive metadata or content depending on the protocols and traffic being observed. Treat captured information accordingly.

foxsniff is primarily intended for:

- Personal labs
- Development environments
- Networking education
- Authorized troubleshooting
- Security research in controlled environments

---

## Roadmap

Potential future improvements include:

- [ ] Human-readable protocol names
- [ ] TCP header parsing
- [ ] UDP header parsing
- [ ] ICMP parsing
- [ ] Source/destination port display
- [ ] TCP flag decoding
- [ ] Packet length and timestamp output
- [ ] Network-interface selection
- [ ] Protocol/IP/port filtering
- [ ] Optional payload inspection
- [ ] PCAP export
- [ ] Better error handling for malformed packets
- [ ] Expanded unit-test coverage
- [ ] IPv6 support
- [ ] Command-line configuration options

These features are intentionally outside the scope of the current minimal implementation but provide natural directions for extending the project.

---

## Contributing

Contributions are welcome.

A typical development workflow is:

```bash
git clone https://github.com/foxhackerzdevs/foxsniff.git
cd foxsniff
python3 -m pip install -e .
```

Before submitting a change:

1. Keep the implementation small and readable.
2. Add or update tests where appropriate.
3. Avoid introducing unnecessary runtime dependencies.
4. Document user-visible behavior.
5. Verify that existing functionality continues to work.

For larger changes, open an issue first to discuss the proposed direction.

---

## License

foxsniff is released under the **MIT License**.

See [LICENSE](LICENSE) for the complete license text.

---

## Disclaimer

foxsniff is provided for educational, development, and authorized network-monitoring purposes.

The authors are not responsible for misuse of the software. You are responsible for ensuring that your use of foxsniff complies with applicable laws, regulations, policies, and network-authorization requirements.

---

## Project Links

- **Source:** https://github.com/foxhackerzdevs/foxsniff
- **License:** [MIT](LICENSE)

---

**Built with Python's standard library. No libpcap. No Scapy. Just raw sockets, bytes, and protocol headers.**