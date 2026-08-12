# foxsniff

**Minimal raw-socket IPv4 packet sniffer for Linux.** No dependencies, no BPF filter syntax to learn — just a small, readable script that unpacks Ethernet and IPv4 headers by hand.

## Install

```bash
pip install foxsniff
```

Or from source:
```bash
git clone https://github.com/foxhackerzdevs/foxsniff.git
cd foxsniff
pip install -e .
```

## Usage

Requires root (raw sockets):
```bash
sudo foxsniff
```
```
Listening for incoming packets...

[+] IPv4 Packet: 192.0.2.1 -> 192.0.2.2
    |- Ethernet Frame: MAC Src: 02:FC:00:00:00:05 | MAC Dst: 02:FC:00:00:00:01
    |- Protocol: 6 | TTL: 60
```

Ctrl+C to stop.

## How it works

Opens an `AF_PACKET`/`SOCK_RAW` socket (Linux-specific) and manually unpacks each captured frame:

- **Ethernet header** (14 bytes): destination MAC, source MAC, EtherType — filters for `0x0800` (IPv4)
- **IPv4 header** (first 20 bytes, correctly handling variable-length headers with options via IHL): TTL, protocol number, source/destination IP

No `libpcap`, no `scapy` — just `socket` and `struct` from the standard library.

## Requirements

Python >= 3.8, Linux (uses `AF_PACKET`, not portable to other platforms — see the note in `main()`).

## License

MIT
