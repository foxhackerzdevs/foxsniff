"""
Unit tests for sniffer's packet-parsing functions, using synthetic
crafted byte sequences with known-correct expected values. These run
without root and without a real NIC.

Regression coverage: unpack_ethernet_frame used to double-apply a
byte-order conversion (struct.unpack('!H', ...) already decodes to a
correct host-native int; applying socket.htons() again on top of that
flipped 0x0800 into 8). Confirmed live against real captured traffic
during development; these tests pin the fix with synthetic data so it
doesn't require root or a real interface to verify in CI.
"""
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from sniffer.sniffer import (
    unpack_ethernet_frame, unpack_ipv4_packet, format_mac, format_ip,
)


def make_ethernet_frame(dest_mac, src_mac, ethertype, payload=b""):
    return dest_mac + src_mac + struct.pack("!H", ethertype) + payload


def make_ipv4_header(ttl, proto, src_ip, dst_ip, ihl_words=5, payload=b""):
    version_ihl = (4 << 4) | ihl_words
    dscp_ecn = 0
    total_len = ihl_words * 4 + len(payload)
    ident = 0
    flags_frag = 0
    checksum = 0  # not validated by the code under test
    header = struct.pack(
        "! B B H H H B B H 4s 4s",
        version_ihl, dscp_ecn, total_len, ident, flags_frag,
        ttl, proto, checksum, src_ip, dst_ip,
    )
    return header + payload


class TestFormatHelpers(unittest.TestCase):
    def test_format_mac(self):
        mac_bytes = bytes.fromhex("aabbccddeeff")
        self.assertEqual(format_mac(mac_bytes), "AA:BB:CC:DD:EE:FF")

    def test_format_ip(self):
        ip_bytes = bytes([192, 168, 1, 10])
        self.assertEqual(format_ip(ip_bytes), "192.168.1.10")

    def test_format_ip_edge_values(self):
        self.assertEqual(format_ip(bytes([0, 0, 0, 0])), "0.0.0.0")
        self.assertEqual(format_ip(bytes([255, 255, 255, 255])), "255.255.255.255")


class TestEthernetUnpack(unittest.TestCase):
    def test_ipv4_ethertype_decodes_correctly(self):
        # Regression check for the byte-order double-conversion bug:
        # this must come out as 0x0800 (2048), not 8.
        dest = bytes.fromhex("aabbccddeeff")
        src = bytes.fromhex("112233445566")
        frame = make_ethernet_frame(dest, src, 0x0800, payload=b"PAYLOAD")

        dest_mac, src_mac, eth_proto, payload = unpack_ethernet_frame(frame)

        self.assertEqual(eth_proto, 0x0800)
        self.assertEqual(eth_proto, 2048)
        self.assertEqual(dest_mac, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(src_mac, "11:22:33:44:55:66")
        self.assertEqual(payload, b"PAYLOAD")

    def test_arp_ethertype_decodes_correctly(self):
        dest = bytes.fromhex("ffffffffffff")
        src = bytes.fromhex("aabbccddeeff")
        frame = make_ethernet_frame(dest, src, 0x0806)  # ARP

        _, _, eth_proto, _ = unpack_ethernet_frame(frame)
        self.assertEqual(eth_proto, 0x0806)


class TestIPv4Unpack(unittest.TestCase):
    def test_basic_header_no_options(self):
        src_ip = bytes([192, 168, 1, 10])
        dst_ip = bytes([10, 0, 0, 1])
        header = make_ipv4_header(ttl=64, proto=6, src_ip=src_ip, dst_ip=dst_ip,
                                   payload=b"TCP_PAYLOAD_HERE")

        version, header_length, ttl, proto, src, target, data = unpack_ipv4_packet(header)

        self.assertEqual(version, 4)
        self.assertEqual(header_length, 20)
        self.assertEqual(ttl, 64)
        self.assertEqual(proto, 6)  # TCP
        self.assertEqual(src, "192.168.1.10")
        self.assertEqual(target, "10.0.0.1")
        self.assertEqual(data, b"TCP_PAYLOAD_HERE")

    def test_udp_protocol_number(self):
        header = make_ipv4_header(ttl=32, proto=17, src_ip=bytes([1, 1, 1, 1]),
                                   dst_ip=bytes([8, 8, 8, 8]))
        _, _, ttl, proto, src, target, _ = unpack_ipv4_packet(header)
        self.assertEqual(proto, 17)  # UDP
        self.assertEqual(ttl, 32)
        self.assertEqual(src, "1.1.1.1")
        self.assertEqual(target, "8.8.8.8")

    def test_header_with_options_ihl(self):
        # IHL=8 -> 32-byte header (20 base + 12 bytes of options)
        src_ip = bytes([172, 16, 0, 1])
        dst_ip = bytes([172, 16, 0, 2])
        header = make_ipv4_header(ttl=128, proto=6, src_ip=src_ip, dst_ip=dst_ip,
                                   ihl_words=8, payload=b"\x00" * 12 + b"REAL_PAYLOAD")

        version, header_length, ttl, proto, src, target, data = unpack_ipv4_packet(header)

        self.assertEqual(header_length, 32)
        # data should start AFTER the options, at the real payload
        self.assertEqual(data, b"REAL_PAYLOAD")


if __name__ == "__main__":
    unittest.main()
