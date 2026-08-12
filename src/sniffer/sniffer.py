import socket
import struct
import sys

def unpack_ethernet_frame(data):
    """Unpacks the 14-byte Ethernet header."""
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    # struct.unpack with '!' (network byte order) already decodes proto
    # into a correct host-native int -- applying socket.htons() again
    # here would double-convert it (e.g. 0x0800 -> 8 instead of 2048).
    return format_mac(dest_mac), format_mac(src_mac), proto, data[14:]

def format_mac(bytes_addr):
    """Converts raw bytes to a human-readable MAC address."""
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def unpack_ipv4_packet(data):
    """Unpacks the IPv4 header."""
    version_and_header_length = data[0]
    version = version_and_header_length >> 4
    header_length = (version_and_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, format_ip(src), format_ip(target), data[header_length:]

def format_ip(bytes_addr):
    """Converts raw bytes to a human-readable IPv4 address."""
    return '.'.join(map(str, bytes_addr))

def main():
    # Create a raw socket to capture all network traffic (Linux specific)
    # For Windows, sniffing requires binding to a specific interface and calling IOCTL
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError:
        print("Error: You must run this script with root/administrator privileges.")
        sys.exit(1)

    print("Listening for incoming packets...")
    
    try:
        while True:
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, payload = unpack_ethernet_frame(raw_data)
            
            # 0x0800 is the EtherType for IPv4 (network byte order handled
            # by struct.unpack's '!' prefix during decoding)
            if eth_proto == 0x0800:
                version, header_length, ttl, proto, src_ip, target_ip, data = unpack_ipv4_packet(payload)
                print(f"\n[+] IPv4 Packet: {src_ip} -> {target_ip}")
                print(f"    |- Ethernet Frame: MAC Src: {src_mac} | MAC Dst: {dest_mac}")
                print(f"    |- Protocol: {proto} | TTL: {ttl}")
    except KeyboardInterrupt:
        print("\nStopping sniffer.")

if __name__ == '__main__':
    main()
