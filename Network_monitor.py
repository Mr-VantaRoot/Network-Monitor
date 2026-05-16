import socket
import struct
import time
import threading
from datetime import datetime
from collections import defaultdict
import sys
import argparse

traffic_log = []
stats = defaultdict(int)
lock = threading.Lock()

PROTOCOLS = {
    1:  "ICMP",
    6:  "TCP",
    17: "UDP",
}

COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt",
}


def parse_ip_header(data):
    ip_header = struct.unpack("!BBHHHBBH4s4s", data[:20])
    protocol = ip_header[6]
    src_ip = socket.inet_ntoa(ip_header[8])
    dst_ip = socket.inet_ntoa(ip_header[9])
    ihl = (ip_header[0] & 0xF) * 4
    return src_ip, dst_ip, protocol, ihl


def parse_tcp_header(data, ihl):
    tcp = struct.unpack("!HHLLBBHHH", data[ihl:ihl+20])
    src_port = tcp[0]
    dst_port = tcp[1]
    return src_port, dst_port


def parse_udp_header(data, ihl):
    udp = struct.unpack("!HHHH", data[ihl:ihl+8])
    src_port = udp[0]
    dst_port = udp[1]
    return src_port, dst_port


def get_service(port):
    return COMMON_PORTS.get(port, "")


def format_packet(src_ip, dst_ip, protocol_name, src_port=None, dst_port=None):
    timestamp = datetime.now().strftime("%H:%M:%S")
    service = ""
    port_info = ""

    if src_port and dst_port:
        service = get_service(dst_port) or get_service(src_port)
        port_info = f":{src_port} → :{dst_port}"
        if service:
            port_info += f" [{service}]"

    return f"[{timestamp}] {protocol_name:<5} {src_ip}{'' if not src_port else f':{src_port}'} → {dst_ip}{'' if not dst_port else f':{dst_port}'} {f'[{service}]' if service else ''}"


def capture_packets(interface=None, packet_count=0, protocol_filter=None):
    try:
        if sys.platform == "win32":
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((socket.gethostbyname(socket.gethostname()), 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    except PermissionError:
        print("[ERROR] Run as administrator/root to capture packets.")
        sys.exit(1)

    print(f"\n[*] Capturing packets... (Ctrl+C to stop)\n")
    print(f"  {'TIME':<10} {'PROTO':<6} {'SOURCE':<22} {'DESTINATION':<22} {'SERVICE'}")
    print("-" * 75)

    count = 0
    try:
        while True:
            raw_data, _ = sock.recvfrom(65535)

            if sys.platform == "win32":
                data = raw_data
            else:
                data = raw_data[14:]

            try:
                src_ip, dst_ip, protocol, ihl = parse_ip_header(data)
            except:
                continue

            protocol_name = PROTOCOLS.get(protocol, f"OTHER({protocol})")

            if protocol_filter and protocol_name != protocol_filter.upper():
                continue

            src_port = dst_port = None

            if protocol == 6:
                try:
                    src_port, dst_port = parse_tcp_header(data, ihl)
                except:
                    pass
            elif protocol == 17:
                try:
                    src_port, dst_port = parse_udp_header(data, ihl)
                except:
                    pass

            service = ""
            if dst_port:
                service = get_service(dst_port) or get_service(src_port or 0)

            timestamp = datetime.now().strftime("%H:%M:%S")
            src_display = f"{src_ip}:{src_port}" if src_port else src_ip
            dst_display = f"{dst_ip}:{dst_port}" if dst_port else dst_ip

            print(f"  {timestamp:<10} {protocol_name:<6} {src_display:<22} {dst_display:<22} {service}")

            with lock:
                stats[protocol_name] += 1
                traffic_log.append({
                    "time": timestamp,
                    "protocol": protocol_name,
                    "src": src_display,
                    "dst": dst_display,
                    "service": service
                })

            count += 1
            if packet_count and count >= packet_count:
                break

    except KeyboardInterrupt:
        print("\n\n[*] Capture stopped.")
        print_stats()

    finally:
        if sys.platform == "win32":
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sock.close()


def print_stats():
    print("\n" + "=" * 40)
    print("  TRAFFIC SUMMARY")
    print("=" * 40)
    total = sum(stats.values())
    for proto, count in sorted(stats.items(), key=lambda x: x[1], reverse=True):
        bar = "█" * (count * 20 // total) if total else ""
        print(f"  {proto:<8} {count:>5} packets  {bar}")
    print(f"\n  Total: {total} packets captured")
    print("=" * 40)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Traffic Monitor")
    parser.add_argument("-n", "--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-f", "--filter", type=str, default=None, help="Protocol filter: TCP, UDP, ICMP")
    args = parser.parse_args()

    capture_packets(packet_count=args.count, protocol_filter=args.filter)
