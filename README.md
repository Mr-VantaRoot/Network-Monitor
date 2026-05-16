# 📡 Python Network Traffic Monitor

A real-time network packet capture and analysis tool built with pure Python. Monitors live traffic on your machine, decodes TCP/UDP/ICMP packets, identifies services, and displays a traffic summary — no third-party libraries required.

---

## Features

- **Real-time packet capture** — monitors live network traffic as it happens
- **Protocol detection** — identifies TCP, UDP, and ICMP packets
- **Service recognition** — maps ports to known services (HTTP, DNS, SSH, etc.)
- **Protocol filter** — focus on a specific protocol only
- **Traffic summary** — displays a breakdown of captured packets on exit
- **Cross-platform** — works on Windows and Linux/Mac
- **No external libraries** — pure Python standard library only

---

## Requirements

- Python 3.6+
- Administrator (Windows) or root (Linux/Mac) privileges
- No pip installs needed

---

## Usage

### Capture all traffic (unlimited)
```bash
# Windows — run as Administrator
python network_monitor.py

# Linux / Mac
sudo python network_monitor.py
```

### Capture a fixed number of packets
```bash
python network_monitor.py -n 100
```

### Filter by protocol
```bash
python network_monitor.py -f TCP
python network_monitor.py -f UDP
python network_monitor.py -f ICMP
```

### Combine options
```bash
sudo python network_monitor.py -n 50 -f TCP
```

Press `Ctrl+C` at any time to stop and view the summary.

---

## Example Output

```
[*] Capturing packets... (Ctrl+C to stop)

  TIME       PROTO  SOURCE                 DESTINATION            SERVICE
---------------------------------------------------------------------------
  10:32:01   TCP    192.168.6.105:52341    142.250.4.100:443      HTTPS
  10:32:01   UDP    192.168.6.105:49152    8.8.8.8:53             DNS
  10:32:02   TCP    192.168.6.1:80         192.168.6.105:50210    HTTP
  10:32:03   ICMP   192.168.6.1            192.168.6.105

[*] Capture stopped.

========================================
  TRAFFIC SUMMARY
========================================
  TCP       142 packets  ████████████████
  UDP        38 packets  ████
  ICMP        5 packets  █

  Total: 185 packets captured
========================================
```

---

## How It Works

1. **Raw Socket** — opens a raw socket to intercept all incoming/outgoing packets at the network layer
2. **IP Header Parsing** — unpacks the IP header to extract source/destination IPs and protocol number
3. **TCP/UDP Parsing** — extracts port numbers from the transport layer header
4. **Service Mapping** — matches port numbers against a dictionary of well-known services
5. **Live Display** — prints each packet in real time with timestamp, protocol, addresses, and service
6. **Summary** — on exit, prints a count and visual bar chart per protocol

---

## Supported Services

| Port | Service | Port | Service  |
|------|---------|------|----------|
| 22   | SSH     | 443  | HTTPS    |
| 25   | SMTP    | 3306 | MySQL    |
| 53   | DNS     | 3389 | RDP      |
| 80   | HTTP    | 8080 | HTTP-Alt |
| 110  | POP3    | 21   | FTP      |

---

## Why Root/Admin is Required

Raw socket access requires elevated privileges on all operating systems — this is the same reason tools like Wireshark ask for admin rights. The tool only reads packet headers and does not modify, inject, or interfere with any traffic.

---

## Disclaimer

This tool is intended for **educational purposes** and should only be used to monitor **your own network or devices you have permission to monitor**. Unauthorized interception of network traffic may be illegal in your jurisdiction.

---

## License

MIT License — free to use and modify.
