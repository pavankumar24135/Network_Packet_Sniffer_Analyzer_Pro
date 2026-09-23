# Network Packet Sniffer & Real-Time Traffic Analyzer — Pro Version

## Added features

- Real-time packet capture using Scapy
- TCP, UDP, DNS, ICMP, ARP, IPv4 and IPv6 recognition
- Source/destination IP
- Source/destination ports
- TCP flags
- Packet size and network layer
- Protocol distribution dashboard
- Protocol dropdown filter
- IP/port search
- Click any packet for detailed JSON information
- Export up to 1000 captured packets to CSV
- Start / Stop / Clear controls

## Run

```bash
pip install -r requirements.txt
python app.py
```

Open:

`http://127.0.0.1:5000`

On Windows, Npcap is required for packet capture.

## Important

Only capture traffic on systems/networks you are authorized to monitor.
