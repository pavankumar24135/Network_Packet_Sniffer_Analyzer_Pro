from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, DNS, ARP, Ether
from datetime import datetime
from collections import Counter
import threading

class PacketSniffer:
    def __init__(self):
        self.running = False
        self.lock = threading.Lock()
        self.packets = []
        self.protocols = Counter()
        self.total_bytes = 0
        self.started_at = None

    def process_packet(self, packet):
        if not self.running:
            return

        timestamp = datetime.now().strftime("%H:%M:%S")
        src = "N/A"
        dst = "N/A"
        protocol = "OTHER"
        sport = "-"
        dport = "-"
        flags = "-"
        network = "N/A"

        if ARP in packet:
            protocol = "ARP"
            src = packet[ARP].psrc or "N/A"
            dst = packet[ARP].pdst or "N/A"
            network = "ARP"
        elif IP in packet:
            network = "IPv4"
            src = packet[IP].src
            dst = packet[IP].dst
            if TCP in packet:
                protocol = "TCP"
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                flags = str(packet[TCP].flags)
            elif UDP in packet:
                if DNS in packet:
                    protocol = "DNS"
                else:
                    protocol = "UDP"
                sport = packet[UDP].sport
                dport = packet[UDP].dport
            elif ICMP in packet:
                protocol = "ICMP"
        elif IPv6 in packet:
            network = "IPv6"
            src = packet[IPv6].src
            dst = packet[IPv6].dst
            if TCP in packet:
                protocol = "TCP"
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                flags = str(packet[TCP].flags)
            elif UDP in packet:
                protocol = "DNS" if DNS in packet else "UDP"
                sport = packet[UDP].sport
                dport = packet[UDP].dport

        info = {
            "id": 0,
            "time": timestamp,
            "source": src,
            "destination": dst,
            "protocol": protocol,
            "network": network,
            "sport": sport,
            "dport": dport,
            "flags": flags,
            "size": len(packet)
        }

        with self.lock:
            info["id"] = len(self.packets) + 1
            self.packets.append(info)
            self.protocols[protocol] += 1
            self.total_bytes += len(packet)
            if len(self.packets) > 1000:
                removed = self.packets.pop(0)
                self.protocols[removed["protocol"]] -= 1
                if self.protocols[removed["protocol"]] <= 0:
                    del self.protocols[removed["protocol"]]

    def capture(self):
        try:
            sniff(prn=self.process_packet, store=False,
                  stop_filter=lambda p: not self.running)
        except Exception as e:
            self.running = False
            print("Capture error:", e)

    def get_packets(self, limit=100):
        with self.lock:
            return list(reversed(self.packets[-limit:]))

    def get_packet(self, packet_id):
        with self.lock:
            for p in self.packets:
                if p["id"] == packet_id:
                    return p
        return None

    def get_stats(self):
        with self.lock:
            return {
                "running": self.running,
                "total_packets": sum(self.protocols.values()),
                "total_bytes": self.total_bytes,
                "protocols": dict(self.protocols)
            }

    def clear(self):
        with self.lock:
            self.packets.clear()
            self.protocols.clear()
            self.total_bytes = 0
