from scapy.all import rdpcap, IP, TCP, UDP, ICMP
import pandas as pd
import os

pcap_path = os.path.expanduser("~/network-anomaly-detector/traffic_sample.pcap")
packets = rdpcap(pcap_path)

print(f"=== Loaded {len(packets)} packets ===\n")

rows = []

for packet in packets:
    if IP in packet:
        row = {
            "timestamp": float(packet.time),
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "ttl": packet[IP].ttl,
            "size": len(packet),
            "protocol": "OTHER",
            "src_port": 0,
            "dst_port": 0
        }

        if TCP in packet:
            row["protocol"] = "TCP"
            row["src_port"] = packet[TCP].sport
            row["dst_port"] = packet[TCP].dport
        elif UDP in packet:
            row["protocol"] = "UDP"
            row["src_port"] = packet[UDP].sport
            row["dst_port"] = packet[UDP].dport
        elif ICMP in packet:
            row["protocol"] = "ICMP"

        rows.append(row)

df = pd.DataFrame(rows)

print(df.to_string())
print(f"\n=== Total IP packets extracted: {len(df)} ===")

csv_path = os.path.expanduser("~/network-anomaly-detector/features.csv")
df.to_csv(csv_path, index=False)
print(f"=== Saved to features.csv ===")
