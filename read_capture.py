from scapy.all import rdpcap, IP, TCP, UDP

packets = rdpcap("traffic_sample.pcap")

print(f"=== Total packets loaded: {len(packets)} ===\n")

for i, packet in enumerate(packets[:20]):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        size = len(packet)

        proto = "OTHER"
        port_info = ""

        if TCP in packet:
            proto = "TCP"
            port_info = f"{packet[TCP].sport} → {packet[TCP].dport}"
        elif UDP in packet:
            proto = "UDP"
            port_info = f"{packet[UDP].sport} → {packet[UDP].dport}"

        print(f"[{i+1:>3}] [{proto}] {src:>15} → {dst:<15} | {port_info:<25} | {size} bytes")

print("\n=== Done (showing first 20 packets) ===")
