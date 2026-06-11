from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
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

        print(f"[{proto}] {src:>15} → {dst:<15} | {port_info:<25} | {size} bytes")

print("=== Starting capture (100 packets) ===")
sniff(prn=process_packet, store=False, count=100)
print("=== Capture complete ===")
