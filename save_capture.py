from scapy.all import sniff, wrpcap
import os

save_path = os.path.expanduser("~/network-anomaly-detector/traffic_sample.pcap")

print("=== Capturing 200 packets and saving to file ===")
packets = sniff(count=200)
wrpcap(save_path, packets)
print(f"=== Saved to {save_path} ===")
