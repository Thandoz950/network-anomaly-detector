import pandas as pd

df = pd.read_csv('/home/thando/network-anomaly-detector/features.csv')

print("=== Protocol Distribution ===")
print(df['protocol'].value_counts())

print("\n=== Packet Size Statistics ===")
print(df['size'].describe())

print("\n=== Top 5 Source IPs ===")
print(df['src_ip'].value_counts().head())

print("\n=== Top 5 Destination Ports ===")
print(df['dst_port'].value_counts().head())

print("\n=== TTL Statistics ===")
print(df['ttl'].describe())
