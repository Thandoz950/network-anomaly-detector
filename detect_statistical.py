import pandas as pd
import numpy as np

df = pd.read_csv('/home/thando/network-anomaly-detector/features.csv')

print("=== Statistical Anomaly Detection ===\n")

# Calculate mean and standard deviation for packet size and TTL
size_mean = df['size'].mean()
size_std = df['size'].std()
ttl_mean = df['ttl'].mean()
ttl_std = df['ttl'].std()

print(f"Baseline packet size: {size_mean:.1f} bytes (std: {size_std:.1f})")
print(f"Baseline TTL: {ttl_mean:.1f} (std: {ttl_std:.1f})\n")

# Flag anomalies — anything beyond 2 standard deviations
anomalies = df[
    (df['size'] > size_mean + 2 * size_std) |
    (df['size'] < size_mean - 2 * size_std) |
    (df['ttl'] > ttl_mean + 2 * ttl_std) |
    (df['ttl'] < ttl_mean - 2 * ttl_std)
].copy()

# Assign severity
def assign_severity(row):
    if row['size'] > size_mean + 3 * size_std:
        return "HIGH"
    elif row['size'] > size_mean + 2 * size_std:
        return "MEDIUM"
    elif row['ttl'] < ttl_mean - 2 * ttl_std:
        return "MEDIUM"
    else:
        return "LOW"

anomalies['severity'] = anomalies.apply(assign_severity, axis=1)

print(f"=== Anomalies Detected: {len(anomalies)} ===\n")
print(anomalies[['src_ip', 'dst_ip', 'protocol', 'size', 'ttl', 'severity']].to_string())

# Save anomalies
anomalies.to_csv('/home/thando/network-anomaly-detector/anomalies_statistical.csv', index=False)
print("\n=== Saved to anomalies_statistical.csv ===")
