"""
Arrowstack Task 2
Network Traffic Packet Inspection & Analysis with Wireshark

Reads a PCAP/PCAPNG captured from an authorized lab/own machine,
summarizes protocols/IPs/ports and creates simple charts.
"""

import argparse
from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, DNS


def get_ip(packet):
    if IP in packet:
        return packet[IP].src, packet[IP].dst
    if IPv6 in packet:
        return packet[IPv6].src, packet[IPv6].dst
    return None, None


def protocol_name(packet):
    if TCP in packet:
        return "TCP"
    if UDP in packet:
        return "UDP"
    if ICMP in packet:
        return "ICMP"
    if DNS in packet:
        return "DNS"
    return packet.lastlayer().name if packet.lastlayer() else "Other"


def analyze(pcap_path: str, output_dir: str):
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    packets = rdpcap(pcap_path)

    protocols = Counter()
    sources = Counter()
    destinations = Counter()
    ports = Counter()
    dns_count = 0
    tcp_count = 0
    udp_count = 0
    icmp_count = 0

    rows = []

    for pkt in packets:
        proto = protocol_name(pkt)
        protocols[proto] += 1

        src, dst = get_ip(pkt)
        if src:
            sources[src] += 1
        if dst:
            destinations[dst] += 1

        if TCP in pkt:
            tcp_count += 1
            ports[f"TCP/{pkt[TCP].dport}"] += 1

        if UDP in pkt:
            udp_count += 1
            ports[f"UDP/{pkt[UDP].dport}"] += 1

        if ICMP in pkt:
            icmp_count += 1

        if DNS in pkt:
            dns_count += 1

        rows.append({
            "src": src or "",
            "dst": dst or "",
            "protocol": proto,
            "length": len(pkt)
        })

    df = pd.DataFrame(rows)
    df.to_csv(out / "packet_summary.csv", index=False)

    summary = pd.DataFrame(
        protocols.items(), columns=["protocol", "packet_count"]
    ).sort_values("packet_count", ascending=False)
    summary.to_csv(out / "protocol_summary.csv", index=False)

    top_ips = pd.DataFrame(
        sources.items(), columns=["source_ip", "packet_count"]
    ).sort_values("packet_count", ascending=False).head(10)
    top_ips.to_csv(out / "top_source_ips.csv", index=False)

    with open(out / "summary.txt", "w", encoding="utf-8") as f:
        f.write(f"Total packets: {len(packets)}\n")
        f.write(f"TCP packets: {tcp_count}\n")
        f.write(f"UDP packets: {udp_count}\n")
        f.write(f"ICMP packets: {icmp_count}\n")
        f.write(f"DNS packets: {dns_count}\n\n")
        f.write("Protocol counts:\n")
        for proto, count in protocols.most_common():
            f.write(f"  {proto}: {count}\n")

    if not summary.empty:
        plt.figure(figsize=(8, 5))
        plt.bar(summary["protocol"], summary["packet_count"])
        plt.title("Protocol Distribution")
        plt.xlabel("Protocol")
        plt.ylabel("Packet Count")
        plt.tight_layout()
        plt.savefig(out / "protocol_distribution.png", dpi=150)
        plt.close()

    if not top_ips.empty:
        plt.figure(figsize=(9, 5))
        plt.bar(top_ips["source_ip"].astype(str), top_ips["packet_count"])
        plt.title("Top Source IPs by Packet Count")
        plt.xlabel("Source IP")
        plt.ylabel("Packet Count")
        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()
        plt.savefig(out / "top_source_ips.png", dpi=150)
        plt.close()

    print("Analysis complete.")
    print(f"Packets analyzed: {len(packets)}")
    print(f"Results saved to: {out.resolve()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", help="Path to .pcap or .pcapng file")
    parser.add_argument("--out", default="results", help="Output directory")
    args = parser.parse_args()
    analyze(args.pcap, args.out)
