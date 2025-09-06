#!/usr/bin/env python3
"""
Net Inspector — Scapy-based packet analyzer for quick SOC-style triage.

Highlights:
- Parse a PCAP (or do a short live capture) and summarize:
  * Top talkers (by bytes and flows)
  * RDP (3389) and SMB (445) activity
  * Possible brute-force or scanning (elevated SYN-to-ACK ratios)
  * DNS queries (top queried names)
- Export CSV summaries if needed

Use ONLY on networks you own or are authorized to test.
Requires: scapy (pip install scapy)
"""
import argparse
import csv
from collections import Counter, defaultdict
from datetime import datetime
import ipaddress

from scapy.all import (
    PcapReader,
    sniff,
    TCP,
    UDP,
    IP,
    IPv6,
    DNS,
    DNSQR,
    Raw,
)

def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def fmt_ip(ip):
    return ip if ip else "?"

def parse_args():
    p = argparse.ArgumentParser(description="Scapy packet triage for RDP/SMB/DNS and top talkers")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", help="Path to PCAP file to parse")
    src.add_argument("--iface", help="Interface to sniff live (e.g., eth0, Wi-Fi)")
    p.add_argument("--seconds", type=int, default=20, help="Live sniff duration (seconds) if --iface is set")
    p.add_argument("--filter", default="tcp or udp", help="BPF filter for live capture (default: tcp or udp)")
    p.add_argument("--csv", help="CSV prefix to export summaries (e.g., results)")
    p.add_argument("--rdp-threshold", type=int, default=30, help="Flag if RDP SYNs per source exceed this count")
    p.add_argument("--syn-ratio-threshold", type=float, default=5.0, help="Flag if SYN:ACK ratio exceeds this value")
    return p.parse_args()

class Stats:
    def __init__(self):
        # traffic
        self.bytes_by_flow = Counter()     # (src, dst) -> bytes
        self.flows_by_host = Counter()     # ip -> unique peers
        self.peer_sets = defaultdict(set)  # ip -> {peers}
        # protocols
        self.tcp_dport_counter = Counter()
        self.udp_dport_counter = Counter()
        # RDP/SMB
        self.rdp_syns_by_src = Counter()
        self.rdp_acks_by_src = Counter()
        self.smb_syns_by_src = Counter()
        self.smb_acks_by_src = Counter()
        # SYN/ACK ratios overall
        self.syns_by_src = Counter()
        self.acks_by_src = Counter()
        # DNS
        self.dns_queries = Counter()
        # timing
        self.first_ts = None
        self.last_ts = None
        # packets counted
        self.total = 0

    def update_time(self, ts):
        if self.first_ts is None:
            self.first_ts = ts
        self.last_ts = ts

    def duration(self):
        if self.first_ts and self.last_ts:
            return max(0.0, self.last_ts - self.first_ts)
        return 0.0

def handle_pkt(pkt, st: Stats):
    st.total += 1
    if hasattr(pkt, "time"):
        st.update_time(pkt.time)

    ip_src = ip_dst = None
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        size = len(pkt[IP])
    elif IPv6 in pkt:
        ip_src = pkt[IPv6].src
        ip_dst = pkt[IPv6].dst
        size = len(pkt[IPv6])
    else:
        return

    # traffic accounting
    st.bytes_by_flow[(ip_src, ip_dst)] += size
    st.peer_sets[ip_src].add(ip_dst)
    st.peer_sets[ip_dst].add(ip_src)

    # TCP/UDP specifics
    if TCP in pkt:
        dport = pkt[TCP].dport
        flags = pkt[TCP].flags
        st.tcp_dport_counter[dport] += 1

        # Track SYN vs ACK (basic scan/brute-force heuristic)
        syn = flags & 0x02 != 0
        ack = flags & 0x10 != 0
        if syn and not ack:
            st.syns_by_src[ip_src] += 1
            if dport == 3389:
                st.rdp_syns_by_src[ip_src] += 1
            if dport == 445:
                st.smb_syns_by_src[ip_src] += 1
        if ack:
            st.acks_by_src[ip_src] += 1
            if dport == 3389:
                st.rdp_acks_by_src[ip_src] += 1
            if dport == 445:
                st.smb_acks_by_src[ip_src] += 1

    elif UDP in pkt:
        dport = pkt[UDP].dport
        st.udp_dport_counter[dport] += 1

        # DNS
        if dport == 53 and DNS in pkt and pkt[DNS].qdcount > 0 and DNSQR in pkt:
            try:
                qname = pkt[DNS][DNSQR].qname.decode(errors="ignore").rstrip(".")
                if qname:
                    st.dns_queries[qname] += 1
            except Exception:
                pass

def summarize(st: Stats, args):
    # finalize flows_by_host
    for host, peers in st.peer_sets.items():
        st.flows_by_host[host] = len(peers)

    print("\n=== Capture Summary ===")
    print(f"Packets: {st.total}")
    dur = st.duration()
    if dur:
        print(f"Duration: {dur:.1f}s  (~{st.total/max(1.0,dur):.1f} pkts/s)")
    if st.first_ts:
        print("First packet:", datetime.fromtimestamp(st.first_ts))
    if st.last_ts:
        print("Last packet: ", datetime.fromtimestamp(st.last_ts))

    # Top talkers (by bytes)
    print("\nTop talkers (by bytes):")
    for (src, dst), b in st.bytes_by_flow.most_common(10):
        print(f"  {fmt_ip(src)} → {fmt_ip(dst)} : {b} bytes")

    # Hosts with most peers (fan-out)
    print("\nHosts with most unique peers:")
    for host, peers in st.flows_by_host.most_common(10):
        print(f"  {fmt_ip(host)} : {peers} peers")

    # Ports
    def top(counter, n=8):
        return ", ".join([f"{p}({c})" for p, c in counter.most_common(n)]) or "none"

    print("\nTop TCP dports:", top(st.tcp_dport_counter))
    print("Top UDP dports:", top(st.udp_dport_counter))

    # RDP/SMB focus
    print("\nRDP activity (SYNs by source):")
    flagged_rdp = []
    for src, syns in st.rdp_syns_by_src.most_common(10):
        acks = st.rdp_acks_by_src[src]
        ratio = syns / max(1, acks)
        flag = syns >= args.rdp_threshold or ratio >= args.syn_ratio_threshold
        print(f"  {src}  SYNs={syns}  ACKs={acks}  SYN:ACK={ratio:.1f}" + ("  [FLAG]" if flag else ""))
        if flag:
            flagged_rdp.append((src, syns, acks, ratio))

    print("\nSMB activity (SYNs by source):")
    for src, syns in st.smb_syns_by_src.most_common(10):
        acks = st.smb_acks_by_src[src]
        ratio = syns / max(1, acks)
        print(f"  {src}  SYNs={syns}  ACKs={acks}  SYN:ACK={ratio:.1f}")

    # SYN anomaly across all TCP
    print("\nPossible scanning sources (high SYN:ACK ratio):")
    suspects = []
    for src, syns in st.syns_by_src.most_common(20):
        acks = st.acks_by_src[src]
        ratio = syns / max(1, acks)
        if syns >= 30 and ratio >= args.syn_ratio_threshold:
            suspects.append((src, syns, acks, ratio))
    if suspects:
        for src, syns, acks, ratio in suspects:
            print(f"  {src}  SYNs={syns}  ACKs={acks}  SYN:ACK={ratio:.1f}  [FLAG]")
    else:
        print("  none")

    # DNS
    print("\nTop DNS queries:")
    for q, c in st.dns_queries.most_common(10):
        print(f"  {q} ({c})")

    # CSV exports
    if args.csv:
        export_csv(st, args.csv, flagged_rdp, suspects)

def export_csv(st: Stats, prefix, flagged_rdp, suspects):
    # bytes_by_flow
    with open(f"{prefix}_flows.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["src", "dst", "bytes"])
        for (src, dst), b in st.bytes_by_flow.most_common():
            w.writerow([src, dst, b])

    # rdp flags
    with open(f"{prefix}_rdp_flags.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["src", "rdp_syns", "rdp_acks", "syn_ack_ratio"])
        for src, syns, acks, ratio in flagged_rdp:
            w.writerow([src, syns, acks, f"{ratio:.2f}"])

    # syn scan suspects
    with open(f"{prefix}_syn_suspects.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["src", "syns", "acks", "syn_ack_ratio"])
        for src, syns, acks, ratio in suspects:
            w.writerow([src, syns, acks, f"{ratio:.2f}"])

    # dns
    with open(f"{prefix}_dns.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["qname", "count"])
        for q, c in st.dns_queries.most_common():
            w.writerow([q, c])

    print(f"\nCSV exported with prefix: {prefix}_*.csv")

def analyze_pcap(path, args):
    st = Stats()
    with PcapReader(path) as pr:
        for pkt in pr:
            try:
                handle_pkt(pkt, st)
            except Exception:
                continue
    summarize(st, args)

def live_sniff(iface, seconds, bpf, args):
    st = Stats()
    print(f"[*] Sniffing {seconds}s on {iface} with filter: {bpf}")
    def cb(pkt):
        try:
            handle_pkt(pkt, st)
        except Exception:
            pass
    sniff(iface=iface, filter=bpf, prn=cb, store=False, timeout=seconds)
    summarize(st, args)

def main():
    args = parse_args()
    if args.pcap:
        analyze_pcap(args.pcap, args)
    else:
        live_sniff(args.iface, args.seconds, args.filter, args)

if __name__ == "__main__":
    main()
