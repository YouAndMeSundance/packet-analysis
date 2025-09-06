# Packet Analysis (Scapy)

Quick SOC-style triage from PCAPs or a short live capture using Scapy. Focuses on:

- Top talkers by bytes and unique peers  
- RDP (3389) and SMB (445) activity  
- Possible brute-force or scanning via SYN:ACK ratios  
- Top DNS queries  

> ⚠️ Use only on networks you own or have explicit permission to test.

---

## Requirements

- Python 3.9+  
- [Scapy](https://scapy.net/) → install with:
```bash
pip install scapy

Analyze a PCAP
python3 net_inspector.py --pcap sample.pcap

Live capture for 20s on an interface
sudo python3 net_inspector.py --iface eth0 --seconds 20 --filter "tcp or udp"

Export CSV summaries
python3 net_inspector.py --pcap sample.pcap --csv results
# creates: results_flows.csv, results_rdp_flags.csv, results_syn_suspects.csv, results_dns.csv

Tune heuristics
# Flag if a source sends >= 50 RDP SYNs or has SYN:ACK >= 6
python3 net_inspector.py --pcap sample.pcap --rdp-threshold 50 --syn-ratio-threshold 6
