# RTT Under Load — Network Parameter Analysis

Computer Networks (BCSE308L) — Digital Assignment 3
VIT Chennai | Slot: F1+TF1 | Dr. SubbuLakshmi T

**Naman Bhukar** · 24BCE5047 · B.Tech CSE

---

## Overview

This repository contains the full artifacts for my DA3 on network parameter
analysis. The parameter studied is **Round Trip Time (RTT)**, measured across
30 `iperf3` tests run against `iperf.he.net` (Hurricane Electric's public
iperf3 endpoint) under three traffic classes:

- **Low (L1–L10)** — 1 stream, light load
- **Medium (M1–M10)** — 2–3 parallel streams, rate caps, longer durations
- **High (H1–H10)** — 5–10 parallel streams or UDP floods up to 200 Mbps

Packets were captured with Wireshark and RTT samples were extracted from
TCP timestamps using a Python script (Scapy + matplotlib).

---

## Repository Structure
.
├── rtt.py                  # Main analysis script
├── pcaps/                  # All 30 packet captures (L1–L10, M1–M10, H1–H10)
├── rtt_graphs/
│   ├── per_file/           # Per-test RTT trend graphs (PNG)
│   └── summary/            # Summary bar chart, boxplot, and CSV
└── README.md

---

## How It Works

1. **Capture** — Each iperf3 run was captured in Wireshark and saved as a
   `.pcapng` file, named by traffic class (e.g. `M5.pcapng`, `H10.pcapng`).

2. **Parse** — `rtt.py` reads every pcap in the folder. For each outgoing TCP
   data segment it records `(sequence_end, timestamp)`. When the matching ACK
   arrives from the server, RTT is computed as the time difference. If a
   capture has very little data traffic, the script falls back to SYN →
   SYN-ACK handshake timing.

3. **Plot** — Per-file RTT trend graphs + summary charts (average RTT bar
   chart, traffic-class boxplot) + a CSV of all metrics.

---

## Running the Script

**Requirements:**
```bash
pip install scapy matplotlib
```

**Run:**
```bash
# Place rtt.py in the same folder as your .pcapng files
python rtt.py
```

Output goes to `rtt_graphs/per_file/` (30 trend plots) and
`rtt_graphs/summary/` (bar chart, boxplot, CSV).

---

## iperf3 Commands Used

Examples from each traffic class:

```bash
# Low traffic
iperf3 -c iperf.he.net -t 10
iperf3 -c iperf.he.net -t 10 -b 5M
iperf3 -c iperf.he.net -t 10 -l 256

# Medium traffic
iperf3 -c iperf.he.net -P 2 -t 30
iperf3 -c iperf.he.net -P 2 -t 30 -b 10M
iperf3 -c iperf.he.net -P 2 -t 45 -b 15M     # worst average RTT: 6886 ms

# High traffic
iperf3 -c iperf.he.net -P 10 -t 30
iperf3 -c iperf.he.net -u -b 100M -t 30
iperf3 -c iperf.he.net -P 10 -t 60 -b 10M -l 8K
```

All 30 commands are documented in the blog.

---

## Key Findings

| Traffic class | Typical avg RTT | Worst run       |
| ------------- | --------------- | --------------- |
| Low           | 258–423 ms      | L9: 423 ms      |
| Medium        | 346–6886 ms     | M9: **6886 ms** |
| High          | 1143–5416 ms    | H2: 5416 ms     |

- **Baseline RTT:** ~250 ms (physical floor of the link)
- **Bufferbloat is real and visible** — M5, M6, M8, M9 all show the
  slow-ramp signature
- **M9 (medium traffic) beat every high-traffic test on average RTT** —
  traffic shape matters more than volume
- **More streams can produce lower RTT than fewer** (H4: 10 streams →
  1143 ms; H1: 5 streams → 4617 ms)
- **UDP without rate control** produces distinctive triangular RTT curves

---

## Links

- 📝 **Blog:** https://rrt-analysis.blogspot.com/2026/04/rtt-under-load-beginners-tour-through.html
- 🎥 **Video:** https://youtu.be/kE-ID_D7Yg0

---

## Tools

- `iperf3` — traffic generation
- Wireshark — packet capture
- Python 3 — Scapy (pcap parsing), matplotlib (plotting)

---

## Acknowledgements

- **Dr. SubbuLakshmi T** — course instructor, BCSE308L
- **VIT Chennai** and **SCOPE**
- My parents and friends for the support
- The Wireshark, Scapy, and iperf3 open-source communities

---

© 2026 Naman Bhukar · VIT Chennai
