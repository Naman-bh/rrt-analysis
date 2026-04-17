import os
import re
import csv
import shutil
from collections import defaultdict, deque
from statistics import mean, stdev

from scapy.all import rdpcap, TCP, IP, IPv6

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


# =========================
# CONFIG
# =========================
INPUT_FOLDER = "."                      
OUTPUT_FOLDER = "rtt_graphs"
PER_FILE_FOLDER = os.path.join(OUTPUT_FOLDER, "per_file")
SUMMARY_FOLDER = os.path.join(OUTPUT_FOLDER, "summary")

TRAFFIC_LABELS = {
    "L": "Low traffic",
    "M": "Medium traffic",
    "H": "High traffic",
}

# =========================
# HELPERS
# =========================
def natural_key(name):
    """Sorts H1, H2, H10 correctly."""
    return [int(part) if part.isdigit() else part.lower() for part in re.split(r"(\d+)", name)]


def get_ip_pair(pkt):
    """Return (src, dst) for IPv4/IPv6 packets, else None."""
    if pkt.haslayer(IP):
        ip = pkt[IP]
        return ip.src, ip.dst
    if pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        return ip6.src, ip6.dst
    return None


def reset_output_folders():
    """Delete old output and recreate clean folders."""
    shutil.rmtree(OUTPUT_FOLDER, ignore_errors=True)
    os.makedirs(PER_FILE_FOLDER, exist_ok=True)
    os.makedirs(SUMMARY_FOLDER, exist_ok=True)


def file_traffic_type(filename):
    """Infer traffic type from file name prefix: H, M, or L."""
    base = os.path.splitext(filename)[0]
    if not base:
        return "X"
    c = base[0].upper()
    return c if c in {"H", "M", "L"} else "X"


def traffic_label(code):
    return TRAFFIC_LABELS.get(code, "Unknown traffic")


# =========================
# RTT EXTRACTION
# =========================
def extract_data_rtt_samples(packets):
    """
    Approximate RTT from TCP data segment -> ACK timing.
    For each outgoing payload segment, store its sequence end.
    When the reverse ACK arrives, assign RTT to all fully acknowledged segments.
    """
    pending = defaultdict(deque)
    samples = []
    start_ts = None

    for pkt in packets:
        if not pkt.haslayer(TCP):
            continue

        ip_pair = get_ip_pair(pkt)
        if ip_pair is None:
            continue

        src, dst = ip_pair
        tcp = pkt[TCP]
        ts = float(pkt.time)
        if start_ts is None:
            start_ts = ts

        flags = int(tcp.flags)
        payload_len = len(bytes(tcp.payload))

        # Store outgoing data segment
        if payload_len > 0 and not (flags & 0x02):  # skip SYN-only packets
            flow = (src, dst, int(tcp.sport), int(tcp.dport))
            seq_end = int(tcp.seq) + payload_len
            pending[flow].append((seq_end, ts))

        # ACK may acknowledge one or more queued data packets
        if flags & 0x10:  # ACK bit set
            data_flow = (dst, src, int(tcp.dport), int(tcp.sport))
            ack_num = int(tcp.ack)

            q = pending[data_flow]
            while q and q[0][0] <= ack_num:
                seq_end, sent_ts = q.popleft()
                rtt = ts - sent_ts
                if rtt >= 0:
                    samples.append((ts - start_ts, rtt))

    return start_ts or 0.0, samples


def extract_handshake_rtt_samples(packets):
    """
    Fallback RTT using SYN -> SYN-ACK handshake.
    Useful if a capture has very little data traffic.
    """
    syn_times = {}
    samples = []
    start_ts = None

    for pkt in packets:
        if not pkt.haslayer(TCP):
            continue

        ip_pair = get_ip_pair(pkt)
        if ip_pair is None:
            continue

        src, dst = ip_pair
        tcp = pkt[TCP]
        ts = float(pkt.time)
        if start_ts is None:
            start_ts = ts

        flags = int(tcp.flags)

        # SYN without ACK
        if (flags & 0x02) and not (flags & 0x10):
            key = (src, dst, int(tcp.sport), int(tcp.dport), int(tcp.seq) + 1)
            syn_times[key] = ts

        # SYN-ACK
        elif (flags & 0x12) == 0x12:
            key = (dst, src, int(tcp.dport), int(tcp.sport), int(tcp.ack))
            if key in syn_times:
                rtt = ts - syn_times[key]
                if rtt >= 0:
                    samples.append((ts - start_ts, rtt))

    return start_ts or 0.0, samples


def extract_rtt_samples_from_pcap(pcap_path):
    packets = rdpcap(pcap_path)

    start_ts, samples = extract_data_rtt_samples(packets)
    if not samples:
        start_ts, samples = extract_handshake_rtt_samples(packets)

    return start_ts, samples


# =========================
# PLOTTING
# =========================
def plot_per_file_rtt(base_name, traffic_code, samples, out_path):
    plt.figure(figsize=(10, 4.5))

    if samples:
        x_ms = [t * 1000 for t, _ in samples]
        y_ms = [r * 1000 for _, r in samples]
        plt.plot(x_ms, y_ms, linewidth=1.2)
    else:
        plt.text(
            0.5, 0.5, "No RTT samples found",
            ha="center", va="center", fontsize=12
        )
        plt.xlim(0, 1)
        plt.ylim(0, 1)

    plt.xlabel("Capture time (ms)")
    plt.ylabel("RTT (ms)")
    plt.title(f"{base_name} - RTT Trend ({traffic_label(traffic_code)})")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path, dpi=300)
    plt.close()


def plot_summary_average_rtt(metrics, out_path):
    labels = [m["file"] for m in metrics]
    avgs = [m["avg_rtt_ms"] for m in metrics]

    plt.figure(figsize=(14, 5))
    plt.bar(range(len(labels)), avgs)
    plt.xticks(range(len(labels)), labels, rotation=45, ha="right")
    plt.xlabel("PCAP file")
    plt.ylabel("Average RTT (ms)")
    plt.title("Average RTT Comparison Across All Files")
    plt.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path, dpi=300)
    plt.close()


def plot_group_boxplot(group_samples, out_path):
    labels = []
    data = []

    for code in ["L", "M", "H"]:
        if group_samples.get(code):
            labels.append(traffic_label(code))
            data.append(group_samples[code])

    plt.figure(figsize=(10, 5))
    if data:
        plt.boxplot(data, labels=labels, showfliers=False)
        plt.xlabel("Traffic condition")
        plt.ylabel("RTT (ms)")
        plt.title("RTT Distribution by Traffic Condition")
        plt.grid(axis="y", alpha=0.3)
    else:
        plt.text(0.5, 0.5, "No grouped samples available", ha="center", va="center")
        plt.xlim(0, 1)
        plt.ylim(0, 1)

    plt.tight_layout()
    plt.savefig(out_path, dpi=300)
    plt.close()


# =========================
# MAIN
# =========================
def main():
    reset_output_folders()

    pcap_files = sorted(
        [
            f for f in os.listdir(INPUT_FOLDER)
            if f.lower().endswith(".pcapng") or f.lower().endswith(".pcap")
        ],
        key=natural_key
    )

    if not pcap_files:
        print("No .pcapng or .pcap files found in the current folder.")
        return

    print(f"Detected {len(pcap_files)} capture files.\n")

    metrics = []
    group_samples = defaultdict(list)

    for pcap_file in pcap_files:
        path = os.path.join(INPUT_FOLDER, pcap_file)
        base = os.path.splitext(pcap_file)[0]
        tcode = file_traffic_type(pcap_file)

        try:
            start_ts, samples = extract_rtt_samples_from_pcap(path)
            rtts_ms = [r * 1000 for _, r in samples]

            avg_rtt = mean(rtts_ms) if rtts_ms else 0.0
            min_rtt = min(rtts_ms) if rtts_ms else 0.0
            max_rtt = max(rtts_ms) if rtts_ms else 0.0
            std_rtt = stdev(rtts_ms) if len(rtts_ms) > 1 else 0.0

            group_samples[tcode].extend(rtts_ms)

            metrics.append({
                "file": base,
                "traffic": traffic_label(tcode),
                "samples": len(rtts_ms),
                "avg_rtt_ms": round(avg_rtt, 4),
                "min_rtt_ms": round(min_rtt, 4),
                "max_rtt_ms": round(max_rtt, 4),
                "std_rtt_ms": round(std_rtt, 4),
            })

            out_file = os.path.join(PER_FILE_FOLDER, f"{base}_rtt.png")
            plot_per_file_rtt(base, tcode, samples, out_file)

            print(
                f"{pcap_file:12s} | samples: {len(rtts_ms):4d} | "
                f"avg RTT: {avg_rtt:.3f} ms | saved: {out_file}"
            )

        except Exception as e:
            print(f"Skipped {pcap_file} بسبب error: {e}")

    # Write CSV summary
    csv_path = os.path.join(SUMMARY_FOLDER, "rtt_summary.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["file", "traffic", "samples", "avg_rtt_ms", "min_rtt_ms", "max_rtt_ms", "std_rtt_ms"]
        )
        writer.writeheader()
        writer.writerows(metrics)

    # Summary graphs
    avg_path = os.path.join(SUMMARY_FOLDER, "average_rtt_comparison.png")
    plot_summary_average_rtt(metrics, avg_path)

    boxplot_path = os.path.join(SUMMARY_FOLDER, "rtt_by_traffic_condition.png")
    plot_group_boxplot(group_samples, boxplot_path)

    print("\nDone.")
    print(f"Per-file graphs: {PER_FILE_FOLDER}")
    print(f"Summary graphs + CSV: {SUMMARY_FOLDER}")


if __name__ == "__main__":
    main()