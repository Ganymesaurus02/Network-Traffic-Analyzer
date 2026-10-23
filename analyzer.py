"""Safe packet summaries, simple anomaly rules, and sample traffic for the demo.

The analyzer records packet metadata only. It does not save packet payloads.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
import ipaddress
import random
from typing import Any

import pandas as pd

FIELDS = ["timestamp", "src_ip", "dst_ip", "protocol", "tcp_flags",
          "src_port", "dst_port", "length", "direction"]


def summarize_packet(packet: Any, local_ips: set[str] | None = None) -> dict[str, Any] | None:
    """Convert one Scapy packet into a metadata-only row; ignore non-IP packets."""
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.inet6 import IPv6
    except ImportError as exc:
        raise RuntimeError("Scapy is required for live capture. Install requirements.txt.") from exc

    ip = packet.getlayer(IP) or packet.getlayer(IPv6)
    if ip is None:
        return None
    transport = packet.getlayer(TCP) or packet.getlayer(UDP)
    if packet.haslayer(TCP):
        protocol = "TCP"
    elif packet.haslayer(UDP):
        protocol = "UDP"
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
    else:
        protocol = "Other"
    if local_ips and ip.src in local_ips:
        direction = "Outgoing"
    elif local_ips and ip.dst in local_ips:
        direction = "Incoming"
    else:
        direction = "Unknown"
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "protocol": protocol,
	"tcp_flags": str(packet[TCP].flags) if packet.haslayer(TCP) else None,
        "src_port": int(transport.sport) if transport else None,
        "dst_port": int(transport.dport) if transport else None,
        "length": int(len(packet)),
        "direction": direction,
    }


def capture_packets(count: int = 100, interface: str | None = None,
                    local_ips: set[str] | None = None) -> list[dict[str, Any]]:
    """Capture a bounded number of packet headers on this authorized device."""
    try:
        from scapy.all import sniff
    except ImportError as exc:
        raise RuntimeError("Scapy is required for live capture. Install requirements.txt.") from exc
    rows: list[dict[str, Any]] = []

    def collect(packet: Any) -> None:
        row = summarize_packet(packet, local_ips)
        if row:
            rows.append(row)

    sniff(iface=interface or None, prn=collect, store=False, count=count, timeout=20)
    return rows


def sample_traffic(n: int = 450, seed: int = 19) -> pd.DataFrame:
    """Generate deterministic, clearly labeled synthetic traffic for learning/demo."""
    rng = random.Random(seed)
    now = datetime.now(timezone.utc)
    devices = ["192.168.1.10", "192.168.1.12", "192.168.1.20", "192.168.1.25"]
    servers = ["1.1.1.1", "8.8.8.8", "142.250.72.14", "104.18.32.47"]
    protocols = ["TCP", "UDP", "ICMP"]
    rows = []
    for i in range(n):
        src = rng.choice(devices)
        dst = rng.choice(servers)
        proto = rng.choices(protocols, weights=[65, 30, 5])[0]
        rows.append({
            "timestamp": (now - timedelta(seconds=(n - i) * 2)).isoformat(timespec="seconds"),
            "src_ip": src, "dst_ip": dst, "protocol": proto, "tcp_flags": "PA" if proto == "TCP" else None,
            "src_port": rng.randint(40000, 64000) if proto != "ICMP" else None,
            "dst_port": rng.choice([53, 80, 443, 443, 443, 123]) if proto != "ICMP" else None,
            "length": rng.randint(60, 1400),
            "direction": "Unknown",
        })
    # Add a visible but modest scan-like pattern for explaining threshold alerts.
    for port in range(20):
        rows.append({
            "timestamp": (now - timedelta(seconds=port)).isoformat(timespec="seconds"),
            "src_ip": "192.168.1.25", "dst_ip": "10.0.0.8", "protocol": "TCP", "tcp_flags": "S",
            "src_port": 53100 + port, "dst_port": 20 + port, "length": 60,
            "direction": "Unknown",
        })
    for attempt in range(6):
        rows.append({
            "timestamp": (
                now.replace(second=30, microsecond=0)
                - timedelta(seconds=attempt)
            ).isoformat(timespec="seconds"),
            "src_ip": "192.168.1.25",
            "dst_ip": "10.0.0.8",
            "protocol": "TCP",
            "tcp_flags": "S",
            "src_port": 54000 + attempt,
            "dst_port": 22,
            "length": 60,
            "direction": "Unknown",
        })
    # Turn a portion of the demo exchanges into inbound replies by reversing
    # source/destination addresses and ports. This gives the dashboard both directions.
    for row in rows[:n // 4]:
        row["src_ip"], row["dst_ip"] = row["dst_ip"], row["src_ip"]
        row["src_port"], row["dst_port"] = row["dst_port"], row["src_port"]

    local_devices = set(devices)
    for row in rows:
        if row["src_ip"] in local_devices:
            row["direction"] = "Outgoing"
        elif row["dst_ip"] in local_devices:
            row["direction"] = "Incoming"
        else:
            row["direction"] = "Unknown"

    return pd.DataFrame(rows, columns=FIELDS)


def detect_suspicious(df: pd.DataFrame, connection_threshold: int = 30,
                      bytes_threshold: int = 100_000,
                      port_threshold: int = 15,
                      spike_threshold: int = 20,
                      syn_threshold: int = 5,
                      known_local_ips: set[str] | None = None) -> pd.DataFrame:
    """Explainable heuristics: many connections or unusually large source volume.

    These rules create leads for human review; they do not prove malicious activity.
    """
    columns = ["severity", "rule", "src_ip", "observed", "threshold", "reason"]
    if df.empty:
        return pd.DataFrame(columns=columns)
    frame = df.copy()
    frame["length"] = pd.to_numeric(frame["length"], errors="coerce").fillna(0)
    findings = []
    counts = frame.groupby("src_ip", dropna=True).size()
    for ip, count in counts.items():
        if count >= connection_threshold:
            findings.append({"severity": "Medium", "rule": "High packet count", "src_ip": ip,
                             "observed": int(count), "threshold": connection_threshold,
                             "reason": "This source produced many packets in the selected capture."})
    totals = frame.groupby("src_ip", dropna=True)["length"].sum()
    for ip, total in totals.items():
        if total >= bytes_threshold:
            findings.append({"severity": "Medium", "rule": "High byte volume", "src_ip": ip,
                             "observed": int(total), "threshold": bytes_threshold,
                             "reason": "This source's captured packet sizes exceed the configured volume threshold."})
    ports_by_source = frame.groupby("src_ip", dropna=True)["dst_port"].nunique()
    for ip, port_count in ports_by_source.items():
        if port_count >= port_threshold:
            findings.append({
                "severity": "Medium",
                "rule": "Many destination ports",
                "src_ip": ip,
                "observed": int(port_count),
                "threshold": port_threshold,
                "reason": "This source contacted many different destination ports in the selected capture.",
            })
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce", utc=True)
    timed_rows = frame.dropna(subset=["timestamp", "src_ip"]).copy()
    timed_rows["minute"] = timed_rows["timestamp"].dt.floor("min")

    packets_per_minute = timed_rows.groupby(["src_ip", "minute"]).size()
    busiest_minute = packets_per_minute.groupby(level="src_ip").max()

    for ip, count in busiest_minute.items():
        if count >= spike_threshold:
            findings.append({
                "severity": "Medium",
                "rule": "High packets per minute",
                "src_ip": ip,
                "observed": int(count),
                "threshold": spike_threshold,
                "reason": "This source produced many packets within one minute of the selected capture.",
            })
    tcp_rows = frame[frame["protocol"].eq("TCP")].copy()
    flags = tcp_rows["tcp_flags"].fillna("").astype(str)

    initial_syn = tcp_rows[
        flags.str.contains("S", regex=False)
        & ~flags.str.contains("A", regex=False)
    ]

    syn_counts = initial_syn.groupby(
        ["src_ip", "dst_ip", "dst_port"], dropna=True
    ).size()

    for (src_ip, dst_ip, dst_port), count in syn_counts.items():
        if count >= syn_threshold:
            findings.append({
                "severity": "Medium",
                "rule": "Repeated TCP connection requests",
                "src_ip": src_ip,
                "observed": int(count),
                "threshold": syn_threshold,
                "reason": f"{count} initial TCP requests from this source to {dst_ip}:{dst_port} were captured.",
            })

    # Flag non-public source addresses that are not in the user's trusted-device list.
    # This is a review hint: private/special-use does not necessarily mean local LAN.
    trusted_ips = set()
    for candidate in known_local_ips or set():
        try:
            trusted_ips.add(
                ipaddress.ip_address(str(candidate).split("%", 1)[0]).compressed
            )
        except ValueError:
            continue

    source_counts = frame.groupby("src_ip", dropna=True).size()
    for ip, count in source_counts.items():
        try:
            address = ipaddress.ip_address(str(ip))
        except ValueError:
            continue

        if address.is_private and address.compressed not in trusted_ips:
            findings.append({
                "severity": "Low",
                "rule": "Unrecognized non-public source IP",
                "src_ip": str(ip),
                "observed": int(count),
                "threshold": "Trusted IP list",
                "reason": "This non-public source IP is not on the trusted list; check whether it belongs to a known device.",
            })
    return pd.DataFrame(findings, columns=columns)


def summarize(df: pd.DataFrame) -> dict[str, int]:
    if df.empty:
        return {"packets": 0, "bytes": 0, "devices": 0, "protocols": 0}
    return {"packets": len(df), "bytes": int(pd.to_numeric(df["length"], errors="coerce").fillna(0).sum()),
            "devices": int(df["src_ip"].nunique()), "protocols": int(df["protocol"].nunique())}
