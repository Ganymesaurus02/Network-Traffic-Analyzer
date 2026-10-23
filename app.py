"""Streamlit dashboard for the Network Traffic Analyzer capstone."""
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

from analyzer import capture_packets, detect_suspicious, sample_traffic, summarize
from storage import list_captures, load_capture, save_capture

st.set_page_config(page_title="Network Traffic Analyzer", page_icon="🛡️", layout="wide")
st.title("🛡️ Network Traffic Analyzer")
st.caption("Learn from packet metadata, monitor authorized traffic, and review explainable alerts.")

if "traffic" not in st.session_state:
    st.session_state.traffic = sample_traffic()
if "source" not in st.session_state:
    st.session_state.source = "Synthetic demo data"

with st.sidebar:
    st.header("Capture controls")
    mode = st.radio("Traffic source", ["Synthetic demo data", "Live capture"], help="Demo data is safe to use anywhere. Live capture is limited to a short capture on a network/device you are authorized to monitor.")
    if mode == "Synthetic demo data":
        amount = st.slider("Synthetic packet rows", 100, 1200, 450, 50)
        if st.button("Load demo traffic", use_container_width=True):
            st.session_state.traffic = sample_traffic(amount)
            st.session_state.source = "Synthetic demo data"
    else:
        st.warning("Live capture may require administrator/root privileges and a capture driver. Only monitor networks you own or have permission to monitor.")
        packet_count = st.slider("Maximum packets", 20, 500, 100, 20)
        interface = st.text_input(
            "Scapy interface (optional)",
            placeholder=r"\Device\NPF_{088B8982-C3E2-4779-A725-320EC284C994}",
            help="Use the NPF interface name for your WiFi adapter, or leave blank to use Scapy's default.",
        )
        local_ip_text = st.text_input(
            "Local Wi-Fi IP addresses",
            placeholder="IPv4, IPv6",
            help="Enter both IP addresses assigned to your WiFi adapter, separated by commas, to label packet direction.",
        )
        local_ips = {
            address.strip().split("%", 1)[0]
            for address in local_ip_text.split(",")
            if address.strip()
        }
        if not local_ips:
            st.caption("Direction will be Unknown until local IP addresses are provided.")
        if st.button("Capture now (up to 20 seconds)", type="primary", use_container_width=True):
            with st.spinner("Capturing packet metadata..."):
                try:
                    rows = capture_packets(packet_count, interface.strip() or None, local_ips)
                    if rows:
                        st.session_state.traffic = pd.DataFrame(rows)
                        st.session_state.source = f"Live capture · {len(rows)} packets"
                        capture_id = save_capture(st.session_state.traffic, st.session_state.source)
                        st.success(f"Saved capture #{capture_id} to MySQL.")
                    else:
                        st.info("No IPv4/IPv6 packets were observed. Try again while using the network.")
                except Exception as exc:
                    st.error(f"Capture failed: {exc}")
    st.divider()
    st.subheader("MySQL storage")
    st.caption("Save the current metadata capture to MySQL, or reload an earlier session.")
    if st.button("Save current traffic to database", use_container_width=True):
        try:
            capture_id = save_capture(st.session_state.traffic, st.session_state.source)
            st.success(f"Saved as capture #{capture_id} in MySQL.")
        except Exception as exc:
            st.error(f"Could not save capture: {exc}")
    try:
        saved = list_captures()
        if not saved.empty:
            choices = saved.to_dict("records")
            selected_id = st.selectbox(
                "Saved capture",
                options=[int(item["id"]) for item in choices],
                format_func=lambda key: next(
                    f"#{item['id']} · {item['created_at']} · {item['source']} ({item['packet_count']} packets)"
                    for item in choices if int(item["id"]) == key
                ),
            )
            if st.button("Load selected capture", use_container_width=True):
                st.session_state.traffic, st.session_state.source = load_capture(selected_id)
                st.rerun()
    except Exception as exc:
        st.error(f"Could not read the local database: {exc}")
    st.caption("Only packet metadata is stored; payload contents are not saved.")

df = st.session_state.traffic.copy()
df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
summary = summarize(df)
st.caption(f"Data source: **{st.session_state.source}** · Saved captures live in MySQL.")

c1, c2, c3, c4 = st.columns(4)
c1.metric("Packets", f"{summary['packets']:,}")
c2.metric("Captured bytes", f"{summary['bytes']:,}")
c3.metric("Source devices", f"{summary['devices']:,}")
c4.metric("Protocols", f"{summary['protocols']:,}")

left, right = st.columns(2)
with left:
    st.subheader("Protocol distribution")
    protocol_counts = df["protocol"].value_counts().rename_axis("protocol").reset_index(name="packets")
    st.plotly_chart(px.pie(protocol_counts, names="protocol", values="packets", hole=.42), use_container_width=True)
with right:
    st.subheader("Packet volume over time")
    timeline = df.dropna(subset=["timestamp"]).set_index("timestamp").resample("1min").size().rename("packets").reset_index()
    st.plotly_chart(px.line(timeline, x="timestamp", y="packets", markers=True), use_container_width=True)

st.subheader("Top source devices")
top_sources = df.groupby("src_ip", as_index=False).agg(packets=("length", "size"), bytes=("length", "sum")).sort_values("packets", ascending=False).head(10)
st.plotly_chart(px.bar(top_sources, x="src_ip", y="packets", color="bytes", labels={"src_ip": "Source IP", "packets": "Packets"}), use_container_width=True)

st.subheader("Explainable suspicious-activity rules")
threshold = st.slider("Packets per source before flagging", 10, 200, 30, 5)
port_threshold = st.slider("Distinct destination ports before flagging", 5, 40, 15, 1)
spike_threshold = st.slider("Packets per minute before flagging", 5, 60, 20, 5)
syn_threshold = st.slider("TCP SYN requests to one destination before flagging", 2, 20, 5, 1)
trusted_ip_text = st.text_area(
    "Trusted device IP addresses (comma or newline separated)",
    value="192.168.1.10, 192.168.1.12, 192.168.1.20",
    help="Only non-public source IPs absent from this list are flagged. Edit this list for your own network.",
)
known_local_ips = {
    address.strip()
    for address in trusted_ip_text.replace("\n", ",").split(",")
    if address.strip()
}
alerts = detect_suspicious(
    df,
    connection_threshold=threshold,
    port_threshold=port_threshold,
    spike_threshold=spike_threshold,
    syn_threshold=syn_threshold,
    known_local_ips=known_local_ips,
)
if alerts.empty:
    st.success("No configured rules fired for this capture. That does not prove traffic is benign.")
else:
    st.dataframe(alerts, use_container_width=True, hide_index=True)
    st.caption("Heuristic flags are review leads, not proof of an attack. Consider device role, capture duration, and network context.")

if "direction" in df.columns:
    st.subheader("Incoming vs outgoing traffic")
    direction_counts = (
        df["direction"]
        .fillna("Unknown")
        .replace("", "Unknown")
        .value_counts()
        .rename_axis("direction")
        .reset_index(name="packets")
    )
    st.plotly_chart(
        px.bar(
            direction_counts,
            x="direction",
            y="packets",
            color="direction",
            labels={"direction": "Traffic direction", "packets": "Packets"},
            title="Packet count by direction",
        ),
        use_container_width=True,
    )
else:
    st.info("Direction data is unavailable for this capture. Load or create a capture that includes direction labels.")

st.subheader("Packet metadata")
st.dataframe(df.sort_values("timestamp", ascending=False), use_container_width=True, hide_index=True)
protocol_summary = (
    df["protocol"].fillna("Unknown").replace("", "Unknown").value_counts()
)
direction_summary = (
    df["direction"].fillna("Unknown").replace("", "Unknown").value_counts()
    if "direction" in df.columns
    else pd.Series(dtype="int64")
)

report_lines = [
    "NETWORK TRAFFIC ANALYZER - TRAFFIC AND SECURITY REPORT",
    f"Generated: {datetime.now().astimezone().isoformat(timespec='seconds')}",
    f"Data source: {st.session_state.source}",
    "",
    "CAPTURE SUMMARY",
    f"Packets: {summary['packets']}",
    f"Captured bytes: {summary['bytes']}",
    f"Source IP addresses: {summary['devices']}",
    f"Protocol types: {summary['protocols']}",
    "",
    "PACKETS BY PROTOCOL",
]
report_lines.extend(
    f"{protocol}: {int(count)}" for protocol, count in protocol_summary.items()
)
report_lines.extend(["", "PACKETS BY DIRECTION"])
if direction_summary.empty:
    report_lines.append("Direction data is unavailable for this capture.")
else:
    report_lines.extend(
        f"{direction}: {int(count)}" for direction, count in direction_summary.items()
    )

report_lines.extend(["", f"SECURITY FINDINGS: {len(alerts)}"])
if alerts.empty:
    report_lines.append("No configured rules triggered. This does not prove the traffic is benign.")
else:
    for _, alert in alerts.iterrows():
        report_lines.append(
            f"- {alert['severity']} | {alert['rule']} | source={alert['src_ip']} | "
            f"observed={alert['observed']} | threshold={alert['threshold']} | "
            f"{alert['reason']}"
        )
report_lines.extend([
    "",
    "LIMITATION",
    "Alerts are explainable heuristic flags for human review, not proof of malicious activity.",
    "Only packet metadata is analyzed; payload contents are not included in this report.",
])

st.download_button(
    "Download traffic and security report (TXT)",
    "\n".join(report_lines).encode("utf-8"),
    file_name=f"network_traffic_report_{datetime.now():%Y%m%d_%H%M%S}.txt",
    mime="text/plain",
)

csv = df.to_csv(index=False).encode("utf-8")
st.download_button("Download traffic CSV", csv, file_name=f"traffic_report_{datetime.now():%Y%m%d_%H%M%S}.csv", mime="text/csv")

