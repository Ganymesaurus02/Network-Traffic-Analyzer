# Network Traffic Analyzer

A safe, educational Python capstone that summarizes authorized network traffic, charts protocol, device, and traffic-direction activity, applies explainable anomaly rules, and exports a traffic/security summary plus packet metadata as CSV. The dashboard never stores packet payload contents. Synthetic demo traffic is available when live capture is unavailable.

## Start here

1. Install Python 3.10 or newer.
2. In this folder, create and activate a virtual environment:

   ```powershell
   py -m venv .venv
   .venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt
   ```

3. Start the dashboard:

   ```powershell
   streamlit run app.py
   ```

4. Begin with **Synthetic demo data**. Pick **Live capture** only on a device/network you own or are explicitly authorized to monitor. On Windows, live capture may require Npcap and an elevated terminal; on Linux/macOS it may require elevated capture privileges. You can still build and demonstrate the project in synthetic mode without those privileges.

## What the system does

| Module | Implementation | Key idea |
| --- | --- | --- |
| Packet capture | Scapy, bounded by packet count and a 20-second timeout | Summarize authorized IPv4/IPv6 packet metadata and direction |
| Monitoring | Pandas groupings and time buckets | Summarize packet counts, bytes, source IPs, protocols, and directions |
| Detection | Explainable per-source heuristics | Flag high packet counts, high byte volume, many destination ports, packet-rate spikes, repeated TCP SYN requests, and unrecognized non-public source IPs |
| Dashboard | Streamlit and Plotly | Show protocol distribution, packets over time, top source activity, direction, and alert findings |
| Storage | MySQL Connector/Python | Save capture sessions and packet metadata in MySQL |
| Reporting | Downloadable text summary and packet CSV | Export capture metrics, protocol/direction counts, alert findings, or packet rows |

## Learn the concepts while you build

### 1. What is a packet?

Applications produce data; networking divides it into packets or segments that travel between systems. Headers describe how to deliver the data (for example, source/destination IP and TCP/UDP ports). The payload is the carried content. This capstone collects metadata such as headers, protocol, and packet length, and deliberately avoids retaining payloads. That is enough to learn traffic patterns while reducing privacy exposure.

### 2. How to read IPs, protocols, and ports

An IP address identifies a network interface at the IP layer. TCP and UDP are transport protocols: TCP establishes a connection and provides ordered delivery; UDP has lower overhead but does not itself guarantee delivery. Ports help route traffic to applications. A port association is a clue, not proof: services can use nonstandard ports, and multiple applications can share one.

### 3. What does a packet capture show?

Scapy receives packets visible to the local capture interface. A switched network usually does not expose every other device's unicast traffic to your machine. Wi-Fi, VPNs, host firewalls, capture drivers, privileges, and filters all affect what is visible. A quiet or empty capture is not evidence that the network has no traffic.

### 4. What is an anomaly?

An anomaly is behavior that differs from an expected baseline; it is not automatically malicious. This project uses explainable heuristics for high packet count, high byte volume, many distinct destination ports, high packets per minute, repeated initial TCP SYN requests to one destination, and non-public source IPs missing from the trusted-IP list. A high count could come from a software update, backup, busy server, or scan. An unrecognized non-public IP is not automatically an attacker. Each alert is a lead to investigate, not a verdict; thresholds and allowlists need network context.

### 5. Why charts and reports?

Charts make distributions and changes easier to spot than raw rows. The dashboard shows protocol composition, packet counts per minute, top-source activity, and incoming/outgoing/unknown packet counts. The downloadable text report summarizes the selected capture and its alert findings; the CSV preserves packet rows for further analysis. Include capture duration, traffic source (synthetic/live), device/interface, thresholds, and limitations when interpreting results.

### 6. Why a database?

A DataFrame is convenient while analyzing data, but it normally lives only in the running app's memory. MySQL stores rows persistently in a database server, so you can close the app and reload a previous capture. The project uses two related tables: `captures` stores one row per capture session, and `packets` stores packet summaries linked to a capture with `capture_id`. This is a one-to-many relationship: one capture contains many packet rows. MySQL Connector/Python connects the Python app to the MySQL Server. Workbench is the graphical client where you can inspect the schema and run SQL queries. The database stores metadata only, never packet payloads.

Before starting the app, create a schema named `network_traffic_analyzer` in MySQL Workbench and configure `.streamlit/secrets.toml` (make a `.streamlit` folder if needed):

```toml
[mysql]
host = "127.0.0.1"
port = 3306
user = "root"
password = "YOUR_MYSQL_PASSWORD"
database = "network_traffic_analyzer"
```

Keep the real secrets file private; it is excluded from Git. The app creates its two tables automatically after connecting.

## Deliverables checklist

- [ ] Source code and GitHub repository
- [ ] Project report: objective, architecture, methods, results, limitations, safe-use boundary
- [ ] Slides and 3–5 minute demo video
- [ ] Dashboard screenshots
- [ ] Traffic/security text report and packet CSV (synthetic data is clearly labeled; live data must be authorized)

## Safety and limits

Use synthetic data by default. Capture only traffic on your own device/network or with explicit authorization. The app does not perform scans, logins, payload inspection, or remote access. It is a learning prototype, not an intrusion-detection guarantee. Do not publish real IP addresses, usernames, or other sensitive network details in screenshots or reports.
