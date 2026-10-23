"""MySQL persistence for capture sessions and metadata-only packet rows."""
from __future__ import annotations

from datetime import datetime, timezone
import os
from typing import Any

import pandas as pd
import streamlit as st


def _connection_settings() -> dict[str, Any]:
    """Read credentials from Streamlit secrets or MYSQL_* environment variables."""
    try:
        values = dict(st.secrets.get("mysql", {}))
    except Exception:
        values = {}
    return {
        "host": os.getenv("MYSQL_HOST", values.get("host", "127.0.0.1")),
        "port": int(os.getenv("MYSQL_PORT", values.get("port", 3306))),
        "user": os.getenv("MYSQL_USER", values.get("user", "root")),
        "password": os.getenv("MYSQL_PASSWORD", values.get("password", "")),
        "database": os.getenv("MYSQL_DATABASE", values.get("database", "network_traffic_analyzer")),
    }


def connect():
    """Open the configured MySQL schema and create project tables if needed."""
    try:
        import mysql.connector
    except ImportError as exc:
        raise RuntimeError("MySQL connector is missing. Run: python -m pip install -r requirements.txt") from exc
    settings = _connection_settings()
    try:
        db = mysql.connector.connect(**settings)
    except mysql.connector.Error as exc:
        raise RuntimeError(
            f"Cannot connect to MySQL at {settings['host']}:{settings['port']} "
            f"using database '{settings['database']}'. Check that MySQL Server is running, "
            f"the schema exists, and your credentials are configured. "
            f"MySQL error {exc.errno}: {exc.msg}"
        ) from exc
    cursor = db.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS captures (
            id BIGINT PRIMARY KEY AUTO_INCREMENT,
            created_at VARCHAR(40) NOT NULL,
            source VARCHAR(120) NOT NULL,
            packet_count INT NOT NULL
        ) ENGINE=InnoDB
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id BIGINT PRIMARY KEY AUTO_INCREMENT,
            capture_id BIGINT NOT NULL,
            timestamp VARCHAR(40) NOT NULL,
            src_ip VARCHAR(45),
            dst_ip VARCHAR(45),
            protocol VARCHAR(12),
	    tcp_flags VARCHAR(8) NULL,
            src_port INT NULL,
            dst_port INT NULL,
            length INT NOT NULL,
            direction VARCHAR(10) NOT NULL DEFAULT 'Unknown',
            INDEX idx_packets_capture (capture_id),
            CONSTRAINT fk_packets_capture FOREIGN KEY (capture_id)
                REFERENCES captures(id) ON DELETE CASCADE
        ) ENGINE=InnoDB
    """)
    db.commit()
    cursor.close()
    return db


def save_capture(df: pd.DataFrame, source: str) -> int:
    """Store one capture session and its packet metadata; return its database ID."""
    db = connect()
    cursor = db.cursor()
    try:
        cursor.execute(
            "INSERT INTO captures (created_at, source, packet_count) VALUES (%s, %s, %s)",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"), source, len(df)),
        )
        capture_id = int(cursor.lastrowid)
        rows: list[tuple[Any, ...]] = []
        for row in df.itertuples(index=False):
            values = row._asdict()
            ts = pd.Timestamp(values["timestamp"])
            src_port = values.get("src_port")
            dst_port = values.get("dst_port")
            # Pandas promotes missing integer ports to NaN; MySQL needs SQL NULL.
            if pd.isna(src_port):
                src_port = None
            if pd.isna(dst_port):
                dst_port = None
            # Pandas uses NaN for missing optional values; MySQL expects SQL NULL.
            # This also covers TCP-only metadata such as flags on UDP/ICMP rows.
            for field_name in ("src_ip", "dst_ip", "protocol", "src_port", "dst_port",
                               "tcp_flags", "direction", "length"):
                if pd.isna(values.get(field_name)):
                    values[field_name] = None
            rows.append((capture_id, ts.isoformat(), values.get("src_ip"), values.get("dst_ip"),
                         values.get("protocol"), values.get("tcp_flags"), src_port, dst_port,
                         values.get("direction", "Unknown"),
                         int(values.get("length") or 0)))
        if rows:
            cursor.executemany(
                """INSERT INTO packets
                   (capture_id, timestamp, src_ip, dst_ip, protocol, tcp_flags, src_port, dst_port, direction, length)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""", rows,
            )
        db.commit()
        return capture_id
    except Exception:
        db.rollback()
        raise
    finally:
        cursor.close()
        db.close()


def list_captures() -> pd.DataFrame:
    db = connect()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id, created_at, source, packet_count FROM captures ORDER BY id DESC")
        return pd.DataFrame(cursor.fetchall(), columns=["id", "created_at", "source", "packet_count"])
    finally:
        cursor.close()
        db.close()


def load_capture(capture_id: int) -> tuple[pd.DataFrame, str]:
    db = connect()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT source FROM captures WHERE id = %s", (capture_id,))
        capture = cursor.fetchone()
        if capture is None:
            raise ValueError(f"Capture {capture_id} was not found.")
        cursor.execute(
            "SELECT timestamp, src_ip, dst_ip, protocol, tcp_flags, src_port, dst_port, length, direction "
            "FROM packets WHERE capture_id = %s ORDER BY id", (capture_id,),
        )
        rows = cursor.fetchall()
        return pd.DataFrame(rows, columns=["timestamp", "src_ip", "dst_ip", "protocol", "tcp_flags", "src_port", "dst_port", "length", "direction"]), str(capture["source"])
    finally:
        cursor.close()
        db.close()
