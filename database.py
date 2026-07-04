"""
SQLite persistence for the network vulnerability scanner course project.

Developer/course metadata is intentionally kept in app.py so the student can
edit it before submission. This module is original code for this coursework.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


DB_PATH = Path("scanner.db")


@contextmanager
def connect() -> Iterable[sqlite3.Connection]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_input TEXT NOT NULL,
                ports TEXT NOT NULL,
                threads INTEGER NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                duration_seconds REAL DEFAULT 0,
                target_count INTEGER DEFAULT 0,
                open_port_count INTEGER DEFAULT 0,
                finding_count INTEGER DEFAULT 0,
                error TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                host TEXT NOT NULL,
                port INTEGER,
                service TEXT,
                rule_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                evidence TEXT,
                recommendation TEXT,
                source TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                service TEXT NOT NULL,
                banner TEXT,
                metadata TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            )
            """
        )


def create_scan(target_input: str, ports: str, threads: int, started_at: str) -> int:
    with connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO scans (target_input, ports, threads, status, started_at)
            VALUES (?, ?, ?, 'running', ?)
            """,
            (target_input, ports, threads, started_at),
        )
        return int(cur.lastrowid)


def update_scan(scan_id: int, **fields: Any) -> None:
    if not fields:
        return
    keys = list(fields.keys())
    sql = "UPDATE scans SET " + ", ".join(f"{key}=?" for key in keys) + " WHERE id=?"
    values = [fields[key] for key in keys] + [scan_id]
    with connect() as conn:
        conn.execute(sql, values)


def insert_services(scan_id: int, services: List[Dict[str, Any]], created_at: str) -> None:
    if not services:
        return
    rows = [
        (
            scan_id,
            item["host"],
            int(item["port"]),
            item.get("protocol", "tcp"),
            item.get("service", "unknown"),
            item.get("banner", ""),
            json.dumps(item.get("metadata", {}), ensure_ascii=False),
            created_at,
        )
        for item in services
    ]
    with connect() as conn:
        conn.executemany(
            """
            INSERT INTO services
            (scan_id, host, port, protocol, service, banner, metadata, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )


def insert_findings(scan_id: int, findings: List[Dict[str, Any]], created_at: str) -> None:
    if not findings:
        return
    rows = [
        (
            scan_id,
            item["host"],
            item.get("port"),
            item.get("service", ""),
            item["rule_id"],
            item["title"],
            item["severity"],
            item["category"],
            item.get("evidence", ""),
            item.get("recommendation", ""),
            item.get("source", ""),
            created_at,
        )
        for item in findings
    ]
    with connect() as conn:
        conn.executemany(
            """
            INSERT INTO findings
            (scan_id, host, port, service, rule_id, title, severity, category,
             evidence, recommendation, source, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )


def get_scan(scan_id: int) -> Optional[Dict[str, Any]]:
    with connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return dict(row) if row else None


def list_scans(limit: int = 20) -> List[Dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]


def get_services(scan_id: int) -> List[Dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM services WHERE scan_id=? ORDER BY host, port", (scan_id,)
        ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        try:
            item["metadata"] = json.loads(item.get("metadata") or "{}")
        except json.JSONDecodeError:
            item["metadata"] = {}
        result.append(item)
    return result


def get_findings(scan_id: int) -> List[Dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT * FROM findings
            WHERE scan_id=?
            ORDER BY
                CASE severity
                    WHEN '高危' THEN 1
                    WHEN '中危' THEN 2
                    WHEN '低危' THEN 3
                    ELSE 4
                END,
                host,
                port
            """,
            (scan_id,),
        ).fetchall()
        return [dict(row) for row in rows]


def scan_summary(scan_id: int) -> Dict[str, Any]:
    scan = get_scan(scan_id)
    if not scan:
        return {}
    services = get_services(scan_id)
    findings = get_findings(scan_id)
    by_severity: Dict[str, int] = {"高危": 0, "中危": 0, "低危": 0, "信息": 0}
    by_category: Dict[str, int] = {}
    by_host: Dict[str, int] = {}
    for finding in findings:
        by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1
        by_category[finding["category"]] = by_category.get(finding["category"], 0) + 1
        by_host[finding["host"]] = by_host.get(finding["host"], 0) + 1
    return {
        "scan": scan,
        "services": services,
        "findings": findings,
        "by_severity": by_severity,
        "by_category": by_category,
        "by_host": by_host,
        "service_count": len(services),
        "finding_count": len(findings),
    }
