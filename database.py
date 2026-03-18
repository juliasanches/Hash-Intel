import sqlite3
import json
from datetime import datetime


DATABASE = "hash.db"


def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id                          INTEGER PRIMARY KEY AUTOINCREMENT,
            hash                        TEXT NOT NULL,
            scanned_at                  TEXT NOT NULL,
            vt_malicious                INTEGER,
            vt_total                    INTEGER,
            vt_threat_label             TEXT,
            vt_first_submission_date    TEXT,
            vt_sandbox_verdicts         TEXT,
            vt_crowdsourced_yara        TEXT,
            mb_signature                TEXT,
            mb_tags                     TEXT,
            mb_ssdeep                   TEXT,
            mb_delivery_method          TEXT,
            mb_origin_country           TEXT,
            otx_pulse_count             INTEGER,
            otx_attack_ids              TEXT,
            otx_type_title              TEXT,
            otx_http_requests           TEXT,
            otx_tcp_connections         TEXT,
            result_json                 TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_scan(hash: str, result: dict):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    vt = result.get("virus_total", {})
    mb = result.get("malware_bazaar", {})
    otx = result.get("alien_vault", {})
    analysis = otx.get("analysis", {})

    cursor.execute("""
        INSERT INTO scans (
            hash, scanned_at,
            vt_malicious, vt_total, vt_threat_label,
            vt_first_submission_date, vt_sandbox_verdicts, vt_crowdsourced_yara,
            mb_signature, mb_tags, mb_ssdeep, mb_delivery_method, mb_origin_country,
            otx_pulse_count, otx_attack_ids, otx_type_title,
            otx_http_requests, otx_tcp_connections,
            result_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        hash,
        datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        vt.get("malicious"),
        vt.get("total_engines"),
        vt.get("threat_label"),
        vt.get("first_submission_date"),
        json.dumps(vt.get("sandbox_verdicts", {})),
        json.dumps(vt.get("crowdsourced_yara_results", [])),
        mb.get("signature"),
        json.dumps(mb.get("tags", [])),
        mb.get("ssdeep"),
        mb.get("delivery_method"),
        mb.get("origin_country"),
        otx.get("pulse_count"),
        json.dumps(otx.get("attack_ids", [])),
        otx.get("type_title"),
        json.dumps(analysis.get("http_requests", [])),
        json.dumps(analysis.get("tcp_connections", [])),
        json.dumps(result),
    ))

    conn.commit()
    conn.close()

def get_history(limit: int = 20):
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            hash,
            scanned_at,
            vt_malicious,
            vt_total,
            vt_threat_label,
            mb_signature,
            mb_delivery_method,
            mb_origin_country,
            otx_pulse_count,
            otx_attack_ids
        FROM scans
        ORDER BY scanned_at DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["otx_attack_ids"] = json.loads(item["otx_attack_ids"]) if item["otx_attack_ids"] else []
        result.append(item)
    
    conn.close()
    return result

def get_history_complete(id: int):
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scans WHERE id = ?", (id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    item = dict(row)
    item["result_json"] = json.loads(item["result_json"]) if item["result_json"] else {}
    item["otx_attack_ids"] = json.loads(item["otx_attack_ids"]) if item["otx_attack_ids"] else []
    return item
