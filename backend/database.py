import os
import sqlite3
from datetime import datetime

# Resilient import of MITRE mapper
try:
    from backend.mitre import map_threat_to_mitre
except ImportError:
    try:
        from mitre import map_threat_to_mitre
    except ImportError:
        def map_threat_to_mitre(attack_type):
            return {"mitre_id": "N/A", "technique": "N/A", "tactic": "N/A", "description": "N/A", "mitigations": []}

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "threats.db")

def get_db_connection():
    """Returns a SQLite connection that yields rows as dictionaries."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the SQLite database tables."""
    print(f"[*] Initializing SQLite database at: {DB_PATH}")
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create sessions table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        filename TEXT NOT NULL,
        uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        status TEXT DEFAULT 'Processing'
    )
    """)
    
    # Create alerts table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        src_ip TEXT,
        dst_ip TEXT,
        src_port INTEGER,
        dst_port INTEGER,
        protocol INTEGER,
        duration REAL,
        pkt_count_out INTEGER,
        pkt_count_in INTEGER,
        byte_count_out INTEGER,
        byte_count_in INTEGER,
        pkt_rate REAL,
        byte_rate REAL,
        avg_pkt_sz REAL,
        tcp_flags_syn INTEGER,
        tcp_flags_ack INTEGER,
        tcp_flags_rst INTEGER,
        anomaly_score REAL,
        attack_type TEXT,
        severity TEXT,
        mitre_id TEXT,
        mitre_technique TEXT,
        mitre_tactic TEXT,
        status TEXT DEFAULT 'New',
        FOREIGN KEY (session_id) REFERENCES sessions (id) ON DELETE CASCADE
    )
    """)
    
    conn.commit()
    conn.close()
    print("[+] Database tables initialized.")

def create_session(session_id, filename):
    """Inserts a new analysis session."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO sessions (id, filename, status) VALUES (?, ?, ?)",
            (session_id, filename, 'Processing')
        )
        conn.commit()
    except Exception as e:
        print(f"[-] Error creating session: {e}")
    finally:
        conn.close()

def update_session_status(session_id, status):
    """Updates the processing status of a session."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE sessions SET status = ? WHERE id = ?",
            (status, session_id)
        )
        conn.commit()
    except Exception as e:
        print(f"[-] Error updating session status: {e}")
    finally:
        conn.close()

def insert_alert(session_id, flow_dict):
    """Maps flow features using MITRE, inserts a threat alert record, and returns the ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Map to MITRE ATT&CK
    attack_type = flow_dict.get('attack_type', 'Normal')
    mitre_data = map_threat_to_mitre(attack_type)
    
    features = flow_dict.get('features', {})
    
    try:
        cursor.execute("""
            INSERT INTO alerts (
                session_id, src_ip, dst_ip, src_port, dst_port, protocol,
                duration, pkt_count_out, pkt_count_in, byte_count_out, byte_count_in,
                pkt_rate, byte_rate, avg_pkt_sz, tcp_flags_syn, tcp_flags_ack, tcp_flags_rst,
                anomaly_score, attack_type, severity,
                mitre_id, mitre_technique, mitre_tactic, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session_id,
            flow_dict.get('src_ip'),
            flow_dict.get('dst_ip'),
            flow_dict.get('src_port'),
            flow_dict.get('dst_port'),
            flow_dict.get('protocol'),
            features.get('duration', 0.0),
            features.get('pkt_count_out', 0),
            features.get('pkt_count_in', 0),
            features.get('byte_count_out', 0),
            features.get('byte_count_in', 0),
            features.get('pkt_rate', 0.0),
            features.get('byte_rate', 0.0),
            features.get('avg_pkt_sz', 0.0),
            features.get('tcp_flags_syn', 0),
            features.get('tcp_flags_ack', 0),
            features.get('tcp_flags_rst', 0),
            flow_dict.get('anomaly_score', 0.0),
            attack_type,
            flow_dict.get('severity', 'Low'),
            mitre_data.get('mitre_id'),
            mitre_data.get('technique'),
            mitre_data.get('tactic'),
            'New'
        ))
        conn.commit()
        alert_id = cursor.lastrowid
        return alert_id
    except Exception as e:
        print(f"[-] Error inserting alert: {e}")
        return None
    finally:
        conn.close()

def get_alerts(session_id=None, severity=None, attack_type=None, limit=None):
    """Retrieves all alerts, optionally filtered by session_id, severity, and attack_type."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []
    
    if session_id:
        query += " AND session_id = ?"
        params.append(session_id)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if attack_type:
        query += " AND attack_type = ?"
        params.append(attack_type)
        
    query += " ORDER BY anomaly_score DESC"
    
    if limit:
        query += " LIMIT ?"
        params.append(int(limit))
        
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]

def get_alert_by_id(alert_id):
    """Retrieves a single alert's details by its ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_session_stats(session_id):
    """Calculates statistics for a specific session (severities, types, top IPs)."""
    alerts = get_alerts(session_id=session_id)
    if not alerts:
        return {
            "total_alerts": 0,
            "severities": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
            "attack_types": {},
            "top_sources": [],
            "top_destinations": [],
            "avg_anomaly_score": 0.0
        }
        
    total = len(alerts)
    sevs = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    types = {}
    src_ips = {}
    dst_ips = {}
    sum_anomaly = 0.0
    
    for a in alerts:
        sevs[a['severity']] = sevs.get(a['severity'], 0) + 1
        types[a['attack_type']] = types.get(a['attack_type'], 0) + 1
        src_ips[a['src_ip']] = src_ips.get(a['src_ip'], 0) + 1
        dst_ips[a['dst_ip']] = dst_ips.get(a['dst_ip'], 0) + 1
        sum_anomaly += a['anomaly_score']
        
    # Sort dictionaries by count desc
    top_src = sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:5]
    top_dst = sorted(dst_ips.items(), key=lambda x: x[1], reverse=True)[:5]
    
    return {
        "total_alerts": total,
        "severities": sevs,
        "attack_types": types,
        "top_sources": [{"ip": ip, "count": count} for ip, count in top_src],
        "top_destinations": [{"ip": ip, "count": count} for ip, count in top_dst],
        "avg_anomaly_score": sum_anomaly / total
    }

def get_all_sessions():
    """Lists all sessions in the system sorted by upload time desc."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sessions ORDER BY uploaded_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]
