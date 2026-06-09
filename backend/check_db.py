# Database Inspector Utility for ThreatSentinel Lite
import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "threats.db")

def main():
    if not os.path.exists(DB_PATH):
        print(f"[-] Database file '{DB_PATH}' does not exist yet. Please upload a PCAP file on the dashboard first to initialize and populate it!")
        return

    print("====================================================")
    print(f" Inspecting ThreatSentinel Database: {DB_PATH}")
    print("====================================================\n")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 1. Inspect Sessions Table
    print("[*] Table: sessions")
    cursor.execute("SELECT * FROM sessions")
    sessions = cursor.fetchall()
    if not sessions:
        print("  (No session records found)")
    else:
        for s in sessions:
            print(f"  - Session ID: {s['id']}")
            print(f"    File Name:  {s['filename']}")
            print(f"    Uploaded:   {s['uploaded_at']}")
            print(f"    Status:     {s['status']}")
            print("-" * 40)

    # 2. Inspect Alerts Table Summary
    print("\n[*] Table: alerts (Logged Threats)")
    cursor.execute("SELECT COUNT(*) as cnt FROM alerts")
    total_alerts = cursor.fetchone()['cnt']
    print(f"  - Total alerts stored: {total_alerts}")

    if total_alerts > 0:
        print("\n  - Sample Alerts (Top 5 highest anomaly scores):")
        cursor.execute("""
            SELECT id, src_ip, dst_ip, attack_type, severity, anomaly_score 
            FROM alerts 
            ORDER BY anomaly_score DESC 
            LIMIT 5
        """)
        alerts = cursor.fetchall()
        for a in alerts:
            print(f"    [{a['severity']}] ID: {a['id']} | {a['src_ip']} -> {a['dst_ip']} | Type: {a['attack_type']} (Score: {a['anomaly_score']:.3f})")
    
    conn.close()
    print("\n====================================================")

if __name__ == "__main__":
    main()
