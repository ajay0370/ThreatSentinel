import os
import uuid
import queue
import threading
from flask import Flask, request, jsonify, Response, send_file
from flask_cors import CORS
from dotenv import load_dotenv

# Load env variables from root folder and backend folder
load_dotenv()
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

# Resilient imports of ML and database modules
try:
    from ml_engine.pipeline import ThreatPipeline
except ImportError:
    try:
        import sys
        sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
        from ml_engine.pipeline import ThreatPipeline
    except ImportError:
        class ThreatPipeline:
            def __init__(self):
                self.loaded = False
            def process_pcap(self, pcap_path):
                return []

try:
    from backend.database import (
        init_db, create_session, update_session_status,
        insert_alert, get_alerts, get_alert_by_id, get_session_stats, get_all_sessions
    )
    from backend.gemini import explain_threat, chat_co_pilot, generate_ai_executive_summary
    from backend.report import generate_pdf_report
except ImportError:
    from database import (
        init_db, create_session, update_session_status,
        insert_alert, get_alerts, get_alert_by_id, get_session_stats, get_all_sessions
    )
    from gemini import explain_threat, chat_co_pilot, generate_ai_executive_summary
    from report import generate_pdf_report

app = Flask(__name__)
CORS(app) # Enable CORS for React dashboard communication

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Global map to manage active SSE queues per session_id
# Format: { session_id: [queue.Queue(), ...] }
sse_listeners = {}
sse_lock = threading.Lock()

# Initialize ML Pipeline
pipeline = ThreatPipeline()

# Initialize Database on startup
init_db()

def analyze_pcap_worker(session_id, file_path):
    """Background thread worker that parses the PCAP, analyses flows, and streams alerts via SSE."""
    print(f"[*] Background worker started for session {session_id} parsing '{file_path}'")
    try:
        # 1. Parse and analyze flows
        flows = pipeline.parse_pcap_to_flows(file_path)
        
        # 2. Iterate through flows and yield results
        for flow in flows:
            # Predict
            analysis = pipeline.analyze_flow(flow)
            
            # Combine alert dictionary
            alert_dict = {
                'src_ip': flow['src_ip'],
                'src_port': flow['src_port'],
                'dst_ip': flow['dst_ip'],
                'dst_port': flow['dst_port'],
                'protocol': flow['protocol'],
                'features': flow['features'],
                'anomaly_score': analysis['anomaly_score'],
                'attack_type': analysis['attack_type'],
                'severity': analysis['severity']
            }
            
            # Save to database
            alert_id = insert_alert(session_id, alert_dict)
            
            if alert_id:
                full_alert = get_alert_by_id(alert_id)
                # Broadcast alert to any active SSE listeners for this session
                with sse_lock:
                    if session_id in sse_listeners:
                        for q in sse_listeners[session_id]:
                            q.put(full_alert)
                            
        # 3. Update session status
        update_session_status(session_id, 'Completed')
        print(f"[+] Background analysis completed successfully for session {session_id}")
        
    except Exception as e:
        print(f"[-] Error in background analysis for session {session_id}: {e}")
        update_session_status(session_id, 'Failed')
    finally:
        # Broadcast termination signal to SSE listeners
        with sse_lock:
            if session_id in sse_listeners:
                for q in sse_listeners[session_id]:
                    q.put("done")

@app.route('/api/sessions', methods=['GET'])
def list_sessions():
    """Lists all historical and active analysis sessions."""
    try:
        sessions = get_all_sessions()
        return jsonify(sessions)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Endpoint to upload a PCAP file and launch the background analysis thread."""
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
        
    if not file.filename.endswith('.pcap'):
        return jsonify({"error": "Only .pcap files are supported"}), 400
        
    session_id = str(uuid.uuid4())
    filename = file.filename
    file_path = os.path.join(UPLOAD_FOLDER, f"{session_id}.pcap")
    file.save(file_path)
    
    # Register session in DB
    create_session(session_id, filename)
    
    # Start analysis in a separate thread
    threading.Thread(
        target=analyze_pcap_worker, 
        args=(session_id, file_path), 
        daemon=True
    ).start()
    
    return jsonify({
        "session_id": session_id,
        "filename": filename,
        "status": "Processing"
    })

@app.route('/api/alerts', methods=['GET'])
def fetch_alerts():
    """Retrieves threat alerts, filtered by session_id."""
    session_id = request.args.get('session_id')
    severity = request.args.get('severity')
    attack_type = request.args.get('attack_type')
    limit = request.args.get('limit')
    
    if not session_id:
        return jsonify({"error": "session_id query parameter is required"}), 400
        
    try:
        alerts = get_alerts(session_id=session_id, severity=severity, attack_type=attack_type, limit=limit)
        return jsonify(alerts)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/alerts/<int:alert_id>', methods=['GET'])
def fetch_alert_details(alert_id):
    """Retrieves details of a single threat alert."""
    try:
        alert = get_alert_by_id(alert_id)
        if not alert:
            return jsonify({"error": "Alert not found"}), 404
        return jsonify(alert)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/stream', methods=['GET'])
def stream_alerts():
    """SSE streaming endpoint that yields threat alerts for a session in real-time."""
    session_id = request.args.get('session_id')
    if not session_id:
        return Response("data: {\"error\": \"session_id is required\"}\n\n", mimetype="text/event-stream")
        
    def event_generator():
        # 1. Fetch and stream all existing alerts first
        existing_alerts = get_alerts(session_id=session_id)
        # Sort existing alerts chronologically by ID
        existing_alerts.sort(key=lambda x: x['id'])
        for a in existing_alerts:
            yield f"data: {import_json_str(a)}\n\n"
            
        # Check current session status
        conn = sse_listeners # just checking references
        # If already completed or failed, we don't need to subscribe
        import sqlite3
        db_conn = sqlite3.connect(os.path.join(os.path.dirname(os.path.abspath(__file__)), "threats.db"))
        db_conn.row_factory = sqlite3.Row
        cur = db_conn.cursor()
        cur.execute("SELECT status FROM sessions WHERE id = ?", (session_id,))
        row = cur.fetchone()
        status = row['status'] if row else "Failed"
        db_conn.close()
        
        if status in ['Completed', 'Failed']:
            yield "event: complete\ndata: analysis finished\n\n"
            return
            
        # 2. Subscribe to new alerts pushed by the background thread
        listener_queue = queue.Queue()
        with sse_lock:
            if session_id not in sse_listeners:
                sse_listeners[session_id] = []
            sse_listeners[session_id].append(listener_queue)
            
        print(f"[*] SSE Client connected to stream for session {session_id}")
        
        try:
            while True:
                # Wait for new alerts from worker thread
                alert = listener_queue.get()
                if alert == "done":
                    yield "event: complete\ndata: analysis finished\n\n"
                    break
                yield f"data: {import_json_str(alert)}\n\n"
        except GeneratorExit:
            print(f"[*] SSE Client disconnected from stream for session {session_id}")
        finally:
            # Clean up subscriber queue
            with sse_lock:
                if session_id in sse_listeners:
                    sse_listeners[session_id].remove(listener_queue)
                    if not sse_listeners[session_id]:
                        del sse_listeners[session_id]
                        
    return Response(event_generator(), mimetype="text/event-stream")

def import_json_str(data_dict):
    import json
    return json.dumps(data_dict)

@app.route('/api/explain', methods=['POST'])
def explain_threat_endpoint():
    """Endpoint to invoke Gemini (or fallback) to explain a threat alert."""
    data = request.json
    if not data or 'alert_id' not in data:
        return jsonify({"error": "alert_id is required"}), 400
        
    try:
        alert = get_alert_by_id(data['alert_id'])
        if not alert:
            return jsonify({"error": "Alert not found"}), 404
            
        explanation = explain_threat(alert)
        return jsonify({"explanation": explanation})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/chat', methods=['POST'])
def chat_copilot_endpoint():
    """Endpoint for interactive SOC chat co-pilot with active session statistics context."""
    data = request.json
    if not data or 'question' not in data or 'session_id' not in data:
        return jsonify({"error": "question and session_id are required"}), 400
        
    try:
        stats = get_session_stats(data['session_id'])
        response = chat_co_pilot(data['question'], stats)
        return jsonify({"response": response})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/report/generate', methods=['GET'])
def generate_report_endpoint():
    """Endpoint to generate, compile, and download the ReportLab PDF summary report."""
    session_id = request.args.get('session_id')
    if not session_id:
        return jsonify({"error": "session_id parameter is required"}), 400
        
    # Check if session exists
    conn = sqlite_check_session(session_id)
    if not conn:
        return jsonify({"error": "Session not found"}), 404
        
    filename = conn['filename']
    
    try:
        # 1. Fetch statistics
        stats = get_session_stats(session_id)
        
        # 2. Invoke Gemini (or fallback) to write AI Executive Summary
        ai_summary = generate_ai_executive_summary(stats)
        
        # 3. Create PDF
        pdf_filename = f"ThreatSentinel_Report_{session_id}.pdf"
        pdf_path = os.path.join(UPLOAD_FOLDER, pdf_filename)
        generate_pdf_report(session_id, filename, ai_summary, pdf_path)
        
        # 4. Send the compiled report
        return send_file(
            pdf_path, 
            mimetype="application/pdf", 
            as_attachment=True, 
            download_name=f"ThreatSentinel_Report_{filename.replace('.pcap', '')}.pdf"
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/stats/historical', methods=['GET'])
def get_historical_stats_endpoint():
    """Endpoint to fetch aggregated statistics and top alerts across all upload sessions."""
    try:
        import sqlite3
        db_conn = sqlite3.connect(os.path.join(os.path.dirname(os.path.abspath(__file__)), "threats.db"))
        db_conn.row_factory = sqlite3.Row
        cur = db_conn.cursor()
        
        # 1. Total sessions uploaded
        cur.execute("SELECT COUNT(*) as cnt FROM sessions")
        total_sessions = cur.fetchone()['cnt']
        
        # 2. Total threats detected (excluding Normal)
        cur.execute("SELECT COUNT(*) as cnt FROM alerts WHERE attack_type != 'Normal'")
        total_threats = cur.fetchone()['cnt']
        
        # 3. Severe threats detected (Critical & High)
        cur.execute("SELECT COUNT(*) as cnt FROM alerts WHERE severity IN ('Critical', 'High')")
        critical_threats = cur.fetchone()['cnt']
        
        # 4. Average anomaly score across all flows
        cur.execute("SELECT AVG(anomaly_score) as avg_score FROM alerts")
        avg_score = cur.fetchone()['avg_score'] or 0.0
        
        # 5. Top 15 alerts sorted by anomaly score desc, including their origin session filename
        cur.execute("""
            SELECT a.*, s.filename 
            FROM alerts a 
            JOIN sessions s ON a.session_id = s.id 
            WHERE a.attack_type != 'Normal' 
            ORDER BY a.anomaly_score DESC 
            LIMIT 15
        """)
        top_alerts = [dict(row) for row in cur.fetchall()]
        
        db_conn.close()
        
        return jsonify({
            "total_sessions": total_sessions,
            "total_threats": total_threats,
            "critical_threats": critical_threats,
            "avg_anomaly_score": avg_score,
            "top_alerts": top_alerts
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def sqlite_check_session(session_id):
    import sqlite3
    db_conn = sqlite3.connect(os.path.join(os.path.dirname(os.path.abspath(__file__)), "threats.db"))
    db_conn.row_factory = sqlite3.Row
    cur = db_conn.cursor()
    cur.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
    row = cur.fetchone()
    db_conn.close()
    return dict(row) if row else None

if __name__ == '__main__':
    print("[*] Starting ThreatSentinel Lite Flask API on port 5000...")
    app.run(host='0.0.0.0', port=5000, debug=True)
