import os
import sys
import joblib
import pandas as pd
import numpy as np
from scapy.all import rdpcap, IP, IPv6, TCP, UDP

def get_model_path(filename):
    """Finds the model file in multiple potential locations to support execution from root or backend folders."""
    possible_paths = [
        os.path.join("ml_engine", "models", filename),
        os.path.join("models", filename),
        os.path.join("..", "ml_engine", "models", filename),
        os.path.join("..", "models", filename),
    ]
    for p in possible_paths:
        if os.path.exists(p):
            return p
    # Fallback to current dir
    return filename

class ThreatPipeline:
    def __init__(self):
        # Load scaler and models
        scaler_path = get_model_path("scaler.pkl")
        if_path = get_model_path("isolation_forest.pkl")
        rf_path = get_model_path("random_forest.pkl")
        
        if not (os.path.exists(scaler_path) and os.path.exists(if_path) and os.path.exists(rf_path)):
            print("[-] Warning: Model files not found. Run training script first.")
            self.loaded = False
        else:
            try:
                self.scaler = joblib.load(scaler_path)
                self.if_model = joblib.load(if_path)
                self.rf_model = joblib.load(rf_path)
                self.loaded = True
                print("[+] Models successfully loaded in ThreatPipeline.")
            except Exception as e:
                print(f"[-] Error loading models: {e}")
                self.loaded = False

    def parse_pcap_to_flows(self, pcap_path):
        """Parses a PCAP file and aggregates packet details into bidirectional flows."""
        print(f"[*] Reading PCAP file '{pcap_path}'...")
        try:
            packets = rdpcap(pcap_path)
        except Exception as e:
            print(f"[-] Error reading PCAP file: {e}")
            return []

        print(f"[*] Parsing {len(packets)} packets...")
        flows = {}
        
        for i, pkt in enumerate(packets):
            # 1. Extract IP / IPv6 layer
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                proto = pkt[IP].proto
            elif pkt.haslayer(IPv6):
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst
                proto = pkt[IPv6].nh
            else:
                # Skip non-IP packets for flow analysis
                continue

            # 2. Extract TCP/UDP port info
            src_port = 0
            dst_port = 0
            syn_flag = 0
            ack_flag = 0
            rst_flag = 0

            if pkt.haslayer(TCP):
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                flags_str = str(pkt[TCP].flags)
                syn_flag = 1 if "S" in flags_str else 0
                ack_flag = 1 if "A" in flags_str else 0
                rst_flag = 1 if "R" in flags_str else 0
            elif pkt.haslayer(UDP):
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport

            # Skip common DNS or local traffic if it clutter metrics, or analyze all
            # Here we analyze all IP traffic.
            
            # 3. Create Bidirectional Flow Key
            # Sort (ip, port) pairs together, not IPs and ports independently.
            # Key format: tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)])) + (protocol,)
            endpoint_a = (src_ip, src_port)
            endpoint_b = (dst_ip, dst_port)
            sorted_endpoints = tuple(sorted([endpoint_a, endpoint_b]))
            flow_key = sorted_endpoints + (proto,)
            
            # Packet length / bytes
            pkt_len = len(pkt)
            pkt_time = float(pkt.time)
            
            if flow_key not in flows:
                flows[flow_key] = {
                    'start_time': pkt_time,
                    'end_time': pkt_time,
                    'initiator': endpoint_a, # The one who sent the first packet
                    'responder': endpoint_b,
                    'pkt_count_out': 1,
                    'pkt_count_in': 0,
                    'byte_count_out': pkt_len,
                    'byte_count_in': 0,
                    'tcp_flags_syn': syn_flag,
                    'tcp_flags_ack': ack_flag,
                    'tcp_flags_rst': rst_flag,
                    'protocol': proto
                }
            else:
                flow = flows[flow_key]
                flow['end_time'] = pkt_time
                
                # Check direction relative to flow initiator
                if endpoint_a == flow['initiator']:
                    flow['pkt_count_out'] += 1
                    flow['byte_count_out'] += pkt_len
                else:
                    flow['pkt_count_in'] += 1
                    flow['byte_count_in'] += pkt_len
                    
                flow['tcp_flags_syn'] += syn_flag
                flow['tcp_flags_ack'] += ack_flag
                flow['tcp_flags_rst'] += rst_flag

        # 4. Compute Features for each Flow
        flow_list = []
        for key, raw_flow in flows.items():
            duration = raw_flow['end_time'] - raw_flow['start_time']
            if duration < 0:
                duration = 0.0
                
            pkt_count_out = raw_flow['pkt_count_out']
            pkt_count_in = raw_flow['pkt_count_in']
            byte_count_out = raw_flow['byte_count_out']
            byte_count_in = raw_flow['byte_count_in']
            
            total_pkts = pkt_count_out + pkt_count_in
            total_bytes = byte_count_out + byte_count_in
            
            pkt_rate = total_pkts / duration if duration > 0 else 0.0
            byte_rate = total_bytes / duration if duration > 0 else 0.0
            avg_pkt_sz = total_bytes / total_pkts if total_pkts > 0 else 0.0
            
            # Save stats dictionary
            flow_stats = {
                'src_ip': raw_flow['initiator'][0],
                'src_port': raw_flow['initiator'][1],
                'dst_ip': raw_flow['responder'][0],
                'dst_port': raw_flow['responder'][1],
                'protocol': raw_flow['protocol'],
                'features': {
                    'duration': duration,
                    'pkt_count_out': pkt_count_out,
                    'pkt_count_in': pkt_count_in,
                    'byte_count_out': byte_count_out,
                    'byte_count_in': byte_count_in,
                    'pkt_rate': pkt_rate,
                    'byte_rate': byte_rate,
                    'avg_pkt_sz': avg_pkt_sz,
                    'tcp_flags_syn': raw_flow['tcp_flags_syn'],
                    'tcp_flags_ack': raw_flow['tcp_flags_ack'],
                    'tcp_flags_rst': raw_flow['tcp_flags_rst'],
                    'protocol': raw_flow['protocol']
                }
            }
            flow_list.append(flow_stats)
            
        print(f"[+] Extracted {len(flow_list)} unique bidirectional flows.")
        return flow_list

    def analyze_flow(self, flow):
        """Uses loaded ML models to analyze a single flow's features."""
        if not self.loaded:
            # Fallback if models are not loaded (simulate logic)
            features = flow['features']
            syn = features['tcp_flags_syn']
            rate = features['pkt_rate']
            
            # Simple heuristic backup
            if rate > 1000 and syn > 10:
                anomaly_score = 0.92
                attack_type = "DDoS"
            elif features['duration'] < 0.1 and features['pkt_count_out'] <= 2 and syn > 0:
                anomaly_score = 0.75
                attack_type = "Port Scan"
            elif features['pkt_count_out'] > 50 and features['duration'] > 5:
                anomaly_score = 0.65
                attack_type = "Brute Force"
            else:
                anomaly_score = 0.05
                attack_type = "Normal"
        else:
            features_dict = flow['features']
            # Reorder features to match training feature_cols
            feature_cols = [
                'duration', 'pkt_count_out', 'pkt_count_in', 
                'byte_count_out', 'byte_count_in', 'pkt_rate', 
                'byte_rate', 'avg_pkt_sz', 'tcp_flags_syn', 
                'tcp_flags_ack', 'tcp_flags_rst', 'protocol'
            ]
            X_row = [features_dict[col] for col in feature_cols]
            X_df = pd.DataFrame([X_row], columns=feature_cols)
            
            # Scale
            X_scaled = self.scaler.transform(X_df)
            
            # 1. Predict Anomaly Score using Isolation Forest
            # clf.score_samples returns the opposite of the anomaly score: [-1.0, 0.0]
            # Normal flows are near -0.5, anomalous flows are near -0.8 or -0.9
            score_raw = self.if_model.score_samples(X_scaled)[0]
            
            # Map score_raw (typically between -0.4 and -0.9) to a [0.0, 1.0] scale
            # We want more negative score_raw to yield higher anomaly_score
            # Let's map score_raw: -0.4 -> 0.0, -0.9 -> 1.0
            # formula: anomaly_score = (-score_raw - 0.4) / 0.5
            anomaly_score = (-score_raw - 0.4) / 0.5
            anomaly_score = float(np.clip(anomaly_score, 0.0, 1.0))
            
            # 2. Predict Attack Type using Random Forest
            class_idx = self.rf_model.predict(X_scaled)[0]
            classes = ['Normal', 'DDoS', 'Port Scan', 'Brute Force']
            attack_type = classes[class_idx]
            
            # Post-processing override: If RF classifies as Normal but anomaly score is very high, 
            # we can identify it as a Zero-Day Anomaly! This matches the capstone's zero-day aspect.
            if attack_type == "Normal" and anomaly_score > 0.60:
                attack_type = "Zero-Day Anomaly"

        # Calculate Severity Scoring (User Requested)
        # Critical > 0.85, High > 0.70, Medium > 0.60, Low otherwise
        if anomaly_score > 0.85:
            severity = "Critical"
        elif anomaly_score > 0.70:
            severity = "High"
        elif anomaly_score > 0.60:
            severity = "Medium"
        else:
            severity = "Low"
            
        return {
            'anomaly_score': anomaly_score,
            'attack_type': attack_type,
            'severity': severity
        }

    def process_pcap(self, pcap_path):
        """Processes a PCAP file end-to-end, returning flow details and threat analyses."""
        flows = self.parse_pcap_to_flows(pcap_path)
        results = []
        for flow in flows:
            analysis = self.analyze_flow(flow)
            
            results.append({
                'src_ip': flow['src_ip'],
                'src_port': flow['src_port'],
                'dst_ip': flow['dst_ip'],
                'dst_port': flow['dst_port'],
                'protocol': flow['protocol'],
                'features': flow['features'],
                'anomaly_score': analysis['anomaly_score'],
                'attack_type': analysis['attack_type'],
                'severity': analysis['severity']
            })
        return results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python pipeline.py <path_to_pcap>")
        sys.exit(1)
        
    pcap_file = sys.argv[1]
    pipeline = ThreatPipeline()
    if not pipeline.loaded:
        print("[-] Pipeline initialized in simulation fallback mode (no models loaded).")
    
    results = pipeline.process_pcap(pcap_file)
    print(f"\n[*] Top 10 Analyzed Flows:")
    # Sort by anomaly score desc
    results_sorted = sorted(results, key=lambda x: x['anomaly_score'], reverse=True)
    for res in results_sorted[:10]:
        print(f"Flow: {res['src_ip']}:{res['src_port']} -> {res['dst_ip']}:{res['dst_port']} | "
              f"Proto: {res['protocol']} | Type: {res['attack_type']} | "
              f"Score: {res['anomaly_score']:.3f} | Severity: {res['severity']}")
