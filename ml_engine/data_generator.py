import os
import random
import pandas as pd
import numpy as np
from scapy.all import Ether, IP, TCP, UDP, wrpcap

def generate_csv_data(output_path, num_samples=3000):
    """Generates a synthetic CSV containing 12 network features for normal and attack flows."""
    print(f"[*] Generating synthetic flow statistics ({num_samples} samples)...")
    
    np.random.seed(42)
    random.seed(42)
    
    data = []
    classes = ['Normal', 'DDoS', 'Port Scan', 'Brute Force']
    
    for _ in range(num_samples):
        # Determine flow class
        # 60% Normal, 15% DDoS, 15% Port Scan, 10% Brute Force
        flow_class = random.choices(classes, weights=[0.60, 0.15, 0.15, 0.10], k=1)[0]
        
        if flow_class == 'Normal':
            duration = random.uniform(1.0, 120.0)
            pkt_count_out = random.randint(5, 50)
            pkt_count_in = random.randint(5, 100)
            byte_count_out = pkt_count_out * random.randint(64, 1000)
            byte_count_in = pkt_count_in * random.randint(64, 1200)
            tcp_flags_syn = random.randint(1, 3)
            tcp_flags_ack = pkt_count_out + pkt_count_in - tcp_flags_syn
            tcp_flags_rst = random.choices([0, 1], weights=[0.95, 0.05], k=1)[0]
            protocol = random.choices([6, 17], weights=[0.70, 0.30], k=1)[0] # TCP or UDP
            
        elif flow_class == 'DDoS':
            duration = random.uniform(0.01, 0.5)
            pkt_count_out = random.randint(1000, 5000)
            pkt_count_in = random.randint(0, 5)
            byte_count_out = pkt_count_out * random.randint(500, 1200)
            byte_count_in = pkt_count_in * random.randint(64, 500)
            tcp_flags_syn = pkt_count_out # high volume of SYNs
            tcp_flags_ack = pkt_count_in
            tcp_flags_rst = random.randint(0, 10)
            protocol = random.choices([6, 17], weights=[0.80, 0.20], k=1)[0]
            
        elif flow_class == 'Port Scan':
            duration = random.uniform(0.001, 0.05)
            pkt_count_out = random.randint(1, 2)
            pkt_count_in = random.choices([0, 1], weights=[0.80, 0.20], k=1)[0]
            byte_count_out = pkt_count_out * random.randint(40, 60)
            byte_count_in = pkt_count_in * random.randint(40, 60)
            tcp_flags_syn = pkt_count_out
            tcp_flags_ack = pkt_count_in
            tcp_flags_rst = random.choices([0, 1], weights=[0.50, 0.50], k=1)[0]
            protocol = 6 # TCP mostly for scan
            
        elif flow_class == 'Brute Force':
            duration = random.uniform(5.0, 30.0)
            pkt_count_out = random.randint(50, 200)
            pkt_count_in = random.randint(50, 200)
            byte_count_out = pkt_count_out * random.randint(80, 150)
            byte_count_in = pkt_count_in * random.randint(80, 200)
            tcp_flags_syn = random.randint(5, 15)
            tcp_flags_ack = pkt_count_out + pkt_count_in - tcp_flags_syn - random.randint(0, 5)
            tcp_flags_rst = random.randint(0, 5)
            protocol = 6 # TCP
            
        # Calculate rates
        total_pkts = pkt_count_out + pkt_count_in
        total_bytes = byte_count_out + byte_count_in
        pkt_rate = total_pkts / duration if duration > 0 else 0
        byte_rate = total_bytes / duration if duration > 0 else 0
        avg_pkt_sz = total_bytes / total_pkts if total_pkts > 0 else 0
        
        # Label mapping
        # Normal=0, DDoS=1, Port Scan=2, Brute Force=3
        label = classes.index(flow_class)
        
        data.append({
            'duration': duration,
            'pkt_count_out': pkt_count_out,
            'pkt_count_in': pkt_count_in,
            'byte_count_out': byte_count_out,
            'byte_count_in': byte_count_in,
            'pkt_rate': pkt_rate,
            'byte_rate': byte_rate,
            'avg_pkt_sz': avg_pkt_sz,
            'tcp_flags_syn': tcp_flags_syn,
            'tcp_flags_ack': tcp_flags_ack,
            'tcp_flags_rst': tcp_flags_rst,
            'protocol': protocol,
            'label': label
        })
        
    df = pd.DataFrame(data)
    df.to_csv(output_path, index=False)
    print(f"[+] Saved synthetic CSV to {output_path}")

def generate_pcap(output_pcap):
    """Generates an actual PCAP containing synthetic network packets representing various flow categories."""
    print(f"[*] Generating test PCAP file '{output_pcap}' using Scapy...")
    
    packets = []
    
    # 1. Normal HTTP Session Simulation
    # Src: 192.168.1.50, Dst: 93.184.216.34 (example.com), ports 49210 -> 80
    src_ip = "192.168.1.50"
    dst_ip = "93.184.216.34"
    sport = 49210
    dport = 80
    
    # TCP Handshake
    t = 100.0
    packets.append(Ether()/IP(src=src_ip, dst=dst_ip, proto=6)/TCP(sport=sport, dport=dport, flags="S", seq=1000)/"") # SYN
    packets[-1].time = t
    t += 0.05
    packets.append(Ether()/IP(src=dst_ip, dst=src_ip, proto=6)/TCP(sport=dport, dport=sport, flags="SA", seq=2000, ack=1001)/"") # SYN-ACK
    packets[-1].time = t
    t += 0.05
    packets.append(Ether()/IP(src=src_ip, dst=dst_ip, proto=6)/TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=2001)/"") # ACK
    packets[-1].time = t
    t += 0.1
    
    # HTTP Request & Response
    packets.append(Ether()/IP(src=src_ip, dst=dst_ip, proto=6)/TCP(sport=sport, dport=dport, flags="PA", seq=1001, ack=2001)/"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    packets[-1].time = t
    t += 0.1
    packets.append(Ether()/IP(src=dst_ip, dst=src_ip, proto=6)/TCP(sport=dport, dport=sport, flags="PA", seq=2001, ack=1500)/"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n[Data]")
    packets[-1].time = t
    t += 0.2
    
    # TCP Connection Teardown
    packets.append(Ether()/IP(src=src_ip, dst=dst_ip, proto=6)/TCP(sport=sport, dport=dport, flags="FA", seq=1500, ack=2101)/"") # FIN-ACK
    packets[-1].time = t
    t += 0.05
    packets.append(Ether()/IP(src=dst_ip, dst=src_ip, proto=6)/TCP(sport=dport, dport=sport, flags="FA", seq=2101, ack=1501)/"") # FIN-ACK
    packets[-1].time = t
    t += 0.05
    packets.append(Ether()/IP(src=src_ip, dst=dst_ip, proto=6)/TCP(sport=sport, dport=dport, flags="A", seq=1501, ack=2102)/"") # ACK
    packets[-1].time = t
    
    # 2. Port Scan Simulation
    # Src: 10.0.0.5, Dst: 10.0.0.100, scanning TCP ports 20-50
    scanner_ip = "10.0.0.5"
    target_ip = "10.0.0.100"
    t = 200.0
    for port in range(20, 51):
        # Send SYN
        packets.append(Ether()/IP(src=scanner_ip, dst=target_ip, proto=6)/TCP(sport=random.randint(50000, 60000), dport=port, flags="S")/"")
        packets[-1].time = t
        t += 0.005
        # 10.0.0.100 responds with RST/ACK on some ports (e.g. closed ports)
        if port not in [22, 80]:
            packets.append(Ether()/IP(src=target_ip, dst=scanner_ip, proto=6)/TCP(sport=port, dport=packets[-1][TCP].sport, flags="RA")/"")
            packets[-1].time = t
            t += 0.002
            
    # 3. DDoS (SYN Flood) Simulation
    # Multiple spoofed IPs -> Target: 192.168.1.100, port 80
    ddos_target = "192.168.1.100"
    t = 300.0
    for i in range(150):
        spoofed_src = f"172.16.5.{random.randint(1, 254)}"
        packets.append(Ether()/IP(src=spoofed_src, dst=ddos_target, proto=6)/TCP(sport=random.randint(1024, 65535), dport=80, flags="S")/"")
        packets[-1].time = t
        t += 0.001 # rapid rate
        
    # 4. SSH Brute Force Simulation
    # Src: 203.0.113.50, Dst: 192.168.1.100, port 22. Multiple rapid attempts
    attacker_ip = "203.0.113.50"
    ssh_target = "192.168.1.100"
    sport = 38402
    dport = 22
    t = 400.0
    for attempt in range(5): # 5 sequential login sessions
        # SYN
        packets.append(Ether()/IP(src=attacker_ip, dst=ssh_target, proto=6)/TCP(sport=sport, dport=dport, flags="S")/"")
        packets[-1].time = t
        t += 0.01
        # SYN-ACK
        packets.append(Ether()/IP(src=ssh_target, dst=attacker_ip, proto=6)/TCP(sport=dport, dport=sport, flags="SA")/"")
        packets[-1].time = t
        t += 0.01
        # ACK
        packets.append(Ether()/IP(src=attacker_ip, dst=ssh_target, proto=6)/TCP(sport=sport, dport=dport, flags="A")/"")
        packets[-1].time = t
        t += 0.05
        
        # Banner exchange & cipher negotiations (10 packets)
        for _ in range(5):
            packets.append(Ether()/IP(src=attacker_ip, dst=ssh_target, proto=6)/TCP(sport=sport, dport=dport, flags="PA")/"SSH authentication data")
            packets[-1].time = t
            t += 0.02
            packets.append(Ether()/IP(src=ssh_target, dst=attacker_ip, proto=6)/TCP(sport=dport, dport=sport, flags="PA")/"SSH auth response")
            packets[-1].time = t
            t += 0.02
            
        # Attacker connection reset / close
        packets.append(Ether()/IP(src=attacker_ip, dst=ssh_target, proto=6)/TCP(sport=sport, dport=dport, flags="R")/"") # RST
        packets[-1].time = t
        t += 0.5
        sport += 1 # next attempt uses a new port
        
    # Write packets to PCAP
    wrpcap(output_pcap, packets)
    print(f"[+] Saved test PCAP to {output_pcap} with {len(packets)} packets")

if __name__ == "__main__":
    os.makedirs("ml_engine", exist_ok=True)
    os.makedirs("ml_engine/models", exist_ok=True)
    generate_csv_data("ml_engine/synthetic_flows.csv", 4000)
    generate_pcap("ml_engine/sample_traffic.pcap")
