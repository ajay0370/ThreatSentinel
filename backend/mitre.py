
MITRE_MAP = {
    "DDoS": {
        "mitre_id": "T1498.001",
        "technique": "Network Service Denial: Direct Network Flood",
        "tactic": "Impact",
        "description": "Adversaries may send packets to a target system in an attempt to overwhelm the system's capacity, denying services to legitimate users.",
        "mitigations": [
            "Implement rate limiting at network edge firewalls to block high-frequency incoming packets.",
            "Deploy a DDoS mitigation service or Web Application Firewall (WAF) to filter malicious traffic.",
            "Configure traffic shaping policies to prioritize legitimate customer traffic over unknown hosts.",
            "Configure firewall rules to block/drop traffic from offending IP ranges identified in the alerts."
        ]
    },
    "Port Scan": {
        "mitre_id": "T1046",
        "technique": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on target hosts to identify potential vulnerabilities and entry points.",
        "mitigations": [
            "Configure network firewalls to block inbound scanning behaviors (e.g., scan detection rules).",
            "Disable unused ports and services on production systems to reduce attack surface.",
            "Implement port knocking or VPN requirements for administrative ports (e.g., SSH, RDP).",
            "Configure Intrusion Detection/Prevention Systems (IDS/IPS) to automatically blacklist scanning IPs."
        ]
    },
    "Brute Force": {
        "mitre_id": "T1110",
        "technique": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute-forcing techniques to gain access to accounts by systematically guessing passwords or cryptographic keys.",
        "mitigations": [
            "Enforce strong password complexity requirements and regular password rotations.",
            "Implement Multi-Factor Authentication (MFA) on all external-facing remote administration ports.",
            "Configure account lockout policies (e.g., lockout for 30 minutes after 5 failed attempts).",
            "Deploy tools like Fail2ban to dynamically block IPs demonstrating repeated authentication failures."
        ]
    },
    "Zero-Day Anomaly": {
        "mitre_id": "T1071.001",
        "technique": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols to bypass network detection, exhibiting highly anomalous flow sizes or duration patterns.",
        "mitigations": [
            "Perform deep packet inspection (DPI) on the anomalous flows to analyze application-layer payloads.",
            "Isolate/quarantine the affected host immediately from the wider network to prevent lateral movement.",
            "Correlate the anomaly timestamp with host-side logs (syslog, event logs) to identify executing processes.",
            "Implement strict zero-trust network segmentation to restrict unauthorized communication channels."
        ]
    },
    "Normal": {
        "mitre_id": "N/A",
        "technique": "N/A",
        "tactic": "N/A",
        "description": "Normal network traffic behavior.",
        "mitigations": []
    }
}

def map_threat_to_mitre(attack_type):
    """Maps an attack type string to its corresponding MITRE ATT&CK details."""
    # Handle variations in naming
    if "ddos" in attack_type.lower():
        key = "DDoS"
    elif "port" in attack_type.lower() or "scan" in attack_type.lower():
        key = "Port Scan"
    elif "brute" in attack_type.lower() or "force" in attack_type.lower():
        key = "Brute Force"
    elif "anomaly" in attack_type.lower() or "zero" in attack_type.lower():
        key = "Zero-Day Anomaly"
    else:
        key = "Normal"
        
    return MITRE_MAP.get(key)
