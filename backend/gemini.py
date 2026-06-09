import os
import google.generativeai as genai

def get_gemini_client():
    """Configures and returns the Gemini API client if API key is present."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return None
    try:
        genai.configure(api_key=api_key)
        return genai.GenerativeModel('gemini-1.5-flash')
    except Exception as e:
        print(f"[-] Error configuring Gemini: {e}")
        return None

def explain_threat(alert):
    """Generates an explanation for a specific alert, using Gemini or falling back to a rule-based expert system."""
    model = get_gemini_client()
    
    # 1. Prepare alert variables
    src = f"{alert.get('src_ip')}:{alert.get('src_port')}"
    dst = f"{alert.get('dst_ip')}:{alert.get('dst_port')}"
    proto = "TCP" if alert.get('protocol') == 6 else ("UDP" if alert.get('protocol') == 17 else f"Proto {alert.get('protocol')}")
    score = alert.get('anomaly_score', 0.0)
    attack = alert.get('attack_type', 'Normal')
    severity = alert.get('severity', 'Low')
    mitre_id = alert.get('mitre_id', 'N/A')
    mitre_tech = alert.get('mitre_technique', 'N/A')
    mitre_tact = alert.get('mitre_tactic', 'N/A')
    
    if model:
        try:
            prompt = f"""You are an expert security analyst at ThreatSentinel. Analyze the following detected network threat alert:
- Source Endpoint: {src}
- Destination Endpoint: {dst}
- Protocol: {proto}
- Anomaly Score: {score:.4f}
- Classified Attack: {attack}
- Severity: {severity}
- MITRE ATT&CK Mapping: {mitre_tech} ({mitre_id}) - Tactic: {mitre_tact}

Provide a concise, professional, and direct explanation of:
1. What this threat means and the specific network behavior.
2. The potential impact on the host or network if left unmitigated.
3. 3-4 actionable remediation steps.

Keep the response under 250 words, using clean markdown formatting (bullet points, bold text). Avoid conversational filler."""
            
            response = model.generate_content(prompt)
            return response.text
        except Exception as e:
            print(f"[-] Gemini API failed: {e}. Falling back to rule-based explanation.")
            
    # 2. Local Fallback Expert System (Rule-based)
    return get_local_threat_explanation(attack, src, dst, proto, score, severity, mitre_id, mitre_tech, mitre_tact)

def chat_co_pilot(user_question, session_stats, history=None):
    """Handles chatbot conversations, providing session statistics as context to Gemini or local fallback."""
    model = get_gemini_client()
    
    # Format session context
    context = f"""[Active Session Context]
- Total Alerts Detected: {session_stats.get('total_alerts', 0)}
- Severity Counts: {session_stats.get('severities', {})}
- Attack Type Distribution: {session_stats.get('attack_types', {})}
- Top Source IPs: {', '.join([f"{item['ip']} ({item['count']})" for item in session_stats.get('top_sources', [])])}
- Top Destination IPs: {', '.join([f"{item['ip']} ({item['count']})" for item in session_stats.get('top_destinations', [])])}
- Average Anomaly Score: {session_stats.get('avg_anomaly_score', 0.0):.4f}"""

    if model:
        try:
            prompt = f"""You are ThreatSentinel Co-pilot, a helpful AI virtual security assistant for a Security Operations Center (SOC) analyst.
You have access to the active analysis session statistics below:
{context}

Analyst Question: "{user_question}"

Respond to the analyst's question using the session context if relevant. You can recommend mitigation plans, analyze IP behaviors, explain network protocols, or summarize active threats. Keep the response concise, authoritative, and focused on cybersecurity. Format with markdown."""
            
            response = model.generate_content(prompt)
            return response.text
        except Exception as e:
            print(f"[-] Gemini Chat API failed: {e}. Falling back to local chat.")

    # 3. Local Fallback Chatbot (Keyword-based)
    return get_local_chat_response(user_question, session_stats, context)

def generate_ai_executive_summary(session_stats):
    """Generates a professional 1-paragraph summary of the session alerts for the PDF report cover/summary page."""
    model = get_gemini_client()
    
    context = f"""- Total Alerts: {session_stats.get('total_alerts', 0)}
- Critical Alerts: {session_stats.get('severities', {}).get('Critical', 0)}
- High Alerts: {session_stats.get('severities', {}).get('High', 0)}
- Medium Alerts: {session_stats.get('severities', {}).get('Medium', 0)}
- Attack Types: {session_stats.get('attack_types', {})}
- Top Sources: {', '.join([f"{item['ip']}" for item in session_stats.get('top_sources', [])[:2]])}
- Average Anomaly Score: {session_stats.get('avg_anomaly_score', 0.0):.4f}"""

    if model:
        try:
            prompt = f"""You are a Senior Threat Intelligence Officer. Write a professional, 1-paragraph executive summary (approx 100-120 words) for a network traffic audit report.
Use the following session detection metrics:
{context}

Focus on summarizing the critical vulnerabilities, potential security compromises (e.g. DDoS, Port Scan), active attack originators, and overall network risk. Do not use bullet points or introductory greeting; start directly with the summary."""
            
            response = model.generate_content(prompt)
            return response.text
        except Exception as e:
            print(f"[-] Gemini Summary API failed: {e}. Falling back to local summary.")
            
    # Local fallback executive summary
    return get_local_executive_summary(session_stats)

# --- Local Fallback Implementation Details ---

def get_local_threat_explanation(attack, src, dst, proto, score, severity, mitre_id, mitre_tech, mitre_tact):
    """Constructs a detailed mock explanation based on the threat parameters."""
    explanation = f"### Threat Investigation: {attack} Detected\n\n"
    explanation += f"An alert with **{severity}** severity was raised on the flow **{src} → {dst}** ({proto}) with an anomaly index of **{score:.4f}**.\n\n"
    
    if attack == "DDoS":
        explanation += (
            "**Analysis:** This flow indicates a high-volume packet rate directed at the target host. "
            "The flow characteristics display a heavy outbound packet count with negligible inbound response, characteristic of a flood attack (e.g. SYN Flood). "
            "This behavior is mapped to MITRE ATT&CK technique **" + mitre_tech + " (" + mitre_id + ")** under the **" + mitre_tact + "** tactic.\n\n"
            "**Potential Impact:** Network bandwidth exhaustion, denial of service for legitimate traffic, and system resource starvation on the target machine.\n\n"
            "**Remediation Steps:**\n"
            "- Implement SYN cookies on the destination host to mitigate half-open TCP connections.\n"
            "- Set up firewall rate-limiting rules dropping traffic from the source IP if packet rate exceeds thresholds.\n"
            "- Engage upstream ISP or cloud DDoS protection (e.g. Cloudflare) to absorb the flood.\n"
            "- Restrict public access to target port if it is not critical."
        )
    elif attack == "Port Scan":
        explanation += (
            "**Analysis:** This activity indicates systematic scanning behavior where the source IP attempts to establish quick connections "
            "to multiple ports on the target host. The short flow duration (<0.05s) and very low packet counts (1-2 packets) are typical of TCP SYN scanning "
            "designed to map open ports. Mapped to MITRE technique **" + mitre_tech + " (" + mitre_id + ")**.\n\n"
            "**Potential Impact:** Host service mapping, vulnerability identification, and reconnaissance leading to targeted exploitation attempts.\n\n"
            "**Remediation Steps:**\n"
            "- Configure firewall rules to detect and block IP addresses scanning multiple ports sequentially.\n"
            "- Close or filter unused ports at the boundary firewall to minimize visibility.\n"
            "- Configure IDS/IPS to dynamically block scan sources for a 24-hour lockout window.\n"
            "- Ensure remote services (SSH/RDP) use non-standard ports or VPN controls."
        )
    elif attack == "Brute Force":
        explanation += (
            "**Analysis:** Multiple consecutive connection attempts were logged between the source IP and the target host. "
            "The flow exhibits regular byte intervals, sustained duration, and frequent TCP flags typical of credential-guessing attacks "
            "directed at authentication endpoints (e.g. SSH/RDP). Mapped to MITRE technique **" + mitre_tech + " (" + mitre_id + ")**.\n\n"
            "**Potential Impact:** Unauthorized credential access, account compromise, host system intrusion, and subsequent lateral movement.\n\n"
            "**Remediation Steps:**\n"
            "- Deploy Fail2ban to block the attacker IP after 3-5 failed login attempts.\n"
            "- Enable Multi-Factor Authentication (MFA) on the target service.\n"
            "- Enforce strong, non-dictionary password policies for all administrative accounts.\n"
            "- Disable root password logins, enforcing public-key-only authentication for SSH."
        )
    elif attack == "Zero-Day Anomaly":
        explanation += (
            "**Analysis:** Anomaly detection has flagged this flow due to outlier statistics (duration, byte/packet ratio) "
            "that differ significantly from baseline normal behavior. The supervised classifier could not match this to known signatures, "
            "indicating a potential zero-day attack or highly unusual data exfiltration. Mapped to MITRE technique **" + mitre_tech + " (" + mitre_id + ")**.\n\n"
            "**Potential Impact:** Exploitation of unpatched software, data exfiltration via stealthy channels, or rogue outbound Command & Control traffic.\n\n"
            "**Remediation Steps:**\n"
            "- Isolate the affected source/destination system from critical networks to limit potential lateral movement.\n"
            "- Inspect the packet payload (via Wireshark or PCAP logs) to determine the exact payload headers and fields.\n"
            "- Audit target host processes running at the timestamp of this flow.\n"
            "- Review system patches and update local IDS signatures to cover this anomaly type."
        )
    else:
        explanation += (
            "**Analysis:** The traffic pattern matches baseline parameters. No critical anomalies or attack signatures were recognized.\n\n"
            "**Remediation Steps:** No immediate actions required. Continue routine monitoring."
        )
        
    return explanation

def get_local_chat_response(question, stats, context):
    """Simulates chatbot responses for a offline fallback, referencing the session stats context."""
    q = question.lower()
    total = stats.get('total_alerts', 0)
    sevs = stats.get('severities', {})
    types = stats.get('attack_types', {})
    
    response = "### ThreatSentinel Co-pilot (Local Expert Fallback Mode)\n\n"
    
    if total == 0:
        return response + "It looks like there is no active session data yet. Please upload a PCAP file so I can analyze the details and assist you!"

    if "summary" in q or "status" in q or "overview" in q or "active" in q:
        response += (
            f"Here is a summary of the active session:\n\n"
            f"- We analyzed a total of **{total}** network flows.\n"
            f"- Out of these, we detected **{sevs.get('Critical', 0)} Critical** and **{sevs.get('High', 0)} High** severity alerts.\n"
            f"- The breakdown of attacks is: " + ", ".join([f"**{k}** ({v})" for k, v in types.items()]) + ".\n"
            f"- The average flow anomaly score is **{stats.get('avg_anomaly_score', 0.0):.3f}**.\n\n"
            f"Please let me know if you want detailed mitigation steps for any of these specific threats."
        )
    elif "ddos" in q or "flood" in q:
        count = types.get('DDoS', 0)
        response += (
            f"Our models identified **{count} DDoS** alerts in this session.\n\n"
            "To contain this, you should immediately:\n"
            "1. **Identify the targets:** Look at the top destination IPs (e.g. " + ", ".join([item['ip'] for item in stats.get('top_destinations', [])[:2]]) + ").\n"
            "2. **Implement rate limiting:** Configure firewall rules at the boundary router to drop traffic from the attacking source IPs.\n"
            "3. **Enable SYN Cookies:** If target ports are TCP/80 or TCP/443, enable TCP SYN Cookies on target servers."
        )
    elif "scan" in q or "port" in q:
        count = types.get('Port Scan', 0)
        response += (
            f"We detected **{count} Port Scan** events.\n\n"
            "Port scanning indicates reconnaissance. The source is surveying your network ports. I recommend:\n"
            "- Blocking the scanning source IP immediately using a null route or firewall drop rule.\n"
            "- Running a local host scan audit to ensure no unnecessary services are exposed to public interfaces."
        )
    elif "brute" in q or "force" in q or "ssh" in q:
        count = types.get('Brute Force', 0)
        response += (
            f"We detected **{count} Brute Force** attempts, likely targeting authentication endpoints like SSH (port 22) or RDP (port 3389).\n\n"
            "**Incident Response Plan:**\n"
            "1. Temporary IP lockout: Use Fail2ban or active firewall rules to drop the source IP.\n"
            "2. Switch to public-key authentication for SSH and disable password logins.\n"
            "3. Ensure all accounts have multi-factor authentication (MFA) active."
        )
    elif "zero" in q or "anomaly" in q or "anomalies" in q:
        count = types.get('Zero-Day Anomaly', 0) + types.get('Anomaly', 0)
        response += (
            f"**Zero-Day Threat Briefing:**\n\n"
            "A **Zero-Day attack** is a security vulnerability or exploit that is unknown to software vendors and security systems. "
            "Because no official patch, signature, or rule exists, traditional signature-based security systems (antivirus/firewalls) cannot detect it.\n\n"
            f"**Detection in this Session:** We identified **{count} Zero-Day Anomaly** flow(s) using our unsupervised ML model (Isolation Forest). "
            "These flows exhibited statistics (such as abnormal duration, byte-to-packet ratios, or TCP flag distributions) "
            "that deviate significantly from normal baseline traffic, despite not matching known threat signatures.\n\n"
            "**Recommended Actions:**\n"
            "1. **Isolate Target Systems:** Quarantine the affected hosts immediately.\n"
            "2. **Payload Inspection:** Open the PCAP in Wireshark and examine raw packet payloads for command-and-control (C2) or data exfiltration footprints.\n"
            "3. **Process Audit:** Check local system logs and process lists on the target host at the timestamp of the alert."
        )
    elif "mitigate" in q or "remediate" in q or "fix" in q:
        response += (
            "To mitigate the current threats, follow these priorities based on severity:\n\n"
        )
        if sevs.get('Critical', 0) > 0:
            response += "- **Critical Alerts (DDoS/Zero-Day):** Restrict traffic from attacking source IPs immediately and isolate affected subnets.\n"
        if sevs.get('High', 0) > 0:
            response += "- **High Alerts (Brute Force):** Block source IPs at the firewall and verify target host credentials.\n"
        if sevs.get('Medium', 0) > 0:
            response += "- **Medium Alerts (Port Scan):** Null route scanning IPs and close unused open ports.\n"
        response += "\nYou can download the full PDF summary report using the 'Report Download' button on the dashboard for detailed, printable remediation sheets."
    else:
        response += (
            "I am ready to help you investigate these security alerts. You can ask me questions like:\n"
            "- *Can you summarize the active threats?*\n"
            "- *How do I mitigate the DDoS alerts?*\n"
            "- *What should I do about the Brute Force activity?*\n"
            "- *Explain the zero-day anomalies detected.*\n\n"
            f"**Current Session Stats:** {total} total alerts, avg anomaly index: {stats.get('avg_anomaly_score', 0.0):.3f}."
        )
        
    return response

def get_local_executive_summary(stats):
    """Generates a professional mock paragraph summary for reports."""
    total = stats.get('total_alerts', 0)
    critical = stats.get('severities', {}).get('Critical', 0)
    high = stats.get('severities', {}).get('High', 0)
    types_list = [f"{v} {k} flow(s)" for k, v in stats.get('attack_types', {}).items() if k != 'Normal']
    types_str = ", ".join(types_list) if types_list else "no known attacks"
    
    summary = (
        f"During this traffic analysis session, ThreatSentinel audited {total} network connections. "
        f"A total of {critical + high} high-severity security threats were identified, encompassing {types_str}. "
        f"The average anomaly score was logged at {stats.get('avg_anomaly_score', 0.0):.3f}, highlighting several outlying communication signatures "
        f"that present risk. Immediate tactical isolation of active malicious source hosts and rate-limiting at network firewalls is highly recommended "
        f"to prevent service interruptions or unauthorized access."
    )
    return summary
