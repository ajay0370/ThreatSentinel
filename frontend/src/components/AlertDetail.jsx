import React, { useState, useEffect } from 'react';
import { X, Sparkles, Loader2, Shield, Info, ShieldAlert } from 'lucide-react';

export default function AlertDetail({ alert, onClose, onUpdateStatus }) {
  const [explanation, setExplanation] = useState('');
  const [loading, setLoading] = useState(false);

  // Reset explanation when alert changes
  useEffect(() => {
    setExplanation('');
  }, [alert.id]);

  const fetchAIExplanation = async () => {
    setLoading(true);
    try {
      const response = await fetch('http://localhost:5000/api/explain', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ alert_id: alert.id }),
      });

      if (!response.ok) {
        throw new Error('Failed to fetch explanation');
      }

      const data = await response.json();
      setExplanation(data.explanation);
    } catch (err) {
      console.error(err);
      setExplanation('### Error\nFailed to fetch AI explanation. Please check backend connection.');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    switch(severity) {
      case 'Critical': return 'var(--color-critical)';
      case 'High': return 'var(--color-high)';
      case 'Medium': return 'var(--color-medium)';
      default: return 'var(--color-low)';
    }
  };

  const getProtoName = (pNum) => {
    if (pNum === 6) return 'TCP';
    if (pNum === 17) return 'UDP';
    if (pNum === 1) return 'ICMP';
    return `Proto ${pNum}`;
  };

  // Quick rendering of mitigations as checklist
  const mitigations = alert.mitre_id !== 'N/A' 
    ? getLocalMitigations(alert.attack_type) 
    : [];

  return (
    <div className="glass-panel" style={styles.container}>
      {/* Header */}
      <div style={styles.header}>
        <div style={styles.titleGroup}>
          <ShieldAlert size={20} color={getSeverityColor(alert.severity)} />
          <h3 style={styles.title}>Flow Investigation</h3>
        </div>
        <button onClick={onClose} style={styles.closeBtn}>
          <X size={18} color="var(--text-secondary)" />
        </button>
      </div>

      <div className="custom-scroll" style={styles.body}>
        {/* Basic Threat Info Card */}
        <div style={styles.threatCard}>
          <div style={styles.threatHeader}>
            <span style={{...styles.badge, borderColor: getSeverityColor(alert.severity), color: getSeverityColor(alert.severity)}}>
              {alert.severity} Severity
            </span>
            <span style={styles.attackType}>{alert.attack_type}</span>
          </div>
          <div style={styles.flowEndpoints}>
            <div style={styles.endpoint}>
              <span style={styles.label}>SOURCE IP</span>
              <span style={styles.value}>{alert.src_ip}:{alert.src_port}</span>
            </div>
            <div style={styles.endpoint}>
              <span style={styles.label}>DESTINATION IP</span>
              <span style={styles.value}>{alert.dst_ip}:{alert.dst_port}</span>
            </div>
          </div>
          <div style={styles.flowMeta}>
            <span>Protocol: <b>{getProtoName(alert.protocol)}</b></span>
            <span>Anomaly Score: <b>{alert.anomaly_score.toFixed(4)}</b></span>
          </div>
        </div>

        {/* Action Panel */}
        <div style={styles.actionPanel}>
          <span style={styles.sectionTitle}>Mitigation Status</span>
          <div style={styles.statusButtons}>
            <button 
              onClick={() => onUpdateStatus(alert.id, 'New')}
              style={{...styles.statusBtn, backgroundColor: alert.status === 'New' ? 'rgba(239, 68, 68, 0.15)' : 'transparent', borderColor: alert.status === 'New' ? 'var(--color-critical)' : 'var(--border-light)'}}
            >
              🔴 New
            </button>
            <button 
              onClick={() => onUpdateStatus(alert.id, 'In Progress')}
              style={{...styles.statusBtn, backgroundColor: alert.status === 'In Progress' ? 'rgba(234, 179, 8, 0.15)' : 'transparent', borderColor: alert.status === 'In Progress' ? 'var(--color-medium)' : 'var(--border-light)'}}
            >
              🟡 In Progress
            </button>
            <button 
              onClick={() => onUpdateStatus(alert.id, 'Resolved')}
              style={{...styles.statusBtn, backgroundColor: alert.status === 'Resolved' ? 'rgba(16, 185, 129, 0.15)' : 'transparent', borderColor: alert.status === 'Resolved' ? 'var(--color-normal)' : 'var(--border-light)'}}
            >
              🟢 Resolved
            </button>
          </div>
        </div>

        {/* AI Co-Pilot Explainer Section */}
        <div style={styles.aiSection}>
          <div style={styles.aiHeader}>
            <Sparkles size={16} color="var(--color-medium)" />
            <span style={styles.aiTitle}>ThreatSentinel Co-Pilot</span>
          </div>
          
          {explanation ? (
            <div style={styles.aiExplanation}>
              {explanation.split('\n').map((line, idx) => {
                if (line.startsWith('### ')) {
                  return <h4 key={idx} style={styles.mdH4}>{line.replace('### ', '')}</h4>;
                } else if (line.startsWith('**') && line.endsWith('**')) {
                  return <p key={idx} style={styles.mdBold}>{line.replace(/\*\*/g, '')}</p>;
                } else if (line.startsWith('- ')) {
                  return <li key={idx} style={styles.mdLi}>{line.replace('- ', '')}</li>;
                } else if (line.trim() !== '') {
                  // handle inline bolding simply for demo
                  return <p key={idx} style={styles.mdPara}>{line.replace(/\*\*/g, '')}</p>;
                }
                return null;
              })}
            </div>
          ) : (
            <div style={styles.aiPrompt}>
              <p style={styles.aiPromptText}>Request an on-demand AI analysis to break down the network mechanics of this threat, understand the attack impact, and view tailored remediation steps.</p>
              <button 
                onClick={fetchAIExplanation} 
                disabled={loading}
                style={styles.aiBtn}
              >
                {loading ? (
                  <>
                    <Loader2 size={16} className="spinner" style={{ marginRight: '8px', animation: 'spin 2s linear infinite' }} />
                    Analyzing Threat...
                  </>
                ) : (
                  <>
                    <Sparkles size={16} style={{ marginRight: '8px' }} />
                    Explain Alert with AI
                  </>
                )}
              </button>
            </div>
          )}
        </div>

        {/* MITRE ATT&CK Info Card */}
        {alert.mitre_id !== 'N/A' && (
          <div style={styles.card}>
            <div style={styles.cardHeader}>
              <Shield size={16} color="var(--accent-primary)" />
              <span style={styles.cardTitle}>MITRE ATT&CK Information</span>
            </div>
            <div style={styles.mitreGrid}>
              <div style={styles.mitreCol}>
                <span style={styles.label}>TECHNIQUE ID</span>
                <span style={styles.mitreBadge}>{alert.mitre_id}</span>
              </div>
              <div style={styles.mitreCol}>
                <span style={styles.label}>TACTIC</span>
                <span style={styles.mitreTacticBadge}>{alert.mitre_tactic}</span>
              </div>
            </div>
            <p style={styles.mitreTechnique}><b>Technique:</b> {alert.mitre_technique}</p>
            
            <div style={styles.mitigationsSection}>
              <span style={styles.mitigationHeading}>Tactical Safeguards:</span>
              <ul style={styles.mitigationList}>
                {mitigations.map((mit, idx) => (
                  <li key={idx} style={styles.mitigationItem}>
                    <input type="checkbox" defaultChecked={alert.status === 'Resolved'} style={styles.checkbox} readOnly />
                    <span>{mit}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}

        {/* Raw Flow Statistics */}
        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <Info size={16} color="var(--text-secondary)" />
            <span style={styles.cardTitle}>Raw Flow Statistics</span>
          </div>
          <div style={styles.statsGrid}>
            <div style={styles.statRow}><span style={styles.statLabel}>Flow Duration:</span><span style={styles.statVal}>{alert.duration.toFixed(4)} s</span></div>
            <div style={styles.statRow}><span style={styles.statLabel}>Packets (Outbound):</span><span style={styles.statVal}>{alert.pkt_count_out}</span></div>
            <div style={styles.statRow}><span style={styles.statLabel}>Packets (Inbound):</span><span style={styles.statVal}>{alert.pkt_count_in}</span></div>
            <div style={styles.statRow}><span style={styles.statLabel}>Bytes (Outbound):</span><span style={styles.statVal}>{alert.byte_count_out.toLocaleString()} B</span></div>
            <div style={styles.statRow}><span style={styles.statLabel}>Bytes (Inbound):</span><span style={styles.statVal}>{alert.byte_count_in.toLocaleString()} B</span></div>
            <div style={styles.statRow}><span style={styles.statLabel}>Packet Transmission Rate:</span><span style={styles.statVal}>{alert.pkt_rate.toFixed(1)} pkts/s</span></div>
            <div style={styles.statRow}><span style={styles.statLabel}>Byte Transmission Rate:</span><span style={styles.statVal}>{alert.byte_rate.toFixed(1)} B/s</span></div>
            <div style={styles.statRow}><span style={styles.statLabel}>Avg Packet Size:</span><span style={styles.statVal}>{alert.avg_pkt_sz.toFixed(1)} B</span></div>
            <div style={styles.statRow}><span style={styles.statLabel}>SYN Count / ACK Count / RST Count:</span><span style={styles.statVal}>{alert.tcp_flags_syn} / {alert.tcp_flags_ack} / {alert.tcp_flags_rst}</span></div>
          </div>
        </div>
      </div>
    </div>
  );
}

// Local mitigation lists for fallback UI completeness
function getLocalMitigations(attack) {
  if (attack === 'DDoS') {
    return [
      "Implement rate limiting at network edge firewalls to block high-frequency incoming packets.",
      "Deploy a DDoS mitigation service or WAF to filter malicious traffic.",
      "Configure traffic shaping policies to prioritize legitimate traffic.",
      "Configure firewall rules to drop traffic from offending IP ranges."
    ];
  }
  if (attack === 'Port Scan') {
    return [
      "Configure network firewalls to block inbound scanning behaviors.",
      "Disable unused ports and services on production systems.",
      "Implement port knocking or VPN requirements for SSH/RDP.",
      "Configure IDS/IPS to automatically blacklist scanning IPs."
    ];
  }
  if (attack === 'Brute Force') {
    return [
      "Enforce strong password complexity requirements.",
      "Implement Multi-Factor Authentication (MFA) on remote administration ports.",
      "Configure account lockout policies after 5 failed attempts.",
      "Deploy tools like Fail2ban to dynamically block brute force source IPs."
    ];
  }
  return [
    "Perform deep packet inspection on the anomalous flow.",
    "Isolate/quarantine the affected host from the wider network.",
    "Correlate the anomaly timestamp with host-side event logs.",
    "Implement strict zero-trust network segmentation."
  ];
}

const styles = {
  container: {
    width: '420px',
    height: '100%',
    borderLeft: '1px solid var(--border-light)',
    display: 'flex',
    flexDirection: 'column',
    flexShrink: 0,
    animation: 'fadeIn 0.2s ease-out forwards',
  },
  header: {
    padding: '20px 24px',
    borderBottom: '1px solid var(--border-light)',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  titleGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  },
  title: {
    fontSize: '16px',
    fontWeight: '700',
    color: 'var(--text-primary)',
  },
  closeBtn: {
    backgroundColor: 'transparent',
    border: 'none',
    cursor: 'pointer',
    padding: '4px',
    borderRadius: '4px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  },
  body: {
    flexGrow: 1,
    padding: '24px',
    display: 'flex',
    flexDirection: 'column',
    gap: '20px',
  },
  threatCard: {
    backgroundColor: 'rgba(255, 255, 255, 0.02)',
    border: '1px solid var(--border-light)',
    borderRadius: '8px',
    padding: '16px',
  },
  threatHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '14px',
  },
  badge: {
    fontSize: '10px',
    fontWeight: '700',
    padding: '2px 8px',
    borderRadius: '4px',
    border: '1px solid',
    textTransform: 'uppercase',
  },
  attackType: {
    fontSize: '15px',
    fontWeight: '700',
    color: 'var(--text-primary)',
  },
  flowEndpoints: {
    display: 'flex',
    flexDirection: 'column',
    gap: '10px',
    marginBottom: '14px',
  },
  endpoint: {
    display: 'flex',
    flexDirection: 'column',
  },
  label: {
    fontSize: '9px',
    fontWeight: '700',
    color: 'var(--text-muted)',
    letterSpacing: '0.5px',
    marginBottom: '2px',
  },
  value: {
    fontSize: '13px',
    fontWeight: '600',
    color: 'var(--text-primary)',
    fontFamily: 'monospace',
  },
  flowMeta: {
    borderTop: '1px solid var(--border-light)',
    paddingTop: '12px',
    display: 'flex',
    justifyContent: 'space-between',
    fontSize: '11px',
    color: 'var(--text-secondary)',
  },
  actionPanel: {
    display: 'flex',
    flexDirection: 'column',
    gap: '10px',
  },
  sectionTitle: {
    fontSize: '11px',
    fontWeight: '700',
    color: 'var(--text-secondary)',
    letterSpacing: '0.5px',
    textTransform: 'uppercase',
  },
  statusButtons: {
    display: 'grid',
    gridTemplateColumns: '1fr 1.2fr 1fr',
    gap: '8px',
  },
  statusBtn: {
    border: '1px solid',
    color: 'var(--text-primary)',
    borderRadius: '6px',
    padding: '8px',
    fontSize: '11px',
    fontWeight: '600',
    cursor: 'pointer',
    textAlign: 'center',
    transition: 'all var(--transition-fast)',
  },
  card: {
    backgroundColor: 'rgba(255,255,255,0.01)',
    border: '1px solid var(--border-light)',
    borderRadius: '8px',
    padding: '16px',
  },
  cardHeader: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    marginBottom: '12px',
  },
  cardTitle: {
    fontSize: '12px',
    fontWeight: '700',
    color: 'var(--text-primary)',
  },
  mitreGrid: {
    display: 'flex',
    gap: '16px',
    marginBottom: '12px',
  },
  mitreCol: {
    display: 'flex',
    flexDirection: 'column',
  },
  mitreBadge: {
    fontSize: '12px',
    fontWeight: '700',
    backgroundColor: 'rgba(59, 130, 246, 0.15)',
    color: 'var(--accent-primary)',
    padding: '4px 8px',
    borderRadius: '4px',
    fontFamily: 'monospace',
  },
  mitreTacticBadge: {
    fontSize: '12px',
    fontWeight: '700',
    backgroundColor: 'rgba(255,255,255,0.06)',
    color: 'var(--text-primary)',
    padding: '4px 8px',
    borderRadius: '4px',
  },
  mitreTechnique: {
    fontSize: '12px',
    color: 'var(--text-secondary)',
    lineHeight: '16px',
    marginBottom: '14px',
  },
  mitigationsSection: {
    borderTop: '1px solid var(--border-light)',
    paddingTop: '12px',
  },
  mitigationHeading: {
    fontSize: '11px',
    fontWeight: '700',
    color: 'var(--text-primary)',
    display: 'block',
    marginBottom: '8px',
  },
  mitigationList: {
    listStyleType: 'none',
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
  },
  mitigationItem: {
    display: 'flex',
    alignItems: 'flex-start',
    gap: '8px',
    fontSize: '11px',
    color: 'var(--text-secondary)',
    lineHeight: '15px',
  },
  checkbox: {
    marginTop: '2px',
  },
  statsGrid: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
  },
  statRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    fontSize: '11px',
    borderBottom: '1px solid rgba(255, 255, 255, 0.02)',
    paddingBottom: '6px',
  },
  statLabel: {
    color: 'var(--text-secondary)',
  },
  statVal: {
    fontFamily: 'monospace',
    color: 'var(--text-primary)',
    fontWeight: '600',
  },
  aiSection: {
    backgroundColor: 'rgba(15, 23, 42, 0.4)',
    border: '1px solid rgba(234, 179, 8, 0.25)',
    borderRadius: '8px',
    padding: '16px',
    boxShadow: '0 4px 20px rgba(0,0,0,0.25)',
  },
  aiHeader: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    marginBottom: '10px',
  },
  aiTitle: {
    fontSize: '12px',
    fontWeight: '800',
    color: 'var(--text-primary)',
    letterSpacing: '0.5px',
  },
  aiPromptText: {
    fontSize: '12px',
    color: 'var(--text-secondary)',
    lineHeight: '16px',
    marginBottom: '12px',
  },
  aiBtn: {
    width: '100%',
    backgroundColor: 'var(--accent-primary)',
    color: 'var(--text-primary)',
    border: 'none',
    borderRadius: '6px',
    padding: '8px 12px',
    fontSize: '12px',
    fontWeight: '600',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    boxShadow: '0 2px 8px var(--glow-low)',
    transition: 'all var(--transition-fast)',
  },
  aiExplanation: {
    backgroundColor: 'rgba(0,0,0,0.25)',
    borderRadius: '6px',
    padding: '12px',
    border: '1px solid var(--border-light)',
  },
  mdH4: {
    fontSize: '13px',
    fontWeight: '700',
    color: 'var(--color-medium)',
    marginTop: '10px',
    marginBottom: '6px',
  },
  mdBold: {
    fontSize: '12px',
    fontWeight: '700',
    color: 'var(--text-primary)',
    marginBottom: '4px',
  },
  mdLi: {
    fontSize: '11px',
    color: 'var(--text-secondary)',
    marginLeft: '12px',
    marginBottom: '4px',
    lineHeight: '15px',
  },
  mdPara: {
    fontSize: '11.5px',
    color: 'var(--text-secondary)',
    marginBottom: '8px',
    lineHeight: '16px',
  }
};
