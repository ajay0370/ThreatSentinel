import React, { useState, useEffect } from 'react';
import { ShieldAlert, Award, Layers, TrendingUp, RefreshCw, AlertTriangle, Eye } from 'lucide-react';
import { API_BASE_URL } from '../config';

export default function ThreatIntel({ onSelectAlert, activeAlertId, onUpdateStatus }) {
  const [intelStats, setIntelStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchIntelStats = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`${API_BASE_URL}/api/stats/historical`);
      if (!response.ok) {
        throw new Error('Failed to retrieve historical threat metrics');
      }
      const data = await response.json();
      setIntelStats(data);
    } catch (err) {
      console.error(err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIntelStats();
  }, []);

  const getSeverityStyle = (severity) => {
    const baseStyle = {
      borderRadius: '9999px',
      padding: '3px 10px',
      fontSize: '11px',
      fontWeight: '600',
      display: 'inline-block',
      textAlign: 'center',
      minWidth: '75px',
      color: '#F9FAFB',
    };

    switch(severity) {
      case 'Critical': return { 
        ...baseStyle, 
        backgroundColor: 'var(--color-critical)', 
        boxShadow: '0 0 8px rgba(239, 68, 68, 0.4)' 
      };
      case 'High': return { 
        ...baseStyle, 
        backgroundColor: 'var(--color-high)', 
        color: '#0A0E1A' 
      };
      case 'Medium': return { 
        ...baseStyle, 
        backgroundColor: 'var(--color-medium)' 
      };
      default: return { 
        ...baseStyle, 
        backgroundColor: 'var(--color-low)' 
      };
    }
  };

  const getProtoName = (pNum) => {
    if (pNum === 6) return 'TCP';
    if (pNum === 17) return 'UDP';
    if (pNum === 1) return 'ICMP';
    return `Proto ${pNum}`;
  };

  return (
    <div style={styles.container}>
      {/* Header */}
      <header style={styles.header}>
        <div>
          <h2 style={styles.pageTitle}>Threat Intelligence Centre</h2>
          <p style={styles.pageSubtitle}>High-level aggregated statistics and top alerts across all packet captures logged in the database.</p>
        </div>
        <button onClick={fetchIntelStats} style={styles.refreshBtn} title="Reload Global Metrics">
          <RefreshCw size={16} className={loading ? "spinner" : ""} />
        </button>
      </header>

      {loading && !intelStats ? (
        <div style={styles.loaderArea}>
          <Loader2 size={32} className="spinner" style={{ color: 'var(--accent-primary)', animation: 'spin 1s linear infinite' }} />
          <p style={{ marginTop: '12px', color: 'var(--text-secondary)' }}>Loading Threat Database...</p>
        </div>
      ) : error ? (
        <div className="glass-panel" style={styles.emptyState}>
          <AlertTriangle size={48} color="var(--color-critical)" style={{ marginBottom: '16px' }} />
          <h3>Database Sync Failed</h3>
          <p style={{ color: 'var(--text-secondary)', fontSize: '13px', marginTop: '4px' }}>{error}</p>
        </div>
      ) : (
        <div style={styles.intelBody}>
          {/* Historical Metrics Cards */}
          <div style={styles.statsGrid}>
            {/* Card 1 */}
            <div className="glass-panel" style={{ ...styles.card, borderLeft: '2px solid var(--accent-secondary)' }}>
              <div style={styles.cardTop}>
                <span style={styles.cardLabel}>TOTAL PCAPS AUDITED</span>
                <Layers size={16} color="var(--accent-secondary)" />
              </div>
              <span style={styles.cardVal}>{intelStats?.total_sessions || 0}</span>
              <span style={styles.cardSub}>Unique Analysis Sessions</span>
            </div>

            {/* Card 2 */}
            <div className="glass-panel" style={{ ...styles.card, borderLeft: '2px solid var(--color-high)' }}>
              <div style={styles.cardTop}>
                <span style={styles.cardLabel}>HISTORICAL THREATS</span>
                <ShieldAlert size={16} color="var(--color-high)" />
              </div>
              <span style={{ ...styles.cardVal, color: 'var(--color-high)' }}>{intelStats?.total_threats || 0}</span>
              <span style={styles.cardSub}>Logged Malicious Flows</span>
            </div>

            {/* Card 3: Severe Threats (Critical & High combined) */}
            <div 
              className={`glass-panel ${intelStats?.critical_threats > 0 ? 'pulse-critical-card' : ''}`} 
              style={{ ...styles.card, borderLeft: '2px solid var(--color-critical)' }}
            >
              <div style={styles.cardTop}>
                <span style={styles.cardLabel}>SEVERE THREATS</span>
                <Award size={16} color="var(--color-critical)" />
              </div>
              <span style={{ ...styles.cardVal, color: 'var(--color-critical)' }}>{intelStats?.critical_threats || 0}</span>
              <span style={styles.cardSub}>Critical & High Severity Alerts</span>
            </div>

            {/* Card 4 */}
            <div className="glass-panel" style={{ ...styles.card, borderLeft: '2px solid var(--accent-primary)' }}>
              <div style={styles.cardTop}>
                <span style={styles.cardLabel}>GLOBAL ANOMALY INDEX</span>
                <TrendingUp size={16} color="var(--accent-primary)" />
              </div>
              <span style={{ ...styles.cardVal, color: 'var(--accent-primary)' }}>{(intelStats?.avg_anomaly_score || 0).toFixed(3)}</span>
              <span style={styles.cardSub}>Database Average Score</span>
            </div>
          </div>

          {/* Top 15 Threats Table */}
          <div className="glass-panel" style={styles.tableCard}>
            <div style={styles.tableHeaderGroup}>
              <Award size={18} color="var(--color-high)" style={{ filter: 'drop-shadow(0 0 4px var(--glow-high))' }} />
              <h4 style={styles.tableTitle}>Top 15 Most Severe Historical Alerts</h4>
            </div>
            
            <div style={styles.tableWrapper}>
              {!intelStats?.top_alerts || intelStats.top_alerts.length === 0 ? (
                <div style={styles.emptyTable}>
                  <p style={{ color: 'var(--text-muted)' }}>No historical threat records logged.</p>
                </div>
              ) : (
                <table style={styles.table}>
                  <thead>
                    <tr style={styles.theadRow}>
                      <th style={styles.th}>Origin PCAP</th>
                      <th style={styles.th}>Source IP</th>
                      <th style={styles.th}>Destination IP</th>
                      <th style={{...styles.th, width: '60px'}}>Proto</th>
                      <th style={styles.th}>Threat Type</th>
                      <th style={{...styles.th, width: '100px'}}>Severity</th>
                      <th style={{...styles.th, width: '90px'}}>MITRE ID</th>
                      <th style={{...styles.th, width: '80px', textAlign: 'right'}}>Score</th>
                      <th style={{...styles.th, width: '50px', textAlign: 'center'}}>View</th>
                    </tr>
                  </thead>
                  <tbody>
                    {intelStats.top_alerts.map((alert, index) => {
                      const isSelected = activeAlertId === alert.id;
                      const rowBgColor = index % 2 === 0 ? '#111827' : '#0D1421';
                      
                      return (
                        <tr 
                          key={alert.id}
                          onClick={() => onSelectAlert(alert)}
                          style={{
                            ...styles.tr,
                            backgroundColor: isSelected ? 'rgba(0, 212, 170, 0.08)' : rowBgColor,
                            borderLeftColor: isSelected ? 'var(--accent-primary)' : 'transparent',
                            borderLeftWidth: '3px',
                            borderLeftStyle: 'solid'
                          }}
                        >
                          {/* Origin File name */}
                          <td style={{...styles.td, color: 'var(--accent-secondary)', fontWeight: '600'}}>
                            {alert.filename.length > 20 ? `${alert.filename.substring(0, 18)}...` : alert.filename}
                          </td>
                          <td style={{...styles.td, ...styles.monoText}}>{alert.src_ip}:{alert.src_port}</td>
                          <td style={{...styles.td, ...styles.monoText}}>{alert.dst_ip}:{alert.dst_port}</td>
                          <td style={styles.td}>
                            <span style={styles.protoBadge}>{getProtoName(alert.protocol)}</span>
                          </td>
                          <td style={styles.td}>{alert.attack_type}</td>
                          <td style={styles.td}>
                            <span style={getSeverityStyle(alert.severity)}>
                              {alert.severity}
                            </span>
                          </td>
                          <td style={styles.td}>
                            <span style={styles.mitreBadge}>{alert.mitre_id}</span>
                          </td>
                          <td style={{...styles.td, textAlign: 'right', fontWeight: '700', fontFamily: 'monospace'}}>
                            {alert.anomaly_score.toFixed(3)}
                          </td>
                          <td style={{...styles.td, textAlign: 'center'}}>
                            <button 
                              onClick={(e) => {
                                e.stopPropagation();
                                onSelectAlert(alert);
                              }}
                              style={styles.viewBtn}
                            >
                              <Eye size={14} color="var(--text-secondary)" />
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// Simple loader wrapper
function Loader2({ size, className, style }) {
  return <RefreshCw size={size} className={className} style={style} />;
}

const styles = {
  container: {
    padding: '0 24px 24px 24px',
    height: '100%',
    overflowY: 'auto',
    display: 'flex',
    flexDirection: 'column',
    flexGrow: 1,
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '20px',
    marginTop: '20px',
  },
  pageTitle: {
    fontSize: '20px',
    fontWeight: '700',
    color: 'var(--text-primary)',
  },
  pageSubtitle: {
    fontSize: '13px',
    color: 'var(--text-secondary)',
    marginTop: '2px',
  },
  refreshBtn: {
    backgroundColor: 'rgba(255,255,255,0.03)',
    border: '1px solid var(--border-light)',
    color: 'var(--text-secondary)',
    borderRadius: '6px',
    width: '36px',
    height: '36px',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    transition: 'all var(--transition-fast)',
  },
  loaderArea: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    flexGrow: 1,
    padding: '40px',
  },
  emptyState: {
    padding: '60px 40px',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    textAlign: 'center',
    flexGrow: 1,
  },
  intelBody: {
    display: 'flex',
    flexDirection: 'column',
    gap: '20px',
  },
  statsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
    gap: '20px',
  },
  card: {
    padding: '20px',
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'center',
    backgroundColor: '#111827',
    borderRadius: '8px',
  },
  cardTop: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '10px',
  },
  cardLabel: {
    fontSize: '13px',
    fontWeight: '600',
    color: '#9CA3AF',
    letterSpacing: '0.5px',
  },
  cardVal: {
    fontSize: '36px',
    fontWeight: '700',
    color: 'var(--text-primary)',
    marginBottom: '4px',
  },
  cardSub: {
    fontSize: '11px',
    color: 'var(--text-muted)',
  },
  tableCard: {
    padding: '24px',
    backgroundColor: '#111827',
    borderRadius: '10px',
  },
  tableHeaderGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    marginBottom: '20px',
  },
  tableTitle: {
    fontSize: '14px',
    fontWeight: '700',
    color: 'var(--text-primary)',
  },
  tableWrapper: {
    border: '1px solid var(--border-light)',
    borderRadius: '8px',
    backgroundColor: '#0A0E1A',
    overflow: 'hidden',
  },
  emptyTable: {
    padding: '40px',
    textAlign: 'center',
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse',
    textAlign: 'left',
  },
  th: {
    padding: '12px 16px',
    fontSize: '11px',
    fontWeight: '700',
    color: 'var(--text-secondary)',
    borderBottom: '1px solid var(--border-light)',
    backgroundColor: 'rgba(255,255,255,0.01)',
  },
  theadRow: {
    position: 'sticky',
    top: 0,
    zIndex: 1,
    backgroundColor: '#0D1421',
  },
  tr: {
    borderBottom: '1px solid var(--border-light)',
    cursor: 'pointer',
    transition: 'all var(--transition-fast)',
  },
  td: {
    padding: '12px 16px',
    fontSize: '13px',
    color: 'var(--text-primary)',
  },
  monoText: {
    fontFamily: '"Courier New", Courier, monospace',
    fontSize: '13px',
    fontWeight: '600',
  },
  protoBadge: {
    fontSize: '10px',
    fontWeight: '600',
    backgroundColor: 'rgba(255,255,255,0.04)',
    color: 'var(--text-secondary)',
    padding: '2px 6px',
    borderRadius: '4px',
  },
  mitreBadge: {
    backgroundColor: '#1E2A3A',
    color: '#60A5FA',
    border: '1px solid #3B82F6',
    borderRadius: '4px',
    padding: '2px 6px',
    fontSize: '11px',
    fontWeight: '600',
    fontFamily: '"Courier New", Courier, monospace',
    display: 'inline-block',
  },
  viewBtn: {
    backgroundColor: 'transparent',
    border: 'none',
    cursor: 'pointer',
    padding: '4px',
    borderRadius: '4px',
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
  }
};
