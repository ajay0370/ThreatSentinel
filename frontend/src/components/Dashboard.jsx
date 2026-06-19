import React from 'react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, PieChart, Pie, Cell, Legend } from 'recharts';
import { Shield, ShieldAlert, Activity, FileDown, RefreshCw, AlertCircle, Volume2 } from 'lucide-react';
import { API_BASE_URL } from '../config';

export default function Dashboard({ stats, alerts = [], activeSession, onRefresh, sessions, activeSessionId, handleSessionChange }) {
  const hasData = stats && stats.total_alerts > 0;
  
  // Format data for Severity Pie Chart
  const severityData = hasData ? [
    { name: 'Critical', value: stats.severities.Critical, color: 'var(--color-critical)' },
    { name: 'High', value: stats.severities.High, color: 'var(--color-high)' },
    { name: 'Medium', value: stats.severities.Medium, color: 'var(--color-medium)' },
    { name: 'Low', value: stats.severities.Low, color: 'var(--color-low)' },
  ].filter(item => item.value > 0) : [];

  // Format data for Attack Type Bar Chart
  const attackData = hasData ? Object.keys(stats.attack_types).map(key => ({
    name: key,
    value: stats.attack_types[key],
    color: key === 'Normal' ? 'var(--color-normal)' : (key === 'DDoS' ? 'var(--color-critical)' : 'var(--accent-primary)')
  })) : [];

  const handleDownloadReport = () => {
    if (!activeSessionId) return;
    window.location.href = `${API_BASE_URL}/api/report/generate?session_id=${activeSessionId}`;
  };

  const getSeverityColor = (severity) => {
    switch(severity) {
      case 'Critical': return 'var(--color-critical)';
      case 'High': return 'var(--color-high)';
      case 'Medium': return 'var(--color-medium)';
      default: return 'var(--color-low)';
    }
  };

  // Get latest 5 threat alerts (excluding Normal) sorted by id desc (latest first)
  const latestThreats = [...alerts]
    .filter(a => a.attack_type !== 'Normal')
    .sort((a, b) => b.id - a.id)
    .slice(0, 5);

  const [isRefreshing, setIsRefreshing] = React.useState(false);

  const handleRefreshClick = async () => {
    setIsRefreshing(true);
    if (onRefresh) {
      await onRefresh();
    }
    setTimeout(() => {
      setIsRefreshing(false);
    }, 600);
  };

  return (
    <div style={styles.container}>
      {/* Top Toolbar */}
      <header style={styles.header}>
        <div>
          <h2 style={styles.pageTitle}>Security Dashboard</h2>
          <p style={styles.pageSubtitle}>
            {activeSession ? `Audit Session Log: ${activeSession.filename}` : 'Select a packet capture session from history or upload a new PCAP.'}
          </p>
        </div>
        
        {activeSessionId && (
          <div style={styles.actions}>
            <button onClick={handleRefreshClick} style={styles.refreshBtn} title="Refresh Statistics">
              <RefreshCw size={16} className={isRefreshing ? "spinner" : ""} />
            </button>
            <button onClick={handleDownloadReport} style={styles.downloadBtn}>
              <FileDown size={16} style={{ marginRight: '8px' }} />
              Report Download
            </button>
          </div>
        )}
      </header>

      {!hasData ? (
        <div className="glass-panel" style={styles.emptyState}>
          <AlertCircle size={48} color="var(--text-muted)" style={{ marginBottom: '16px' }} />
          <h3 style={{ color: 'var(--text-primary)' }}>No Session Data Displayed</h3>
          <p style={{ color: 'var(--text-secondary)', fontSize: '13px', marginTop: '4px', maxWidth: '400px' }}>
            Please upload a packet capture file using the Upload panel or select an existing session from the sidebar history to populate metrics.
          </p>
        </div>
      ) : (
        <div style={styles.dashboardBody}>
          {/* Stats Cards Row */}
          <div style={styles.statsGrid}>
            {/* Card 1: Total Audited */}
            <div className="glass-panel fade-in" style={{ ...styles.card, borderLeft: '2px solid var(--accent-secondary)' }}>
              <div style={styles.cardTop}>
                <span style={styles.cardLabel}>TOTAL FLOWS AUDITED</span>
                <Activity size={16} color="var(--accent-secondary)" />
              </div>
              <span style={styles.cardVal}>{stats.total_alerts}</span>
              <span style={styles.cardSub}>Unique Bidirectional Connections</span>
            </div>

            {/* Card 2: Anomalies */}
            <div className="glass-panel fade-in" style={{ ...styles.card, borderLeft: '2px solid var(--color-medium)', animationDelay: '0.05s' }}>
              <div style={styles.cardTop}>
                <span style={styles.cardLabel}>ANOMALIES DETECTED</span>
                <Shield size={16} color="var(--color-medium)" />
              </div>
              <span style={{ ...styles.cardVal, color: 'var(--color-medium)' }}>
                {stats.total_alerts - (stats.attack_types.Normal || 0)}
              </span>
              <span style={styles.cardSub}>Exhibiting Outlying Profiles</span>
            </div>

            {/* Card 3: Severe Threats (Critical & High combined) */}
            <div 
              className={`glass-panel fade-in ${(stats.severities.Critical + stats.severities.High) > 0 ? 'pulse-critical-card' : ''}`} 
              style={{ 
                ...styles.card, 
                borderLeft: '2px solid var(--color-critical)',
                animationDelay: '0.1s' 
              }}
            >
              <div style={styles.cardTop}>
                <span style={styles.cardLabel}>SEVERE THREATS</span>
                <ShieldAlert size={16} color="var(--color-critical)" />
              </div>
              <span style={{ ...styles.cardVal, color: 'var(--color-critical)' }}>
                {stats.severities.Critical + stats.severities.High}
              </span>
              <span style={styles.cardSub}>Critical & High Severity Alerts</span>
            </div>

            {/* Card 4: Avg Anomaly Index */}
            <div className="glass-panel fade-in" style={{ ...styles.card, borderLeft: '2px solid var(--accent-primary)', animationDelay: '0.15s' }}>
              <div style={styles.cardTop}>
                <span style={styles.cardLabel}>AVG ANOMALY INDEX</span>
                <Shield size={16} color="var(--accent-primary)" />
              </div>
              <span style={{ ...styles.cardVal, color: 'var(--accent-primary)' }}>
                {stats.avg_anomaly_score.toFixed(3)}
              </span>
              <div style={styles.progressContainer}>
                <div 
                  style={{ 
                    ...styles.progressBar, 
                    width: `${stats.avg_anomaly_score * 100}%`,
                    backgroundColor: stats.avg_anomaly_score > 0.6 ? 'var(--color-critical)' : 'var(--accent-primary)'
                  }} 
                />
              </div>
            </div>
          </div>

          {/* Threat Ticker Marquee Bar */}
          {latestThreats.length > 0 && (
            <div className="ticker-wrap fade-in">
              <div style={{ display: 'flex', alignItems: 'center', position: 'absolute', backgroundColor: 'var(--bg-sidebar)', zIndex: 2, paddingRight: '12px' }}>
                <Volume2 size={14} color="var(--accent-primary)" style={{ marginRight: '6px' }} />
                <span style={{ fontSize: '11px', fontWeight: '800', color: 'var(--accent-primary)', letterSpacing: '0.5px' }}>THREAT FEED:</span>
              </div>
              <div className="ticker-content">
                {latestThreats.map((threat, idx) => (
                  <span key={`${threat.id}-${idx}`} className="ticker-item" style={{ color: getSeverityColor(threat.severity) }}>
                    [{threat.severity.toUpperCase()}] {threat.attack_type} on Port {threat.dst_port} ({threat.src_ip} → {threat.dst_ip}) Anomaly: {threat.anomaly_score.toFixed(3)}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Charts Row */}
          <div style={styles.chartsGrid}>
            {/* Pie Chart Card */}
            <div className="glass-panel fade-in" style={styles.chartCard}>
              <h4 style={styles.chartTitle}>Severity Breakdown</h4>
              <div style={styles.chartWrapper}>
                <ResponsiveContainer width="100%" height={220}>
                  <PieChart>
                    <Pie
                      data={severityData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={80}
                      paddingAngle={4}
                      dataKey="value"
                      stroke="#111827"
                      strokeWidth={2}
                    >
                      {severityData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip 
                      contentStyle={{ backgroundColor: '#1F2937', borderColor: '#374151', borderRadius: '6px' }} 
                      itemStyle={{ color: '#F9FAFB' }} 
                    />
                    <Legend 
                      verticalAlign="bottom" 
                      height={36} 
                      formatter={(value) => <span style={{ color: 'var(--text-secondary)', fontSize: '11px', fontWeight: '600' }}>{value}</span>}
                    />
                  </PieChart>
                </ResponsiveContainer>
                {/* Center text overlay for Donut Chart */}
                <div style={styles.pieCenterText}>
                  <span style={styles.pieCenterNumber}>{stats.total_alerts}</span>
                  <span style={styles.pieCenterLabel}>TOTAL FLOWS</span>
                </div>
              </div>
            </div>

            {/* Bar Chart Card */}
            <div className="glass-panel" style={styles.chartCard}>
              <h4 style={styles.chartTitle}>Detected Attack Vectors</h4>
              <div style={styles.chartWrapper}>
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={attackData} margin={{ top: 10, right: 10, left: -20, bottom: 5 }}>
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#1F2937" />
                    <XAxis dataKey="name" stroke="#6B7280" />
                    <YAxis stroke="#6B7280" />
                    <Tooltip 
                      contentStyle={{ backgroundColor: '#1F2937', borderColor: '#374151', borderRadius: '6px' }} 
                      itemStyle={{ color: '#F9FAFB' }}
                    />
                    <Bar dataKey="value">
                      {attackData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
          
          {/* Top Sources / Targets Table */}
          <div style={styles.chartsGrid}>
            <div className="glass-panel" style={{ ...styles.chartCard, flex: 1 }}>
              <h4 style={styles.chartTitle}>Top Attacking IP Addresses</h4>
              <div style={styles.tableWrapper}>
                {stats.top_sources.length === 0 ? (
                  <span style={styles.noData}>No Source IPs logged</span>
                ) : (
                  <table className="soc-table">
                    <thead>
                      <tr>
                        <th>Rank</th>
                        <th>Source IP Address</th>
                        <th style={{ textAlign: 'right' }}>Malicious Flows</th>
                      </tr>
                    </thead>
                    <tbody>
                      {stats.top_sources.map((item, idx) => (
                        <tr key={idx}>
                          <td style={{ color: 'var(--text-muted)' }}>#{idx + 1}</td>
                          <td style={{ color: 'var(--text-primary)', fontFamily: 'monospace', fontWeight: '600' }}>{item.ip}</td>
                          <td style={{ textAlign: 'right', fontWeight: '700', color: 'var(--color-critical)' }}>{item.count}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>

            <div className="glass-panel" style={{ ...styles.chartCard, flex: 1 }}>
              <h4 style={styles.chartTitle}>Top Target IP Addresses</h4>
              <div style={styles.tableWrapper}>
                {stats.top_destinations.length === 0 ? (
                  <span style={styles.noData}>No Target IPs logged</span>
                ) : (
                  <table className="soc-table">
                    <thead>
                      <tr>
                        <th>Rank</th>
                        <th>Target IP Address</th>
                        <th style={{ textAlign: 'right' }}>Incoming Attacks</th>
                      </tr>
                    </thead>
                    <tbody>
                      {stats.top_destinations.map((item, idx) => (
                        <tr key={idx}>
                          <td style={{ color: 'var(--text-muted)' }}>#{idx + 1}</td>
                          <td style={{ color: 'var(--text-primary)', fontFamily: 'monospace', fontWeight: '600' }}>{item.ip}</td>
                          <td style={{ textAlign: 'right', fontWeight: '700', color: 'var(--color-high)' }}>{item.count}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
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
  actions: {
    display: 'flex',
    gap: '10px',
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
  downloadBtn: {
    backgroundColor: 'var(--accent-primary)',
    color: '#0A0E1A',
    border: 'none',
    borderRadius: '6px',
    padding: '0 16px',
    fontSize: '13px',
    fontWeight: '700',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    height: '36px',
    boxShadow: '0 4px 12px var(--glow-teal)',
    transition: 'all var(--transition-fast)',
  },
  emptyState: {
    padding: '60px 40px',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    textAlign: 'center',
    flexGrow: 1,
    margin: '0 24px',
  },
  dashboardBody: {
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
  progressContainer: {
    width: '100%',
    height: '4px',
    backgroundColor: 'rgba(255,255,255,0.05)',
    borderRadius: '2px',
    marginTop: '10px',
    overflow: 'hidden',
  },
  progressBar: {
    height: '100%',
    borderRadius: '2px',
    transition: 'width 0.5s ease-out',
  },
  chartsGrid: {
    display: 'flex',
    gap: '20px',
    flexWrap: 'wrap',
  },
  chartCard: {
    flex: '1 1 400px',
    padding: '20px',
    backgroundColor: '#111827',
  },
  chartTitle: {
    fontSize: '14px',
    fontWeight: '700',
    color: 'var(--text-primary)',
    marginBottom: '16px',
  },
  chartWrapper: {
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    position: 'relative',
  },
  pieCenterText: {
    position: 'absolute',
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'center',
    alignItems: 'center',
    top: '41%',
    left: '50%',
    transform: 'translate(-50%, -50%)',
    pointerEvents: 'none',
  },
  pieCenterNumber: {
    fontSize: '22px',
    fontWeight: '800',
    color: 'var(--text-primary)',
    lineHeight: '1',
  },
  pieCenterLabel: {
    fontSize: '9px',
    fontWeight: '700',
    color: 'var(--text-muted)',
    marginTop: '4px',
    letterSpacing: '0.5px',
  },
  tableWrapper: {
    marginTop: '10px',
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse',
    fontSize: '13px',
  },
  th: {
    textAlign: 'left',
    color: 'var(--text-secondary)',
    fontSize: '11px',
    fontWeight: '700',
    paddingBottom: '8px',
    borderBottom: '1px solid var(--border-light)',
  },
  td: {
    padding: '10px 8px',
  },
  tr: {
    transition: 'all var(--transition-fast)',
  },
  noData: {
    fontSize: '12px',
    color: 'var(--text-muted)',
  }
};
