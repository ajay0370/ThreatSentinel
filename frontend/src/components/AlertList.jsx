import React, { useState } from 'react';
import { Search, SlidersHorizontal, AlertTriangle, Eye, ShieldAlert } from 'lucide-react';

export default function AlertList({ alerts, onSelectAlert, activeAlertId, onUpdateStatus }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('All');
  const [typeFilter, setTypeFilter] = useState('All');

  const formatTime = (timeStr) => {
    if (!timeStr) return '';
    const date = new Date(timeStr);
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  };

  const getProtoName = (pNum) => {
    if (pNum === 6) return 'TCP';
    if (pNum === 17) return 'UDP';
    if (pNum === 1) return 'ICMP';
    return `Proto ${pNum}`;
  };

  const filteredAlerts = alerts.filter(alert => {
    const matchesSearch = 
      alert.src_ip.includes(searchTerm) ||
      alert.dst_ip.includes(searchTerm) ||
      alert.attack_type.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.severity.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesSeverity = severityFilter === 'All' || alert.severity === severityFilter;
    const matchesType = typeFilter === 'All' || alert.attack_type === typeFilter;

    return matchesSearch && matchesSeverity && matchesType;
  });

  // Upgraded Severity Badges: Coloured pill elements with Critical subtle glow
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

  return (
    <div className="glass-panel" style={styles.container}>
      {/* Header and Toolbar */}
      <div style={styles.header}>
        <div style={styles.titleGroup}>
          <ShieldAlert size={20} color="var(--accent-primary)" style={{ filter: 'drop-shadow(0 0 4px var(--glow-teal))' }} />
          <h3 style={styles.title}>Threat Log</h3>
          <span style={styles.badge}>{filteredAlerts.length} Alerts</span>
        </div>
        
        <div style={styles.toolbar}>
          <div style={styles.searchWrapper}>
            <Search size={16} color="var(--text-muted)" style={styles.searchIcon} />
            <input 
              type="text" 
              placeholder="Search IP, type, severity..." 
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={styles.searchInput}
            />
          </div>

          <div style={styles.filters}>
            <SlidersHorizontal size={14} color="var(--text-secondary)" />
            <select 
              value={severityFilter} 
              onChange={(e) => setSeverityFilter(e.target.value)}
              style={styles.filterSelect}
            >
              <option value="All">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>

            <select 
              value={typeFilter} 
              onChange={(e) => setTypeFilter(e.target.value)}
              style={styles.filterSelect}
            >
              <option value="All">All Attacks</option>
              <option value="DDoS">DDoS</option>
              <option value="Port Scan">Port Scan</option>
              <option value="Brute Force">Brute Force</option>
              <option value="Zero-Day Anomaly">Zero-Day Anomaly</option>
              <option value="Normal">Normal</option>
            </select>
          </div>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="custom-scroll" style={styles.tableWrapper}>
        {filteredAlerts.length === 0 ? (
          <div style={styles.emptyState}>
            <AlertTriangle size={36} color="var(--text-muted)" style={{ marginBottom: '12px' }} />
            <p style={styles.emptyText}>No alerts match the current filter criteria.</p>
          </div>
        ) : (
          <table style={styles.table}>
            <thead>
              <tr style={styles.theadRow}>
                <th style={{...styles.th, width: '90px'}}>Time</th>
                <th style={styles.th}>Source IP</th>
                <th style={styles.th}>Destination IP</th>
                <th style={{...styles.th, width: '70px'}}>Proto</th>
                <th style={styles.th}>Attack Vector</th>
                <th style={{...styles.th, width: '100px'}}>Severity</th>
                <th style={{...styles.th, width: '110px'}}>MITRE Ref</th>
                <th style={{...styles.th, width: '110px'}}>Incident Status</th>
                <th style={{...styles.th, width: '50px'}}>View</th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.map((alert, index) => {
                const isSelected = activeAlertId === alert.id;
                const isHighPriority = alert.severity === 'Critical' || alert.severity === 'High';
                
                // Alternate row backgrounds: odd rows #111827, even rows #0D1421
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
                    <td style={styles.td}>{formatTime(alert.timestamp)}</td>
                    
                    {/* Source IP: Courier New Monospace */}
                    <td style={{...styles.td, ...styles.monoText}}>{alert.src_ip}:{alert.src_port}</td>
                    
                    {/* Destination IP: Courier New Monospace */}
                    <td style={{...styles.td, ...styles.monoText}}>{alert.dst_ip}:{alert.dst_port}</td>
                    
                    <td style={styles.td}>
                      <span style={styles.protoBadge}>{getProtoName(alert.protocol)}</span>
                    </td>
                    <td style={styles.td}>
                      <span style={{ fontWeight: alert.attack_type !== 'Normal' ? '600' : 'normal' }}>
                        {alert.attack_type}
                      </span>
                    </td>
                    <td style={styles.td}>
                      <span style={getSeverityStyle(alert.severity)}>
                        {alert.severity}
                      </span>
                    </td>
                    
                    {/* MITRE badge styled as requested */}
                    <td style={styles.td}>
                      {alert.mitre_id && alert.mitre_id !== 'N/A' ? (
                        <span style={styles.mitreBadge}>{alert.mitre_id}</span>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>-</span>
                      )}
                    </td>

                    <td style={styles.td} onClick={(e) => e.stopPropagation()}>
                      <select 
                        value={alert.status} 
                        onChange={(e) => onUpdateStatus(alert.id, e.target.value)}
                        style={{
                          ...styles.statusSelect,
                          color: alert.status === 'Resolved' ? 'var(--color-normal)' : (alert.status === 'In Progress' ? 'var(--color-high)' : 'var(--text-primary)')
                        }}
                      >
                        <option value="New">🔴 New</option>
                        <option value="In Progress">🟡 Active</option>
                        <option value="Resolved">🟢 Closed</option>
                      </select>
                    </td>
                    <td style={styles.td}>
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
  );
}

const styles = {
  container: {
    display: 'flex',
    flexDirection: 'column',
    flexGrow: 1,
    height: '100%',
    padding: '24px',
    overflow: 'hidden',
    backgroundColor: 'var(--bg-card)',
  },
  header: {
    display: 'flex',
    flexDirection: 'column',
    gap: '16px',
    marginBottom: '20px',
  },
  titleGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  },
  title: {
    fontSize: '18px',
    fontWeight: '700',
    color: 'var(--text-primary)',
  },
  badge: {
    fontSize: '11px',
    fontWeight: '600',
    backgroundColor: 'rgba(255,255,255,0.06)',
    color: 'var(--text-secondary)',
    padding: '2px 8px',
    borderRadius: '20px',
  },
  toolbar: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    gap: '16px',
    flexWrap: 'wrap',
  },
  searchWrapper: {
    position: 'relative',
    width: '260px',
  },
  searchIcon: {
    position: 'absolute',
    left: '10px',
    top: '50%',
    transform: 'translateY(-50%)',
  },
  searchInput: {
    width: '100%',
    backgroundColor: 'var(--bg-main)',
    border: '1px solid var(--border-light)',
    borderRadius: '6px',
    padding: '8px 8px 8px 34px',
    color: 'var(--text-primary)',
    fontSize: '13px',
    outline: 'none',
    transition: 'all var(--transition-fast)',
  },
  filters: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  },
  filterSelect: {
    backgroundColor: 'var(--bg-main)',
    border: '1px solid var(--border-light)',
    color: 'var(--text-primary)',
    padding: '8px 12px',
    borderRadius: '6px',
    fontSize: '13px',
    outline: 'none',
    cursor: 'pointer',
  },
  tableWrapper: {
    flexGrow: 1,
    border: '1px solid var(--border-light)',
    borderRadius: '8px',
    backgroundColor: '#0A0E1A',
  },
  emptyState: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    height: '100%',
    padding: '40px',
  },
  emptyText: {
    color: 'var(--text-secondary)',
    fontSize: '13px',
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse',
    textAlign: 'left',
  },
  th: {
    padding: '12px 16px',
    fontSize: '12px',
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
  statusSelect: {
    backgroundColor: 'transparent',
    border: 'none',
    fontSize: '12px',
    fontWeight: '600',
    cursor: 'pointer',
    outline: 'none',
  },
  viewBtn: {
    backgroundColor: 'transparent',
    border: 'none',
    cursor: 'pointer',
    padding: '4px',
    borderRadius: '4px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  }
};
