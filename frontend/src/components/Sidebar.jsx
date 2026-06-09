import React from 'react';
import { LayoutDashboard, ShieldAlert, MessageSquare, Shield, Layers, TrendingUp } from 'lucide-react';

export default function Sidebar({ activeTab, setActiveTab, backendStatus, sessions, activeSessionId, handleSessionChange }) {
  return (
    <aside style={styles.sidebar}>
      {/* Brand Header */}
      <div style={styles.brand}>
        <Shield size={28} color="var(--accent-primary)" style={{ filter: 'drop-shadow(0 0 6px var(--glow-teal))' }} />
        <div>
          <h1 style={styles.brandText}>ThreatSentinel</h1>
          <span style={styles.brandSubtitle}>LITE v1.0</span>
        </div>
      </div>

      {/* Navigation Menu */}
      <nav style={styles.nav}>
        <button 
          onClick={() => setActiveTab('dashboard')}
          style={{
            ...styles.navLink,
            ...(activeTab === 'dashboard' ? styles.navLinkActive : {})
          }}
        >
          <LayoutDashboard size={20} color={activeTab === 'dashboard' ? 'var(--accent-primary)' : 'var(--text-secondary)'} />
          <span>Dashboard</span>
        </button>

        <button 
          onClick={() => setActiveTab('alerts')}
          style={{
            ...styles.navLink,
            ...(activeTab === 'alerts' ? styles.navLinkActive : {})
          }}
        >
          <ShieldAlert size={20} color={activeTab === 'alerts' ? 'var(--accent-primary)' : 'var(--text-secondary)'} />
          <span>Alerts Log</span>
        </button>

        <button 
          onClick={() => setActiveTab('intel')}
          style={{
            ...styles.navLink,
            ...(activeTab === 'intel' ? styles.navLinkActive : {})
          }}
        >
          <TrendingUp size={20} color={activeTab === 'intel' ? 'var(--accent-primary)' : 'var(--text-secondary)'} />
          <span>Threat Intel</span>
        </button>

        <button 
          onClick={() => setActiveTab('chat')}
          style={{
            ...styles.navLink,
            ...(activeTab === 'chat' ? styles.navLinkActive : {})
          }}
        >
          <MessageSquare size={20} color={activeTab === 'chat' ? 'var(--accent-primary)' : 'var(--text-secondary)'} />
          <span>AI Co-Pilot</span>
        </button>
      </nav>

      {/* Session History & Selector */}
      <div style={styles.sessionBox}>
        <div style={styles.sessionHeader}>
          <Layers size={14} color="var(--text-secondary)" />
          <span style={styles.sessionTitle}>ANALYSIS SESSIONS</span>
        </div>
        
        {sessions.length === 0 ? (
          <div style={styles.noSessions}>No sessions loaded</div>
        ) : (
          <select 
            value={activeSessionId || ''} 
            onChange={(e) => handleSessionChange(e.target.value)}
            style={styles.select}
          >
            {sessions.map((s, idx) => (
              <option key={`${s.id}-${idx}`} value={s.id}>
                {s.filename.length > 22 ? `${s.filename.substring(0, 20)}...` : s.filename} ({s.status})
              </option>
            ))}
          </select>
        )}
      </div>

      {/* System Connection Footer */}
      <div style={styles.footer}>
        <div style={styles.statusRow}>
          <div style={{
            ...styles.indicator,
            backgroundColor: backendStatus === 'online' ? 'var(--accent-primary)' : 'var(--color-critical)'
          }} />
          <span style={styles.statusText}>
            API Endpoint: {backendStatus === 'online' ? 'Connected' : 'Disconnected'}
          </span>
        </div>
        <span style={styles.copyright}>CSE Capstone Project</span>
      </div>
    </aside>
  );
}

const styles = {
  sidebar: {
    width: '260px',
    height: '100%',
    backgroundColor: 'var(--bg-sidebar)',
    borderRight: '1px solid var(--border-light)',
    display: 'flex',
    flexDirection: 'column',
    padding: '24px 16px',
    flexShrink: 0,
  },
  brand: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    marginBottom: '40px',
  },
  brandText: {
    fontSize: '18px',
    fontWeight: '800',
    letterSpacing: '0.5px',
    color: 'var(--text-primary)',
  },
  brandSubtitle: {
    fontSize: '10px',
    fontWeight: '700',
    color: 'var(--text-muted)',
    letterSpacing: '1px',
    display: 'block',
    marginTop: '-2px',
  },
  nav: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
    flexGrow: 1,
  },
  navLink: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    paddingTop: '12px',
    paddingBottom: '12px',
    paddingRight: '12px',
    paddingLeft: '12px',
    borderRadius: '8px',
    borderTopWidth: '0px',
    borderBottomWidth: '0px',
    borderRightWidth: '0px',
    borderLeftWidth: '3px',
    borderLeftStyle: 'solid',
    borderLeftColor: 'transparent',
    backgroundColor: 'transparent',
    color: 'var(--text-secondary)',
    fontSize: '14px',
    fontWeight: '500',
    cursor: 'pointer',
    textAlign: 'left',
    transition: 'all var(--transition-fast)',
  },
  navLinkActive: {
    backgroundColor: 'rgba(255, 255, 255, 0.04)',
    color: 'var(--text-primary)',
    fontWeight: '600',
    borderLeftColor: 'var(--accent-primary)',
    paddingLeft: '9px',
  },
  sessionBox: {
    marginTop: 'auto',
    marginBottom: '20px',
    backgroundColor: 'rgba(255, 255, 255, 0.02)',
    border: '1px solid var(--border-light)',
    borderRadius: '8px',
    padding: '12px',
  },
  sessionHeader: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    marginBottom: '8px',
  },
  sessionTitle: {
    fontSize: '11px',
    fontWeight: '700',
    color: 'var(--text-secondary)',
    letterSpacing: '0.5px',
  },
  noSessions: {
    fontSize: '12px',
    color: 'var(--text-muted)',
    textAlign: 'center',
    padding: '4px 0',
  },
  select: {
    width: '100%',
    backgroundColor: 'var(--bg-main)',
    border: '1px solid var(--border-light)',
    color: 'var(--text-primary)',
    padding: '6px 8px',
    borderRadius: '6px',
    fontSize: '12px',
    outline: 'none',
    cursor: 'pointer',
  },
  footer: {
    borderTop: '1px solid var(--border-light)',
    paddingTop: '16px',
    display: 'flex',
    flexDirection: 'column',
    gap: '4px',
  },
  statusRow: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  },
  indicator: {
    width: '8px',
    height: '8px',
    borderRadius: '50%',
  },
  statusText: {
    fontSize: '12px',
    color: 'var(--text-secondary)',
    fontWeight: '500',
  },
  copyright: {
    fontSize: '10px',
    color: 'var(--text-muted)',
    marginTop: '4px',
  }
};
