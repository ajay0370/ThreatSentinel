import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Dashboard from './components/Dashboard';
import UploadZone from './components/UploadZone';
import AlertList from './components/AlertList';
import AlertDetail from './components/AlertDetail';
import CoPilotChat from './components/CoPilotChat';
import ThreatIntel from './components/ThreatIntel';
import { Shield } from 'lucide-react';
import { API_BASE_URL } from './config';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [sessions, setSessions] = useState([]);
  const [activeSessionId, setActiveSessionId] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [activeAlert, setActiveAlert] = useState(null);
  const [backendStatus, setBackendStatus] = useState('offline');
  const [currentTime, setCurrentTime] = useState('');

  // 1. Live clock for the navbar
  useEffect(() => {
    const formatTime = () => {
      const now = new Date();
      return now.getFullYear() + '-' + 
             String(now.getMonth() + 1).padStart(2, '0') + '-' + 
             String(now.getDate()).padStart(2, '0') + ' ' + 
             String(now.getHours()).padStart(2, '0') + ':' + 
             String(now.getMinutes()).padStart(2, '0') + ':' + 
             String(now.getSeconds()).padStart(2, '0');
    };
    
    setCurrentTime(formatTime());
    const clockInterval = setInterval(() => {
      setCurrentTime(formatTime());
    }, 1000);
    
    return () => clearInterval(clockInterval);
  }, []);

  // 2. Fetch sessions on load and check backend status
  const fetchSessions = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/sessions`);
      if (response.ok) {
        const data = await response.json();
        setSessions(data);
        setBackendStatus('online');
        
        // If there is no active session yet, set the most recent one
        if (data.length > 0 && !activeSessionId) {
          setActiveSessionId(data[0].id);
        }
      } else {
        setBackendStatus('offline');
      }
    } catch (err) {
      console.error("Error fetching sessions:", err);
      setBackendStatus('offline');
    }
  };
  
  const handleRefresh = async () => {
    await fetchSessions();
    if (activeSessionId) {
      try {
        const response = await fetch(`${API_BASE_URL}/api/alerts?session_id=${activeSessionId}`);
        if (response.ok) {
          const data = await response.json();
          setAlerts(data);
        }
      } catch (err) {
        console.error("Error manual refreshing alerts:", err);
      }
    }
  };

  useEffect(() => {
    fetchSessions();
    const interval = setInterval(fetchSessions, 10000); // Poll every 10s for updates
    return () => clearInterval(interval);
  }, [activeSessionId]);

  // 3. Load alerts and subscribe to SSE stream when session changes
  useEffect(() => {
    if (!activeSessionId) {
      setAlerts([]);
      setActiveAlert(null);
      return;
    }

    setAlerts([]); // Reset alerts for new session
    setActiveAlert(null);

    console.log(`[*] Connecting to SSE stream for session: ${activeSessionId}`);
    const eventSource = new EventSource(`${API_BASE_URL}/api/stream?session_id=${activeSessionId}`);

    eventSource.onmessage = (event) => {
      try {
        const newAlert = JSON.parse(event.data);
        setAlerts(prev => {
          if (prev.some(a => a.id === newAlert.id)) {
            return prev.map(a => a.id === newAlert.id ? newAlert : a);
          }
          return [...prev, newAlert];
        });
      } catch (err) {
        console.error("Error parsing SSE payload:", err);
      }
    };

    eventSource.addEventListener('complete', () => {
      console.log("[+] SSE analysis complete signal received.");
      fetchSessions(); // Reload sessions list to update status
      eventSource.close();
    });

    eventSource.onerror = (err) => {
      console.error("SSE connection error or closed:", err);
      eventSource.close();
    };

    return () => {
      eventSource.close();
    };
  }, [activeSessionId]);

  const handleUpdateStatus = async (alertId, newStatus) => {
    setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, status: newStatus } : a));
    if (activeAlert && activeAlert.id === alertId) {
      setActiveAlert(prev => ({ ...prev, status: newStatus }));
    }
  };

  const handleUploadSuccess = (sessionData) => {
    setSessions(prev => [sessionData, ...prev]);
    setActiveSessionId(sessionData.id);
    setActiveTab('dashboard'); 
  };

  const handleSessionChange = (sessionId) => {
    setActiveSessionId(sessionId);
  };

  const getActiveSession = () => {
    return sessions.find(s => s.id === activeSessionId) || null;
  };

  const computeStats = () => {
    if (alerts.length === 0) {
      return {
        total_alerts: 0,
        severities: { Critical: 0, High: 0, Medium: 0, Low: 0 },
        attack_types: { Normal: 0, DDoS: 0, 'Port Scan': 0, 'Brute Force': 0, 'Zero-Day Anomaly': 0 },
        top_sources: [],
        top_destinations: [],
        avg_anomaly_score: 0.0
      };
    }

    const total = alerts.length;
    const severities = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    const attack_types = {};
    const src_ips = {};
    const dst_ips = {};
    let sum_anomaly = 0.0;

    alerts.forEach(a => {
      severities[a.severity] = (severities[a.severity] || 0) + 1;
      attack_types[a.attack_type] = (attack_types[a.attack_type] || 0) + 1;
      src_ips[a.src_ip] = (src_ips[a.src_ip] || 0) + 1;
      dst_ips[a.dst_ip] = (dst_ips[a.dst_ip] || 0) + 1;
      sum_anomaly += a.anomaly_score;
    });

    const top_src = Object.entries(src_ips)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([ip, count]) => ({ ip, count }));

    const top_dst = Object.entries(dst_ips)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([ip, count]) => ({ ip, count }));

    return {
      total_alerts: total,
      severities,
      attack_types,
      top_sources: top_src,
      top_destinations: top_dst,
      avg_anomaly_score: sum_anomaly / total
    };
  };

  const activeSessionStats = computeStats();
  const currentSession = getActiveSession();

  return (
    <div style={styles.appContainer}>
      {/* Sidebar Navigation */}
      <Sidebar 
        activeTab={activeTab} 
        setActiveTab={setActiveTab}
        backendStatus={backendStatus}
        sessions={sessions}
        activeSessionId={activeSessionId}
        handleSessionChange={handleSessionChange}
      />

      {/* Main Content Area */}
      <main style={styles.mainContent}>
        {/* Global SOC Navbar */}
        <header style={styles.navbar}>
          <div style={styles.navLeft}>
            <Shield size={20} color="var(--accent-primary)" style={{ filter: 'drop-shadow(0 0 6px var(--glow-teal))' }} />
            <span style={styles.navTitle}>THREATSENTINEL LITE</span>
            <div style={styles.navDivider} />
            <div style={styles.statusGroup}>
              <span className="pulse-dot"></span>
              <span style={styles.statusLabel}>SYSTEM ACTIVE</span>
            </div>
          </div>
          <div style={styles.navRight}>
            <span style={styles.timestamp}>{currentTime}</span>
          </div>
        </header>

        <div style={styles.tabContent}>
          {activeTab === 'dashboard' && (
            <div style={styles.dashboardLayout}>
              {/* Upload Zone at Top */}
              <UploadZone onUploadSuccess={handleUploadSuccess} />
              
              {/* Dynamic Overview Metrics & Charts */}
              <Dashboard 
                stats={activeSessionStats}
                alerts={alerts}
                activeSession={currentSession}
                onRefresh={handleRefresh}
                sessions={sessions}
                activeSessionId={activeSessionId}
                handleSessionChange={handleSessionChange}
              />
            </div>
          )}

          {activeTab === 'alerts' && (
            <div style={styles.alertsLayout}>
              <AlertList 
                alerts={alerts}
                onSelectAlert={setActiveAlert}
                activeAlertId={activeAlert?.id}
                onUpdateStatus={handleUpdateStatus}
              />
              {activeAlert && (
                <AlertDetail 
                  alert={activeAlert}
                  onClose={() => setActiveAlert(null)}
                  onUpdateStatus={handleUpdateStatus}
                />
              )}
            </div>
          )}

          {activeTab === 'intel' && (
            <div style={styles.intelLayout}>
              <ThreatIntel 
                onSelectAlert={setActiveAlert}
                activeAlertId={activeAlert?.id}
                onUpdateStatus={handleUpdateStatus}
              />
              {activeAlert && (
                <AlertDetail 
                  alert={activeAlert}
                  onClose={() => setActiveAlert(null)}
                  onUpdateStatus={handleUpdateStatus}
                />
              )}
            </div>
          )}

          {activeTab === 'chat' && (
            <div style={styles.chatLayout}>
              <CoPilotChat 
                activeSessionId={activeSessionId} 
                sessions={sessions}
              />
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

const styles = {
  appContainer: {
    display: 'flex',
    height: '100vh',
    width: '100vw',
    backgroundColor: 'var(--bg-main)',
    overflow: 'hidden',
  },
  mainContent: {
    flexGrow: 1,
    height: '100%',
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
  },
  navbar: {
    height: '56px',
    backgroundColor: 'var(--bg-sidebar)',
    borderBottom: '1px solid var(--border-light)',
    padding: '0 24px',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    flexShrink: 0,
  },
  navLeft: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  },
  navTitle: {
    fontSize: '14px',
    fontWeight: '700',
    color: 'var(--text-primary)',
    letterSpacing: '0.75px',
  },
  navDivider: {
    width: '1px',
    height: '16px',
    backgroundColor: 'var(--border-light)',
    margin: '0 4px',
  },
  statusGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  },
  statusLabel: {
    fontSize: '11px',
    fontWeight: '600',
    color: 'var(--accent-primary)',
    letterSpacing: '0.5px',
  },
  navRight: {
    display: 'flex',
    alignItems: 'center',
  },
  timestamp: {
    fontFamily: 'monospace',
    fontSize: '12px',
    color: 'var(--text-secondary)',
    backgroundColor: 'rgba(255, 255, 255, 0.02)',
    padding: '4px 10px',
    borderRadius: '4px',
    border: '1px solid var(--border-light)',
  },
  tabContent: {
    flexGrow: 1,
    height: 'calc(100% - 56px)',
    overflow: 'hidden',
  },
  dashboardLayout: {
    height: '100%',
    display: 'flex',
    flexDirection: 'column',
    overflowY: 'auto',
    padding: '20px 0',
  },
  alertsLayout: {
    height: '100%',
    display: 'flex',
    overflow: 'hidden',
  },
  intelLayout: {
    height: '100%',
    display: 'flex',
    overflow: 'hidden',
  },
  chatLayout: {
    height: '100%',
    padding: '30px',
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
  }
};
