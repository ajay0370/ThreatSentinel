import React, { useState, useRef, useEffect } from 'react';
import { Send, Sparkles, Loader2, Bot, User, Trash2 } from 'lucide-react';
import { API_BASE_URL } from '../config';

export default function CoPilotChat({ activeSessionId, sessions }) {
  const [messages, setMessages] = useState([
    {
      id: 1,
      sender: 'copilot',
      text: "Hello! I am ThreatSentinel Co-pilot. I have loaded your active session details. You can ask me to summarize the network threat profile, explain any specific alerts, or draft containment recommendations."
    }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const chatEndRef = useRef(null);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  const handleSend = async (textToSend) => {
    const query = textToSend || input;
    if (!query.trim()) return;

    if (!activeSessionId) {
      setMessages(prev => [
        ...prev,
        { id: Date.now(), sender: 'analyst', text: query },
        { id: Date.now() + 1, sender: 'copilot', text: "⚠️ Please upload a PCAP file or select an active analysis session first so I can assist you with context-aware security insights." }
      ]);
      if (!textToSend) setInput('');
      return;
    }

    const userMsg = { id: Date.now(), sender: 'analyst', text: query };
    setMessages(prev => [...prev, userMsg]);
    if (!textToSend) setInput('');
    setLoading(true);

    try {
      const response = await fetch(`${API_BASE_URL}/api/chat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          question: query,
          session_id: activeSessionId
        }),
      });

      if (!response.ok) {
        throw new Error('Chat API returned an error');
      }

      const data = await response.json();
      setMessages(prev => [
        ...prev,
        { id: Date.now() + 2, sender: 'copilot', text: data.response }
      ]);
    } catch (err) {
      console.error(err);
      setMessages(prev => [
        ...prev,
        { id: Date.now() + 2, sender: 'copilot', text: "❌ Connection error. I couldn't reach the ThreatSentinel API server. Please check that Flask is running." }
      ]);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      handleSend();
    }
  };

  const clearChat = () => {
    setMessages([
      {
        id: 1,
        sender: 'copilot',
        text: "Chat logs cleared. Ask me anything about the active traffic capture!"
      }
    ]);
  };

  const quickPrompts = [
    "Summarize active threats",
    "How to mitigate DDoS alerts?",
    "Explain zero-day anomalies",
    "Provide incident response checklist"
  ];

  return (
    <div className="glass-panel" style={styles.container}>
      {/* Header */}
      <div style={styles.header}>
        <div style={styles.titleGroup}>
          <Sparkles size={18} color="var(--accent-primary)" />
          <h3 style={styles.title}>ThreatSentinel Co-pilot</h3>
        </div>
        <button onClick={clearChat} style={styles.clearBtn} title="Clear Chat History">
          <Trash2 size={16} color="var(--text-muted)" />
        </button>
      </div>

      {/* Message Area */}
      <div className="custom-scroll" style={styles.messageList}>
        {messages.map((msg) => {
          const isCopilot = msg.sender === 'copilot';
          return (
            <div 
              key={msg.id} 
              style={{
                ...styles.messageWrapper,
                justifyContent: isCopilot ? 'flex-start' : 'flex-end'
              }}
            >
              {isCopilot ? (
                <div style={styles.avatarCopilot}>
                  <Bot size={16} color="var(--accent-primary)" />
                </div>
              ) : (
                null
              )}
              
              <div 
                style={{
                  ...styles.bubble,
                  ...(isCopilot ? styles.bubbleCopilot : styles.bubbleAnalyst)
                }}
              >
                {msg.text.split('\n').map((line, index) => {
                  if (line.startsWith('- ')) {
                    return <li key={index} style={styles.li}>{line.replace('- ', '')}</li>;
                  }
                  if (line.startsWith('### ')) {
                    return <h4 key={index} style={styles.h4}>{line.replace('### ', '')}</h4>;
                  }
                  if (line.trim() !== '') {
                    return <p key={index} style={styles.p}>{line.replace(/\*\*/g, '')}</p>;
                  }
                  return <div key={index} style={{ height: '6px' }} />;
                })}
              </div>

              {!isCopilot ? (
                <div style={styles.avatarUser}>
                  <User size={16} color="var(--accent-secondary)" />
                </div>
              ) : (
                null
              )}
            </div>
          );
        })}
        
        {loading && (
          <div style={styles.messageWrapper}>
            <div style={styles.avatarCopilot}>
              <Bot size={16} color="var(--accent-primary)" />
            </div>
            <div style={{...styles.bubble, ...styles.bubbleCopilot, display: 'flex', alignItems: 'center', gap: '8px'}}>
              <Loader2 size={14} className="spinner" style={{ color: 'var(--accent-primary)' }} />
              <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Co-pilot is investigating...</span>
            </div>
          </div>
        )}
        <div ref={chatEndRef} />
      </div>

      {/* Quick Pills */}
      <div style={styles.pillsContainer}>
        {quickPrompts.map((prompt, idx) => (
          <button 
            key={idx} 
            onClick={() => handleSend(prompt)} 
            disabled={loading}
            style={styles.pill}
          >
            {prompt}
          </button>
        ))}
      </div>

      {/* Input Area */}
      <div style={styles.inputArea}>
        <input 
          type="text" 
          placeholder="Ask a question about network alerts..." 
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyPress}
          disabled={loading}
          style={styles.input}
        />
        <button 
          onClick={() => handleSend()} 
          disabled={loading || !input.trim()}
          style={{
            ...styles.sendBtn,
            backgroundColor: input.trim() && !loading ? 'var(--accent-primary)' : 'rgba(255,255,255,0.03)'
          }}
        >
          <Send size={16} color={input.trim() && !loading ? '#0A0E1A' : 'var(--text-muted)'} />
        </button>
      </div>
    </div>
  );
}

const styles = {
  container: {
    display: 'flex',
    flexDirection: 'column',
    height: '100%',
    width: '100%',
    padding: '20px',
    overflow: 'hidden',
    backgroundColor: '#0A0E1A', // Changed to #0A0E1A
    borderWidth: '0px',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '16px',
    paddingBottom: '12px',
    borderBottomWidth: '1px',
    borderBottomStyle: 'solid',
    borderBottomColor: 'var(--border-light)',
  },
  titleGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  },
  title: {
    fontSize: '15px',
    fontWeight: '700',
    color: 'var(--text-primary)',
  },
  clearBtn: {
    backgroundColor: 'transparent',
    border: 'none',
    cursor: 'pointer',
    padding: '4px',
    borderRadius: '4px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  },
  messageList: {
    flexGrow: 1,
    display: 'flex',
    flexDirection: 'column',
    gap: '16px',
    padding: '10px 4px',
    marginBottom: '10px',
  },
  messageWrapper: {
    display: 'flex',
    alignItems: 'flex-start',
    gap: '12px',
  },
  avatarCopilot: {
    width: '32px',
    height: '32px',
    borderRadius: '50%',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    flexShrink: 0,
    marginTop: '4px',
    borderWidth: '2px',
    borderStyle: 'solid',
    borderColor: 'var(--accent-primary)',
    backgroundColor: 'rgba(0, 212, 170, 0.1)',
  },
  avatarUser: {
    width: '32px',
    height: '32px',
    borderRadius: '50%',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    flexShrink: 0,
    marginTop: '4px',
    borderWidth: '2px',
    borderStyle: 'solid',
    borderColor: 'var(--accent-secondary)',
    backgroundColor: 'rgba(59, 130, 246, 0.1)',
  },
  bubble: {
    padding: '12px 16px',
    borderRadius: '12px',
    maxWidth: '75%',
    lineHeight: '18px',
  },
  bubbleCopilot: {
    backgroundColor: '#111827',
    color: 'var(--text-primary)',
    borderTopWidth: '1px',
    borderBottomWidth: '1px',
    borderRightWidth: '1px',
    borderLeftWidth: '3px',
    borderTopStyle: 'solid',
    borderBottomStyle: 'solid',
    borderRightStyle: 'solid',
    borderLeftStyle: 'solid',
    borderTopColor: 'var(--border-light)',
    borderBottomColor: 'var(--border-light)',
    borderRightColor: 'var(--border-light)',
    borderLeftColor: 'var(--accent-primary)', // 3px solid teal left border
    borderTopLeftRadius: '2px',
  },
  bubbleAnalyst: {
    backgroundColor: '#1E3A8A', // User messages: right-aligned dark blue bubble
    color: 'var(--text-primary)',
    borderTopRightRadius: '2px',
  },
  p: {
    fontSize: '13px',
    marginBottom: '4px',
  },
  li: {
    fontSize: '12.5px',
    marginLeft: '14px',
    marginBottom: '3px',
    color: 'var(--text-secondary)',
  },
  h4: {
    fontSize: '13px',
    fontWeight: '700',
    color: 'var(--color-medium)',
    marginTop: '6px',
    marginBottom: '4px',
  },
  pillsContainer: {
    display: 'flex',
    gap: '8px',
    flexWrap: 'wrap',
    marginBottom: '12px',
    paddingTop: '8px',
    borderTopWidth: '1px',
    borderTopStyle: 'solid',
    borderTopColor: 'var(--border-light)',
  },
  pill: {
    backgroundColor: 'rgba(255,255,255,0.02)',
    borderWidth: '1px',
    borderStyle: 'solid',
    borderColor: 'var(--border-light)',
    color: 'var(--text-secondary)',
    borderRadius: '16px',
    padding: '4px 10px',
    fontSize: '11px',
    fontWeight: '500',
    cursor: 'pointer',
    transition: 'all var(--transition-fast)',
  },
  inputArea: {
    display: 'flex',
    gap: '8px',
    alignItems: 'center',
    backgroundColor: 'rgba(0,0,0,0.2)',
    borderWidth: '1px',
    borderStyle: 'solid',
    borderColor: 'var(--border-light)',
    borderRadius: '8px',
    padding: '4px 6px',
  },
  input: {
    flexGrow: 1,
    backgroundColor: 'transparent',
    border: 'none',
    color: 'var(--text-primary)',
    fontSize: '13px',
    padding: '8px',
    outline: 'none',
  },
  sendBtn: {
    border: 'none',
    borderRadius: '6px',
    width: '32px',
    height: '32px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    cursor: 'pointer',
    transition: 'all var(--transition-fast)',
  }
};
