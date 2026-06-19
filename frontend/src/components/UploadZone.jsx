import React, { useState, useRef } from 'react';
import { Upload, File, Loader2, AlertCircle, CheckCircle } from 'lucide-react';
import { API_BASE_URL } from '../config';

export default function UploadZone({ onUploadSuccess }) {
  const [dragOver, setDragOver] = useState(false);
  const [file, setFile] = useState(null);
  const [uploadState, setUploadState] = useState('idle'); // idle | uploading | success | error
  const [errorMessage, setErrorMessage] = useState('');
  const fileInputRef = useRef(null);

  const handleDragOver = (e) => {
    e.preventDefault();
    setDragOver(true);
  };

  const handleDragLeave = () => {
    setDragOver(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      validateAndSetFile(files[0]);
    }
  };

  const handleFileSelect = (e) => {
    const files = e.target.files;
    if (files.length > 0) {
      validateAndSetFile(files[0]);
    }
  };

  const validateAndSetFile = (selectedFile) => {
    if (!selectedFile.name.endsWith('.pcap')) {
      setUploadState('error');
      setErrorMessage('Unsupported file type. Please upload a .pcap file.');
      setFile(null);
      return;
    }
    
    // Limits size to 50MB for demo stability
    if (selectedFile.size > 50 * 1024 * 1024) {
      setUploadState('error');
      setErrorMessage('File size exceeds 50MB. Please use a smaller PCAP.');
      setFile(null);
      return;
    }
    
    setFile(selectedFile);
    setUploadState('idle');
    setErrorMessage('');
  };

  const uploadPCAP = async () => {
    if (!file) return;

    setUploadState('uploading');
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch(`${API_BASE_URL}/api/upload`, {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Server error uploading file.');
      }

      const data = await response.json();
      setUploadState('success');
      
      // Pass the new session info back to main app state
      setTimeout(() => {
        onUploadSuccess(data);
        setFile(null);
        setUploadState('idle');
      }, 1500);

    } catch (err) {
      console.error(err);
      setUploadState('error');
      setErrorMessage(err.message || 'Failed to connect to the backend server.');
    }
  };

  return (
    <div className="glass-panel" style={styles.container}>
      <h3 style={styles.title}>Packet Capture Audit (PCAP)</h3>
      <p style={styles.subtitle}>Upload network captures to extract traffic flows and identify real-time zero-day anomalies or known attack vectors.</p>
      
      <div 
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => uploadState === 'idle' && fileInputRef.current?.click()}
        style={{
          ...styles.dropzone,
          ...(dragOver ? styles.dropzoneActive : {}),
          ...(uploadState !== 'idle' ? styles.dropzoneDisabled : {})
        }}
      >
        <input 
          type="file" 
          ref={fileInputRef} 
          onChange={handleFileSelect} 
          style={{ display: 'none' }}
          accept=".pcap"
          disabled={uploadState !== 'idle'}
        />

        {uploadState === 'idle' && !file && (
          <div style={styles.dropContent}>
            <Upload size={48} color="var(--accent-primary)" style={styles.icon} />
            <p style={styles.dropText}>Drag and drop your <b>.pcap</b> file here, or click to browse</p>
            <span style={styles.fileLimit}>Max File Size: 50MB</span>
          </div>
        )}

        {file && uploadState === 'idle' && (
          <div style={styles.dropContent}>
            <File size={48} color="var(--accent-primary)" style={styles.icon} />
            <p style={styles.filename}>{file.name}</p>
            <p style={styles.filesize}>{(file.size / (1024 * 1024)).toFixed(2)} MB</p>
            <button 
              onClick={(e) => {
                e.stopPropagation();
                uploadPCAP();
              }}
              style={styles.uploadBtn}
            >
              Analyze PCAP
            </button>
          </div>
        )}

        {uploadState === 'uploading' && (
          <div style={styles.dropContent}>
            <Loader2 size={40} className="spinner" style={{ ...styles.icon, color: 'var(--accent-primary)' }} />
            <p style={styles.statusText}>Analyzing Capture...</p>
            
            {/* Added Teal Progress Bar with CSS animation */}
            <div style={styles.progressBarBg}>
              <div className="pulse-progress" style={styles.progressBarFill}></div>
            </div>
            
            <p style={styles.subtext}>Transmitting flows to ThreatSentinel ML Engine</p>
          </div>
        )}

        {uploadState === 'success' && (
          <div style={styles.dropContent}>
            <CheckCircle size={48} color="var(--color-normal)" style={styles.icon} />
            <p style={styles.successText}>Upload Complete!</p>
            <p style={styles.subtext}>Initializing SSE Live Analysis feed...</p>
          </div>
        )}

        {uploadState === 'error' && (
          <div style={styles.dropContent}>
            <AlertCircle size={48} color="var(--color-critical)" style={styles.icon} />
            <p style={styles.errorText}>Upload Failed</p>
            <p style={styles.errorMessage}>{errorMessage}</p>
            <button 
              onClick={(e) => {
                e.stopPropagation();
                setUploadState('idle');
                setFile(null);
              }}
              style={styles.retryBtn}
            >
              Try Again
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

const styles = {
  container: {
    padding: '24px',
    margin: '20px 24px 0 24px',
    backgroundColor: 'var(--bg-card)',
  },
  title: {
    fontSize: '16px',
    fontWeight: '700',
    color: 'var(--text-primary)',
    marginBottom: '6px',
  },
  subtitle: {
    fontSize: '13px',
    color: 'var(--text-secondary)',
    marginBottom: '20px',
  },
  dropzone: {
    borderWidth: '2px',
    borderStyle: 'dashed',
    borderColor: 'var(--accent-primary)',
    borderRadius: '12px',
    padding: '40px 20px',
    textAlign: 'center',
    cursor: 'pointer',
    backgroundColor: '#0D1421',
    transition: 'all var(--transition-normal)',
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
  },
  dropzoneActive: {
    borderColor: '#00FF9D',
    backgroundColor: 'rgba(0, 255, 157, 0.03)',
    boxShadow: '0 0 16px rgba(0, 255, 157, 0.25)',
  },
  dropzoneDisabled: {
    cursor: 'default',
    pointerEvents: 'none',
  },
  dropContent: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
  },
  icon: {
    marginBottom: '16px',
  },
  dropText: {
    fontSize: '14px',
    color: 'var(--text-secondary)',
    marginBottom: '6px',
  },
  fileLimit: {
    fontSize: '11px',
    color: 'var(--text-muted)',
  },
  filename: {
    fontSize: '15px',
    fontWeight: '600',
    color: 'var(--text-primary)',
    marginBottom: '4px',
  },
  filesize: {
    fontSize: '12px',
    color: 'var(--text-secondary)',
    marginBottom: '20px',
  },
  uploadBtn: {
    backgroundColor: 'var(--accent-primary)',
    color: '#0A0E1A',
    border: 'none',
    borderRadius: '6px',
    padding: '10px 20px',
    fontSize: '13px',
    fontWeight: '700',
    cursor: 'pointer',
    boxShadow: '0 4px 12px var(--glow-teal)',
    transition: 'all var(--transition-fast)',
  },
  retryBtn: {
    backgroundColor: 'transparent',
    color: 'var(--color-critical)',
    border: '1px solid var(--color-critical)',
    borderRadius: '6px',
    padding: '8px 16px',
    fontSize: '12px',
    fontWeight: '600',
    cursor: 'pointer',
    transition: 'all var(--transition-fast)',
  },
  statusText: {
    fontSize: '15px',
    fontWeight: '600',
    color: 'var(--text-primary)',
    marginBottom: '4px',
  },
  successText: {
    fontSize: '15px',
    fontWeight: '600',
    color: 'var(--color-normal)',
    marginBottom: '4px',
  },
  errorText: {
    fontSize: '15px',
    fontWeight: '600',
    color: 'var(--color-critical)',
    marginBottom: '4px',
  },
  errorMessage: {
    fontSize: '12px',
    color: 'var(--text-secondary)',
    marginBottom: '16px',
    maxWidth: '300px',
  },
  subtext: {
    fontSize: '12px',
    color: 'var(--text-secondary)',
  },
  progressBarBg: {
    width: '200px',
    height: '6px',
    backgroundColor: 'rgba(255, 255, 255, 0.05)',
    borderRadius: '3px',
    margin: '16px 0',
    overflow: 'hidden',
  },
  progressBarFill: {
    height: '100%',
    backgroundColor: 'var(--accent-primary)',
    borderRadius: '3px',
  }
};
