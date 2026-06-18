# 🛡️ ThreatSentinel Lite

> **AI-powered network threat detection and analytics platform combining machine learning anomaly detection with LLM-generated threat explanations for SOC analysts.**

Traditional signature-based intrusion detection systems struggle to detect novel or zero-day attacks, and raw alerts are often too technical for rapid triage. **ThreatSentinel Lite** bridges this gap by combining unsupervised anomaly detection with supervised attack classification, then leveraging an LLM to generate plain-English explanations and executive-ready reports.

---

## 🚀 Features

- **Dual-model detection**
  - Isolation Forest for anomaly and zero-day detection
  - Random Forest for known attack classification

- **MITRE ATT&CK Mapping**
  - Maps detections to standardized MITRE ATT&CK technique IDs for SOC-friendly analysis.

- **Real-time Alerting**
  - Server-Sent Events (SSE) stream alerts to the dashboard without polling.

- **LLM Threat Co-pilot**
  - Gemini-powered explanations describing why network flows were flagged.

- **Executive Summary Generation**
  - Automatically generates AI-written PDF reports for non-technical stakeholders.

- **SOC-style Dashboard**
  - Dark-themed React interface with charts and alert history visualizations.

---

# 🏗️ Architecture

```text
PCAP / Network Flow Data
        │
        ▼
Scapy Feature Extraction
        │
        ▼
┌─────────────────────┐
│  Isolation Forest   │ → Anomaly Detection
│  Random Forest      │ → Attack Classification
└─────────────────────┘
        │
        ▼
MITRE ATT&CK Mapping
        │
        ▼
Flask REST API + SSE
        │
        ▼
┌─────────────────────┬────────────────────────┐
│ React SOC Dashboard │ Gemini LLM Co-pilot    │
│ (Recharts)          │ Explanations + Reports │
└─────────────────────┴────────────────────────┘
```

---

# 📊 Model Performance

Evaluated on the **CIC-IDS2017** dataset.

## Isolation Forest (Binary Anomaly Detection)

| Metric | Score |
|----------|------:|
| Accuracy | 95.88% |
| Precision | 92.08% |
| Recall | 98.13% |
| F1-Score | 95.01% |

## Random Forest (Multi-Class Classification)

| Metric | Score |
|----------|------:|
| Accuracy | 100%* |
| Precision | 100%* |
| Recall | 100%* |
| F1-Score | 100%* |

> **Note:** These results were obtained on an 800-sample stratified test split. Such high performance warrants scrutiny for potential data leakage (e.g., flow-level near duplicates or feature leakage). Further validation on larger, time-separated hold-out datasets is in progress. These numbers should be considered preliminary rather than production-validated.

### Confusion Matrix

```text
              Predicted
              Normal  DDoS  PortScan  BruteForce
Normal         480      0      0          0
DDoS             0    115      0          0
Port Scan        0      0    125          0
Brute Force      0      0      0         80
```

---

# 🛠️ Tech Stack

### Machine Learning
- Python
- Scikit-learn
- Pandas
- Scapy

### Backend
- Flask
- SQLite
- Server-Sent Events (SSE)

### Frontend
- React.js
- Recharts

### AI / LLM
- Google Gemini API

### Reporting
- ReportLab

### Dataset
- CIC-IDS2017

### Deployment
- Render

---

# ⚙️ Installation

## Prerequisites

- Python 3.x
- Node.js and npm
- Google Gemini API key

---

## Backend Setup

```bash
git clone https://github.com/YOUR_USERNAME/ThreatSentinel-Lite.git

cd ThreatSentinel-Lite/backend

python -m venv venv

# Linux / macOS
source venv/bin/activate

# Windows
venv\Scripts\activate

pip install -r requirements.txt

# Create environment file
cp .env.example .env

# Add your GEMINI_API_KEY and configuration

python app.py
```

---

## Frontend Setup

```bash
cd ../frontend

npm install

npm start
```

---

## Running the Application

Frontend:

```text
http://localhost:3000
```

Backend API:

```text
http://localhost:5000
```

---

# 📂 Project Structure

```text
ThreatSentinel-Lite/
│
├── backend/
│   ├── app.py
│   ├── api/                # Flask routes
│   ├── models/             # Trained model files
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   └── App.js
│   └── package.json
│
├── data/                   # Dataset and preprocessing scripts
│
└── README.md
```

---

# 🚀 Usage

1. Start the backend and frontend.
2. Upload a PCAP file or connect a live traffic source.
3. Monitor real-time detections on the dashboard.
4. Click an alert to view a Gemini-generated explanation.
5. Export executive summaries as PDF reports.

---

# 🔮 Future Improvements

- [ ] Validate model performance on larger, time-separated datasets.
- [ ] Add live packet capture support.
- [ ] Expand attack classes beyond:
  - DDoS
  - Port Scan
  - Brute Force
- [ ] Implement user authentication for multi-analyst SOC environments.
- [ ] Add role-based access control (RBAC).
- [ ] Containerize services using Docker.
- [ ] Deploy with CI/CD pipelines.

---

# 📜 License

This project is licensed under the **MIT License**.

---

## ⭐ Acknowledgements

- **CIC-IDS2017** dataset
- **Google Gemini API**
- **Scikit-learn**
- **Flask**
- **React**
- **MITRE ATT&CK Framework**

---
