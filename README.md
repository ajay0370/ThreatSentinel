# 🛡️ ThreatSentinel Lite
### AI-Powered Zero-Day Threat Detection System

> **AI-powered network threat detection and analytics platform combining machine learning anomaly detection with LLM-generated threat explanations for SOC analysts.**

Traditional signature-based intrusion detection systems struggle to detect novel or zero-day attacks, and raw alerts are often too technical for rapid triage. **ThreatSentinel Lite** bridges this gap by combining unsupervised anomaly detection with supervised attack classification, then leveraging an LLM to generate plain-English explanations and executive-ready reports.

---

## 🌟 Key Features

* **Dual-Model Detection Engine:**
  * **Isolation Forest (Unsupervised Anomaly Detector):** Learns standard network baseline communication and flags high-anomaly outliers as Zero-Day anomalies (95.88% accuracy).
  * **Random Forest Classifier (Supervised Multi-Class):** Classifies known attack vectors including **DDoS**, **Port Scans**, and **Brute Force** attempts (100% accuracy).
* **MITRE ATT&CK Mapping:** Maps all flagged threats to standardized MITRE ATT&CK technique/tactic IDs and recommendations for SOC-friendly analysis.
* **Real-Time SOC Dashboard:** Streams threat alerts row-by-row onto a sleek dark-themed browser dashboard via Server-Sent Events (SSE).
* **Gemini AI Incident Co-Pilot:** A chat widget loaded with active session context enables analysts to investigate IP behaviors, request mitigation plans, and discuss threat profiles.
* **Local Expert Heuristics Fallback:** Automatically switches to rule-based heuristics if the Gemini API Key is missing or offline, ensuring robust operation.
* **Executive Summary PDF Generation:** Automatically generates custom-compiled ReportLab PDF reports containing AI executive summaries, charts, top alerts, and MITRE recommendations.

---

## 🏗️ System Architecture

```text
PCAP / Network Flow Data
        │
        ▼
Scapy Feature Extraction
        │
        ▼
┌─────────────────────┐
│  Isolation Forest   │ → Anomaly Detection (Zero-Day mapping)
│  Random Forest      │ → Attack Classification
└─────────────────────┘
        │
        ▼
MITRE ATT&CK Mapping
        │
        ▼
Flask REST API + SSE (SQLite threats.db)
        │
        ▼
┌─────────────────────┬────────────────────────┐
│ React SOC Dashboard │ Gemini LLM Co-pilot    │
│ (Recharts)          │ Explanations + Reports │
└─────────────────────┴────────────────────────┘
```

---

## 📂 Project Directory Structure

```text
ThreatSentinel/
├── ml_engine/
│   ├── models/
│   │   ├── scaler.pkl              # Standardized feature scaling model
│   │   ├── isolation_forest.pkl    # Outlier detection model (Zero-Day mapping)
│   │   ├── random_forest.pkl       # Labeled threat classifier
│   │   └── evaluation.json         # Performance metrics (Precision, Recall)
│   ├── data_generator.py           # Synthetic flow generator & Scapy PCAP compiler
│   ├── train.py                    # Model trainer (supports --mode flags)
│   └── pipeline.py                 # PCAP flow extractor & prediction pipeline
├── backend/
│   ├── app.py                      # Flask Server (REST endpoints + CORS + SSE)
│   ├── database.py                 # SQLite database setup & queries (threats.db)
│   ├── mitre.py                    # MITRE ATT&CK technique mapper
│   ├── report.py                   # ReportLab PDF compiler
│   ├── gemini.py                   # Gemini LLM integration + expert fallback
│   └── requirements.txt            # Backend python dependencies (pinned)
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Sidebar.jsx         # Sidebar tab and session history lists
│   │   │   ├── Dashboard.jsx       # Chart panels and stats overview cards
│   │   │   ├── UploadZone.jsx      # Drag-and-drop file upload with progress
│   │   │   ├── AlertList.jsx       # Dynamic searchable threats logs table
│   │   │   ├── AlertDetail.jsx     # Flow details drawer & MITRE mitigations
│   │   │   ├── ThreatIntel.jsx     # Aggregated database stats & top 15 historical threats
│   │   │   └── CoPilotChat.jsx     # Conversational co-pilot interface
│   │   ├── App.jsx                 # Global state controller & SSE connection
│   │   ├── main.jsx                # Vite mounting script
│   │   └── index.css               # Dark theme variables & animations
│   ├── package.json                # Frontend NPM packages
│   └── vite.config.js              # Vite configuration
├── runtime.txt                     # Force Python 3.11.9 for Render Deployment
├── requirements.txt                # Root copy of backend dependencies
└── setup.sh                        # One-command developer environment installer
```

---

## 📈 ML Engine Feature Engineering & Performance

The pipeline aggregates packet headers and payloads into bidirectional flows grouped by:
`tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)])) + (protocol,)`

### Extracted Features (12 dimensions):
1. `duration` (flow length in seconds)
2. `pkt_count_out` (packets sent)
3. `pkt_count_in` (packets received)
4. `byte_count_out` (bytes sent)
5. `byte_count_in` (bytes received)
6. `pkt_rate` (packets per second)
7. `byte_rate` (bytes per second)
8. `avg_pkt_sz` (average packet size in bytes)
9. `tcp_flags_syn` (count of SYN flags)
10. `tcp_flags_ack` (count of ACK flags)
11. `tcp_flags_rst` (count of RST flags)
12. `protocol` (IP protocol number, e.g. TCP=6, UDP=17)

### Model Evaluation (CIC-IDS2017 Dataset Split):

#### 1. Isolation Forest (Binary Anomaly Detection)
* **Accuracy:** `95.88%`
* **Precision:** `92.08%`
* **Recall:** `98.13%`
* **F1-Score:** `95.01%`

#### 2. Random Forest (Multi-Class Classification)
* **Accuracy:** `100.00%`
* **Precision:** `100.00%`
* **Recall:** `100.00%`
* **F1-Score:** `100.00%`

*Note: These results were obtained on an 800-sample stratified test split. Such high performance warrants scrutiny for potential data leakage (e.g. flow-level near duplicates or feature leakage). Further validation on larger, time-separated hold-out datasets is in progress.*

#### Confusion Matrix:
```text
               Predicted:
               Normal   DDoS   PortScan   BruteForce
  Normal         480      0        0          0
  DDoS             0    115        0          0
  Port Scan        0      0      125          0
  Brute Force      0      0        0         80
```

---

## 🛠️ Tech Stack

* **Machine Learning:** Python, Scikit-learn, Pandas, Scapy, Joblib
* **Backend API:** Flask, SQLite (sqlite3), Server-Sent Events (SSE)
* **Frontend UI:** React.js, Recharts, Lucide-React
* **AI/LLM:** Google Gemini API (gemini-1.5-flash model)
* **Reporting:** ReportLab PDF Library

---

## 🏁 Local Installation & Launch

### Prerequisites
* Python 3.11
* Node.js (v18+) and NPM
* Google Gemini API Key (optional)

### Setup & Run Commands

1. **Clone the repository:**
   ```bash
   git clone https://github.com/ajay0370/ThreatSentinel.git
   cd ThreatSentinel
   ```

2. **Configure Environment Variables:**
   Create a `.env` file in the root workspace folder:
   ```ini
   FLASK_APP=backend/app.py
   FLASK_ENV=development
   PORT=5000
   GEMINI_API_KEY=your_gemini_api_key_here
   ```

3. **Install Dependencies (Automatic):**
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```
   *For Windows (PowerShell):*
   ```powershell
   python -m venv venv
   .\venv\Scripts\activate
   pip install -r backend/requirements.txt
   cd frontend
   npm install
   cd ..
   ```

4. **Compile Test PCAP (Optional):**
   Generate the synthetic datasets and PCAPs:
   ```bash
   python ml_engine/data_generator.py
   python ml_engine/train.py --mode synthetic
   ```

5. **Run the Backend API Server:**
   ```bash
   python backend/app.py
   ```
   *Backend listens on:* `http://localhost:5000`

6. **Run the React SOC Dashboard:**
   Open a separate terminal:
   ```bash
   cd frontend
   npm run dev
   ```
   *Interface listens on:* `http://localhost:5173`

---

## ☁️ Deployment Guide (Render)

Render hosts the Flask python backend. Follow these instructions to deploy it successfully:

### Step 1: Push Project to GitHub
Commit all local changes (including `runtime.txt` and `requirements.txt` configs) and push them to your repository on GitHub.

### Step 2: Configure Render Settings
1. Go to your [Render Dashboard](https://dashboard.render.com).
2. Click **New +** and select **Web Service**.
3. Connect your GitHub repository.
4. Set the following parameters:
   * **Name:** `ThreatSentinel-Backend`
   * **Region:** `Oregon (US West)` (or closest matching region)
   * **Branch:** `main`
   * **Runtime:** `Python`

5. Configure **Root Directory** and **Commands**:

   * **If your "Root Directory" is set to `backend` (Recommended):**
     * **Build Command:** `pip install -r requirements.txt`
     * **Start Command:** `gunicorn --bind 0.0.0.0:$PORT app:app`

   * **If your "Root Directory" is empty or `/` (Repository Root):**
     * **Build Command:** `pip install -r requirements.txt`
     * **Start Command:** `gunicorn --bind 0.0.0.0:$PORT backend.app:app`

### Step 3: Add Environment Variables
1. Scroll down to the **Environment** section.
2. Click **Add Environment Variable** and enter:
   * **Key:** `GEMINI_API_KEY`
   * **Value:** *(Paste your Google Gemini API Key)*
3. Add a second environment variable:
   * **Key:** `PYTHON_VERSION`
   * **Value:** `3.11.9`

### Step 4: Deploy Service
1. Click **Create Web Service** at the bottom of the page.
2. Wait for the build logs to install dependencies. Render will automatically read `runtime.txt`, install Python 3.11.9, download the precompiled binary wheels, and boot up gunicorn.

---

## 🔮 Future Improvements

- [ ] Validate model performance on larger, time-separated datasets.
- [ ] Add live packet capture support.
- [ ] Implement user authentication for multi-analyst SOC environments.
- [ ] Add role-based access control (RBAC).
- [ ] Containerize services using Docker.

---

## 📜 License & Acknowledgement

* This project is licensed under the **MIT License**.
* Dataset derived from the **CIC-IDS2017** dataset.
