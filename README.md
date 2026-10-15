# PhishAudit AI: Forensic URL Intelligence for the Modern Web

> Real-time, zero-day phishing detection in the browser powered by a 5-stage cascading machine learning pipeline.


## Executive Summary

Traditional phishing defense systems rely heavily on reactive threat intelligence and static blacklists. A zero-day phishing URL must claim its first victims before being cataloged. 

PhishAudit AI bridges this critical defense gap. Embedded within Chromium via a Manifest V3 extension, it audits URLs upon browser navigation using an intelligent Five-Stage Cascading Pipeline. By combining curated high-reputation whitelisting, string-metric typosquatting detection, targeted brand combo-squatting heuristics, and a 37-feature Random Forest classifier, PhishAudit AI delivers accurate risk assessments in milliseconds before the user enters sensitive credentials.

---

## Key Features

* Zero-Day Structural Analysis: Evaluates 37 URL-only lexical, structural, heuristic, and information-theoretic features without requiring slow external DNS or DOM downloads.
* Five-Stage Cascading Pipeline: Employs dynamic decision boundaries instead of a rigid global threshold:
  * Stage 1 (Tier 1 Bypass): Sub-millisecond pass-through for 100+ verified high-reputation domains.
  * Stage 2 (Tier 2 Typosquatting Gate): Levenshtein edit distance (1 to 2) against trusted roots enforces an aggressive detection threshold (tau = 0.30).
  * Stage 3 (Tier 4 Combo-Squatting / HVT Gate): High-Value Target (HVT) brand matching across 40+ institutions lowers the threshold to tau = 0.25.
  * Stage 4 (Tier 3 Keyword Context Shifting): Unknown domains adjust thresholds dynamically (tau = 0.35 for 3 or more credential tokens; tau = 0.50 for 1 to 2 tokens; tau = 0.75 baseline).
  * Stage 5: Baseline Random Forest inference (tau = 0.6205 cost-sensitive optimum).
* Bangladesh Financial Sector Protection: Explicit threat models for regional Mobile Financial Services (MFS) and banks frequently targeted by SMS phishing: bKash, Nagad, DBBL Rocket, BRAC Bank, City Bank, EBL, UCBL, and Islami Bank.
* Real-Time Extension UX: Instant badge indicators (green for safe, red for phishing) and browser alert notifications.
* Fail-Safe Offline Design: If the backend service is offline, browsing continues uninterrupted with an Unknown status; the tool never blocks or crashes navigation.
* Security Operations Dashboard: Dedicated React 19 and Recharts administrative console providing live audit streams, risk distributions, and model performance metrics.

---

## System Architecture

```
                  +----------------------------------------------+
                  |          Chromium Browser Client             |
                  |   (Manifest V3 Service Worker / Popup UI)    |
                  +----------------------┬-----------------------+
                                         | JSON over HTTP
                                         v
                  +----------------------------------------------+
                  |             FastAPI Backend API              |
                  |              (Port 8000 Engine)              |
                  +----------------------┬-----------------------+
                                         |
        +--------------------------------+--------------------------------+
        v                                                                 v
+-------------------------------+                       +--------------------------------+
|  5-Stage Cascading Detection  |                       |         Data Layer             |
|  ---------------------------  |                       |  ----------------------------  |
|  Stage 1: Trusted Bypass      |                       |  SQLAlchemy ORM                |
|  Stage 2: Levenshtein Gate    |                       |  PostgreSQL (Prod)             |
|  Stage 3: Combo-Squatting HVT |                       |  SQLite Fallback (Dev/Demo)    |
|  Stage 4: Keyword Shifting    |                       |  Audit Logs & Model Metrics    |
|  Stage 5: Random Forest (37F) |                       +--------------------------------+
+---------------+---------------+
                |
                v
+-------------------------------+
|     React Admin Dashboard     |
|  (KPIs, Recharts, Audit Logs) |
+-------------------------------+
```

---

## The 37-Feature Extraction Taxonomy

All features are extracted in under 2ms directly from the raw URL string, preserving client privacy:

| Category | Count | Features Extracted |
| :--- | :---: | :--- |
| Lexical | 16 | Total length (url_len), counts of @, ?, -, =, ., #, %, +, $, !, *, ,, //, digit count, letter count |
| Structural | 4 | HTTPS usage, raw IPv4 pattern match, URL shortening service match (bit.ly, tinyurl, etc.), abnormal URL structure |
| Phishing Heuristics | 12 | Brand token presence, brand in subdomain, brand in path, consecutive hyphen count, digit count, long domain flag, excessive subdomains, suspicious TLD (.xyz, .top, .tk), keyword count, redirect markers, parameter count, encoded character count |
| Information-Theoretic | 5 | Shannon character entropy of URL path, domain trigram entropy, digit-to-alphabet ratio, subdomain depth count, total tokenization count |

---

## Empirical Evaluation and Research Results

Evaluated across 521,065 cleaned binary URLs (82.17% benign, 17.83% phishing) from the Malicious URL Detection Dataset (Enhanced 2026), and externally stress-tested on the PhiUSIIL dataset (235,795 URLs):

### 1. Primary Model Baseline (Test Set: 104,213 URLs)
* Optimal Decision Threshold (tau): 0.6205 (calibrated via Precision-Recall curve optimization)
* Accuracy: 93.10%
* Precision: 90.90% (minimal false alarms on legitimate web services)
* Recall: 79.50%
* F1-Score: 84.80%
* ROC-AUC: 96.30%

### 2. 5-Fold Stratified Cross-Validation
* Accuracy: 93.16% +/- 0.08%
* F1-Score: 81.47% +/- 0.23%
* ROC-AUC: 96.22% +/- 0.06%

### 3. Confusion Matrix Breakdown
* True Negatives (TN): 81,311
* True Positives (TP): 15,705
* False Positives (FP): 4,320
* False Negatives (FN): 2,877

### 4. External Cross-Dataset Generalization (PhiUSIIL Benchmark)
Evaluating the standalone Random Forest on 235,795 unseen URLs from PhiUSIIL demonstrated a 24.96% drop in ROC-AUC (from 96.26% to 71.30%). The baseline model achieved 100% recall but experienced a precision drop to 58.0% due to class prior shift (57:43 distribution vs. 82% benign in training). 

Key Finding: Fixed classification thresholds do not generalize across varying real-world distributions. This empirical finding provides the core academic justification for PhishAudit AI's dynamic cascading pipeline.

---

## Repository Directory Structure

```text
PhishAudit_AI/
|-- backend/
|   |-- connection.py            # Database engine & session generator (SQLAlchemy)
|   |-- cross_dataset_eval.py    # PhiUSIIL external dataset generalization benchmark
|   |-- data/                    # Datasets (Primary Kaggle 2026 & PhiUSIIL)
|   |-- data_audit.py            # Dataset integrity & domain overlap audit
|   |-- data_preprocessing.py    # Data cleaning & normalization pipeline
|   |-- database/
|   |   `-- models.py            # ORM schemas (AuditLog, ModelMetrics, User, Whitelist)
|   |-- domain_gate.py           # Stage 1 (Bypass) & Stage 2 (Levenshtein typosquatting)
|   |-- feature_extractor.py     # 37-feature extraction & normalization engine
|   |-- hvt_domains.py           # Stage 3 (Combo-squatting) & Stage 4 (Keyword shifting)
|   |-- main.py                  # FastAPI application & master pipeline orchestrator
|   |-- ml_engine.py             # Inference runner & feature vectorizer
|   |-- models/                  # Serialized artifacts (rf_model.pkl, optimal_threshold.pkl)
|   |-- requirements.txt         # Python dependencies
|   |-- run_api.py               # API launcher with SQLite failover & initial data seeder
|   |-- save_metrics.py          # Metric calculation & persistence script
|   |-- train_model.py           # Random Forest training & threshold optimizer
|   `-- trusted_domains.py       # Curated 100+ reputation whitelist
|-- dashboard/
|   |-- src/
|   |   |-- components/          # React components (AuditTable, MetricsChart, StatsCard, Header)
|   |   |-- App.jsx              # Main dashboard controller with 30s auto-polling
|   |   `-- App.css              # Dark/light theme styles
|   |-- package.json             # React 19 + Vite dependencies
|   `-- vite.config.js
`-- extension/
    |-- background.js            # Chrome MV3 background service worker
    |-- manifest.json            # Extension configuration & permissions
    |-- popup.html               # Extension popup layout
    |-- popup.js                 # Risk score meter, theme switcher, whitelist & reporting
    |-- popup.css                # Extension UI styles
    `-- icons/                   # Extension icons
```

---

## Installation and Setup

### Prerequisites
* Python 3.10+ (Python 3.11 recommended)
* Node.js 18+ and npm
* Google Chrome or any Chromium-based browser

---

### Step 1: Start the Backend API

```bash
cd backend

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate        # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the API server (Includes auto SQLite fallback and initial metric seeding)
python run_api.py
```
* API Server: http://127.0.0.1:8000
* Interactive Swagger Documentation: http://127.0.0.1:8000/docs

---

### Step 2: Launch the Admin Dashboard

```bash
cd dashboard

# Install dependencies
npm install

# Start development server
npm run dev
```
* Dashboard URL: http://localhost:5173

---

### Step 3: Install the Chrome Extension

1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Toggle on Developer mode (top-right corner).
3. Click Load unpacked (top-left).
4. Select the `extension/` directory from this repository.
5. The PhishAudit AI shield icon will appear in your browser toolbar.

---

## API Reference

### `POST /audit`
Evaluates a target URL through the 5-stage cascading pipeline.

Request Payload:
```json
{
  "url": "http://secure-paypal-login.xyz/account/verify"
}
```

Response Payload:
```json
{
  "url": "http://secure-paypal-login.xyz/account/verify",
  "status": "Phishing",
  "score": 0.9782,
  "db_id": 142,
  "recommendation": "block",
  "tier": 4,
  "threshold_used": 0.25,
  "source": "hvt_combo_squatting",
  "combo_brand": "paypal",
  "keywords_found": ["login", "verify", "account", "secure"],
  "closest_match": "paypal.com",
  "error": null
}
```

### `GET /metrics`
Retrieves the latest verified model evaluation metrics for the admin console.

### `GET /logs`
Retrieves the 100 most recent URL audit events recorded in the database.

---

## Privacy and Security Boundaries

PhishAudit AI is engineered under a strict privacy-first design:
* URL String Only: Only the URL string is transmitted for analysis.
* No DOM Scraping: Webpage HTML, form fields, cookies, and session tokens are never inspected or transmitted.
* No Network MITM: Does not intercept user payloads, form submissions, or network packets.
* Audit Trail Security: Feature vectors stored in the audit logs are numerical metadata, preserving confidentiality.

---

## Academic Research Context

This project is submitted in partial fulfillment of the requirements for the degree of Bachelor of Science in Computer Science at BRAC University.

* Project Title: Phishing URL Detection Using Machine Learning and Deep Learning
* System Name: PhishAudit AI
* Course: CSE400 Senior Design / Capstone Project
* Authors:
  * Azharul Habib (Student ID: 22241009)
  * Sadia Hakim Mollik (Student ID: 22201674)
* Supervisors:
  * Mr. Annajiat Alim Rasel (Senior Lecturer, Department of CSE, BRAC University)
  * Mehedi Hasan Emo (Lecturer, Department of CSE, BRAC University)

---

## License
This project is developed for educational and academic research purposes under BRAC University.