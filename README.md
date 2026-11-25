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
  * Stage 4 (Tier 3 Keyword Context Shifting): Unknown domains adjust thresholds dynamically (tau = 0.35 for 3 or more credential tokens; tau = 0.50 for 1 to 2 tokens; otherwise the serving cutoff 0.7411850967153485 applies).
  * Stage 5: Random Forest inference with the scheme-blind retrain at the serving cutoff 0.7411850967153485 (see "Served Model and Serving Cutoff").
  * The thresholds of Stages 2 to 4 (0.30, 0.25, 0.35, 0.50) were set for the previous model and have not been validated with the model now served.
* Bangladesh Financial Sector Protection: Explicit threat models for regional Mobile Financial Services (MFS) and banks frequently targeted by SMS phishing: bKash, Nagad, DBBL Rocket, BRAC Bank, City Bank, EBL, UCBL, and Islami Bank.
* Real-Time Extension UX: Instant badge indicators (red "!" for phishing, grey "?" when no verdict is available) and browser alert notifications.
* Fail-Safe Offline Design: If the backend service is offline, browsing continues uninterrupted with an Unknown status; the tool never blocks or crashes navigation. Prediction failures also give Unknown, not Safe.
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
|  Stage 3: Combo-Squatting HVT |                       |  (no SQLite fallback)          |
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

> **Historical results (P2).** The numbers below were reported in P2. The 0.6205 threshold was selected using test labels, and the model was trained on features stored in a CSV file. They are kept for the record, not as a clean held-out evaluation. Re-evaluation under a stricter protocol is part of P3. They describe the previous model, which the service no longer uses; see "Served Model and Serving Cutoff" for the model now served.

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
> **Predates the label-mapping fix.** This section was written before commit `ef95e93` corrected the PhiUSIIL label mapping, so its figures should be treated as superseded and unverified.

Evaluating the standalone Random Forest on 235,795 unseen URLs from PhiUSIIL demonstrated a 24.96% drop in ROC-AUC (from 96.26% to 71.30%). The baseline model achieved 100% recall but experienced a precision drop to 58.0% due to class prior shift (57:43 distribution vs. 82% benign in training). 

Key Finding: Fixed classification thresholds do not generalize across varying real-world distributions. This empirical finding provides the core academic justification for PhishAudit AI's dynamic cascading pipeline.

---

## Served Model and Serving Cutoff

* Model: a 100-tree Random Forest (`max_depth` 20, balanced class weights, `random_state` 42) trained on URLs normalized with N(u). The file is `backend/models/scheme_blind_rf_v1.joblib`, SHA256 `14b852f7390467fd34b447aa4eab77171a26018dbae5b686e514bc7c33a024c8`. It is not in Git; place it there yourself or point `PHISHAUDIT_MODEL_PATH` (and `PHISHAUDIT_MODEL_SHA256`) at it.
* Normalization N(u): remove a leading `http://` or `https://` (case-insensitive), then a leading `www.`. Nothing else changes. Strings with another scheme or a leading `//` are left unchanged. Every URL is normalized before feature extraction, so `https://www.example.com/a` and `example.com/a` give the same score. The cascade's other stages still see the original URL.
* Features: the 37 features of URL-feature contract 1.0.0, computed by an unmodified, vendored copy of the research extractor in `backend/vendor/url-features-v1/` (every file is listed with its SHA256 in `VENDOR_MANIFEST.json` and checked by a test). Any extractor error, such as userinfo (`user@host`), an unsupported scheme or an invalid host, gives Unknown, never Safe.
* Serving cutoff: `0.7411850967153485` in `backend/serving_config.py`, the single source of truth. A model score greater than or equal to it is a phishing decision at the model stage (Stage 4 default and Stage 5). It is the smallest observed validation score that keeps benign false positives at or under 1% (607 of 60,725). On the research validation split (group-disjoint from training; 75,606 rows) it catches 8,576 of 14,881 phishing URLs (recall 57.6%) with ROC-AUC 0.903 and average precision 0.805.
* What that does not show: the cutoff was chosen and evaluated on the same validation rows, so it is a validation estimate, not a guarantee, and no held-out test result is claimed. The research plan's own criterion for this model (at least 10,403 true positives at the 1% budget) was not met; the model is served by the project owner's decision, because the previous model's validation figures do not describe browser-form URLs (forcing `https://` onto validation URLs raised its benign false positives from 1.0% to 83.4% at its cutoff). The cutoff has not been tested on browser traffic.
* Decisions use the unrounded score. The `score` returned to clients and stored in the audit log is rounded to 4 decimals for display.
* Fail closed: if the model file is missing, its SHA256 differs from the expected value, the file cannot be loaded, its class order or feature count is wrong, a library version differs from the one it was saved with, or the extractor cannot start, nothing is scored and audits that reach the model return Unknown with an error message. Startup logs either "Model verified and loaded" or "MODEL UNAVAILABLE (...)". The trusted-domain bypass does not use the model and still returns Safe.
* Not validated with this model: the trusted-domain bypass, the typosquatting, combo-squatting and keyword stages and their constants. They were left as they were. In the milestone smoke check (63 hand-written legitimate sites, results in the research evidence directory), 4 were flagged, all by these lower-threshold stages; the model stage alone flagged none of the 14 sites that reached it.

---

## Repository Directory Structure

```text
PhishAudit_AI/
|-- backend/
|   |-- benchmarks/
|   |   `-- latency.py           # In-process latency and memory benchmark of /audit
|   |-- connection.py            # Database engine & session generator (SQLAlchemy)
|   |-- cross_dataset_eval.py    # LEGACY (unused by the service): PhiUSIIL benchmark of the old model
|   |-- data/                    # Datasets (Primary Kaggle 2026 & PhiUSIIL; not in Git)
|   |-- data_audit.py            # LEGACY (unused by the service): dataset integrity & domain overlap audit
|   |-- database/
|   |   `-- models.py            # ORM schemas (AuditLog, ModelMetrics, User, Whitelist)
|   |-- domain_gate.py           # Stage 1 (Bypass) & Stage 2 (Levenshtein typosquatting)
|   |-- feature_extractor.py     # LEGACY (unused by the service): old 37-feature extractor
|   |-- hvt_domains.py           # Stage 3 (Combo-squatting) & Stage 4 (Keyword shifting)
|   |-- main.py                  # FastAPI application & master pipeline orchestrator
|   |-- ml_engine.py             # Hash-checked model loading and scoring (N(u) -> features -> score)
|   |-- models/                  # scheme_blind_rf_v1.joblib (served, not in Git); legacy rf_model.pkl, feature_columns.pkl, optimal_threshold.pkl are unused
|   |-- normalization.py         # N(u) scheme-blind URL normalizer
|   |-- requirements.txt         # Pinned Python dependencies (Python 3.11)
|   |-- requirements-dev.txt     # Test dependencies (pytest, httpx)
|   |-- sanity/                  # Hand-written URL lists and a smoke-check runner
|   |-- serving_config.py        # Served model path, expected SHA256 and the serving cutoff
|   |-- tests/                   # Backend tests (in-memory SQLite, stub model files)
|   |-- save_metrics.py          # LEGACY (unused by the service): metrics of the old model
|   |-- train_model.py           # LEGACY (unused by the service): old training script
|   |-- trusted_domains.py       # Curated 100+ reputation whitelist
|   |-- url_features.py          # Contract 1.0.0 feature extraction through the vendored extractor
|   `-- vendor/url-features-v1/  # Byte-identical frozen extractor, contract files and VENDOR_MANIFEST.json
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
* Python 3.11 (the pinned dependencies and the feature extractor, which checks exact library versions at startup, were validated on 3.11.8)
* Node.js 18+ and npm
* Google Chrome or any Chromium-based browser

---

### Step 1: Start the Backend API

The backend needs a database reachable through `DATABASE_URL` (PostgreSQL is what the project was run against). `connection.py` raises an error if `DATABASE_URL` is not set; there is no SQLite fallback in the application code.

```bash
cd backend

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate        # On Windows: venv\Scripts\activate

# Install the pinned dependencies (exact versions; the extractor and the
# model require them, and the service refuses to score otherwise)
pip install -r requirements.txt

# Create backend/.env containing your database connection string
#   DATABASE_URL=postgresql://<user>:<password>@localhost:5432/<database>

# Place the served model at models/scheme_blind_rf_v1.joblib (it is not in Git).
# Its SHA256 must be 14b852f7390467fd34b447aa4eab77171a26018dbae5b686e514bc7c33a024c8.
# To keep it elsewhere, set PHISHAUDIT_MODEL_PATH (and PHISHAUDIT_MODEL_SHA256 if
# the file is a different, separately approved model).

# Run the API server from inside backend/
uvicorn main:app --port 8000
```
* On startup the log shows either `Model verified and loaded` or `MODEL UNAVAILABLE (reason)`. Without a verified model every audit that reaches the model returns Unknown.
* `GET /` reports whether the model loaded, its SHA256, the serving cutoff and the extractor contract version.
* API Server: http://127.0.0.1:8000
* Interactive Swagger Documentation: http://127.0.0.1:8000/docs

Run the tests (no database, server or model file needed; tests that need the real model file or the research workspace are skipped when it is absent):

```bash
cd backend
pip install -r requirements-dev.txt
python -m pytest
```

The legacy scripts (`train_model.py`, `save_metrics.py`, `cross_dataset_eval.py`, `data_audit.py`) are not used by the service and need pandas, which `requirements.txt` does not install.

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

### `GET /`
Returns `status` and `service`, plus a `model` object: `model_loaded`, `model_version`, `model_sha256` (of the verified file, otherwise `null`), `model_error`, `model_load_seconds`, `serving_cutoff`, `normalizer`, `extractor_contract_version` and `extractor_bundle_sha256`.

### `POST /audit`
Evaluates a target URL through the 5-stage cascading pipeline. If the model is unavailable, the extractor rejects the URL, or the prediction fails, the response has `status: "Unknown"`, `recommendation: "unavailable"`, `score: null` and an `error` message; it is never reported as Safe, and it is not written to the audit log. The returned and stored `score` is rounded to 4 decimals for display; the Phishing/Safe decision uses the unrounded score.

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
Returns the latest stored model metrics for the admin console. `accuracy` is always `null` (the table has no accuracy column). The response includes a `caveat` field: the stored metrics were computed on the full dataset including training rows, so they are not held-out results.

### `GET /logs`
Retrieves the 100 most recent URL audit events recorded in the database.

---

## Known Limitations

* Reported P2 metrics and the 0.6205 threshold are historical (see Empirical Evaluation); the threshold was chosen on test labels.
* Metrics stored in the database come from `save_metrics.py`, which evaluates on the full dataset including training rows. They are not held-out results.
* The cross-dataset (PhiUSIIL) numbers predate the label-mapping fix.
* The serving cutoff (0.7411850967153485) comes from validation scores only. It has not been checked on held-out test data or on browser traffic, and the research plan's own pass criterion for the served model was not met (see "Served Model and Serving Cutoff").
* The trusted-domain bypass and the typosquatting, combo-squatting and keyword stages, with their thresholds (0.30, 0.25, 0.35, 0.50), are not validated with the served model. In a 63-site smoke check they produced all 4 false alarms; that check is not a performance estimate.
* The model and the metrics shown by `/metrics` do not match: stored metrics come from `save_metrics.py` for the previous model.
* The extension also sends non-http(s) URLs such as `file:` or `data:`; those return Unknown.
* The legacy training and evaluation scripts, `feature_extractor.py` and the old files in `models/` are unused by the service and were not run or updated for the new model.
* The database is PostgreSQL via `DATABASE_URL`; there is no SQLite fallback.
* Unknown results (model unavailable, extractor error or prediction failure) are returned to the client but are not stored in the audit log (the schema has no Unknown handling).
* The extension has not been covered by automated tests.

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