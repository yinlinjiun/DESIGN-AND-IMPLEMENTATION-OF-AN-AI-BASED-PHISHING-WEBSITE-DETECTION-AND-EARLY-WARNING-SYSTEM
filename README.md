# AI-Based Phishing Website Detection & Alert System

An end-to-end phishing website detection and early-warning platform built with Python, Flask, and scikit-learn. The system combines **URL semantic analysis** and **webpage content analysis** into a multimodal feature set, then classifies websites with a machine-learning ensemble and explains every decision through human-readable risk factors.

It is designed as a complete **"detect → alert → manage"** workflow and is suitable for a graduation project or a lightweight security demonstration.

---

## Features

- **Real-time detection** — Submit a URL on the web page and get an instant verdict (Phishing / Legitimate) with a probability score and a risk level (High / Medium / Low).
- **Multimodal feature extraction**
  - URL features: IP-address hosts, `@` symbols, suspicious/brand/threat keywords, typosquatting, abnormal URL structure, HTTP(S) usage, and more.
  - Webpage features: HTTPS & SSL certificate validity, forms & sensitive fields, iframes, pop-up scripts, meta-refresh redirects, external resources, right-click disabling, and more.
- **Multi-model machine learning** — Trains Random Forest, Gradient Boosting, Logistic Regression, SVM, MLP, and a soft-voting ensemble, then automatically selects the best model by F1 score.
- **Interpretable results** — Each detection lists the concrete risk factors that triggered the warning, and the raw extracted features are shown on the page.
- **Fallback rule engine** — When no trained model is available or model prediction fails, a rule-based scoring function still returns a reliable risk judgment.
- **Trusted-domain whitelist** — Common well-known domains (Google, GitHub, Apple, etc.) are automatically down-weighted to avoid false positives.
- **User accounts** — Registration, login/logout, per-user detection history, and recent-detection records.
- **Report & review** — Users can report suspicious sites (an AI detection runs automatically on submit); admins review reports and mark them as *pending / confirmed phishing / false positive / handled*.
- **Admin dashboard** — Statistics for users, reports, pending reports and detections, plus the latest reports and detection records.
- **Security hardening** — URL validation with SSRF protection (blocks private/reserved/loopback targets by default) and a configurable allowance for local testing.
- **Zero-setup launch** — The SQLite database and tables are auto-initialized on first run; `start.py` boots the server and opens the browser for you.

---

## Tech Stack

| Layer      | Technology |
|------------|-----------|
| Backend    | Python 3, Flask 3 |
| Machine Learning | scikit-learn, joblib, pandas, numpy |
| Web scraping / parsing | requests, BeautifulSoup, tldextract, python-whois |
| Storage    | SQLite (auto-initialized) |
| Frontend   | Server-rendered Jinja2 templates (responsive, no external CDN) |

---

## Project Structure

```
源代码/
├── app.py                 # Flask web app: detection API, auth, reports, admin
├── feature_extractor.py   # URL + webpage feature extraction and rule scoring
├── model_trainer.py       # Trains & evaluates all ML models, saves best model
├── data_loader.py         # Loads UCI / Kaggle datasets or generates synthetic data
├── train.py               # End-to-end training script
├── check_data.py          # Helper to inspect the data/ directory
├── start.py               # Launches the server and opens the browser
├── start.bat              # One-click launcher for Windows
├── requirements.txt
├── data/
│   ├── archive/Phishing_Legitimate_full.csv   # Kaggle dataset (48 features)
│   └── phishing+websites/Training Dataset.arff # UCI dataset (30 features)
├── models/                # Trained models & scalers (joblib .pkl)
├── templates/             # Jinja2 HTML templates
└── app.db                 # SQLite database (created automatically)
```

---

## Installation

> Requires **Python 3.8+**. It is recommended to use a virtual environment.

```bash
# 1. Create and activate a virtual environment (optional but recommended)
python -m venv venv
# Windows
venv\Scripts\activate
# Linux / macOS
source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Train the model — skip if a trained model already exists in models/
python train.py
```

---

## Running the App

### Option A — One-click launch (Windows)

Double-click `start.bat`, or run:

```bash
python start.py
```

The server starts on `http://127.0.0.1:5000` and the default browser opens automatically.

### Option B — Run directly

```bash
python app.py
```

Then open `http://127.0.0.1:5000` in your browser.

> On the first run the SQLite database (`app.db`) and all tables are created automatically, along with a default administrator account.

---

## Training the Model

```bash
python train.py
```

The training pipeline:

1. Loads the **Kaggle dataset** first; falls back to the **UCI dataset**; if neither exists, generates a synthetic dataset for demonstration.
2. Preprocesses features into a numeric matrix `X` and label vector `y`.
3. Splits data **80% / 20%** (stratified) and standardizes features for linear models.
4. Trains **6 candidate models** (Random Forest, Gradient Boosting, Logistic Regression, SVM, MLP, soft-voting ensemble).
5. Evaluates each with accuracy / precision / recall / F1 / confusion matrix.
6. **Selects the best model by F1 score** and saves it (plus the scaler) to `models/` as `*.pkl` via joblib.
7. Exports a top-20 feature-importance plot to `models/feature_importance.png` (for tree models).

At startup, `app.py` automatically loads the saved model, preferring the ensemble over the individual models.

---

## Datasets

| Dataset | Source | Notes |
|---------|--------|-------|
| Kaggle Phishing Dataset | [Phishing Dataset for Machine Learning](https://www.kaggle.com/datasets/shashwatwork/phishing-dataset-for-machine-learning) | `data/archive/Phishing_Legitimate_full.csv`, 48 features |
| UCI Phishing Websites | [UCI ML Repository](https://archive.ics.uci.edu/ml/datasets/Phishing+Websites) | `data/phishing+websites/Training Dataset.arff`, 30 features |

If you place your own copies of these files under `data/`, they will be picked up automatically by `data_loader.py`.

---

## API

### `POST /api/detect`

Detects whether a URL is a phishing site.

**Request body (JSON):**

```json
{ "url": "https://example.com" }
```

**Response:**

```json
{
  "success": true,
  "url": "https://example.com",
  "is_phishing": false,
  "probability": 0.08,
  "risk_level": "低风险",
  "risk_factors": ["未发现明显风险因素"],
  "features": { "...": "..." }
}
```

> Note: `risk_level` and `risk_factors` are currently rendered in Chinese (matching the project's thesis language). Risk levels map as: probability ≥ 0.7 → High risk; ≥ 0.4 → Medium risk; otherwise → Low risk.

### Web pages

| Route | Description |
|-------|-------------|
| `/` | Home — detection form + recent records |
| `/register`, `/login`, `/logout` | User authentication |
| `/report` | Submit a suspicious site (requires login) |
| `/my-reports` | View your submitted reports (requires login) |
| `/admin` | Admin dashboard (requires admin) |
| `/admin/reports` | Review and manage reports (requires admin) |

---

## Default Account

| Role  | Username | Password     |
|-------|----------|--------------|
| Admin | `admin`  | `admin123456` |

> **Security note:** Change the default admin password immediately when deploying outside a local/demo environment. Also set a strong `SECRET_KEY` via environment variable.

---

## Configuration (Environment Variables)

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `phishing-detection-graduation-project` | Flask session signing key |
| `ALLOW_LOCAL_TESTING` | `1` | Allow detection of loopback/localhost targets (for local demo pages) |
| `ALLOW_PRIVATE_NETWORK` | `1` | Allow detection of private/LAN addresses |

For a hardened deployment, set `ALLOW_LOCAL_TESTING=0` and `ALLOW_PRIVATE_NETWORK=0` to block scanning of internal networks (SSRF protection).

---

## Detection Workflow

```
User enters URL
      │
      ▼
URL validation & SSRF guard
      │
      ▼
Multimodal feature extraction
  ├── URL semantic analysis
  └── Webpage content analysis (HTTP fetch + HTML parse)
      │
      ▼
Model prediction (or rule-score fallback)
      │
      ▼
Risk calibration (trusted-domain whitelist, high-risk combinations)
      │
      ▼
Human-readable risk factors + verdict + probability
      │
      ▼
Persist record → show result / trigger report flow
```

---

## Disclaimer

This project is intended for **educational and research purposes** (e.g., a graduation thesis). It should not be used as the sole security control for production environments. Network-facing deployments must apply additional protections (authentication, rate limiting, TLS, and secure secret management).
