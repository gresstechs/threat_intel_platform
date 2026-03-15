# Automated Threat Intelligence Correlation Platform

> MSc Applied Computing Dissertation Project — University of Sunderland (2024/25)  
> **Student:** Chidera Progress Nwaokwa (240054490)  
> **Supervisor:** Dr. Hazem Eissa  
> **Ethics Reference:** 035333

---

## Overview

An automated threat intelligence correlation platform that integrates three open-source threat intelligence feeds — **AlienVault OTX**, **VirusTotal**, and **AbuseIPDB** — with ensemble machine learning (Random Forest + XGBoost) to improve threat detection accuracy and reduce Security Operations Centre (SOC) analyst workload.

This project directly addresses the SOC information overload problem documented by Sundaramurthy et al. (2022), where analysts process 12,000+ alerts/day with 85% false positive rates. By correlating multi-source intelligence through ML, the platform targets a **40% reduction in analyst workload** and **>95% threat classification accuracy**.

---

## Research Question

> *How can automated correlation of multiple threat intelligence feeds using machine learning improve threat detection accuracy and reduce security analyst workload compared to single-source threat intelligence systems?*

---

## Project Objectives

| # | Objective | Success Criterion |
|---|-----------|-------------------|
| O1 | Integrate OTX, VirusTotal & AbuseIPDB APIs with normalisation & PostgreSQL storage | < 5 sec per indicator |
| O2 | Ensemble ML model (Random Forest + XGBoost) for multi-class threat classification | > 95% accuracy, F1 > 0.93 |
| O3 | Automated alert prioritisation system | ≥ 40% workload reduction |
| O4 | Grafana real-time monitoring dashboard | 8+ panels, < 2 sec response |
| O5 | 5 automated MITRE ATT&CK response playbooks | > 90% execution success |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                  Threat Intelligence Platform                    │
├──────────────┬──────────────────┬──────────────────────────────┤
│ Data Sources │  Correlation     │  Response & Visualisation    │
│              │  Engine          │                              │
│  OTX API ───►│                  │  Grafana Dashboards (8+)     │
│  VT API  ───►│  Normaliser  ───►│  Alert Prioritisation        │
│  Abuse   ───►│  ML Classifier   │  MITRE ATT&CK Playbooks (5)  │
│              │  (RF + XGBoost)  │  Jenkins CI/CD Pipeline      │
├──────────────┴──────────────────┴──────────────────────────────┤
│                    PostgreSQL Database                           │
│  threat_indicators | correlation_results | ingestion_log        │
└─────────────────────────────────────────────────────────────────┘
```

---

## Repository Structure

```
threat-intel-platform/
├── src/
│   ├── api/
│   │   ├── otx_client.py          # AlienVault OTX API v1 client
│   │   ├── virustotal_client.py   # VirusTotal API v3 client
│   │   └── abuseipdb_client.py    # AbuseIPDB API v2 client
│   ├── core/
│   │   ├── normaliser.py          # Unified ThreatIndicator schema
│   │   ├── db.py                  # PostgreSQL schema & CRUD
│   │   └── config.py              # Configuration management
│   ├── ml/
│   │   ├── feature_engineering.py # Feature extraction pipeline
│   │   ├── model_trainer.py       # RF + XGBoost training
│   │   └── predictor.py           # Inference & scoring
│   ├── automation/
│   │   ├── alert_prioritiser.py   # Alert ranking algorithm
│   │   └── playbooks/             # 5 MITRE ATT&CK playbooks
│   └── main.py                    # CLI orchestrator
├── tests/
│   └── test_platform.py           # 42+ unit tests (pytest)
├── dashboards/
│   └── grafana/                   # Grafana dashboard JSON configs
├── docs/
│   └── D1.3_api_integration.docx  # Technical documentation
├── jenkins/
│   └── Jenkinsfile                # CI/CD pipeline definition
├── .env.example                   # Environment variable template
├── .gitignore
├── requirements.txt
└── README.md
```

---

## Quick Start

### Prerequisites

- Python 3.12+
- PostgreSQL 14+
- API keys for OTX, VirusTotal, and AbuseIPDB (free tier)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/gresstechs/threat-intel-platform.git
cd threat-intel-platform

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate      # Linux/macOS
# venv\Scripts\activate       # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env with your API keys and database credentials
```

### Database Setup

```bash
# Create PostgreSQL database
psql -U postgres -c "CREATE DATABASE threat_intel;"
psql -U postgres -c "CREATE USER threat_user WITH PASSWORD 'yourpassword';"
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE threat_intel TO threat_user;"
```

The schema is created automatically on first run via `db.py`.

### Usage

```bash
# Query a single indicator across all three feeds
python src/main.py --indicator 198.51.100.1 --type ip

# Run a bulk ingestion cycle (OTX pulses + AbuseIPDB blacklist)
python src/main.py --ingest

# Print database statistics
python src/main.py --stats
```

---

## Running Tests

```bash
# Run full test suite with coverage
pytest tests/ -v --cov=src --cov-report=term-missing

# Expected output: 42 passed
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.12 |
| Database | PostgreSQL 14 |
| ML Framework | scikit-learn, XGBoost |
| CI/CD | Jenkins |
| Dashboards | Grafana |
| API Clients | requests, tenacity |
| Testing | pytest, pytest-cov |
| Config | python-dotenv |

---

## Progress

| Deliverable | Status | Deadline |
|-------------|--------|----------|
| D1.1 Literature Review | ✅ Complete | Week 4 |
| D1.2 Ethics Approval | ✅ Complete | Week 3 |
| D1.3 API Integration Module | ✅ Complete | Week 6 |
| D1.4 PostgreSQL Database | 🔄 In Progress | Week 8 |
| D2.1 Training Dataset | ⏳ Pending | Week 10 |
| D2.2 ML Model (>95% accuracy) | ⏳ Pending | Week 14 |
| D3.1 Alert Prioritisation | ⏳ Pending | Week 16 |
| D3.2 Jenkins CI/CD | ⏳ Pending | Week 18 |
| D3.3 Response Playbooks | ⏳ Pending | Week 20 |
| D4.1 Grafana Dashboards | ⏳ Pending | Week 20 |
| D5.1 Performance Report | ⏳ Pending | Week 22 |
| D5.2 Evaluation Report | ⏳ Pending | Week 23 |
| D6.1 Dissertation | ⏳ Pending | Week 26 |

---

## Security

- API keys are stored in `.env` only — never committed to version control
- `.env` is listed in `.gitignore`
- All API access is read-only (no data submitted to external services)
- Testing uses mock data — no live API calls during unit tests
- Platform designed for **defensive security only**

---

## Academic Context

- **Programme:** MSc Applied Computing, University of Sunderland
- **Module:** PROM03 — MSc Dissertation
- **Timeline:** February – August 2026 (26 weeks)
- **Builds on:** CTI placement achieving 99.88% malware detection accuracy (single-source)
- **Extends to:** Multi-source correlation with ML-based classification

---

## License

This project is developed for academic research purposes.  
© 2026 Chidera Progress Nwaokwa — University of Sunderland.  
Not licensed for commercial use.
