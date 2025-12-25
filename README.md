# Shadow Ops - Phishing Detection Platform

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED)

**Shadow Ops** is an advanced phishing detection engine designed for security operations centers (SOCs) and threat analysts. It goes beyond simple keyword matching by combining three layers of forensic analysis:

1.  **Machine Learning Intent Analysis**: Logistic Regression model trained on 40k+ verified phishing samples.
2.  **Deep Header Forensics**: Automated validation of SPF, DKIM, DMARC, and relay chain consistency.
3.  **Real-Time URL Intelligence**: Recursive redirection tracking and typosquatting detection.

## 🚀 Quick Start

### Using Docker
```bash
docker-compose up -d
```
The dashboard will be available at http://localhost:5000.

### Local Installation
```bash
pip install -r requirements.txt
python src/app.py
```

## 📚 Documentation
- [**Setup Guide**](docs/SETUP.md): Installation, configuration, and API usage.
- [**System Architecture**](docs/ARCHITECTURE.md): Technical deep-dive into the ML and forensic engines.

## Key Features
- **Defense-in-Depth**: Does not rely on a single metric. A clean SPF record won't hide malicious text intent.
- **Explainable Metrics**: Returns detailed forensic findings (e.g., *"High Risk: Display Name 'PayPal' conflicts with Return-Path 'mailer@bad-domain.com'"*).
- **Format Support**: Analyzes raw text strings or standard `.eml` files.

## Project Structure
```
shadow-ops/
├── docs/               # Architecture & Setup documentation
├── scripts/            # Deployment and utility scripts
├── src/                # Core application source code
│   ├── web/            # Flask application
│   ├── models/         # Trained ML models
│   └── forensics.py    # Analysis modules
├── Dockerfile
└── docker-compose.yml
```

---
*For educational and defensive security purposes only.*
