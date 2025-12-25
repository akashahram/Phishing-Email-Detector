# Shadow Ops: Multi-Layered Phishing Defense Platform

Shadow Ops is a forensic-grade phishing detection platform. Unlike standard filters, it uses a **Defense-in-Depth** architecture to analyze the "DNA" of an email across three distinct layers.

## Project Architecture
The system utilizes a microservice-ready Flask architecture:
- **ML Engine:** TF-IDF Vectorization + Logistic Regression for intent analysis.
- **Forensics Module:** Deep-dive inspection of SPF/DKIM/DMARC and Route Trace analysis.
- **URL Intel:** Recursive redirect tracking and typosquatting detection using Levenshtein distance.

## SOC Analyst Use-Case
Shadow Ops provides **Explainable AI (XAI)**. Instead of a binary "Spam" result, it provides a granular risk report:
> "High Risk (98%): Identity Mismatch (From vs Return-Path) + Suspicious Relay detected in 'Received' headers."

## Tech Stack
- **Backend:** Python (Flask)
- **Security:** BeautifulSoup4 (Normalization), Regex (Header Parsing)
- **AI/ML:** Scikit-learn, Pandas
- **Intelligence:** PhishTank API, SequenceMatcher