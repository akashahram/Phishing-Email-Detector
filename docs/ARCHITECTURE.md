# System Architecture

## Overview
Shadow Ops is an enterprise-grade phishing detection platform designed to identify malicious intent in email communications through a multi-layered analysis engine. The system integrates natural language processing (NLP), cryptographic header verification, and real-time threat intelligence to provide a comprehensive risk assessment.

## High-Level Design
The application is built on a microservices-ready architecture using Flask as the API gateway. It utilizes a modular design pattern to separate concerns between data ingestion, analysis, and reporting.

### Core Components

#### 1. Analysis Gateway (`src/app.py`)
Serves as the central orchestration layer.
- **Responsibility**: Request handling, input normalization, and result aggregation.
- **Workflow**: 
  1. Receives raw `.eml` or text input.
  2. Normalizes content (HTML stripping, whitespace reduction).
  3. Dispatches payload to parallel analysis engines.
  4. Aggregates probability scores into a unified JSON response.

#### 2. ML Inference Engine (`src/models`)
Determines the malicious intent of the email body text.
- **Algorithm**: Logistic Regression with TF-IDF Vectorization.
- **Training**: Trained on a balanced dataset of 40,000+ legitimate and phishing emails.
- **Features**: N-gram analysis aiming to detect urgency, financial coercion, and account compromise threats.

#### 3. Forensic Analysis Module (`src/forensics.py`)
Performs deep-packet inspection of email headers to validate sender identity.
- **Authentication**: Validates SPF (Sender Policy Framework), DKIM (DomainKeys Identified Mail), and DMARC alignment.
- **Route Tracing**: Analyzes `Received` headers to identify suspicious relay hops or residential IP usage.
- **Identity Verification**: Detects mismatch discrepancies between `From`, `Reply-To`, and `Return-Path` headers to identify spoofing attempts.

#### 4. Threat Intelligence Module (`src/url_intelligence.py`)
Analyzes embedded hyperlinks for malicious characteristics.
- **Heuristics**: Detects typosquatting (Levenshtein distance), IP-based URLs, and obfuscation techniques.
- **Network Analysis**: Recursively follows HTTP redirects (301/302) to uncover the final destination.
- **Reputation**: (Optional) Integrates with PhishTank API for known-bad signature matching.

## Technology Stack
- **Language**: Python 3.9+
- **Framework**: Flask
- **Machine Learning**: scikit-learn, joblib, pandas
- **Forensics**: authres, dnspython
- **Containerization**: Docker, Docker Compose
