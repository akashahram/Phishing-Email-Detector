# app.py - SHADOW OPS Simple Edition (No Auth Required)
from flask import Flask, render_template, request, jsonify
import os, joblib, email, re
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import tldextract
from forensics import EmailForensics
from url_intelligence import URLIntelligence

app = Flask(__name__, static_folder="static", template_folder="templates")

# Load model + vectorizer
BASE = os.path.dirname(__file__)
ROOT = os.path.join(BASE, "..")
# Models are now in src/models
MODELS_DIR = os.path.join(ROOT, "src", "models")

model_path = os.path.join(MODELS_DIR, "phishing_model.pkl")
vectorizer_path = os.path.join(MODELS_DIR, "vectorizer.pkl")

if not os.path.exists(model_path) or not os.path.exists(vectorizer_path):
    raise FileNotFoundError("Model files not found. Make sure phishing_model.pkl and vectorizer.pkl are in ../models/")

model = joblib.load(model_path)
vectorizer = joblib.load(vectorizer_path)

# config
THRESHOLD = 0.80
KEYWORDS = ["verify your account","password reset","account suspended","urgent action required",
            "confirm your identity","billing information","login to continue","update your account"]
url_regex = re.compile(r'https?://[^\s\'\"<>]+', re.IGNORECASE)
SUSPICIOUS_TLDS = {'cf','tk','ga','gq','ml'}

def extract_clean_text_from_eml(file_bytes):
    """Extract text and return both cleaned text and message object for forensics"""
    try:
        msg = email.message_from_bytes(file_bytes)
    except Exception:
        return file_bytes.decode('utf-8', errors='ignore'), None
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain":
                payload = part.get_payload(decode=True)
                if payload: body += payload.decode(errors='ignore')
            elif ctype == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    html = payload.decode(errors='ignore')
                    body += BeautifulSoup(html, "html.parser").get_text(separator=" ")
    else:
        payload = msg.get_payload(decode=True)
        if payload: body += payload.decode(errors='ignore')
    return " ".join(body.split()), msg

def extract_url_features(text):
    urls = url_regex.findall(text or "")
    num_urls = len(urls)
    unique_domains = set()
    has_ip = 0
    suspicious_tlds = 0
    for u in urls:
        try:
            parsed = urlparse(u)
            hostname = parsed.hostname or ""
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname): has_ip = 1
            ext = tldextract.extract(hostname)
            if ext.suffix and ext.suffix.lower() in SUSPICIOUS_TLDS: suspicious_tlds += 1
            domain = ext.registered_domain or hostname
            if domain: unique_domains.add(domain)
        except Exception:
            continue
    return {"num_urls": num_urls, "num_unique_domains": len(unique_domains), "has_ip": int(has_ip), "suspicious_tlds": suspicious_tlds}

def predict_text_with_details(text, email_msg=None):
    """Commercial-grade prediction with ML + URL Intelligence + Email Forensics"""
    clean = " ".join(str(text).split())
    X = vectorizer.transform([clean])
    
    try:
        ml_prob = float(model.predict_proba(X)[0][1])
    except Exception:
        pred = int(model.predict(X)[0])
        ml_prob = 0.99 if pred==1 else 0.01

    lw = clean.lower()
    keyword_matched = None
    for kw in KEYWORDS:
        if kw in lw:
            ml_prob = min(0.99, ml_prob + 0.12)
            keyword_matched = kw
            break
    
    urls = url_regex.findall(clean)
    url_intel = URLIntelligence(timeout=1)
    url_analysis = url_intel.analyze_multiple_urls(urls)
    url_risk_score = url_analysis.get("risk_score", 0)
    
    forensics_score = 0
    forensics_findings = []
    if email_msg:
        forensics = EmailForensics(email_msg)
        forensics_result = forensics.analyze()
        forensics_score = forensics_result.get("risk_score", 0)
        forensics_findings = forensics_result.get("findings", [])
    
    url_prob = url_risk_score / 100.0
    forensics_prob = forensics_score / 100.0
    final_prob = max(ml_prob, url_prob, forensics_prob)
    
    if final_prob < 0.70:
        if email_msg:
            final_prob = (ml_prob * 0.40) + (url_prob * 0.35) + (forensics_prob * 0.25)
        else:
            final_prob = (ml_prob * 0.60) + (url_prob * 0.40)
    
    final_prob = min(0.99, final_prob)
    prediction = 1 if final_prob >= THRESHOLD else 0
    
    reasons = []
    if url_risk_score >= 50:
        reasons.append("Malicious URL detected")
    if forensics_score >= 60:
        reasons.append("Email header anomalies")
    if keyword_matched:
        reasons.append(f"Phishing keyword: '{keyword_matched}'")
    if ml_prob >= 0.85:
        reasons.append("High ML confidence")
    
    reason = " | ".join(reasons) if reasons else ("Phishing detected" if prediction == 1 else "No threats detected")
    basic_signals = extract_url_features(clean)
    
    return {
        "prediction": int(prediction),
        "probability": round(final_prob, 4),
        "ml_score": round(ml_prob, 4),
        "url_risk_score": url_risk_score,
        "forensics_score": forensics_score,
        "signals": basic_signals,
        "url_findings": url_analysis.get("findings", []),
        "forensics_findings": forensics_findings,
        "reason": reason
    }

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/privacy")
def privacy():
    return render_template("privacy.html")

@app.route("/terms")
def terms():
    return render_template("terms.html")

@app.route("/predict", methods=["POST"])
def predict_route():
    data = request.get_json() or {}
    text = data.get("text","")
    if not text or not text.strip(): return jsonify({"error":"No text provided"}), 400
    out = predict_text_with_details(text)
    return jsonify(out)

@app.route("/scan_eml", methods=["POST"])
def scan_eml_route():
    if "file" not in request.files: return jsonify({"error":"No file uploaded"}), 400
    f = request.files["file"]
    b = f.read()
    cleaned, email_msg = extract_clean_text_from_eml(b)
    out = predict_text_with_details(cleaned, email_msg)
    out["cleaned_text"] = cleaned
    return jsonify(out)

if __name__ == "__main__":
    print("\n" + "="*50)
    print("🚀 SHADOW OPS - Phishing Detection System")
    print("="*50)
    print("\n✅ Server starting at: http://localhost:5000")
    print("✅ No authentication required - Simple mode")
    print("\nPress Ctrl+C to stop the server\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
