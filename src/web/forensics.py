# forensics.py - Email Header Forensics Module
import email
import re
from email.utils import parseaddr
from urllib.parse import urlparse
import socket

class EmailForensics:
    """
    Deep forensic analysis of email headers for commercial-grade phishing detection.
    Analyzes authentication results, sender verification, and mail server chains.
    """
    
    def __init__(self, email_message):
        """
        Initialize with an email.message.Message object
        """
        self.msg = email_message
        self.risk_score = 0
        self.findings = []
        
    def analyze(self):
        """
        Run all forensic checks and return aggregated results
        """
        self._check_authentication()
        self._check_sender_mismatch()
        self._check_received_chain()
        self._check_suspicious_headers()
        
        return {
            "risk_score": min(100, self.risk_score),
            "findings": self.findings,
            "is_high_risk": self.risk_score >= 60
        }
    
    def _check_authentication(self):
        """
        Check SPF, DKIM, and DMARC authentication results
        """
        auth_results = self.msg.get("Authentication-Results", "")
        
        # Check for SPF failures
        if "spf=fail" in auth_results.lower() or "spf=softfail" in auth_results.lower():
            self.risk_score += 30
            self.findings.append({
                "severity": "high",
                "category": "authentication",
                "message": "SPF authentication failed - sender may be spoofed"
            })
        elif "spf=none" in auth_results.lower():
            self.risk_score += 10
            self.findings.append({
                "severity": "medium",
                "category": "authentication",
                "message": "No SPF record found for sender domain"
            })
            
        # Check for DKIM failures
        if "dkim=fail" in auth_results.lower():
            self.risk_score += 25
            self.findings.append({
                "severity": "high",
                "category": "authentication",
                "message": "DKIM signature verification failed"
            })
        elif "dkim=none" in auth_results.lower():
            self.risk_score += 5
            self.findings.append({
                "severity": "low",
                "category": "authentication",
                "message": "No DKIM signature present"
            })
            
        # Check for DMARC failures
        if "dmarc=fail" in auth_results.lower():
            self.risk_score += 20
            self.findings.append({
                "severity": "high",
                "category": "authentication",
                "message": "DMARC policy check failed"
            })
    
    def _check_sender_mismatch(self):
        """
        Compare From header with Return-Path and Reply-To for spoofing indicators
        """
        from_header = self.msg.get("From", "")
        return_path = self.msg.get("Return-Path", "")
        reply_to = self.msg.get("Reply-To", "")
        
        # Extract email addresses
        from_name, from_addr = parseaddr(from_header)
        _, return_addr = parseaddr(return_path)
        _, reply_addr = parseaddr(reply_to)
        
        # Extract domains
        from_domain = self._extract_domain(from_addr)
        return_domain = self._extract_domain(return_addr)
        reply_domain = self._extract_domain(reply_addr)
        
        # Check for domain mismatches
        if return_domain and from_domain != return_domain:
            self.risk_score += 25
            self.findings.append({
                "severity": "high",
                "category": "sender_verification",
                "message": f"From domain ({from_domain}) doesn't match Return-Path ({return_domain})"
            })
        
        if reply_domain and from_domain != reply_domain:
            self.risk_score += 15
            self.findings.append({
                "severity": "medium",
                "category": "sender_verification",
                "message": f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})"
            })
        
        # Check for display name spoofing
        if from_name and self._is_brand_impersonation(from_name, from_domain):
            self.risk_score += 20
            self.findings.append({
                "severity": "high",
                "category": "brand_impersonation",
                "message": f"Display name '{from_name}' doesn't match domain '{from_domain}'"
            })
    
    def _check_received_chain(self):
        """
        Analyze the Received headers for suspicious relay patterns
        """
        received_headers = self.msg.get_all("Received", [])
        
        if not received_headers:
            self.risk_score += 5
            self.findings.append({
                "severity": "low",
                "category": "relay_analysis",
                "message": "No Received headers found (unusual)"
            })
            return
        
        # Check for excessive hops (potential relay abuse)
        if len(received_headers) > 10:
            self.risk_score += 10
            self.findings.append({
                "severity": "medium",
                "category": "relay_analysis",
                "message": f"Excessive mail server hops ({len(received_headers)})"
            })
        
        # Check for suspicious server names in chain
        suspicious_patterns = [r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', r'\.tk', r'\.cf', r'\.ga', r'\.ml', r'\.gq']
        for header in received_headers:
            for pattern in suspicious_patterns:
                if re.search(pattern, header, re.IGNORECASE):
                    self.risk_score += 8
                    self.findings.append({
                        "severity": "medium",
                        "category": "relay_analysis",
                        "message": f"Suspicious relay server detected: {pattern}"
                    })
                    break
    
    def _check_suspicious_headers(self):
        """
        Check for other suspicious header patterns
        """
        # Check X-Mailer for known phishing tools
        x_mailer = self.msg.get("X-Mailer", "")
        suspicious_mailers = ["PHPMailer", "Bulk", "Mass", "Spam"]
        
        for mailer in suspicious_mailers:
            if mailer.lower() in x_mailer.lower():
                self.risk_score += 10
                self.findings.append({
                    "severity": "medium",
                    "category": "headers",
                    "message": f"Suspicious mail client detected: {mailer}"
                })
                break
        
        # Check for missing standard headers
        required_headers = ["Message-ID", "Date"]
        for header in required_headers:
            if not self.msg.get(header):
                self.risk_score += 5
                self.findings.append({
                    "severity": "low",
                    "category": "headers",
                    "message": f"Missing standard header: {header}"
                })
    
    def _extract_domain(self, email_addr):
        """Extract domain from email address"""
        if not email_addr or "@" not in email_addr:
            return ""
        return email_addr.split("@")[-1].strip("<>").lower()
    
    def _is_brand_impersonation(self, display_name, domain):
        """
        Check if display name suggests a brand that doesn't match the domain
        """
        # Common brands to check
        brands = {
            "paypal": ["paypal.com"],
            "amazon": ["amazon.com", "amazon.co.uk"],
            "microsoft": ["microsoft.com", "outlook.com", "live.com"],
            "apple": ["apple.com", "icloud.com"],
            "google": ["google.com", "gmail.com"],
            "facebook": ["facebook.com", "fb.com"],
            "bank": ["bank", "chase.com", "wellsfargo.com", "bankofamerica.com"],
            "irs": ["irs.gov"],
            "fedex": ["fedex.com"],
            "ups": ["ups.com"],
            "dhl": ["dhl.com"]
        }
        
        display_lower = display_name.lower()
        
        for brand, legitimate_domains in brands.items():
            if brand in display_lower:
                # Check if domain matches any legitimate domain
                if not any(legit in domain for legit in legitimate_domains):
                    return True
        
        return False
