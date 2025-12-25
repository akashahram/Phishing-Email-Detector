# url_intelligence.py - Advanced URL Threat Intelligence
import re
import socket
import os
from urllib.parse import urlparse
from datetime import datetime, timedelta
import requests
from difflib import SequenceMatcher
from phishtank_integration import PhishTankChecker

class URLIntelligence:
    """
    Advanced URL analysis for phishing detection.
    Includes domain age checking, redirect analysis, and typosquatting detection.
    """
    
    # Known legitimate domains for typosquatting detection
    LEGITIMATE_BRANDS = [
        "paypal.com", "amazon.com", "microsoft.com", "apple.com", "google.com",
        "facebook.com", "instagram.com", "twitter.com", "linkedin.com",
        "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
        "fedex.com", "ups.com", "dhl.com", "usps.com",
        "netflix.com", "spotify.com", "dropbox.com"
    ]
    
    def __init__(self, timeout=1, use_phishtank=True):
        self.timeout = timeout
        self.findings = []
        self.risk_score = 0
        self.use_phishtank = use_phishtank
        
        # Initialize PhishTank (optional API key from environment)
        if self.use_phishtank:
            api_key = os.getenv('PHISHTANK_API_KEY')  # Optional
            self.phishtank = PhishTankChecker(api_key=api_key)
    
    def analyze_url(self, url):
        """
        Comprehensive URL analysis
        Returns dict with risk score and findings
        """
        self.findings = []
        self.risk_score = 0
        
        if not url or not url.strip():
            return {"risk_score": 0, "findings": []}
        
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        
        # Run all checks
        self._check_phishtank(url)  # Check PhishTank first (most authoritative)
        self._check_ip_address(domain)
        self._check_suspicious_tld(domain)
        self._check_typosquatting(domain)
        self._check_url_length(url)
        self._check_suspicious_patterns(url)
        self._check_redirect_chain(url)
        self._check_domain_age(domain)
        
        return {
            "risk_score": min(100, self.risk_score),
            "findings": self.findings,
            "is_high_risk": self.risk_score >= 50
        }
    
    def _check_phishtank(self, url):
        """Check URL against PhishTank verified phishing database"""
        if not self.use_phishtank:
            return
        
        try:
            result = self.phishtank.check_url(url)
            
            if result['is_phishing']:
                # PhishTank verified this as phishing - CRITICAL finding
                self.risk_score += 100  # Instant max score
                self.findings.append({
                    "severity": "critical",
                    "category": "phishtank_verified",
                    "message": f"URL verified as phishing by PhishTank (ID: {result.get('phish_id', 'N/A')})"
                })
        except Exception:
            # PhishTank check failed - continue with other checks
            pass
    
    def _check_ip_address(self, domain):
        """Check if URL uses IP address instead of domain"""
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, domain):
            self.risk_score += 40
            self.findings.append({
                "severity": "critical",
                "category": "url_structure",
                "message": f"URL uses IP address ({domain}) instead of domain name"
            })
    
    def _check_suspicious_tld(self, domain):
        """Check for suspicious top-level domains"""
        suspicious_tlds = ['.tk', '.cf', '.ga', '.gq', '.ml', '.xyz', '.top', '.work', '.click']
        
        for tld in suspicious_tlds:
            if domain.lower().endswith(tld):
                self.risk_score += 25
                self.findings.append({
                    "severity": "high",
                    "category": "domain",
                    "message": f"Suspicious TLD detected: {tld}"
                })
                break
    
    def _check_typosquatting(self, domain):
        """
        Detect typosquatting attempts (e.g., paypa1.com, g00gle.com)
        """
        domain_lower = domain.lower()
        
        for legitimate in self.LEGITIMATE_BRANDS:
            # Check for exact match (legitimate)
            if domain_lower == legitimate:
                continue
            
            # Calculate similarity
            similarity = SequenceMatcher(None, domain_lower, legitimate).ratio()
            
            # High similarity but not exact = potential typosquatting
            if similarity > 0.85:
                self.risk_score += 35
                self.findings.append({
                    "severity": "critical",
                    "category": "typosquatting",
                    "message": f"Possible typosquatting: '{domain}' resembles '{legitimate}' ({int(similarity*100)}% similar)"
                })
                break
            
            # Check for common character substitutions
            if self._check_character_substitution(domain_lower, legitimate):
                self.risk_score += 30
                self.findings.append({
                    "severity": "high",
                    "category": "typosquatting",
                    "message": f"Character substitution detected: '{domain}' mimics '{legitimate}'"
                })
                break
    
    def _check_character_substitution(self, domain, legitimate):
        """
        Check for common character substitutions (0 for o, 1 for l, etc.)
        """
        substitutions = {
            '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
            '7': 't', '8': 'b', '9': 'g'
        }
        
        # Replace numbers with letters and check similarity
        normalized = domain
        for num, letter in substitutions.items():
            normalized = normalized.replace(num, letter)
        
        return normalized == legitimate
    
    def _check_url_length(self, url):
        """Phishing URLs are often excessively long"""
        if len(url) > 150:
            self.risk_score += 15
            self.findings.append({
                "severity": "medium",
                "category": "url_structure",
                "message": f"Unusually long URL ({len(url)} characters)"
            })
    
    def _check_suspicious_patterns(self, url):
        """
        Check for suspicious patterns in URL structure
        """
        url_lower = url.lower()
        
        # Multiple subdomains (e.g., secure.login.paypal.phishing.com)
        parsed = urlparse(url)
        domain_parts = parsed.netloc.split('.')
        if len(domain_parts) > 4:
            self.risk_score += 20
            self.findings.append({
                "severity": "high",
                "category": "url_structure",
                "message": f"Excessive subdomains ({len(domain_parts)} levels)"
            })
        
        # Suspicious keywords in URL
        suspicious_keywords = ['login', 'verify', 'account', 'secure', 'update', 'confirm', 'banking', 'signin']
        keyword_count = sum(1 for kw in suspicious_keywords if kw in url_lower)
        
        if keyword_count >= 2:
            self.risk_score += 15
            self.findings.append({
                "severity": "medium",
                "category": "url_structure",
                "message": f"Multiple suspicious keywords in URL ({keyword_count} found)"
            })
        
        # @ symbol in URL (can hide real domain)
        if '@' in url:
            self.risk_score += 30
            self.findings.append({
                "severity": "high",
                "category": "url_structure",
                "message": "@ symbol in URL (domain obfuscation technique)"
            })
    
    def _check_redirect_chain(self, url):
        """
        Follow redirects to find final destination
        Note: This makes actual HTTP requests - use with caution
        """
        try:
            # Only check HTTP/HTTPS URLs
            if not url.startswith(('http://', 'https://')):
                return
            
            response = requests.head(url, allow_redirects=True, timeout=self.timeout)
            
            # Check if there were redirects
            if len(response.history) > 0:
                final_url = response.url
                
                if len(response.history) > 3:
                    self.risk_score += 20
                    self.findings.append({
                        "severity": "high",
                        "category": "redirects",
                        "message": f"Multiple redirects detected ({len(response.history)} hops)"
                    })
                
                # Check if final domain differs from original
                original_domain = urlparse(url).netloc
                final_domain = urlparse(final_url).netloc
                
                if original_domain != final_domain:
                    self.risk_score += 15
                    self.findings.append({
                        "severity": "medium",
                        "category": "redirects",
                        "message": f"Redirect to different domain: {original_domain} → {final_domain}"
                    })
        
        except requests.RequestException:
            # Network error or timeout - don't penalize
            pass
        except Exception:
            # Any other error - skip this check
            pass
    
    def _check_domain_age(self, domain):
        """
        Check domain registration age (stub implementation)
        In production, integrate with WhoisXML API or similar service
        """
        # This is a STUB - real implementation would query WHOIS data
        # For now, we'll use a heuristic: check if domain resolves
        
        try:
            socket.gethostbyname(domain)
            # Domain exists - in production, check actual registration date
            # For now, we'll skip scoring
            pass
        except socket.gaierror:
            # Domain doesn't resolve
            self.risk_score += 25
            self.findings.append({
                "severity": "high",
                "category": "domain",
                "message": f"Domain does not resolve: {domain}"
            })
        except Exception:
            pass
    
    def analyze_multiple_urls(self, urls):
        """
        Analyze multiple URLs and return aggregate risk
        """
        if not urls:
            return {"risk_score": 0, "findings": [], "url_count": 0}
        
        all_findings = []
        max_risk = 0
        
        for url in urls[:10]:  # Limit to first 10 URLs to avoid performance issues
            result = self.analyze_url(url)
            all_findings.extend(result["findings"])
            max_risk = max(max_risk, result["risk_score"])
        
        return {
            "risk_score": max_risk,
            "findings": all_findings,
            "url_count": len(urls),
            "is_high_risk": max_risk >= 50
        }
