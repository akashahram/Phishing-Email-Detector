# phishtank_integration.py - PhishTank API Integration
import requests
import hashlib
import time
from datetime import datetime, timedelta

class PhishTankChecker:
    """
    Integration with PhishTank API for real-time phishing URL verification.
    
    PhishTank is a free community-driven database of verified phishing URLs.
    API Docs: https://www.phishtank.com/api_info.php
    """
    
    def __init__(self, api_key=None, use_cache=True, cache_duration_hours=24):
        """
        Initialize PhishTank checker
        
        Args:
            api_key: Optional API key for higher rate limits (free to register)
            use_cache: Cache results to avoid repeated API calls
            cache_duration_hours: How long to cache results
        """
        self.api_key = api_key
        self.base_url = "https://checkurl.phishtank.com/checkurl/"
        self.use_cache = use_cache
        self.cache_duration = timedelta(hours=cache_duration_hours)
        self.cache = {}  # In-memory cache (use Redis/DB for production)
        
    def check_url(self, url):
        """
        Check if URL is in PhishTank's verified phishing database
        
        Args:
            url: URL to check
            
        Returns:
            dict: {
                'is_phishing': bool,
                'verified': bool,
                'phish_id': str or None,
                'submission_time': str or None,
                'verified_time': str or None,
                'source': 'phishtank'
            }
        """
        if not url or not url.strip():
            return self._empty_result()
        
        # Check cache first
        if self.use_cache:
            cached = self._get_from_cache(url)
            if cached:
                return cached
        
        try:
            # Prepare request
            params = {
                'url': url,
                'format': 'json'
            }
            
            if self.api_key:
                params['app_key'] = self.api_key
            
            # Make API request
            response = requests.post(
                self.base_url,
                data=params,
                timeout=5,
                headers={'User-Agent': 'phishing-detector/1.0'}
            )
            
            if response.status_code == 200:
                data = response.json()
                result = self._parse_response(data)
                
                # Cache the result
                if self.use_cache:
                    self._add_to_cache(url, result)
                
                return result
            else:
                # API error - return neutral result
                return self._empty_result()
                
        except requests.RequestException:
            # Network error - fail gracefully
            return self._empty_result()
        except Exception:
            # Any other error - fail gracefully
            return self._empty_result()
    
    def check_multiple_urls(self, urls, max_checks=5):
        """
        Check multiple URLs (limited to avoid rate limiting)
        
        Args:
            urls: List of URLs to check
            max_checks: Maximum number of URLs to check (to avoid rate limits)
            
        Returns:
            dict: {
                'phishing_urls': list of URLs found in PhishTank,
                'total_checked': int,
                'phishing_count': int
            }
        """
        phishing_urls = []
        urls_to_check = urls[:max_checks]  # Limit to avoid rate limits
        
        for url in urls_to_check:
            result = self.check_url(url)
            if result['is_phishing']:
                phishing_urls.append({
                    'url': url,
                    'phish_id': result.get('phish_id'),
                    'verified': result.get('verified')
                })
            
            # Rate limiting: sleep between requests (be nice to free API)
            if not self.api_key:
                time.sleep(0.5)  # 2 requests/second max for free tier
        
        return {
            'phishing_urls': phishing_urls,
            'total_checked': len(urls_to_check),
            'phishing_count': len(phishing_urls)
        }
    
    def _parse_response(self, data):
        """Parse PhishTank API response"""
        results = data.get('results', {})
        
        in_database = results.get('in_database', False)
        verified = results.get('verified', False)
        
        return {
            'is_phishing': in_database and verified,
            'verified': verified,
            'phish_id': results.get('phish_id'),
            'submission_time': results.get('submission_time'),
            'verified_time': results.get('verified_time'),
            'source': 'phishtank'
        }
    
    def _empty_result(self):
        """Return empty result when API unavailable"""
        return {
            'is_phishing': False,
            'verified': False,
            'phish_id': None,
            'submission_time': None,
            'verified_time': None,
            'source': 'phishtank'
        }
    
    def _get_cache_key(self, url):
        """Generate cache key from URL"""
        return hashlib.md5(url.encode()).hexdigest()
    
    def _get_from_cache(self, url):
        """Retrieve from cache if not expired"""
        cache_key = self._get_cache_key(url)
        
        if cache_key in self.cache:
            cached_data, timestamp = self.cache[cache_key]
            
            # Check if cache is still valid
            if datetime.now() - timestamp < self.cache_duration:
                return cached_data
            else:
                # Expired - remove from cache
                del self.cache[cache_key]
        
        return None
    
    def _add_to_cache(self, url, result):
        """Add result to cache"""
        cache_key = self._get_cache_key(url)
        self.cache[cache_key] = (result, datetime.now())
    
    def clear_cache(self):
        """Clear all cached results"""
        self.cache.clear()
    
    def get_cache_stats(self):
        """Get cache statistics"""
        return {
            'cached_urls': len(self.cache),
            'cache_duration_hours': self.cache_duration.total_seconds() / 3600
        }


# Convenience function for quick checks
def is_url_in_phishtank(url, api_key=None):
    """
    Quick check if URL is in PhishTank database
    
    Args:
        url: URL to check
        api_key: Optional PhishTank API key
        
    Returns:
        bool: True if URL is verified phishing, False otherwise
    """
    checker = PhishTankChecker(api_key=api_key)
    result = checker.check_url(url)
    return result['is_phishing']
