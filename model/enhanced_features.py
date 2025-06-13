"""
Quick fix for enhanced features - removing aggressive brand detection
"""

import re
import numpy as np
from urllib.parse import urlparse, parse_qs
import tld
from collections import Counter
import math

class EnhancedURLFeatureExtractor:
    def __init__(self):
        # Only truly suspicious keywords, not brand names
        self.suspicious_keywords = [
            'login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm',
            'banking', 'suspended', 'limited', 'expired', 'renewal', 'billing',
            'urgent', 'immediate', 'click', 'winner', 'prize', 'free'
        ]
        
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.top']
        
        self.feature_names = [
            # Basic features
            'url_length', 'num_digits', 'num_special_chars', 'has_ip_pattern',
            'num_subdomains', 'path_length', 'has_suspicious_words', 'tld_in_path',
            'domain_length', 'vowel_consonant_ratio', 'char_entropy',
            'digit_letter_ratio', 'consecutive_consonants', 'homograph_score',
            'query_params_count', 'fragment_length', 'url_depth',
            'has_redirect_words', 'has_url_shortener', 'has_suspicious_port',
            'suspicious_tld', 'domain_tokens_count', 'brand_name_abuse',
            'punycode_domain', 'domain_hyphens', 'domain_vowels_ratio',
            'hex_strings_count', 'base64_patterns', 'obfuscation_score',
            'social_engineering_words', 'urgency_words', 'tech_brand_spoofing'
        ]

    def extract_features(self, url):
        parsed = urlparse(url)
        
        features = {}
        
        # Basic features
        features['url_length'] = len(url)
        features['num_digits'] = sum(c.isdigit() for c in url)
        features['num_special_chars'] = len(re.findall(r'[^a-zA-Z0-9]', url))
        features['has_ip_pattern'] = int(bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url)))
        features['num_subdomains'] = len(parsed.netloc.split('.')) - 2 if parsed.netloc else 0
        features['path_length'] = len(parsed.path)
        
        # Fixed suspicious words - only count if not in legitimate domain
        domain = parsed.netloc.lower()
        suspicious_count = 0
        for word in self.suspicious_keywords:
            if word in url.lower():
                # Don't count as suspicious if the word matches the main domain
                if not (word in domain and len(word) > 3):
                    suspicious_count += 1
        features['has_suspicious_words'] = suspicious_count
        
        features['tld_in_path'] = self._check_tld_in_path(parsed)
        
        # Lexical features
        features['domain_length'] = len(domain)
        
        # Vowel/consonant ratio
        vowels = sum(1 for c in domain if c in 'aeiou')
        consonants = sum(1 for c in domain if c.isalpha() and c not in 'aeiou')
        features['vowel_consonant_ratio'] = vowels / max(consonants, 1)
        
        # Character entropy
        char_freq = Counter(url.lower())
        entropy = -sum((freq/len(url)) * math.log2(freq/len(url)) 
                      for freq in char_freq.values() if freq > 0)
        features['char_entropy'] = entropy
        
        features['digit_letter_ratio'] = sum(c.isdigit() for c in url) / max(sum(c.isalpha() for c in url), 1)
        features['consecutive_consonants'] = len(re.findall(r'[bcdfghjklmnpqrstvwxyz]{4,}', domain))
        features['homograph_score'] = self._calculate_homograph_score(domain)
        
        # Structure features
        features['query_params_count'] = len(parse_qs(parsed.query))
        features['fragment_length'] = len(parsed.fragment)
        features['url_depth'] = len([p for p in parsed.path.split('/') if p])
        
        redirect_words = ['redirect', 'forward', 'redir', 'goto', 'continue']
        features['has_redirect_words'] = int(any(word in url.lower() for word in redirect_words))
        
        shorteners = ['bit.ly', 'tinyurl', 't.co', 'short.ly', 'goo.gl']
        features['has_url_shortener'] = int(any(short in domain for short in shorteners))
        
        # Check for suspicious ports
        suspicious_ports = [':8080', ':8000', ':3000', ':4444', ':1337']
        features['has_suspicious_port'] = int(any(port in url for port in suspicious_ports))
        
        # Domain features
        features['suspicious_tld'] = int(any(domain.endswith(tld) for tld in self.suspicious_tlds))
        features['domain_tokens_count'] = len(re.findall(r'[a-zA-Z]+', domain))
        
        # Brand name abuse - only flag if typosquatting detected
        brands = ['paypal', 'amazon', 'microsoft', 'google', 'apple', 'facebook']
        brand_abuse = 0
        for brand in brands:
            if brand in domain and not self._is_legitimate_domain(domain, brand):
                brand_abuse = 1
                break
        features['brand_name_abuse'] = brand_abuse
        
        features['punycode_domain'] = int(domain.startswith('xn--'))
        features['domain_hyphens'] = domain.count('-')
        
        domain_vowels = sum(1 for c in domain if c in 'aeiou')
        features['domain_vowels_ratio'] = domain_vowels / max(len(domain), 1)
        
        # Pattern features
        features['hex_strings_count'] = len(re.findall(r'[0-9a-fA-F]{8,}', url))
        features['base64_patterns'] = len(re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', url))
        features['obfuscation_score'] = self._calculate_obfuscation_score(url)
        
        social_words = ['account', 'verify', 'confirm', 'update', 'suspended']
        features['social_engineering_words'] = sum(1 for word in social_words if word in url.lower())
        
        urgency_words = ['urgent', 'immediate', 'expires', 'limited', 'act now']
        features['urgency_words'] = sum(1 for word in urgency_words if word in url.lower())
        
        tech_brands = ['microsoft', 'google', 'apple', 'adobe', 'mozilla']
        tech_spoofing = 0
        for brand in tech_brands:
            if brand in domain and not self._is_legitimate_domain(domain, brand):
                tech_spoofing = 1
                break
        features['tech_brand_spoofing'] = tech_spoofing
        
        return np.array([features[name] for name in self.feature_names])
    
    def _check_tld_in_path(self, parsed_url):
        common_tlds = ['.com', '.org', '.net', '.edu', '.gov']
        return int(any(tld in parsed_url.path for tld in common_tlds))
    
    def _calculate_homograph_score(self, domain):
        # Simple homograph detection
        suspicious_chars = ['0', '1', 'l', 'I', 'o', 'O']
        return sum(1 for char in domain if char in suspicious_chars) / max(len(domain), 1)
    
    def _calculate_obfuscation_score(self, url):
        score = 0
        # URL encoding
        score += url.count('%') * 0.3
        # Multiple slashes
        score += url.count('//') * 0.2
        # Excessive dots
        score += max(0, url.count('.') - 3) * 0.1
        return min(score, 1.0)
    
    def _is_legitimate_domain(self, domain, brand):
        # Check if it's the actual legitimate domain
        legitimate_patterns = [
            f"{brand}.com",
            f"www.{brand}.com", 
            f"{brand}.org",
            f"www.{brand}.org"
        ]
        return any(domain == pattern or domain.endswith('.' + pattern) for pattern in legitimate_patterns)
