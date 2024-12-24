import re
from urllib.parse import urlparse
import tld
import numpy as np

__all__ = ['URLFeatureExtractor']

class URLFeatureExtractor:
    def __init__(self):
        self.feature_names = [
            'url_length', 'num_digits', 'num_special_chars',
            'has_ip_pattern', 'num_subdomains', 'path_length',
            'has_suspicious_words', 'tld_in_path'
        ]
        
    def extract_features(self, url):
        parsed = urlparse(url)
        features = {
            'url_length': len(url),
            'num_digits': sum(c.isdigit() for c in url),
            'num_special_chars': len(re.findall(r'[^a-zA-Z0-9]', url)),
            'has_ip_pattern': self._check_ip_pattern(url),
            'num_subdomains': len(parsed.netloc.split('.')) - 1,
            'path_length': len(parsed.path),
            'has_suspicious_words': self._check_suspicious_words(url),
            'tld_in_path': self._check_tld_in_path(parsed)
        }
        return np.array([features[name] for name in self.feature_names])

    def _check_ip_pattern(self, url):
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        return int(bool(re.search(ip_pattern, url)))

    def _check_suspicious_words(self, url):
        suspicious = ['login', 'signin', 'verify', 'secure', 'account']
        return sum(word in url.lower() for word in suspicious)

    def _check_tld_in_path(self, parsed_url):
        try:
            return int(tld.get_tld(parsed_url.path, fail_silently=True) is not None)
        except:
            return 0
