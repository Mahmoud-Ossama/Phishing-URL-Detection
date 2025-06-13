"""
Typosquatting Detection Module

This module detects domain names that are variations of popular legitimate sites,
including character substitutions, insertions, deletions, and transpositions.
"""

import re
import difflib
from urllib.parse import urlparse
import logging

# Try to import Levenshtein, with fallback
try:
    import Levenshtein # type: ignore
    HAS_LEVENSHTEIN = True
except ImportError:
    HAS_LEVENSHTEIN = False
    # Fallback implementation of Levenshtein distance
    def levenshtein_distance(s1, s2):
        if len(s1) < len(s2):
            return levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]

logger = logging.getLogger(__name__)

class TyposquattingDetector:
    """
    Detects typosquatting attempts by comparing domains against a list of popular sites
    """
    
    def __init__(self):
        # Popular domains that are commonly typosquatted
        self.popular_domains = {
            'google.com': ['googel.com', 'gooogle.com', 'goolge.com', 'g00gle.com', 'googlle.com'],
            'facebook.com': ['facabook.com', 'facebok.com', 'faceebok.com', 'faceebook.com'],
            'amazon.com': ['amaz0n.com', 'amazom.com', 'amazon.co', 'amazone.com'],
            'paypal.com': ['payp4l.com', 'paypaI.com', 'paypal.co', 'paipal.com'],
            'microsoft.com': ['microsft.com', 'microsooft.com', 'miscrosoft.com'],
            'apple.com': ['appel.com', 'aple.com', 'appl.com', 'apple.co'],
            'twitter.com': ['twiter.com', 'twiiter.com', 'twttier.com'],
            'instagram.com': ['instragram.com', 'instagr4m.com', 'instagramm.com'],
            'linkedin.com': ['linkdin.com', 'lnkedin.com', 'linkedln.com'],
            'netflix.com': ['netflik.com', 'netflixs.com', 'netlix.com'],
            'youtube.com': ['youtub.com', 'youtubee.com', 'yotube.com'],
            'gmail.com': ['gmai.com', 'gmaiI.com', 'gmai1.com'],
            'github.com': ['githb.com', 'gitub.com', 'github.co'],
            'stackoverflow.com': ['stackoverflw.com', 'stackoverflow.co'],
            'reddit.com': ['redit.com', 'reditt.com', 'reddit.co'],
            'wikipedia.org': ['wikipedi.org', 'wikipedia.com', 'wikpedia.org'],
            'ebay.com': ['ebey.com', 'ebaay.com', 'ebay.co'],
            'dropbox.com': ['dropbx.com', 'dropboks.com', 'dro pbox.com'],
            'adobe.com': ['adobee.com', 'adob.com', 'adobe.co'],
            'yahoo.com': ['yaho.com', 'yahooo.com', 'yahoo.co']
        }
        
        # Character substitution patterns commonly used in typosquatting
        self.char_substitutions = {
            'o': ['0', 'oo', 'u'],
            'a': ['4', '@', 'aa'],
            'e': ['3', 'ee', 'a'],
            'i': ['1', 'l', 'I', '!'],
            'l': ['1', 'I', 'i'],
            's': ['5', '$', 'z'],
            't': ['7', '+'],
            'g': ['q', '9'],
            'm': ['n', 'rn'],
            'n': ['m', 'r']
        }
        
        # Build reverse lookup for known typosquats
        self.known_typosquats = {}
        for legitimate, typosquats in self.popular_domains.items():
            for typosquat in typosquats:
                self.known_typosquats[typosquat] = legitimate
    
    def extract_domain(self, url):
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            # Remove www. prefix
            if domain.startswith('www.'):
                domain = domain[4:]
            return domain
        except:
            return None
    
    def is_known_typosquat(self, domain):
        """Check if domain is a known typosquat"""
        return domain in self.known_typosquats
    
    def find_similar_legitimate_domain(self, domain):
        """Find the most similar legitimate domain"""
        best_match = None
        best_score = 0
        
        for legitimate_domain in self.popular_domains.keys():
            # Calculate similarity using multiple metrics
            
            # 1. Levenshtein distance
            if HAS_LEVENSHTEIN:
                distance = Levenshtein.distance(domain, legitimate_domain)
            else:
                distance = levenshtein_distance(domain, legitimate_domain)
            
            max_len = max(len(domain), len(legitimate_domain))
            levenshtein_similarity = 1 - (distance / max_len)
            
            # 2. Sequence matcher
            sequence_similarity = difflib.SequenceMatcher(None, domain, legitimate_domain).ratio()
            
            # 3. Combined score
            combined_score = (levenshtein_similarity + sequence_similarity) / 2
              # Must be reasonably similar but not identical, and domain must be long enough
            if 0.75 <= combined_score < 1.0 and combined_score > best_score and len(domain) >= 5:
                best_score = combined_score
                best_match = legitimate_domain
        
        return best_match, best_score
    
    def detect_character_substitution(self, domain):
        """Detect common character substitutions"""
        substitution_score = 0
        suspicious_chars = 0
        
        for char in domain:
            # Count digits in domain (often used for substitution)
            if char.isdigit():
                suspicious_chars += 1
            
            # Count special characters commonly used in substitution
            if char in ['0', '4', '3', '1', '5', '7', '@', '$', '!']:
                substitution_score += 1
        
        # Check for multiple consecutive identical characters
        consecutive_chars = len(re.findall(r'(.)\1{1,}', domain))
        if consecutive_chars > 0:
            substitution_score += consecutive_chars
        
        return substitution_score, suspicious_chars
    
    def detect_homograph_attack(self, domain):
        """Detect homograph attacks (similar looking characters)"""
        # Common homograph substitutions
        homographs = {
            'o': ['0', 'ο', 'о'],  # Latin o, zero, Greek omicron, Cyrillic o
            'a': ['а', 'α'],       # Latin a, Cyrillic a, Greek alpha
            'e': ['е', 'ε'],       # Latin e, Cyrillic e, Greek epsilon
            'i': ['і', 'ι'],       # Latin i, Cyrillic i, Greek iota
            'l': ['ӏ', '1', 'I'],  # Latin l, Cyrillic l, digit 1, capital I
            'p': ['р', 'ρ'],       # Latin p, Cyrillic p, Greek rho
            'c': ['с', 'ϲ'],       # Latin c, Cyrillic c, Greek c
            'x': ['х', 'χ'],       # Latin x, Cyrillic x, Greek chi
        }
        
        suspicious_chars = 0
        for char in domain:
            for legitimate_char, homograph_list in homographs.items():
                if char in homograph_list:
                    suspicious_chars += 1
                    break
        
        return suspicious_chars
    
    def detect_subdomain_typosquatting(self, domain):
        """Detect subdomain typosquatting attacks where legitimate brand names are used as subdomains"""
        parts = domain.split('.')
        
        if len(parts) < 3:  # Need at least subdomain.domain.tld
            return False, None, 0.0
        
        subdomain = parts[0].lower()
        main_domain = '.'.join(parts[1:])
        
        # Check if subdomain matches any of our popular domains (without .com/.org etc.)
        for legitimate_domain in self.popular_domains.keys():
            legitimate_name = legitimate_domain.split('.')[0]  # e.g., 'amazon' from 'amazon.com'
            
            # Exact match
            if subdomain == legitimate_name:
                return True, legitimate_domain, 0.95
            
            # High similarity match
            if HAS_LEVENSHTEIN:
                distance = Levenshtein.distance(subdomain, legitimate_name)
            else:
                distance = levenshtein_distance(subdomain, legitimate_name)
            
            max_len = max(len(subdomain), len(legitimate_name))
            if max_len > 0:
                similarity = 1 - (distance / max_len)
                  # If very similar (80%+) and subdomain is not a common legitimate subdomain
                if similarity >= 0.8 and subdomain not in ['www', 'mail', 'shop', 'secure', 'login', 'api', 'cdn', 'static', 
                                                            'support', 'help', 'dev', 'test', 'stage', 'admin', 'account', 
                                                            'user', 'app', 'mobile', 'web', 'blog', 'news', 'forum']:
                    return True, legitimate_domain, similarity
        
        return False, None, 0.0

    def analyze_domain(self, url):
        """Comprehensive typosquatting analysis"""
        domain = self.extract_domain(url)
        if not domain:
            return {
                'is_typosquatting': False,
                'confidence': 0.0,
                'analysis': 'Invalid domain'
            }
        
        analysis = {
            'domain': domain,
            'is_typosquatting': False,
            'confidence': 0.0,
            'legitimate_target': None,
            'similarity_score': 0.0,
            'substitution_score': 0,
            'homograph_score': 0,
            'analysis': []
        }
        
        # 1. Check if it's a known typosquat
        if self.is_known_typosquat(domain):
            analysis['is_typosquatting'] = True
            analysis['confidence'] = 0.95
            analysis['legitimate_target'] = self.known_typosquats[domain]
            analysis['analysis'].append(f"Known typosquat of {self.known_typosquats[domain]}")
            return analysis
        
        # 2. Check for subdomain typosquatting attacks
        is_subdomain_attack, subdomain_target, subdomain_confidence = self.detect_subdomain_typosquatting(domain)
        if is_subdomain_attack:
            analysis['is_typosquatting'] = True
            analysis['confidence'] = subdomain_confidence
            analysis['legitimate_target'] = subdomain_target
            analysis['analysis'].append(f"Subdomain typosquatting attack using '{domain.split('.')[0]}' as subdomain to impersonate {subdomain_target}")
            return analysis

        # 3. Find similar legitimate domains
        similar_domain, similarity_score = self.find_similar_legitimate_domain(domain)
        if similar_domain:
            analysis['legitimate_target'] = similar_domain
            analysis['similarity_score'] = similarity_score
            
            if similarity_score > 0.8:
                analysis['analysis'].append(f"Very similar to legitimate domain {similar_domain} (similarity: {similarity_score:.2f})")
        
        # 4. Check for character substitutions
        substitution_score, suspicious_chars = self.detect_character_substitution(domain)
        analysis['substitution_score'] = substitution_score
        if substitution_score > 0:
            analysis['analysis'].append(f"Contains {substitution_score} suspicious character substitutions")
        
        # 5. Check for homograph attacks
        homograph_score = self.detect_homograph_attack(domain)
        analysis['homograph_score'] = homograph_score
        if homograph_score > 0:
            analysis['analysis'].append(f"Contains {homograph_score} homograph characters")
        
        # 5. Detect subdomain typosquatting
        subdomain_typosquat, legitimate_target, subdomain_similarity = self.detect_subdomain_typosquatting(domain)
        if subdomain_typosquat:
            analysis['is_typosquatting'] = True
            analysis['confidence'] = max(analysis['confidence'], subdomain_similarity)
            analysis['legitimate_target'] = legitimate_target
            analysis['analysis'].append(f"Subdomain typosquatting detected, similar to {legitimate_target} (similarity: {subdomain_similarity:.2f})")
        
        # 6. Calculate overall confidence
        confidence = 0.0
        
        # High similarity to legitimate domain
        if similarity_score > 0.8:
            confidence += 0.6
        elif similarity_score > 0.7:
            confidence += 0.3
        
        # Character substitutions
        if substitution_score > 0:
            confidence += min(substitution_score * 0.2, 0.3)
        
        # Homograph attacks
        if homograph_score > 0:
            confidence += min(homograph_score * 0.3, 0.4)
        
        # Domain length similarity check
        if similar_domain and abs(len(domain) - len(similar_domain)) <= 2:
            confidence += 0.1
        
        # Cap confidence
        confidence = min(confidence, 0.95)
        
        # Determine if it's likely typosquatting
        analysis['confidence'] = confidence
        analysis['is_typosquatting'] = confidence > 0.5
        
        if analysis['is_typosquatting']:
            analysis['analysis'].append(f"Overall typosquatting confidence: {confidence:.2f}")
        
        return analysis

# Global detector instance
typosquatting_detector = TyposquattingDetector()
