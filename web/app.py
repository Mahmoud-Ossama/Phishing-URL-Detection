from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
import os
import joblib
import sys
import logging
import pickle
import warnings
import numpy as np
import whois
import socket
import json
import requests
import dns.resolver
from ipwhois import IPWhois
from datetime import datetime
from urllib.parse import urlparse
import ssl
import OpenSSL
import idna
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from pysafebrowsing import SafeBrowsing
import base64
import hashlib
import sqlite3

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from model.url_features import URLFeatureExtractor
from model.random_forest_detector import RandomForestDetector
from model.enhanced_features import EnhancedURLFeatureExtractor
from model.ensemble_detector import EnsembleDetector
from model.adaptive_detector import AdaptiveDetector
from model.typosquatting_detector import typosquatting_detector

# Simple calibrator implementation
class ModelCalibrator:
    def __init__(self):
        self.rf_bias = -0.3
        self.rf_scale = 0.8
    
    def calibrate_rf_prediction(self, probability):
        calibrated = (probability + self.rf_bias) * self.rf_scale
        return float(np.clip(calibrated, 0.01, 0.99))
    
    def apply_ensemble_logic(self, rf_prob, typosquatting_analysis=None):
        # If typosquatting is detected, boost the risk score significantly
        if typosquatting_analysis and typosquatting_analysis.get('is_typosquatting', False):
            typo_confidence = typosquatting_analysis.get('confidence', 0.0)
            typo_boost = 0.4 + (typo_confidence * 0.4)
            ensemble_prob = max(rf_prob, typo_boost)
            return min(ensemble_prob, 0.95)
        
        # For single model, apply some smoothing
        if rf_prob < 0.3:
            return rf_prob * 0.8  # Reduce false positives
        elif rf_prob > 0.7:
            return min(rf_prob * 1.1, 0.95)  # Boost high confidence
        
        return rf_prob

# Initialize calibrator
calibrator = ModelCalibrator()

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Add secret key for flash messages
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Google Safe Browsing API with the API key
GOOGLE_API_KEY = 'AIzaSyC1XapH75xT8_WKnYGv1H5FcFdlLBV8kYo'
safe_browsing = SafeBrowsing(GOOGLE_API_KEY)

# Initialize VirusTotal API with the API key
VIRUSTOTAL_API_KEY = '1b2addb6b59847dfd4d5743544064172635ec4ab2f6a1ba523c17dad8fb9d1e4'

# Create a custom unpickler that ignores missing attributes
class CustomUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        try:
            return super().find_class(module, name)
        except (AttributeError, ModuleNotFoundError, ImportError):
            # Return a placeholder if the class can't be found
            logger.warning(f"Could not find class {module}.{name}, using placeholder")
            return type(name, (), {})

def safe_load_pickle(file_path):
    """Load a pickle file safely, ignoring missing attributes"""
    with open(file_path, 'rb') as f:
        return CustomUnpickler(f).load()

def load_model(model_class, model_name):
    """Try loading model from either .joblib or .pkl with error handling"""
    models_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models')
    model = model_class()
    
    # Suppress scikit-learn version warnings
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=UserWarning)
        
        joblib_path = os.path.join(models_dir, f'{model_name.lower()}_detector.joblib')
        pkl_path = os.path.join(models_dir, f'{model_name.lower()}_detector.pkl')
        
        if os.path.exists(joblib_path):
            try:
                model.model = joblib.load(joblib_path)
                logger.info(f"Successfully loaded {model_name} model from {joblib_path}")
                return model
            except Exception as e:
                logger.error(f"Error loading {joblib_path}: {str(e)}")
                # Try to use a custom loading approach for joblib
                try:
                    model.model = safe_load_pickle(joblib_path)
                    logger.info(f"Successfully loaded {model_name} model with CustomUnpickler")
                    return model
                except Exception as inner_e:
                    logger.error(f"CustomUnpickler also failed for {joblib_path}: {str(inner_e)}")
                    # Continue to try pickle file
        
        if os.path.exists(pkl_path):
            try:
                model.model = safe_load_pickle(pkl_path)
                logger.info(f"Successfully loaded {model_name} model from {pkl_path}")
                return model
            except Exception as e:
                logger.error(f"Error loading {pkl_path}: {str(e)}")
                raise
        
        # If we get here, no model was successfully loaded
        raise FileNotFoundError(f"No valid model file found for {model_name}")

# Initialize enhanced feature extractor and models
extractor = EnhancedURLFeatureExtractor()
ensemble_model = None
adaptive_model = None

# Enhanced model loading with PKL support
def load_enhanced_model(model_name):
    """Load enhanced PKL models with thresholds"""
    models_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models')
    
    try:
        # Load PKL model
        model_path = os.path.join(models_dir, f'enhanced_{model_name}_detector.pkl')
        threshold_path = os.path.join(models_dir, f'enhanced_{model_name}_threshold.pkl')
        
        if os.path.exists(model_path) and os.path.exists(threshold_path):
            with open(model_path, 'rb') as f:
                model = pickle.load(f)
            with open(threshold_path, 'rb') as f:
                threshold = pickle.load(f)
            
            logger.info(f"✅ Loaded enhanced {model_name} PKL model (threshold: {threshold})")
            return model, threshold
        else:
            logger.warning(f"Enhanced {model_name} PKL model not found")
            return None, None
            
    except Exception as e:
        logger.error(f"Failed to load enhanced {model_name} model: {e}")
        return None, None

# Update model loading
try:
    logger.info("Loading ML models...")
      # Try to load new enhanced PKL models first
    enhanced_rf_model, rf_threshold = load_enhanced_model('random_forest')
    
    if enhanced_rf_model and rf_threshold:
        rf_model = RandomForestDetector()
        rf_model.model = enhanced_rf_model
        rf_model.threshold = rf_threshold
        logger.info(f"✅ Using enhanced RF model with threshold {rf_threshold}")
    else:
        # Fallback to old model loading
        rf_model = load_model(RandomForestDetector, 'randomforest')
        rf_model.threshold = 0.5  # Default threshold
        logger.info("Using fallback RF model")
    
    # Load ensemble model (fallback to old models)
    models_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models')
    ensemble_path = os.path.join(models_dir, 'ensemble_detector_detector.joblib')
    if os.path.exists(ensemble_path):
        ensemble_model = EnsembleDetector()
        ensemble_model.model = joblib.load(ensemble_path)
        logger.info("Loaded Ensemble model")
    
    # Load adaptive model (fallback to old models)
    adaptive_path = os.path.join(models_dir, 'adaptive_detector_detector.joblib')
    if os.path.exists(adaptive_path):
        adaptive_model = AdaptiveDetector()
        adaptive_model.model = joblib.load(adaptive_path)
        logger.info("Loaded Adaptive model")
        
except Exception as e:
    logger.error(f"Error loading models: {str(e)}")
    # Continue with default/placeholder models
    rf_model = RandomForestDetector()
    logger.warning("Using placeholder models due to loading errors")

def get_whois_info(url):
    """Extract WHOIS information for a domain"""
    try:
        # Parse the URL to get the domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Remove 'www.' if present
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Query WHOIS information
        whois_info = whois.whois(domain)
        
        # Process and format the WHOIS data
        result = {}
        
        # Handle domain age calculation
        creation_date = whois_info.get('creation_date')
        expiration_date = whois_info.get('expiration_date')
        
        # Some domains return lists of dates
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        
        # Calculate domain age if creation date is available
        if creation_date:
            if isinstance(creation_date, str):
                try:
                    creation_date = datetime.strptime(creation_date, "%Y-%m-%d")
                except ValueError:
                    try:
                        creation_date = datetime.strptime(creation_date, "%d-%b-%Y")
                    except ValueError:
                        creation_date = None
            
            if isinstance(creation_date, datetime):
                domain_age = (datetime.now() - creation_date).days
                result['domain_age'] = f"{domain_age} days ({int(domain_age/365)} years, {domain_age%365} days)"
                result['creation_date'] = creation_date.strftime("%Y-%m-%d")
        
        # Format expiration date if available
        if expiration_date and isinstance(expiration_date, datetime):
            result['expiration_date'] = expiration_date.strftime("%Y-%m-%d")
        
        # Add other WHOIS information
        for key in ['registrar', 'whois_server', 'org', 'country', 'state', 'name_servers']:
            if key in whois_info and whois_info[key]:
                value = whois_info[key]
                if isinstance(value, list):
                    result[key] = ', '.join(value) if all(isinstance(x, str) for x in value) else str(value)
                else:
                    result[key] = str(value)
        
        return {
            'success': True,
            'data': result
        }
    
    except Exception as e:
        logger.error(f"Error retrieving WHOIS information: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }

def get_ip_info(url):
    """Get IP address and geolocation information for a domain"""
    try:
        # Parse the URL to get the domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Remove 'www.' if present
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Get IP address
        try:
            ip_address = socket.gethostbyname(domain)
        except socket.gaierror:
            return {
                'success': False,
                'error': 'Could not resolve domain to IP address'
            }
        
        result = {'ip_address': ip_address}
        
        # Try different IP information services
        
        # 1. Try ipapi.co (no API key required)
        try:
            response = requests.get(f"https://ipapi.co/{ip_address}/json/", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if 'error' not in data:
                    result['service'] = 'ipapi.co'
                    result['country'] = data.get('country_name')
                    result['region'] = data.get('region')
                    result['city'] = data.get('city')
                    result['latitude'] = data.get('latitude')
                    result['longitude'] = data.get('longitude')
                    result['org'] = data.get('org')
                    result['asn'] = data.get('asn')
                    return {
                        'success': True,
                        'data': result
                    }
        except Exception as e:
            logger.debug(f"ipapi.co error: {str(e)}")
        
        # 2. Try ip-api.com (free, no API key)
        try:
            response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    result['service'] = 'ip-api.com'
                    result['country'] = data.get('country')
                    result['region'] = data.get('regionName')
                    result['city'] = data.get('city')
                    result['latitude'] = data.get('lat')
                    result['longitude'] = data.get('lon')
                    result['org'] = data.get('org')
                    result['isp'] = data.get('isp')
                    result['asn'] = data.get('as')
                    return {
                        'success': True,
                        'data': result
                    }
        except Exception as e:
            logger.debug(f"ip-api.com error: {str(e)}")
        
        # 3. Try ipwhois (local library, more technical details)
        try:
            obj = IPWhois(ip_address)
            data = obj.lookup_rdap(depth=1)
            result['service'] = 'ipwhois'
            result['asn'] = str(data.get('asn')) if data.get('asn') is not None else ''
            result['asn_description'] = str(data.get('asn_description')) if data.get('asn_description') is not None else ''
            result['country'] = str(data.get('asn_country_code')) if data.get('asn_country_code') is not None else ''
            
            # Try to get network information
            network = data.get('network', {})
            if network:
                result['network_name'] = str(network.get('name')) if network.get('name') is not None else ''
                result['network_range'] = f"{network.get('start_address')} - {network.get('end_address')}"
            
            return {
                'success': True,
                'data': result
            }
        except Exception as e:
            logger.debug(f"ipwhois error: {str(e)}")
        
        # If we reach here without returning, we couldn't get detailed geolocation,
        # but we at least have the IP address
        if ip_address:
            return {
                'success': True,
                'data': {'ip_address': ip_address}
            }
        
        return {
            'success': False,
            'error': 'Could not retrieve IP geolocation information'
        }
        
    except Exception as e:
        logger.error(f"Error retrieving IP information: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }

def get_ssl_info(url):
    """Get SSL certificate information for a domain"""
    try:
        # Parse the URL to get the domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
            
        # Remove 'www.' if present
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Encode domain as IDNA for international domain support
        hostname_idna = idna.encode(domain)
        
        # Set up SSL context
        context = ssl.create_default_context()
        
        # Connect to get certificate
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Get certificate in DER format
                der_cert = ssock.getpeercert(True)
                if der_cert is None:
                    raise ValueError("Failed to retrieve DER certificate from server.")
                # Convert to OpenSSL certificate
                x509_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, der_cert)
                # Load with cryptography for more detailed analysis
                cert = x509.load_der_x509_certificate(der_cert, default_backend())
                
                # Prepare result
                result = {}
                
                # Basic info
                result['subject'] = dict(x509_cert.get_subject().get_components())
                result['issuer'] = dict(x509_cert.get_issuer().get_components())
                
                # Convert byte strings to regular strings
                result['subject'] = {key.decode('utf-8'): value.decode('utf-8') for key, value in result['subject'].items()}
                result['issuer'] = {key.decode('utf-8'): value.decode('utf-8') for key, value in result['issuer'].items()}
                
                # Get certificate validity
                not_before = cert.not_valid_before
                not_after = cert.not_valid_after
                
                result['valid_from'] = not_before.strftime('%Y-%m-%d')
                result['valid_until'] = not_after.strftime('%Y-%m-%d')
                result['days_left'] = (not_after - datetime.now()).days
                
                # Get common name
                try:
                    common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                    result['common_name'] = common_names[0].value if common_names else None
                except:
                    result['common_name'] = None
                
                # Get alternative names
                try:
                    ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    alt_names = ext.value.get_values_for_type(x509.DNSName)
                    result['alternative_names'] = alt_names
                except:
                    result['alternative_names'] = []
                
                # Certificate version
                result['version'] = cert.version.name
                
                # Serial number
                result['serial_number'] = format(cert.serial_number, 'x')
                
                # Certificate fingerprints
                result['fingerprint'] = x509_cert.digest('sha256').decode('utf-8')
                
                # Check if certificate is valid for the domain
                domain_validated = False
                if result['common_name'] == domain:
                    domain_validated = True
                elif domain in result['alternative_names']:
                    domain_validated = True
                elif f"*.{domain.split('.', 1)[1]}" in result['alternative_names']:
                    domain_validated = True  # Wildcard certificate
                
                result['domain_validated'] = domain_validated
                
                # Certificate status
                now = datetime.now()
                if now < not_before:
                    result['status'] = 'not_yet_valid'
                elif now > not_after:
                    result['status'] = 'expired'
                else:
                    result['status'] = 'valid'
                
                # Check if the certificate is self-signed
                result['self_signed'] = result['subject'] == result['issuer']
                
                # Simplify subject and issuer
                result['subject_cn'] = result['subject'].get('CN')
                result['issuer_cn'] = result['issuer'].get('CN')
                result['issuer_o'] = result['issuer'].get('O')
                
                return {
                    'success': True,
                    'data': result
                }
                
    except ssl.SSLError as e:
        return {
            'success': False,
            'error': f"SSL Error: {str(e)}"
        }
    except socket.gaierror as e:
        return {
            'success': False,
            'error': f"DNS Error: {str(e)}"
        }
    except Exception as e:
        logger.error(f"Error retrieving SSL information: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }

def check_google_safebrowsing(url):
    """Check if URL is flagged by Google Safe Browsing API"""
    try:
        # Query the Google Safe Browsing API
        result = safe_browsing.lookup_urls([url])
        
        # Get the result for the URL
        url_result = result.get(url, {})
        
        # Check if the URL is in the Google Safe Browsing list
        is_unsafe = url_result.get('malicious', False)
        
        if is_unsafe:
            # Get threat details
            threats = []
            for platform in url_result.get('threats', {}).keys():
                threats.extend(url_result['threats'][platform])
            
            # Return result with threat information
            return {
                'success': True,
                'safe': False,
                'threats': threats,
                'platforms': list(url_result.get('threats', {}).keys()),
                'cache_duration': url_result.get('cache_duration', ''),
                'data': url_result
            }
        else:
            # Return result indicating the URL is safe
            return {
                'success': True,
                'safe': True,
                'data': url_result
            }
            
    except Exception as e:
        logger.error(f"Error checking Google Safe Browsing: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }

def check_virustotal(url):
    """Check if URL is flagged as malicious by VirusTotal"""
    try:
        # Base URL for VirusTotal API v3
        base_url = "https://www.virustotal.com/api/v3"
        
        # Headers for authentication
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY,
            "Accept": "application/json"
        }
        
        # First, check if we can get a report directly by URL identifier
        # URL identifier is created by base64 encoding the URL
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        # Request URL info
        response = requests.get(
            f"{base_url}/urls/{url_id}",
            headers=headers
        )
        
        # If URL not found, submit it for analysis
        if response.status_code == 404:
            logger.info(f"URL not found in VirusTotal, submitting for analysis: {url}")
            # Submit URL for analysis
            analysis_response = requests.post(
                f"{base_url}/urls",
                headers=headers,
                data={"url": url}
            )
            
            if analysis_response.status_code == 200:
                # Extract analysis ID
                analysis_id = analysis_response.json().get('data', {}).get('id')
                if analysis_id:
                    logger.info(f"URL submitted to VirusTotal. Analysis ID: {analysis_id}")
                    return {
                        'success': True,
                        'status': 'submitted',
                        'message': 'URL submitted for analysis. Results not yet available.'
                    }
            
            return {
                'success': False,
                'error': 'Failed to submit URL for analysis'
            }
        
        # If we got a successful response, analyze the results
        if response.status_code == 200:
            data = response.json().get('data', {})
            attributes = data.get('attributes', {})
            
            # Get last analysis results and stats
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            last_analysis_results = attributes.get('last_analysis_results', {})
            
            # Calculate total vendors that analyzed the URL
            total_vendors = sum(last_analysis_stats.values())
            
            # Get detection counts
            malicious_count = last_analysis_stats.get('malicious', 0)
            suspicious_count = last_analysis_stats.get('suspicious', 0)
            
            # Get other metadata
            categories = attributes.get('categories', {})
            first_submission_date = attributes.get('first_submission_date')
            last_analysis_date = attributes.get('last_analysis_date')
            times_submitted = attributes.get('times_submitted', 0)
            
            # Format dates if available
            if first_submission_date:
                first_submission_date = datetime.fromtimestamp(first_submission_date).strftime('%Y-%m-%d %H:%M:%S')
            if last_analysis_date:
                last_analysis_date = datetime.fromtimestamp(last_analysis_date).strftime('%Y-%m-%d %H:%M:%S')
            
            # Create a list of security vendors flagging the URL as malicious
            flagging_vendors = [
                {'name': vendor, 'result': details.get('result'), 'category': details.get('category')}
                for vendor, details in last_analysis_results.items()
                if details.get('category') in ['malicious', 'suspicious']
            ]
            
            # Determine overall status
            if malicious_count + suspicious_count > 0:
                status = 'malicious' if malicious_count > 0 else 'suspicious'
            else:
                status = 'clean'
            
            # Return formatted results
            return {
                'success': True,
                'status': status,
                'total_vendors': total_vendors,
                'malicious_count': malicious_count,
                'suspicious_count': suspicious_count,
                'detection_ratio': f"{malicious_count + suspicious_count}/{total_vendors}",
                'first_submission_date': first_submission_date,
                'last_analysis_date': last_analysis_date,
                'times_submitted': times_submitted,
                'categories': categories,
                'flagging_vendors': flagging_vendors,
                'url': url,
                'permalink': f"https://www.virustotal.com/gui/url/{url_id}/detection"
            }
        
        return {
            'success': False,
            'error': f"VirusTotal API error: {response.status_code} - {response.text}"
        }
            
    except Exception as e:
        logger.error(f"Error checking VirusTotal: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/red-flag', methods=['POST'])
def flag_url():
    """Mark a URL as a red flag and save it to the database"""
    try:
        url = request.form.get('url')
        notes = request.form.get('notes', '')
        
        if not url:
            flash('No URL provided', 'error')
            return redirect(url_for('home'))
        
        # Get user's IP address
        user_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', 'Unknown'))
        
        db_path = os.path.join(os.path.dirname(__file__), 'redflags.db')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Try to insert the URL (will fail if duplicate due to UNIQUE constraint)
        try:
            cursor.execute('''
                INSERT INTO red_flags (url, user_ip, notes)
                VALUES (?, ?, ?)
            ''', (url, user_ip, notes))
            conn.commit()
            flash(f'URL "{url}" has been flagged as suspicious!', 'success')
            logger.info(f"URL flagged: {url} by IP: {user_ip}")
        except sqlite3.IntegrityError:
            # URL already exists in database
            flash(f'URL "{url}" is already flagged!', 'warning')
            logger.info(f"Attempted to flag already flagged URL: {url}")
        
        conn.close()
        
    except Exception as e:
        logger.error(f"Error flagging URL: {str(e)}")
        flash('Error occurred while flagging URL', 'error')
    
    # Redirect back to the previous page or home
    return redirect(request.referrer or url_for('home'))

@app.route('/red-flags')
def view_red_flags():
    """Display all red-flagged URLs"""
    try:
        db_path = os.path.join(os.path.dirname(__file__), 'redflags.db')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get all flagged URLs ordered by most recent first
        cursor.execute('''
            SELECT url, flagged_at, user_ip, notes
            FROM red_flags
            ORDER BY flagged_at DESC
        ''')
        
        flagged_urls = cursor.fetchall()
        conn.close()
        
        # Convert to list of dictionaries for easier template access
        flagged_data = []
        for row in flagged_urls:
            flagged_data.append({
                'url': row[0],
                'flagged_at': row[1],
                'user_ip': row[2],
                'notes': row[3] or 'No notes provided'
            })
        
        return render_template('red_flags.html', flagged_urls=flagged_data)
        
    except Exception as e:
        logger.error(f"Error retrieving red flags: {str(e)}")
        flash('Error occurred while retrieving red flags', 'error')
        return redirect(url_for('home'))

@app.route('/predict', methods=['POST'])
def predict():
    try:
        url = request.form.get('url')
        if not url:
            return jsonify({'error': 'No URL provided'}), 400

        # Perform typosquatting analysis first
        typosquatting_analysis = typosquatting_detector.analyze_domain(url)
        logger.debug(f"Typosquatting analysis: {typosquatting_analysis}")

        # Extract enhanced features
        try:
            enhanced_features = extractor.extract_features(url)
            enhanced_features = enhanced_features.reshape(1, -1)
            logger.debug(f"Enhanced features shape: {enhanced_features.shape}")
            
            # Log feature names and values for debugging
            if hasattr(extractor, 'feature_names') and len(extractor.feature_names) >= 8:
                logger.debug("Enhanced features (first 8):")
                for i in range(min(8, len(extractor.feature_names))):
                    logger.debug(f"  {extractor.feature_names[i]}: {enhanced_features[0][i]}")
        except Exception as e:
            logger.error(f"Error extracting enhanced features: {str(e)}")
            # Fall back to basic features
            from model.url_features import URLFeatureExtractor
            basic_extractor = URLFeatureExtractor()
            enhanced_features = basic_extractor.extract_features(url)
            enhanced_features = enhanced_features.reshape(1, -1)
            
            # Log basic feature names and values
            if hasattr(basic_extractor, 'feature_names'):
                logger.debug("Basic features:")
                for i in range(len(basic_extractor.feature_names)):
                    logger.debug(f"  {basic_extractor.feature_names[i]}: {enhanced_features[0][i]}")
          # Use enhanced features for all models since they were trained on enhanced features
        logger.debug(f"Enhanced features shape: {enhanced_features.shape}")
        logger.debug(f"Feature names count: {len(extractor.feature_names) if hasattr(extractor, 'feature_names') else 'Unknown'}")
          # Make predictions using enhanced features
        try:
            rf_pred, rf_prob = rf_model.predict(enhanced_features)
            # Apply calibration to improve reliability
            rf_prob_calibrated = calibrator.calibrate_rf_prediction(rf_prob)
            rf_pred_calibrated = 1 if rf_prob_calibrated > 0.5 else 0
            logger.debug(f"RF prediction: {rf_pred}, probability: {rf_prob} -> calibrated: {rf_pred_calibrated}, {rf_prob_calibrated}")
        except Exception as e:
            logger.error(f"Error with RandomForest prediction: {str(e)}")
            rf_pred_calibrated, rf_prob_calibrated = 0, 0.0
        
        # Get predictions from enhanced models
        ensemble_pred, ensemble_prob = 0, 0.0
        adaptive_pred, adaptive_prob = 0, 0.0
        
        if ensemble_model and ensemble_model.model:
            try:
                ensemble_pred, ensemble_prob = ensemble_model.predict(enhanced_features)
                logger.debug(f"Ensemble prediction: {ensemble_pred}, probability: {ensemble_prob}")
            except Exception as e:
                logger.error(f"Error with Ensemble prediction: {str(e)}")
          # Collect intelligence data for adaptive model
        whois_info = get_whois_info(url)
        ip_info = get_ip_info(url)
        ssl_info = get_ssl_info(url) if url.startswith('https://') else {'success': False}
        safebrowsing_info = check_google_safebrowsing(url)
        virustotal_info = check_virustotal(url)
        
        intelligence_data = {
            'whois': whois_info,
            'ip_info': ip_info,
            'ssl_info': ssl_info,
            'safebrowsing': safebrowsing_info,
            'virustotal': virustotal_info
        }
        
        # Get adaptive prediction with intelligence
        if adaptive_model and adaptive_model.model:
            try:
                adaptive_pred, adaptive_prob = adaptive_model.predict_with_intelligence(
                    enhanced_features, intelligence_data
                )
                logger.debug(f"Adaptive prediction: {adaptive_pred}, probability: {adaptive_prob}")
            except Exception as e:                logger.error(f"Error with Adaptive prediction: {str(e)}")
        
        # Create ensemble prediction using calibrated results with typosquatting analysis
        rf_prob_for_ensemble = rf_prob_calibrated if 'rf_prob_calibrated' in locals() else 0.2
        ensemble_prob_combined = calibrator.apply_ensemble_logic(
            rf_prob_for_ensemble,
            typosquatting_analysis
        )
        ensemble_pred_combined = 1 if ensemble_prob_combined > 0.5 else 0
          # Calculate Combined ML Detection Result (ML models only)
        ml_combined_prob = calculate_combined_ml_result(
            rf_prob_calibrated if 'rf_prob_calibrated' in locals() else 0.0,
            ensemble_prob_combined,
            adaptive_prob,
            typosquatting_analysis
        )
        ml_combined_prediction = 'Phishing' if ml_combined_prob > 0.5 else 'Legitimate'
        
        result = {
            'url': url,
            'ml_combined': {
                'prediction': ml_combined_prediction,
                'probability': ml_combined_prob,
                'confidence': abs(ml_combined_prob - 0.5) * 2,  # 0-1 scale confidence
                'risk_level': get_risk_level(ml_combined_prob)
            },            'random_forest': {
                'prediction': 'Phishing' if locals().get('rf_pred_calibrated', 0) == 1 else 'Legitimate',
                'probability': locals().get('rf_prob_calibrated', 0.0),
                'original_probability': locals().get('rf_prob', 0.0)
            },
            'ensemble': {
                'prediction': 'Phishing' if ensemble_pred_combined == 1 else 'Legitimate',
                'probability': ensemble_prob_combined,
                'available': True
            },
            'typosquatting': typosquatting_analysis,
            'adaptive': {
                'prediction': 'Phishing' if adaptive_pred == 1 else 'Legitimate',
                'probability': adaptive_prob,
                'available': adaptive_model is not None and adaptive_model.model is not None
            },
            'whois': whois_info,
            'ip_info': ip_info,
            'ssl_info': ssl_info,
            'safebrowsing': safebrowsing_info,
            'virustotal': virustotal_info
        }
        
        return render_template('result.html', result=result)
    
    except Exception as e:
        logger.exception("Error during prediction")
        return jsonify({'error': str(e)}), 500
        return jsonify({'error': str(e)}), 500

# Balanced Phishing Detector class for new models
class BalancedPhishingDetector:
    def __init__(self, model, threshold=0.75):
        self.model = model
        self.threshold = threshold
        self.feature_extractor = EnhancedURLFeatureExtractor()
    
    def predict(self, X):
        """Predict with balanced approach"""
        if len(X.shape) == 1:
            X = X.reshape(1, -1)
        
        proba = self.model.predict_proba(X)
        pred_proba = proba[:, 1] if proba.shape[1] > 1 else proba[:, 0]
        
        # Use threshold to balance false positives and false negatives
        predictions = (pred_proba >= self.threshold).astype(int)
        
        return predictions[0] if len(predictions) == 1 else predictions, pred_proba[0] if len(pred_proba) == 1 else pred_proba
    
    def train(self, X_train, y_train, X_val=None, y_val=None):
        """Train the underlying model"""
        self.model.fit(X_train, y_train)

def calculate_combined_ml_result(rf_prob, ensemble_prob, adaptive_prob, typosquatting_analysis):
    """
    Calculate a combined ML detection result using weighted average of ML models only
    
    Args:
        rf_prob: Random Forest probability
        ensemble_prob: Ensemble probability
        adaptive_prob: Adaptive model probability
        typosquatting_analysis: Typosquatting analysis results
    
    Returns:
        Combined probability score (0.0 to 1.0)
    """
    # Updated weights for ML models only
    weights = {
        'ensemble': 0.50,          # 50% - Primary model (highest weight)
        'random_forest': 0.30,     # 30% - Secondary model
        'adaptive': 0.12,          # 12% - Intelligence integration
        'typosquatting': 0.08      # 8% - Domain analysis
    }
    
    # Calculate typosquatting probability
    typo_prob = 0.0
    if typosquatting_analysis and typosquatting_analysis.get('is_typosquatting', False):
        # Convert typosquatting confidence to probability
        confidence = typosquatting_analysis.get('confidence', 0.0)
        typo_prob = min(0.8 + (confidence * 0.2), 0.95)  # Scale to 80-95% range
    
    # Calculate weighted average
    combined_score = (
        ensemble_prob * weights['ensemble'] +
        rf_prob * weights['random_forest'] +
        adaptive_prob * weights['adaptive'] +
        typo_prob * weights['typosquatting']
    )
    
    # Apply additional logic for high-confidence cases
    high_confidence_threshold = 0.8
    
    # If Ensemble model has very high confidence in phishing, boost the score
    if ensemble_prob > high_confidence_threshold:
        boost_factor = 1.15  # Moderate boost for ensemble
        combined_score = min(combined_score * boost_factor, 0.95)
        logger.debug(f"Ensemble high confidence boost applied: {ensemble_prob:.2f}")
    # If Random Forest has very high confidence but ensemble is lower, small boost
    elif rf_prob > high_confidence_threshold and ensemble_prob < 0.6:
        boost_factor = 1.05
        combined_score = min(combined_score * boost_factor, 0.95)
        logger.debug(f"Random Forest high confidence boost applied: {rf_prob:.2f}")
    
    # If both main models agree on legitimate (both < 0.3), reduce score more aggressively
    if rf_prob < 0.3 and ensemble_prob < 0.3:
        combined_score *= 0.8
        logger.debug(f"Both models indicate low threat, score reduced")
    
    # Log the combination for debugging
    logger.debug(f"ML Score combination - Ensemble: {ensemble_prob:.2f} (50%), RF: {rf_prob:.2f} (30%), "
                f"Adaptive: {adaptive_prob:.2f} (12%), Typo: {typo_prob:.2f} (8%), Final: {combined_score:.2f}")
    
    # Ensure score is within bounds
    return max(0.0, min(1.0, combined_score))

def get_risk_level(probability):
    """
    Convert probability to human-readable risk level
    
    Args:
        probability: Phishing probability (0.0 to 1.0)
    
    Returns:
        Risk level string
    """
    if probability < 0.2:
        return 'Very Low Risk'
    elif probability < 0.35:
        return 'Low Risk'
    elif probability < 0.5:
        return 'Suspicious'  # New level: 35% to 50%
    elif probability < 0.65:
        return 'Medium Risk'  # Now 50% to 65%
    elif probability < 0.8:
        return 'High Risk'
    else:
        return 'Very High Risk'

# Database initialization
def init_database():
    """Initialize the SQLite database for red-flagged URLs"""
    db_path = os.path.join(os.path.dirname(__file__), 'redflags.db')
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Create red_flags table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS red_flags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE NOT NULL,
                flagged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_ip TEXT,
                notes TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
        return True
    except Exception as e:
        logger.error(f"Error initializing database: {str(e)}")
        return False

# Initialize database on app startup
init_database()

@app.route('/test-modal')
def test_modal():
    """Test route for modal functionality"""
    return render_template('modal_test.html')

if __name__ == '__main__':
    # Check if this is a production environment
    is_production = os.environ.get('RAILWAY_ENVIRONMENT') == 'production'
    
    # If we're in production, disable debug mode
    debug_mode = not is_production
    
    # Get port from environment
    port = int(os.environ.get('PORT', 5000))
    
    # Run the Flask app directly
    logger.info(f"Starting Flask application on port {port}")
    if not is_production:
        logger.info(f"Application available at: http://localhost:{port}")
    
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
