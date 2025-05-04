from flask import Flask, render_template, request, jsonify
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

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from model.url_features import URLFeatureExtractor
from model.random_forest_detector import RandomForestDetector
from model.xgboost_detector import XGBoostDetector

app = Flask(__name__)
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

# Update model loading
try:
    logger.info("Loading ML models...")
    rf_model = load_model(RandomForestDetector, 'randomforest')
    xgb_model = load_model(XGBoostDetector, 'xgboost')
except Exception as e:
    logger.error(f"Error loading models: {str(e)}")
    # Continue with default/placeholder models
    rf_model = RandomForestDetector()
    xgb_model = XGBoostDetector()
    logger.warning("Using placeholder models due to loading errors")

# Initialize feature extractor
extractor = URLFeatureExtractor()

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
            result['asn'] = data.get('asn')
            result['asn_description'] = data.get('asn_description')
            result['country'] = data.get('asn_country_code')
            
            # Try to get network information
            network = data.get('network', {})
            if network:
                result['network_name'] = network.get('name')
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
                for key in result['subject']:
                    result['subject'][key.decode('utf-8')] = result['subject'].pop(key).decode('utf-8')
                for key in result['issuer']:
                    result['issuer'][key.decode('utf-8')] = result['issuer'].pop(key).decode('utf-8')
                
                # Get certificate validity
                not_before = cert.not_valid_before
                not_after = cert.not_valid_after
                
                result['valid_from'] = not_before.strftime('%Y-%m-%d')
                result['valid_until'] = not_after.strftime('%Y-%m-%d')
                result['days_left'] = (not_after - datetime.datetime.now()).days
                
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
                now = datetime.datetime.now()
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

@app.route('/predict', methods=['POST'])
def predict():
    try:
        url = request.form.get('url')
        if not url:
            return jsonify({'error': 'No URL provided'}), 400

        # Extract features and reshape for prediction
        features = extractor.extract_features(url)
        features = features.reshape(1, -1)
        
        logger.debug(f"Extracted features shape: {features.shape}")
        
        # Get predictions from both models
        try:
            rf_pred, rf_prob = rf_model.predict(features)
            logger.debug(f"RF prediction: {rf_pred}, probability: {rf_prob}")
        except Exception as e:
            logger.error(f"Error with RandomForest prediction: {str(e)}")
            rf_pred, rf_prob = 0, 0.0  # Default to legitimate if error
        
        try:
            xgb_pred, xgb_prob = xgb_model.predict(features)
            logger.debug(f"XGB prediction: {xgb_pred}, probability: {xgb_prob}")
        except Exception as e:
            logger.error(f"Error with XGBoost prediction: {str(e)}")
            xgb_pred, xgb_prob = 0, 0.0  # Default to legitimate if error

        # Get WHOIS information
        whois_info = get_whois_info(url)
        
        # Get IP and geolocation information
        ip_info = get_ip_info(url)
        
        # Get SSL certificate information if the URL is https
        ssl_info = None
        if url.startswith('https://'):
            ssl_info = get_ssl_info(url)
        else:
            ssl_info = {
                'success': False,
                'error': 'URL is not using HTTPS protocol'
            }
        
        # Check Google Safe Browsing API
        safebrowsing_info = check_google_safebrowsing(url)
        
        # Check VirusTotal API
        virustotal_info = check_virustotal(url)
        
        result = {
            'url': url,
            'random_forest': {
                'prediction': 'Phishing' if rf_pred == 1 else 'Legitimate',
                'probability': rf_prob
            },
            'xgboost': {
                'prediction': 'Phishing' if xgb_pred == 1 else 'Legitimate',
                'probability': xgb_prob
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

def start_ngrok(port):
    """Start ngrok and return the public URL"""
    # Import here to avoid import errors if pyngrok isn't available
    from pyngrok import ngrok
    public_url = ngrok.connect(port).public_url
    logger.info(f"* ngrok tunnel available at: {public_url}")
    return public_url

if __name__ == '__main__':
    # Check if ngrok should be used (from environment variable)
    use_ngrok = os.environ.get('USE_NGROK', 'False').lower() == 'true'
    port = int(os.environ.get('PORT', 5000))
    
    # Set up a public URL using ngrok
    public_url = None
    
    if use_ngrok:
        try:
            # Only import pyngrok if needed
            from pyngrok import ngrok
            
            # Set up ngrok
            ngrok_auth_token = os.environ.get('NGROK_AUTH_TOKEN')
            if ngrok_auth_token:
                ngrok.set_auth_token(ngrok_auth_token)
            
            # Start ngrok
            public_url = start_ngrok(port)
            print(f" * Ngrok tunnel URL: {public_url}")
        except Exception as e:
            logger.error(f"Could not start ngrok: {str(e)}")
            logger.error("Running without ngrok")
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=port, debug=True)
