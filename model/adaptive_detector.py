import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV
from .base_detector import BaseDetector
import pickle
import os
import warnings
from datetime import datetime, timedelta
import logging

# Configure logging and warnings
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
warnings.filterwarnings('ignore', category=FutureWarning)
warnings.filterwarnings('ignore', category=UserWarning)

class AdaptiveDetector(BaseDetector):
    def __init__(self):
        super().__init__()
        self.model = None
        self.confidence_threshold = 0.8
        self.retrain_threshold = 100  # Retrain after 100 uncertain predictions
        self.uncertain_samples = []
        self.last_retrain = datetime.now()
        
        # Dynamic feature weights based on external intelligence
        self.feature_weights = None
        self.intelligence_feedback = {}
        
        # Initialize with a basic model
        self._initialize_model()

    def _initialize_model(self):
        """Initialize the base model with optimized parameters"""
        self.model = RandomForestClassifier(
            n_estimators=150,
            max_depth=12,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            class_weight='balanced',
            n_jobs=-1,  # Use all available cores
            warm_start=True  # Allow incremental training
        )

    def predict_with_intelligence(self, url_features, intelligence_data=None):
        """Enhanced prediction using external intelligence"""
        try:
            # Ensure input is properly shaped
            if url_features.ndim == 1:
                url_features = url_features.reshape(1, -1)
            
            # Get base ML prediction
            base_pred, base_prob = self.predict(url_features)
            
            # Adjust prediction based on intelligence
            if intelligence_data:
                adjusted_prob = self._adjust_probability_with_intelligence(
                    base_prob, intelligence_data
                )
                
                # Update prediction if probability crosses threshold
                adjusted_pred = 1 if adjusted_prob > 0.5 else 0
                
                # Store feedback for model adaptation
                self._store_intelligence_feedback(intelligence_data, base_pred, adjusted_pred)
                
                return adjusted_pred, adjusted_prob
            
            return base_pred, base_prob
            
        except Exception as e:
            logger.error(f"Error in predict_with_intelligence: {str(e)}")
            return 0, 0.3

    def _adjust_probability_with_intelligence(self, base_prob, intelligence):
        """Adjust ML probability based on external intelligence"""
        adjustments = []
        
        try:
            # WHOIS intelligence
            if intelligence.get('whois', {}).get('success'):
                whois_data = intelligence['whois'].get('data', {})
                if 'domain_age' in whois_data:
                    try:
                        age_days = int(whois_data['domain_age'].split(' ')[0])
                        if age_days < 30:
                            adjustments.append(0.3)  # Increase phishing probability
                        elif age_days > 365:
                            adjustments.append(-0.2)  # Decrease phishing probability
                    except (ValueError, IndexError):
                        pass  # Skip if age format is unexpected
            
            # VirusTotal intelligence
            if intelligence.get('virustotal', {}).get('success'):
                vt_data = intelligence['virustotal']
                status = vt_data.get('status', 'unknown')
                if status == 'malicious':
                    adjustments.append(0.4)  # Strong indicator
                elif status == 'clean':
                    adjustments.append(-0.3)
            
            # Google Safe Browsing
            if intelligence.get('safebrowsing', {}).get('success'):
                if not intelligence['safebrowsing'].get('safe', True):
                    adjustments.append(0.5)  # Very strong indicator
            
            # SSL intelligence
            if intelligence.get('ssl_info', {}).get('success'):
                ssl_data = intelligence['ssl_info'].get('data', {})
                if ssl_data.get('self_signed'):
                    adjustments.append(0.2)
                if not ssl_data.get('domain_validated'):
                    adjustments.append(0.25)
            
            # IP geolocation intelligence
            if intelligence.get('ip_info', {}).get('success'):
                ip_data = intelligence['ip_info'].get('data', {})
                high_risk_countries = ['RU', 'CN', 'NG', 'IR', 'KP', 'UA']
                country = ip_data.get('country', '')
                if any(risk_country in country for risk_country in high_risk_countries):
                    adjustments.append(0.15)
            
        except Exception as e:
            logger.error(f"Error adjusting probability: {str(e)}")
        
        # Apply adjustments with bounds checking
        adjusted_prob = base_prob + sum(adjustments)
        return max(0.0, min(1.0, adjusted_prob))  # Clamp to [0,1]

    def _store_intelligence_feedback(self, intelligence, base_pred, final_pred):
        """Store intelligence feedback for model adaptation"""
        try:
            feedback = {
                'timestamp': datetime.now(),
                'base_prediction': int(base_pred),
                'final_prediction': int(final_pred),
                'intelligence_signals': self._extract_intelligence_signals(intelligence)
            }
            
            # Store in memory with size limit
            feedback_id = len(self.intelligence_feedback)
            
            # Cleanup old feedback if memory gets too large
            if len(self.intelligence_feedback) > 1000:
                # Keep only recent feedback (last 30 days)
                recent_cutoff = datetime.now() - timedelta(days=30)
                self.intelligence_feedback = {
                    k: v for k, v in self.intelligence_feedback.items() 
                    if v['timestamp'] > recent_cutoff
                }
            
            self.intelligence_feedback[feedback_id] = feedback
            
        except Exception as e:
            logger.error(f"Error storing intelligence feedback: {str(e)}")

    def _extract_intelligence_signals(self, intelligence):
        """Extract key signals from intelligence data"""
        signals = {}
        
        try:
            # WHOIS signals
            if intelligence.get('whois', {}).get('success'):
                whois_data = intelligence['whois'].get('data', {})
                if 'domain_age' in whois_data:
                    try:
                        signals['domain_age'] = int(whois_data['domain_age'].split(' ')[0])
                    except (ValueError, IndexError):
                        signals['domain_age'] = -1  # Unknown age
            
            # VirusTotal signals
            if intelligence.get('virustotal', {}).get('success'):
                vt_data = intelligence['virustotal']
                signals['vt_malicious'] = vt_data.get('malicious_count', 0)
                signals['vt_total'] = vt_data.get('total_vendors', 0)
            
            # Safe Browsing signals
            if intelligence.get('safebrowsing', {}).get('success'):
                signals['gsb_safe'] = intelligence['safebrowsing'].get('safe', True)
            
            # SSL signals
            if intelligence.get('ssl_info', {}).get('success'):
                ssl_data = intelligence['ssl_info'].get('data', {})
                signals['ssl_valid'] = ssl_data.get('status') == 'valid'
                signals['ssl_self_signed'] = ssl_data.get('self_signed', False)
            
        except Exception as e:
            logger.error(f"Error extracting intelligence signals: {str(e)}")
        
        return signals

    def should_retrain(self):
        """Determine if model should be retrained"""
        try:
            if len(self.uncertain_samples) >= self.retrain_threshold:
                return True
            
            # Check if enough time has passed
            time_since_retrain = datetime.now() - self.last_retrain
            if time_since_retrain > timedelta(days=7):
                return len(self.uncertain_samples) > 50
            
            return False
        except Exception as e:
            logger.error(f"Error checking retrain condition: {str(e)}")
            return False

    def adaptive_retrain(self, new_X, new_y):
        """Retrain model with new data"""
        try:
            if self.model is None:
                self._initialize_model()
            
            # Validate input data
            if len(new_X) == 0 or len(new_y) == 0:
                logger.warning("No new data provided for retraining")
                return
            
            new_X = np.array(new_X)
            new_y = np.array(new_y)
            
            # Ensure proper shape
            if new_X.ndim == 1:
                new_X = new_X.reshape(1, -1)
            
            # For RandomForest with warm_start, we need to increase n_estimators
            current_estimators = self.model.get_params()['n_estimators']
            self.model.set_params(n_estimators=current_estimators + 50)
            
            # Retrain with new data
            self.model.fit(new_X, new_y)
            
            # Reset counters
            self.uncertain_samples = []
            self.last_retrain = datetime.now()
            
            logger.info(f"Model retrained at {self.last_retrain} with {len(new_X)} samples")
            
        except Exception as e:
            logger.error(f"Error during adaptive retraining: {str(e)}")
            # Reinitialize model if training fails
            self._initialize_model()

    def get_intelligence_summary(self):
        """Get summary of intelligence feedback for analysis"""
        try:
            if not self.intelligence_feedback:
                return {}
            
            total_feedback = len(self.intelligence_feedback)
            agreement_count = sum(
                1 for feedback in self.intelligence_feedback.values()
                if feedback['base_prediction'] == feedback['final_prediction']
            )
            
            agreement_rate = agreement_count / total_feedback if total_feedback > 0 else 0
            
            return {
                'total_feedback': total_feedback,
                'agreement_rate': agreement_rate,
                'last_update': max(f['timestamp'] for f in self.intelligence_feedback.values()) if self.intelligence_feedback else None
            }
            
        except Exception as e:
            logger.error(f"Error getting intelligence summary: {str(e)}")
            return {}
