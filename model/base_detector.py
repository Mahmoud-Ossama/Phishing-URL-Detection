from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score, classification_report
import joblib
import pickle
import os
import warnings
import numpy as np

class BaseDetector:
    def __init__(self):
        self.model = None
        self.feature_extractor = None

    def train(self, X_train, y_train, X_test, y_test):
        """Train the model on pre-split data and return metrics"""
        if self.model is None:
            raise ValueError("Model not initialized. Please assign a model to 'self.model' before training.")
        self.model.fit(X_train, y_train)
        
        y_pred = self.model.predict(X_test)
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred),
            'recall': recall_score(y_test, y_pred),
            'f1': f1_score(y_test, y_pred),
            'detailed_report': classification_report(y_test, y_pred)
        }
        return metrics
    
    def predict(self, url_features):
        try:
            if self.model is None:
                raise ValueError("Model not initialized")
            
            # Log model information for debugging
            import logging
            logger = logging.getLogger(__name__)
            logger.debug(f"Model type: {type(self.model).__name__}")
            logger.debug(f"Input shape: {url_features.shape}")
            
            # Add robustness for different predict_proba implementations
            try:
                # Try normal prediction first
                pred = self.model.predict(url_features)[0]
                proba = self.model.predict_proba(url_features)[0]
                phish_prob = proba[1] if len(proba) > 1 else proba[0]
                
                logger.debug(f"Model prediction successful: pred={pred}, prob={phish_prob}")
                
            except Exception as e:
                # If that fails, try a fallback approach
                logger.warning(f"Standard prediction failed: {str(e)}. Using fallback approach.")
                # Return sensible defaults instead of fixed values
                pred = 0  # Default to legitimate
                phish_prob = 0.1  # Very low risk default
                
                # You could implement basic heuristics here based on URL features
                if hasattr(url_features, 'shape') and url_features.shape[1] > 10:
                    # Check for obvious phishing indicators in the feature vector
                    # This is a simple heuristic - more sophisticated logic could be added
                    suspicious_indicators = 0
                    
                    # Example checks based on feature positions (adjust based on actual feature order)
                    if url_features.shape[1] >= 8:
                        # Check URL length (assuming it's the first feature)
                        if url_features[0, 0] > 100:  # Very long URL
                            suspicious_indicators += 1
                        
                        # Check number of special characters (assuming it's feature index 2)
                        if url_features[0, 2] > 50:  # Many special characters
                            suspicious_indicators += 1
                        
                        # Check for IP pattern (assuming it's feature index 3)
                        if url_features[0, 3] > 0:  # Has IP pattern
                            suspicious_indicators += 2
                            
                        # Check number of subdomains (assuming it's feature index 4)
                        if url_features[0, 4] > 3:  # Many subdomains
                            suspicious_indicators += 1
                    
                    # Adjust prediction based on suspicious indicators
                    if suspicious_indicators >= 3:
                        pred = 1
                        phish_prob = 0.7 + (suspicious_indicators - 3) * 0.1
                        phish_prob = min(phish_prob, 0.95)  # Cap at 95%
                    elif suspicious_indicators >= 1:
                        phish_prob = 0.3 + suspicious_indicators * 0.1
                
                logger.debug(f"Fallback prediction: pred={pred}, prob={phish_prob}")
            
            return int(pred), float(phish_prob)
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Prediction error in {self.__class__.__name__}: {str(e)}")
            # Return safe default values
            return 0, 0.2  # Default to legitimate with low risk
    
    def get_feature_importance(self):
        if self.model is None:
            raise ValueError("Model not initialized. Please assign and train a model before accessing feature importance.")
        if not hasattr(self.model, 'feature_importances_'):
            raise ValueError("Model not trained yet or does not support feature importance")
        return self.model.feature_importances_

    def save_model(self, path):
        """Save model using either joblib or pickle based on extension"""
        _, ext = os.path.splitext(path)
        if ext == '.pkl':
            with open(path, 'wb') as f:
                pickle.dump(self.model, f)
        else:
            joblib.dump(self.model, path)

    @classmethod
    def load_model(cls, path):
        """Load model using either joblib or pickle based on extension"""
        instance = cls()
        _, ext = os.path.splitext(path)
        if ext == '.pkl':
            with open(path, 'rb') as f:
                instance.model = pickle.load(f)
        else:
            instance.model = joblib.load(path)
        return instance
