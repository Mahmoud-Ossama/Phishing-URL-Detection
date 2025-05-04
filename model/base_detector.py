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
            
            # Add robustness for different predict_proba implementations
            try:
                # Try normal prediction first
                pred = self.model.predict(url_features)[0]
                proba = self.model.predict_proba(url_features)[0]
                phish_prob = proba[1] if len(proba) > 1 else proba[0]
            except Exception as e:
                # If that fails, try a fallback approach
                warnings.warn(f"Standard prediction failed: {str(e)}. Using fallback approach.")
                # Simple fallback: just return a fixed prediction based on basic heuristics
                # This is a simplistic approach - in production you might want to train a simpler model
                pred = 0  # Default to legitimate
                phish_prob = 0.2  # Low risk default
                
                # You could implement basic heuristics here, e.g.:
                if hasattr(url_features, 'shape') and url_features.shape[1] > 10:
                    # Example heuristic: check if URL has too many dots, special chars, etc.
                    phish_indicators = np.sum(url_features[0, :10] > 0.7)  # Arbitrary threshold
                    if phish_indicators > 5:
                        pred = 1
                        phish_prob = 0.8
            
            return int(pred), float(phish_prob)
        except Exception as e:
            print(f"Prediction error in {self.__class__.__name__}: {str(e)}")
            # Return safe default values
            return 0, 0.2  # Default to legitimate with low risk
    
    def get_feature_importance(self):
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
