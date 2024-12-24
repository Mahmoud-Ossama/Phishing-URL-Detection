import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score, classification_report
import xgboost as xgb
import joblib

__all__ = ['PhishingDetector', 'RandomForestDetector', 'XGBoostDetector']

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
        """Predict and return both class and probability."""
        try:
            # Ensure we have a valid model
            if self.model is None:
                raise ValueError("Model not initialized")
                
            # Get predictions
            pred = self.model.predict(url_features)[0]
            proba = self.model.predict_proba(url_features)[0]
            
            # For binary classification, get probability of class 1 (phishing)
            phish_prob = proba[1] if len(proba) > 1 else proba[0]
            
            return int(pred), float(phish_prob)
            
        except Exception as e:
            print(f"Prediction error in {self.__class__.__name__}: {str(e)}")
            raise
    
    def get_feature_importance(self):
        if not hasattr(self.model, 'feature_importances_'):
            raise ValueError("Model not trained yet")
        return self.model.feature_importances_

    def save_model(self, path):
        joblib.dump(self.model, path)

    @classmethod
    def load_model(cls, path):
        instance = cls()
        instance.model = joblib.load(path)
        return instance

class RandomForestDetector(BaseDetector):
    def __init__(self):
        super().__init__()
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            random_state=42
        )

class XGBoostDetector(BaseDetector):
    def __init__(self):
        super().__init__()
        self.model = xgb.XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            random_state=42
        )

# For backwards compatibility
PhishingDetector = RandomForestDetector
