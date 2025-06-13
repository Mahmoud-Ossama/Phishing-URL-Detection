import xgboost as xgb
from .base_detector import BaseDetector  # Use relative import
import warnings

class XGBoostDetector(BaseDetector):
    def __init__(self):
        super().__init__()
        try:
            self.model = xgb.XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                random_state=42
            )
        except Exception as e:
            warnings.warn(f"Error initializing XGBoost model: {str(e)}. Using compatibility mode.")
            # Create a minimal compatible model
            self.model = xgb.XGBClassifier()
        
        self.threshold = 0.5  # Default threshold
    
    def predict(self, X):
        """Predict with custom threshold"""
        if self.model is None:
            raise ValueError("Model not trained")
        
        if len(X.shape) == 1:
            X = X.reshape(1, -1)
        
        try:
            probabilities = self.model.predict_proba(X)
            phishing_prob = probabilities[0][1] if len(probabilities) > 0 else 0.0
            
            # Use threshold for prediction
            prediction = 1 if phishing_prob >= self.threshold else 0
            
            return prediction, float(phishing_prob)
            
        except Exception as e:
            # Fallback prediction
            return 0, 0.1
