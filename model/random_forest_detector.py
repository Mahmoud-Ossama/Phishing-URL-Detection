from sklearn.ensemble import RandomForestClassifier
from .base_detector import BaseDetector  # Changed to relative import

class RandomForestDetector(BaseDetector):
    def __init__(self):
        super().__init__()
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            random_state=42
        )
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
