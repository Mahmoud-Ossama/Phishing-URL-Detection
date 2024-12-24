from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score, classification_report
import joblib
import pickle
import os

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
            pred = self.model.predict(url_features)[0]
            proba = self.model.predict_proba(url_features)[0]
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
