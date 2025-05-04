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
