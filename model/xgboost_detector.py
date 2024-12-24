import xgboost as xgb
from .base_detector import BaseDetector  # Use relative import

class XGBoostDetector(BaseDetector):
    def __init__(self):
        super().__init__()
        self.model = xgb.XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            random_state=42
        )
