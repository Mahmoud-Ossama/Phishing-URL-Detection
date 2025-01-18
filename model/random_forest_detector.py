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
