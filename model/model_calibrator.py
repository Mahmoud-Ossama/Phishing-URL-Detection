"""
Model calibration utilities to improve prediction reliability
"""

import numpy as np
import logging

logger = logging.getLogger(__name__)

def sigmoid(x):
    """Simple sigmoid function"""
    return 1 / (1 + np.exp(-np.clip(x, -500, 500)))

class ModelCalibrator:
    """
    Applies calibration to model predictions to make them more reliable
    """
    
    def __init__(self):
        # Calibration parameters - these can be tuned based on validation data
        self.rf_bias = -0.3  # RandomForest tends to be overconfident, reduce slightly
        self.xgb_bias = -0.6  # XGBoost is very aggressive, reduce significantly
        self.rf_scale = 0.8   # Scale down RF confidence
        self.xgb_scale = 0.6  # Scale down XGB confidence more
    
    def calibrate_rf_prediction(self, probability):
        """
        Calibrate RandomForest predictions
        """
        # Apply bias and scaling
        calibrated = (probability + self.rf_bias) * self.rf_scale
        
        # Ensure within bounds
        calibrated = np.clip(calibrated, 0.01, 0.99)
        
        return float(calibrated)
    
    def calibrate_xgb_prediction(self, probability):
        """
        Calibrate XGBoost predictions (more aggressive calibration)
        """
        # Apply bias and scaling
        calibrated = (probability + self.xgb_bias) * self.xgb_scale
        
        # Ensure within bounds
        calibrated = np.clip(calibrated, 0.01, 0.99)
        
        return float(calibrated)
    
    def apply_ensemble_logic(self, rf_prob, xgb_prob, typosquatting_analysis=None):
        """
        Apply ensemble logic to combine predictions intelligently
        """
        # If typosquatting is detected, boost the risk score significantly
        if typosquatting_analysis and typosquatting_analysis.get('is_typosquatting', False):
            typo_confidence = typosquatting_analysis.get('confidence', 0.0)
            # Boost score based on typosquatting confidence
            typo_boost = 0.4 + (typo_confidence * 0.4)  # 0.4 to 0.8 boost
            
            # Take the higher of model prediction or typosquatting detection
            ensemble_prob = max((rf_prob + xgb_prob) / 2, typo_boost)
            
            # But don't exceed 0.95
            return min(ensemble_prob, 0.95)
        
        # If both models agree on low risk, trust them
        if rf_prob < 0.3 and xgb_prob < 0.3:
            return min(rf_prob, xgb_prob)
        
        # If both models agree on high risk, average but cap
        if rf_prob > 0.7 and xgb_prob > 0.7:
            return min((rf_prob + xgb_prob) / 2, 0.95)
        
        # If models disagree significantly, be conservative
        if abs(rf_prob - xgb_prob) > 0.4:
            return (rf_prob + xgb_prob) / 2 * 0.8  # Conservative blend
        
        # Normal case: weighted average favoring the more conservative prediction
        weight_rf = 0.6  # RandomForest gets higher weight as it's less aggressive
        weight_xgb = 0.4
        
        return weight_rf * rf_prob + weight_xgb * xgb_prob

# Global calibrator instance
calibrator = ModelCalibrator()
