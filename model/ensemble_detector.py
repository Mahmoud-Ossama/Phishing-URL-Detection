import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier, StackingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
import warnings
import xgboost as xgb
import lightgbm as lgb
from .base_detector import BaseDetector

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore', category=FutureWarning)
warnings.filterwarnings('ignore', category=UserWarning)

class EnsembleDetector(BaseDetector):
    def __init__(self):
        super().__init__()
        
        # Define multiple base models with updated parameters
        self.base_models = {
            'random_forest': RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                class_weight='balanced',
                n_jobs=-1  # Use all available cores
            ),
            'xgboost': xgb.XGBClassifier(
                n_estimators=200,
                max_depth=8,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=42,
                scale_pos_weight=1,
                eval_metric='logloss',  # Specify eval metric to avoid warning
                use_label_encoder=False  # Avoid deprecation warning
            ),
            'lightgbm': lgb.LGBMClassifier(
                n_estimators=200,
                max_depth=8,
                learning_rate=0.1,
                feature_fraction=0.8,
                bagging_fraction=0.8,
                random_state=42,
                class_weight='balanced',
                verbosity=-1,  # Suppress LightGBM output
                force_col_wise=True  # Handle small dataset warning
            ),
            'gradient_boost': GradientBoostingClassifier(
                n_estimators=150,
                max_depth=6,
                learning_rate=0.1,
                random_state=42
            ),
            'neural_network': MLPClassifier(
                hidden_layer_sizes=(100, 50),
                max_iter=500,
                random_state=42,
                early_stopping=True,
                validation_fraction=0.1,
                solver='adam',  # Specify solver to avoid warning
                alpha=0.0001  # Add regularization
            ),
            'svm': SVC(
                kernel='rbf',
                probability=True,
                random_state=42,
                class_weight='balanced',
                gamma='scale'  # Use scale instead of auto to avoid warning
            ),
            'logistic': LogisticRegression(
                random_state=42,
                class_weight='balanced',
                max_iter=1000,
                solver='liblinear'  # Specify solver for small datasets
            )
        }
        
        # Create ensemble based on configuration
        self.use_stacking = True
        
        if self.use_stacking:
            # Use stacking classifier for better performance
            self.model = StackingClassifier(
                estimators=[(name, model) for name, model in self.base_models.items()],
                final_estimator=LogisticRegression(random_state=42, solver='liblinear'),
                cv=5,
                stack_method='predict_proba',
                n_jobs=-1  # Parallel processing
            )
        else:
            # Use voting classifier as fallback
            self.model = VotingClassifier(
                estimators=[(name, model) for name, model in self.base_models.items()],
                voting='soft',  # Use predicted probabilities
                n_jobs=-1
            )

    def predict(self, url_features):
        try:
            if self.model is None:
                raise ValueError("Model not initialized")
            
            # Ensure input is properly shaped
            if url_features.ndim == 1:
                url_features = url_features.reshape(1, -1)
            
            pred_result = self.model.predict(url_features)
            pred = pred_result[0] if hasattr(pred_result, '__getitem__') and len(pred_result) > 0 else pred_result
            
            proba_result = self.model.predict_proba(url_features)
            proba = proba_result[0] if hasattr(proba_result, '__getitem__') and len(proba_result) > 0 else proba_result
            
            # Get probability of phishing class (class 1)
            phish_prob = proba[1] if hasattr(proba, '__getitem__') and len(proba) > 1 else (proba[0] if hasattr(proba, '__getitem__') else proba)
            
            # Convert to scalar values to avoid type conversion errors
            pred_scalar = pred.item() if hasattr(pred, 'item') else pred
            phish_prob_scalar = phish_prob.item() if hasattr(phish_prob, 'item') else phish_prob
            
            return int(pred_scalar), float(phish_prob_scalar)
            
        except Exception as e:
            print(f"Prediction error in {self.__class__.__name__}: {str(e)}")
            # Return conservative estimate
            return 0, 0.3

    def get_model_predictions(self, url_features):
        """Get predictions from all individual models"""
        predictions = {}
        
        # Ensure input is properly shaped
        if url_features.ndim == 1:
            url_features = url_features.reshape(1, -1)
        
        for name, model in self.base_models.items():
            try:
                if hasattr(model, 'predict_proba'):
                    pred = model.predict(url_features)[0]
                    proba = model.predict_proba(url_features)[0]
                    predictions[name] = {
                        'prediction': int(pred),
                        'probability': float(proba[1] if len(proba) > 1 else proba[0])
                    }
            except Exception as e:
                print(f"Error in {name} prediction: {str(e)}")
                predictions[name] = {'prediction': 0, 'probability': 0.0}
                
        return predictions

    def get_feature_importance(self):
        """Get feature importance from ensemble model"""
        try:
            if isinstance(self.model, StackingClassifier) and hasattr(self.model, 'final_estimator_'):
                # For stacking classifier, get importance from final estimator
                return getattr(self.model.final_estimator_, 'coef_', [0] * 26)[0]
            else:
                # Return average importance from base models
                importances = []
                for name, model in self.base_models.items():
                    if hasattr(model, 'feature_importances_'):
                        importances.append(model.feature_importances_)
                
                if importances:
                    return np.mean(importances, axis=0)
                else:
                    return np.zeros(26)  # Default for 26 features
        except Exception as e:
            print(f"Error getting feature importance: {str(e)}")
            return np.zeros(26)
