import pandas as pd
import numpy as np
import os
import sys
from sklearn.model_selection import train_test_split  # Add this import

from url_features import URLFeatureExtractor
from random_forest_detector import RandomForestDetector
from xgboost_detector import XGBoostDetector

def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def train_and_evaluate(model, X_train, X_test, y_train, y_test, model_name):
    print(f"\n{'='*20} {model_name} {'='*20}")
    metrics = model.train(X_train, y_train, X_test, y_test)
    
    print(f"\nModel Performance Metrics:")
    print(f"Accuracy: {metrics['accuracy']:.4f}")
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"Recall: {metrics['recall']:.4f}")
    print(f"F1-Score: {metrics['f1']:.4f}")
    
    print("\nDetailed Classification Report:")
    print(metrics['detailed_report'])
    
    print(f"\nFeature Importance:")
    importance = model.get_feature_importance()
    for name, imp in zip(extractor.feature_names, importance):
        print(f"{name}: {imp:.4f}")
    
    # Create models directory if it doesn't exist
    models_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models')
    ensure_dir(models_dir)
    
    # Save as joblib
    joblib_path = os.path.join(models_dir, f'{model_name.lower()}_detector.joblib')
    model.save_model(joblib_path)
    
    # Save as pickle
    pkl_path = os.path.join(models_dir, f'{model_name.lower()}_detector.pkl')
    model.save_model(pkl_path)
    
    return metrics

def main():
    # Fix data path to be relative to script location
    data_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                            'data', 'data_imbal - 55000 - Sheet1.csv')
    data = pd.read_csv(data_path)
    
    # Extract features
    global extractor
    extractor = URLFeatureExtractor()
    X = np.vstack([extractor.extract_features(url) for url in data['URLs']])
    y = data['Labels'].values
    
    # Split data once for both models
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Train and evaluate both models
    models = {
        'RandomForest': RandomForestDetector(),
        'XGBoost': XGBoostDetector()
    }
    
    results = {}
    for name, model in models.items():
        results[name] = train_and_evaluate(
            model, X_train, X_test, y_train, y_test, name
        )
    
    # Compare models
    print("\n" + "="*50)
    print("Models Comparison:")
    print("="*50)
    for name, metrics in results.items():
        print(f"{name}:")
        print(f"Accuracy: {metrics['accuracy']:.4f}")
        print(f"F1-Score: {metrics['f1']:.4f}")
        print("-"*30)

if __name__ == "__main__":
    main()
