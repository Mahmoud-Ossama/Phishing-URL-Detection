from flask import Flask, render_template, request, jsonify
import os
import joblib
import sys
import logging
import pickle

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from model.url_features import URLFeatureExtractor
from model.random_forest_detector import RandomForestDetector
from model.xgboost_detector import XGBoostDetector

app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def load_model(model_class, model_name):
    """Try loading model from either .joblib or .pkl"""
    models_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models')
    model = model_class()
    
    # Try joblib first, then pickle
    try:
        joblib_path = os.path.join(models_dir, f'{model_name.lower()}_detector.joblib')
        model.model = joblib.load(joblib_path)
    except:
        pkl_path = os.path.join(models_dir, f'{model_name.lower()}_detector.pkl')
        with open(pkl_path, 'rb') as f:
            model.model = pickle.load(f)
    
    return model

# Update model loading
try:
    rf_model = load_model(RandomForestDetector, 'randomforest')
    xgb_model = load_model(XGBoostDetector, 'xgboost')
except Exception as e:
    logger.error(f"Error loading models: {str(e)}")
    raise

# Initialize feature extractor
extractor = URLFeatureExtractor()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        url = request.form.get('url')
        if not url:
            return jsonify({'error': 'No URL provided'}), 400

        # Extract features and reshape for prediction
        features = extractor.extract_features(url)
        features = features.reshape(1, -1)
        
        logger.debug(f"Extracted features shape: {features.shape}")
        logger.debug(f"Features: {features}")

        # Get predictions from both models
        rf_pred, rf_prob = rf_model.predict(features)
        logger.debug(f"RF prediction: {rf_pred}, probability: {rf_prob}")
        
        xgb_pred, xgb_prob = xgb_model.predict(features)
        logger.debug(f"XGB prediction: {xgb_pred}, probability: {xgb_prob}")

        result = {
            'url': url,
            'random_forest': {
                'prediction': 'Phishing' if rf_pred == 1 else 'Legitimate',
                'probability': rf_prob
            },
            'xgboost': {
                'prediction': 'Phishing' if xgb_pred == 1 else 'Legitimate',
                'probability': xgb_prob
            }
        }
        
        return render_template('result.html', result=result)
    
    except Exception as e:
        logger.exception("Error during prediction")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
