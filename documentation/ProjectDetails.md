# Technical Details of the Flask Phishing Detection Project

This document provides detailed technical information about the implementation of the URL phishing detection system.

## Project Structure

```
FlaskPhishingDetection/
│
├── data/                      # Contains the dataset
│   └── data_imbal - 55000 - Sheet1.csv
│
├── models/                    # Saved machine learning models
│   ├── randomforest_detector.joblib
│   └── xgboost_detector.pkl
│
├── model/                     # ML model code
│   ├── __init__.py
│   ├── base_detector.py
│   ├── random_forest_detector.py
│   ├── xgboost_detector.py
│   ├── url_features.py
│   ├── requirements.txt
│   └── main.py
│
├── web/                       # Web application code
│   ├── app.py
│   ├── static/
│   │   └── css/
│   │       └── style.css
│   └── templates/
│       ├── index.html
│       └── result.html
│
├── run_with_ngrok.py          # Script to run with ngrok
└── ngrok_config.yml           # Temporary file created during runtime
```

## Feature Extraction

The `URLFeatureExtractor` class in `model/url_features.py` extracts the following features from URLs:

1. **url_length**: Total length of the URL
   - Implementation: `len(url)`

2. **num_digits**: Count of numeric characters
   - Implementation: `sum(c.isdigit() for c in url)`

3. **num_special_chars**: Count of non-alphanumeric characters
   - Implementation: `len(re.findall(r'[^a-zA-Z0-9]', url))`

4. **has_ip_pattern**: Detects IP addresses in the URL
   - Implementation: Pattern matching using regex `r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'`

5. **num_subdomains**: Count of subdomains
   - Implementation: `len(parsed.netloc.split('.')) - 1`

6. **path_length**: Length of the URL path
   - Implementation: `len(parsed.path)`

7. **has_suspicious_words**: Counts occurrences of suspicious terms
   - Implementation: Checks for words like 'login', 'signin', 'verify', etc.

8. **tld_in_path**: Detects top-level domains in the URL path
   - Implementation: Uses the `tld` library to check for TLDs in the path

## Model Implementations

### Base Detector
The `BaseDetector` class in `model/base_detector.py` provides the common functionality:

- Training with metrics calculation
- Prediction with probability scores
- Model persistence (saving/loading)
- Feature importance extraction
- Error handling for version compatibility issues

### Random Forest Detector
The `RandomForestDetector` uses scikit-learn's implementation with:
- 100 trees
- Maximum depth of 10
- Minimum samples split of 5

### XGBoost Detector
The `XGBoostDetector` uses the XGBoost library with:
- 100 estimators
- Maximum depth of 6
- Learning rate of 0.1

## Web Application

### Backend (app.py)
- Flask-based REST API
- Custom error handling for model loading and prediction
- URL validation and feature extraction
- Dual model inference

### Frontend
- Bootstrap 5 for responsive design
- Font Awesome for icons
- Custom CSS with a cybersecurity theme
- Interactive form with validation
- Result display with visual indicators of phishing probability

## Deployment with Ngrok

The `run_with_ngrok.py` script:
1. Terminates any existing ngrok processes
2. Creates a configuration file for ngrok
3. Starts ngrok with the configuration
4. Retrieves the public URL via ngrok's API
5. Starts the Flask application
6. Cleans up resources on exit

## Performance Considerations

- **Model Size**: Both models are compact (<5MB) for quick loading
- **Inference Speed**: Average prediction time is under 100ms
- **Compatibility**: Custom unpickling for handling version differences
- **Error Handling**: Graceful degradation when models fail to load

## Security Considerations

- Input validation to prevent attacks
- Try-except blocks to handle unexpected inputs
- Default to "legitimate" classification in case of errors to minimize false positives
- Separation of model loading and inference code

## Dependencies

Major libraries used:
- scikit-learn (>=1.0.2)
- XGBoost (>=1.7.0)
- Flask (>=2.0.0)
- pyngrok (>=5.1.0)
- tld (>=0.12.6)
- numpy (>=1.21.0)
- pandas (>=1.3.0)
