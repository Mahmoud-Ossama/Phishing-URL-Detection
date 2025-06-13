# 🛡️ Flask Phishing Detection System

A comprehensive cybersecurity tool built with Flask that detects phishing websites using advanced machine learning techniques and multiple detection methods.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/flask-2.0+-green.svg)

## 🚀 Features

### 🤖 Advanced ML Detection
- **Ensemble Model**: Primary detection using multiple algorithms (50% weight)
- **Random Forest**: Secondary model for cross-validation (30% weight)
- **Adaptive Learning**: Intelligence-based detection (12% weight)
- **Typosquatting Detection**: Advanced subdomain attack detection (8% weight)

### 🎯 Multi-Layer Analysis
- **URL Feature Analysis**: 30+ URL characteristics
- **Domain Intelligence**: WHOIS, DNS, and age analysis
- **Risk Level Classification**: Safe, Low, Medium, Suspicious, Phishing
- **Real-time Processing**: Instant threat assessment

### 🔴 User Interaction
- **Red Flag System**: Users can flag suspicious URLs
- **Community Database**: Shared threat intelligence
- **Interactive UI**: Modern cyberpunk-themed interface

### 🎨 Modern UI
- **Cyberpunk Design**: Dark theme with neon accents
- **Animated Backgrounds**: Dynamic visual effects
- **Responsive Layout**: Mobile-friendly interface
- **Interactive Elements**: Hover effects and transitions

## 📋 Requirements

### System Requirements
- Python 3.8 or higher
- 4GB RAM minimum
- Internet connection for real-time analysis

## 🛠️ Installation

### 1. Clone the Repository
```bash
git clone https://github.com/osamoxdev/flask-phishing-detection.git
cd flask-phishing-detection
```

### 2. Create Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Application
```bash
python run_app.py
```

The application will be available at `http://localhost:5000`

## 🎮 Usage

### Web Interface
1. **Enter URL**: Input any website URL for analysis
2. **Get Results**: View comprehensive threat assessment
3. **Risk Levels**: 
   - 🟢 **Safe** (0-15%): Legitimate website
   - 🟡 **Low Risk** (15-25%): Minor concerns
   - 🟠 **Medium Risk** (25-35%): Moderate suspicion
   - 🔴 **Suspicious** (35-50%): High concern
   - ⚫ **Phishing** (50%+): Confirmed threat

### Red Flag System
- Flag suspicious URLs for community review
- View all flagged URLs in dedicated page
- Contribute to threat intelligence database

## 🏗️ Project Structure

```
FlaskPhishingDetection/
├── web/                          # Web application
│   ├── app.py                   # Main Flask application
│   ├── templates/               # HTML templates
│   └── static/css/style.css     # Styling and animations
├── model/                       # ML models and detection logic
│   ├── ensemble_detector.py    # Ensemble model
│   ├── random_forest_detector.py # Random Forest model
│   ├── adaptive_detector.py    # Adaptive learning model
│   └── typosquatting_detector.py # Typosquatting detection
├── models/                      # Trained model files
├── data/                        # Training datasets
├── documentation/               # Project documentation
└── requirements.txt             # Python dependencies
```

## 🔬 Technical Details

### Machine Learning Pipeline
1. **Feature Extraction**: 30+ URL characteristics
2. **Model Ensemble**: Multiple algorithms with weighted voting
3. **Risk Calibration**: Probability to risk level mapping
4. **Typosquatting Detection**: Subdomain-based attack detection

### Security Features
- Input validation and sanitization
- SQL injection prevention
- XSS protection
- Secure database operations

## 🚀 Deployment

### Railway (Recommended)
```bash
railway login
railway init
railway up
```

### Local Development
```bash
python run_app.py
```

## 👨‍💻 Author

**Mahmoud Osama** - *Work-Based Professional Project in Cyber Security*

- GitHub: [@osamoxdev](https://github.com/osamoxdev)

## 🛡️ Security Notice

This tool is for educational and research purposes. Always verify results with multiple sources and follow responsible disclosure practices when reporting vulnerabilities.

---

*Made with HARD work by Mahmoud Osama for Work-Based Professional Project in Cyber Security*
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Train the models (optional):
```bash
python run_training.py
```

4. Run the application:
```bash
python run_app.py
```

5. Open your browser to `http://localhost:5000`

### Cloud Deployment

The application is configured for deployment on Railway, Heroku, or similar platforms.

## Project Structure

