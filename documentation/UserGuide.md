# URL Phishing Detector User Guide

This guide explains how to use the URL Phishing Detector application to check if a URL is legitimate or potentially malicious.

## Table of Contents
1. [Getting Started](#getting-started)
2. [Using the Web Interface](#using-the-web-interface)
3. [Understanding Results](#understanding-results)
4. [Frequently Asked Questions](#frequently-asked-questions)
5. [Troubleshooting](#troubleshooting)

## Getting Started

### Prerequisites
- Python 3.7 or higher
- pip (Python package manager)

### Installation

1. Clone the repository or download the source code
   ```
   git clone https://github.com/yourusername/FlaskPhishingDetection.git
   cd FlaskPhishingDetection
   ```

2. Install required dependencies
   ```
   pip install -r model/requirements.txt
   ```

3. Run the application with ngrok for public access
   ```
   python run_with_ngrok.py
   ```

4. The console will display a public URL that looks like:
   ```
   ============================================================
   🔗 Your ngrok public URL: https://xxxx-xxxx-xxxx.ngrok-free.app
   ============================================================
   ```

5. Open this URL in any web browser to access the application

## Using the Web Interface

1. **Enter the URL**: Type or paste the full URL you want to check in the input field
   - Make sure to include the protocol (http:// or https://)
   - Example: `https://example.com/login.php`

2. **Submit for Analysis**: Click the "Analyze URL" button

3. **Wait for Results**: The system will process the URL and display the analysis results

## Understanding Results

The results page provides information from two different machine learning models:

### Random Forest Model
- Shows whether the URL is classified as "Legitimate" or "Phishing"
- Displays a risk score indicating the confidence level of the prediction
- Green indicates legitimate, red indicates phishing

### XGBoost Model
- Provides an independent classification using a different algorithm
- Also displays a risk score
- Helps confirm the results of the first model

### Interpreting the Results

- **Both models say "Legitimate"**: The URL is likely safe
- **Both models say "Phishing"**: Strongly avoid this URL
- **Models disagree**: Exercise caution and consider additional verification

### Risk Score

The risk score represents the probability of the URL being a phishing attempt:
- 0-20%: Very likely legitimate
- 21-40%: Probably legitimate
- 41-60%: Uncertain
- 61-80%: Probably phishing
- 81-100%: Very likely phishing

## Frequently Asked Questions

### Q: How accurate is this tool?
A: The models have been trained on over 55,000 URLs and achieve approximately 96% accuracy on test data. However, no detection system is perfect.

### Q: Can I check multiple URLs at once?
A: Currently, the system only supports checking one URL at a time.

### Q: Does the system store my URLs?
A: No, URLs are processed in memory and are not permanently stored.

### Q: Does it work on shortened URLs?
A: Yes, the system analyzes the actual destination of shortened URLs.

## Troubleshooting

### Common Issues

1. **"No URL provided" error**
   - Ensure you've entered a URL in the input field
   - Check that the URL includes the protocol (http:// or https://)

2. **Slow response time**
   - This may be due to ngrok connection limits or high traffic
   - Try again after a few minutes

3. **"Could not connect" error**
   - The ngrok session may have expired (they last 2 hours on free tier)
   - Restart the application with `python run_with_ngrok.py`

4. **Inconsistent results**
   - Some URLs exist in the gray area between legitimate and phishing
   - When in doubt, verify the URL through other means

### Getting Support

If you encounter issues not covered in this guide, please:
1. Check the console output for error messages
2. Ensure all dependencies are correctly installed
3. Create an issue on the GitHub repository with details of the problem
