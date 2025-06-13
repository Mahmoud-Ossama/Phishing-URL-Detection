import sys
import os

# Add the project directory to Python path
sys.path.append(os.path.dirname(__file__))

# Import and run the web application
from web.app import app

if __name__ == "__main__":
    print("Flask Phishing Detection - Starting Application")
    print("="*50)
    
    # Get port from environment or use default
    port = int(os.environ.get('PORT', 5000))
    
    print(f"Application will be available at:")
    print(f"Local: http://localhost:{port}")
    print("="*50)
    
    try:
        app.run(host='0.0.0.0', port=port, debug=False)
    except KeyboardInterrupt:
        print("\nApplication stopped by user.")
    except Exception as e:
        print(f"\nApplication failed to start: {str(e)}")
