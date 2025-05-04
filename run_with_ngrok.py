import os
import sys
import subprocess
import json
import time
import re

def create_ngrok_config():
    """Create a temporary ngrok config file to allow multiple tunnels in one session"""
    
    # Get port from args or use default
    port = sys.argv[1] if len(sys.argv) > 1 else 5000
    
    # Create a temporary config file
    config_path = os.path.join(os.path.dirname(__file__), "ngrok_config.yml")
    
    # Write the config in YAML format
    with open(config_path, "w") as f:
        f.write(f"version: 2\n")
        f.write(f"authtoken: 2tQjaBrws3URWiuLOwWD3xRIFC5_4n5cz8xXhJe5V48vUiTAD\n")
        f.write(f"tunnels:\n")
        f.write(f"  flask-app:\n")
        f.write(f"    proto: http\n")
        f.write(f"    addr: 127.0.0.1:{port}\n")
        f.write(f"    inspect: true\n")
    
    return config_path, port

def kill_existing_ngrok_processes():
    """Kill any existing ngrok processes to avoid the 'limited to 1 simultaneous session' error"""
    if sys.platform == 'win32':
        os.system('taskkill /f /im ngrok.exe >nul 2>&1')
    else:
        os.system('pkill -f ngrok > /dev/null 2>&1')
    # Give it a moment to fully terminate
    time.sleep(1)

def extract_ngrok_url(output):
    """Extract the ngrok public URL from command output"""
    url_match = re.search(r'https://[a-zA-Z0-9-]+\.ngrok(-free)?\.app', output)
    if url_match:
        return url_match.group(0)
    return None

def main():
    print("Setting up ngrok for Flask application...")
    
    # First, kill any existing ngrok processes
    print("Terminating any existing ngrok processes...")
    kill_existing_ngrok_processes()
    
    # Create ngrok config file
    config_path, port = create_ngrok_config()
    print(f"Created ngrok config at: {config_path}")
    
    # Start ngrok and capture its output
    print("Starting ngrok tunnel...")
    ngrok_cmd = f"ngrok start --config={config_path} flask-app"
    
    # Start ngrok in a separate process
    ngrok_process = subprocess.Popen(
        ngrok_cmd, 
        shell=True, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Give ngrok some time to start
    time.sleep(3)
    
    # Try to get the public URL from the ngrok web interface
    public_url = None
    try:
        import requests
        response = requests.get("http://127.0.0.1:4040/api/tunnels")
        tunnels = response.json()["tunnels"]
        if tunnels:
            public_url = tunnels[0]["public_url"]
    except Exception as e:
        print(f"Error getting URL from ngrok API: {str(e)}")
    
    if public_url:
        print("\n" + "="*60)
        print(f"🔗 Your ngrok public URL: {public_url}")
        print("="*60 + "\n")
    else:
        print("\nNgrok is running. Please check http://localhost:4040 to see your public URL")
    
    # Set environment variable for flask to not start another ngrok instance
    os.environ['USE_NGROK'] = 'False'
    os.environ['PORT'] = str(port)
    
    # Run the Flask application
    print("Starting Flask application...")
    app_path = os.path.join('web', 'app.py')
    
    try:
        # Run Flask app and wait for it to complete
        flask_process = subprocess.run([sys.executable, app_path])
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        # Clean up
        print("Terminating ngrok process...")
        ngrok_process.terminate()
        
        # Remove config file
        try:
            os.remove(config_path)
            print(f"Removed temporary config file: {config_path}")
        except:
            pass

if __name__ == "__main__":
    main()
