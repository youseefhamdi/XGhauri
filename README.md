# Clone the repository
git clone https://github.com/yourusername/xghauri.git
cd xghauri

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install XGhauri
pip install -e .

# Download and install browser drivers
python -m playwright install
webdriver-manager chrome firefox

# Configure Burp Suite integration
cp config/burp_integration.yaml.example config/burp_integration.yaml
# Edit configuration with your Burp Suite API details
