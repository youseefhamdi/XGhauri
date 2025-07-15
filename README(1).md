# XGhauri - Advanced AI-Powered XSS Exploitation Tool

![XGhauri Logo](https://img.shields.io/badge/XGhauri-v1.0.0-red.svg)
![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Pro%202025-orange.svg)

**XGhauri** is a cutting-edge Cross-Site Scripting (XSS) exploitation tool that combines traditional security testing with advanced AI capabilities. Designed to rival tools like SQLmap and Ghauri but specialized for XSS vulnerabilities, it provides intelligent payload generation, seamless Burp Suite integration, and adaptive learning mechanisms.

## 🚀 Key Features

- **AI-Powered Payload Generation**: Context-aware payload generation with machine learning optimization
- **Deep Burp Suite Integration**: Seamless integration with Burp Suite Pro 2025 for request import and proxy handling
- **Intelligent Response Analysis**: Advanced response pattern recognition and WAF bypass detection
- **Browser Verification**: Real-world XSS execution verification using Selenium/Playwright
- **Adaptive Learning**: Reinforcement learning for payload optimization based on target behavior
- **Multi-Context Support**: Handles HTML, JavaScript, attribute, and CSS injection contexts
- **Comprehensive Reporting**: Professional HTML, JSON, and text reports with screenshots
- **Modular Architecture**: Extensible design for easy customization and enhancement

## 📋 Requirements

### System Requirements
- **Operating System**: Kali Linux, Ubuntu, or any Linux distribution
- **Python**: 3.8 or higher
- **Memory**: Minimum 4GB RAM (8GB recommended for AI features)
- **Storage**: 2GB free space

### Software Dependencies
- **Burp Suite Pro 2025** (required for full functionality)
- **Firefox Browser** with FoxyProxy extension
- **Chrome/Chromium** (for Selenium browser verification)
- **Git** (for installation)

## 🛠️ Installation

### Step 1: Clone the Repository
```bash
git clone https://github.com/yourusername/xghauri.git
cd xghauri
```

### Step 2: Install Python Dependencies
```bash
# Install basic dependencies
pip install -r requirements.txt

# Install AI/ML dependencies (optional but recommended)
pip install tensorflow scikit-learn torch

# Install additional browser automation dependencies
pip install selenium playwright
```

### Step 3: Install System Dependencies
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install Chrome for Selenium
wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" | sudo tee /etc/apt/sources.list.d/google-chrome.list
sudo apt update
sudo apt install google-chrome-stable -y

# Install ChromeDriver
sudo apt install chromium-chromedriver -y
```

### Step 4: Set Up Directory Structure
```bash
# Create necessary directories
mkdir -p reports/screenshots
mkdir -p ai/models
mkdir -p logs
mkdir -p payloads/custom

# Set permissions
chmod +x main.py
```

### Step 5: Initial Configuration
```bash
# Copy default configuration
cp config/config.yaml.example config/config.yaml

# Edit configuration as needed
nano config/config.yaml
```

## 🔧 Burp Suite Integration Setup

### Step 1: Configure Burp Suite REST API
1. Open **Burp Suite Pro 2025**
2. Navigate to **Settings** → **Suite** → **REST API**
3. Enable **"Service running"**
4. Set service URL: `http://127.0.0.1:8080`
5. Click **"Generate API key"** and copy the key
6. Save the settings

### Step 2: Configure FoxyProxy in Firefox
1. Install **FoxyProxy** extension from Firefox Add-ons
2. Open FoxyProxy settings
3. Add new proxy configuration:
   - **Title**: Burp Suite
   - **Host**: `127.0.0.1`
   - **Port**: `8080`
   - **Type**: HTTP
4. Save and enable the proxy

### Step 3: Configure XGhauri for Burp Integration
```bash
# Edit configuration file
nano config/config.yaml
```

Add your Burp Suite API key:
```yaml
burp_integration:
  api_enabled: true
  api_key: "your_burp_api_key_here"
  host: "127.0.0.1"
  port: 8080
  proxy_enabled: true
  auto_import: true
```

### Step 4: Test Integration
```bash
# Test Burp API connection
python main.py --test-burp-connection

# Test proxy functionality
python main.py --test-proxy
```

## 📖 Usage Guide

### Basic Usage

#### 1. Simple URL Scan
```bash
# Basic XSS scan on a single URL
python main.py -u https://example.com/search?q=test

# Scan with verbose output
python main.py -u https://example.com/search?q=test --verbose

# Scan with custom payload file
python main.py -u https://example.com/search?q=test --payloads payloads/custom.txt
```

#### 2. Advanced Scanning Options
```bash
# AI-powered scan with browser verification
python main.py -u https://example.com --ai-mode --verify-browser --screenshot

# Multi-threaded scan with custom delay
python main.py -u https://example.com --threads 20 --delay 0.5

# Comprehensive crawl and scan
python main.py --crawl https://example.com --depth 3 --threads 10
```

#### 3. Burp Suite Integration
```bash
# Import requests from Burp Suite XML export
python main.py --burp-import requests.xml --ai-mode

# Use Burp as proxy for live scanning
python main.py -u https://example.com --burp-proxy --burp-api-key YOUR_KEY

# Scan using Burp proxy history
python main.py --burp-history --ai-mode --verify-browser
```

#### 4. AI Training and Learning
```bash
# Train AI model from previous scan results
python main.py --train training_data.json

# Use pre-trained model for scanning
python main.py -u https://example.com --ai-model ai/models/xss_model.h5

# Enable adaptive learning during scan
python main.py -u https://example.com --adaptive-learning
```

### Command Line Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `-u, --url` | Target URL to scan | `-u https://example.com` |
| `--burp-import` | Import requests from Burp Suite file | `--burp-import requests.xml` |
| `--burp-proxy` | Use Burp Suite as proxy | `--burp-proxy` |
| `--burp-api-key` | Burp Suite API key | `--burp-api-key YOUR_KEY` |
| `--ai-mode` | Enable AI-powered scanning | `--ai-mode` |
| `--verify-browser` | Verify XSS in real browser | `--verify-browser` |
| `--screenshot` | Take screenshots of successful XSS | `--screenshot` |
| `--threads` | Number of scanning threads | `--threads 10` |
| `--delay` | Delay between requests (seconds) | `--delay 0.5` |
| `--crawl` | Crawl website before scanning | `--crawl https://example.com` |
| `--depth` | Crawling depth | `--depth 3` |
| `--payloads` | Custom payload file | `--payloads custom.txt` |
| `--output` | Output report file | `--output report.html` |
| `--format` | Report format (html/json/text) | `--format html` |
| `--train` | Train AI model | `--train data.json` |
| `--verbose` | Enable verbose output | `--verbose` |

### Configuration File Options

Edit `config/config.yaml` for advanced configuration:

```yaml
# Scan Settings
scan_settings:
  threads: 10
  delay: 0.1
  timeout: 30
  verify_browser: true
  screenshot: true
  max_payload_length: 10000

# AI Settings
ai_settings:
  enabled: true
  model_path: "ai/models/"
  mutation_rate: 0.1
  confidence_threshold: 0.7
  adaptive_learning: true

# Burp Integration
burp_integration:
  api_enabled: true
  api_key: "your_api_key_here"
  host: "127.0.0.1"
  port: 8080
  proxy_enabled: true
  auto_import: true

# Browser Settings
browser_settings:
  headless: true
  browser_type: "chrome"
  timeout: 30
  screenshot_path: "reports/screenshots/"

# Payload Settings
payload_settings:
  custom_payloads: "payloads/custom.txt"
  context_aware: true
  bypass_techniques: true
  encoding_mutations: true

# Reporting
reporting:
  format: "html"
  output_dir: "reports/"
  include_screenshots: true
  detailed_analysis: true
```

## 📁 Project Structure

```
xghauri/
├── main.py                    # Main CLI entry point
├── requirements.txt           # Python dependencies
├── setup.py                   # Installation script
├── README.md                  # This file
├── config/
│   ├── config.yaml           # Configuration file
│   └── settings.py           # Settings management
├── core/
│   ├── xss_core.py          # Core XSS exploitation engine
│   ├── scanner.py           # Scan orchestration
│   └── __init__.py
├── modules/
│   ├── payload_generator.py  # Payload generation logic
│   ├── response_analyzer.py  # Response analysis
│   ├── context_analyzer.py   # Context detection
│   ├── browser_verifier.py   # Browser verification
│   └── waf_detector.py       # WAF detection and bypass
├── ai/
│   ├── trainer.py            # AI model training
│   ├── models.py             # ML model definitions
│   ├── reinforcement.py      # RL-based optimization
│   └── data_processor.py     # Training data processing
├── burp_integration/
│   ├── burp_importer.py      # Burp Suite request import
│   ├── burp_api.py           # Burp Suite API integration
│   └── proxy_handler.py      # Proxy configuration
├── utils/
│   ├── logger.py             # Logging system
│   ├── http_client.py        # HTTP client wrapper
│   ├── crawler.py            # Web crawler
│   ├── report_generator.py   # Report generation
│   └── banner.py             # CLI banner
├── payloads/
│   ├── payloads.txt          # Base payload database
│   ├── context_payloads.json # Context-specific payloads
│   └── bypass_payloads.json  # WAF bypass payloads
├── reports/                  # Generated reports
│   └── screenshots/          # XSS screenshots
└── logs/                     # Application logs
```

## 🔍 Workflow Examples

### Workflow 1: Basic Web Application Testing
```bash
# Step 1: Basic reconnaissance
python main.py --crawl https://target.com --depth 2

# Step 2: Targeted XSS testing
python main.py -u https://target.com/search?q=test --ai-mode --verify-browser

# Step 3: Generate comprehensive report
python main.py -u https://target.com --output detailed_report.html --format html
```

### Workflow 2: Burp Suite Integration
```bash
# Step 1: Configure browser to use Burp proxy
# (Enable FoxyProxy with Burp configuration)

# Step 2: Browse target application manually
# (Generate traffic in Burp Suite)

# Step 3: Export requests from Burp Suite
# File → Export → Export selected items → XML

# Step 4: Import and test with XGhauri
python main.py --burp-import requests.xml --ai-mode --screenshot
```

### Workflow 3: AI Training and Optimization
```bash
# Step 1: Collect training data
python main.py --collect-training-data https://target.com

# Step 2: Train AI model
python main.py --train training_data.json

# Step 3: Use trained model for improved scanning
python main.py -u https://target.com --ai-model ai/models/trained_model.h5
```

### Workflow 4: Bug Bounty Hunting
```bash
# Step 1: Automated discovery
python main.py --crawl https://target.com --depth 3 --threads 15

# Step 2: Intelligent payload testing
python main.py -u https://target.com --ai-mode --bypass-waf --verify-browser

# Step 3: Generate professional report
python main.py -u https://target.com --output bounty_report.html --format html --include-poc
```

## 🧠 AI Features

### Machine Learning Capabilities
- **Context Recognition**: Automatically identifies injection contexts (HTML, JS, attributes)
- **Response Pattern Analysis**: Learns from server responses to optimize payloads
- **WAF Bypass Generation**: Generates creative bypass techniques for security filters
- **Adaptive Learning**: Continuously improves based on scan results

### AI Model Training
```bash
# Train from successful XSS attempts
python main.py --train-success-data successful_xss.json

# Train from WAF bypass attempts
python main.py --train-bypass-data waf_bypasses.json

# Use reinforcement learning for optimization
python main.py --reinforcement-learning --target https://example.com
```

## 📊 Reporting

### Report Types
- **HTML Reports**: Interactive web-based reports with screenshots
- **JSON Reports**: Machine-readable format for integration
- **Text Reports**: Simple console-friendly output

### Report Features
- Vulnerability classification (Reflected, Stored, DOM-based)
- Severity scoring (Critical, High, Medium, Low)
- Payload effectiveness analysis
- Screenshot evidence
- Remediation recommendations

## 🛡️ Ethical Usage

**XGhauri** is designed for ethical security testing and bug bounty hunting. Please ensure you:

- **Only test applications you own or have explicit permission to test**
- **Follow responsible disclosure practices**
- **Comply with bug bounty program rules and regulations**
- **Use the tool for defensive security purposes**
- **Respect rate limits and avoid DoS conditions**

## 🤝 Contributing

We welcome contributions from the security community! Here's how you can help:

### Development Setup
```bash
# Fork the repository
git clone https://github.com/yourusername/xghauri.git
cd xghauri

# Create development environment
python -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/
```

### Contribution Guidelines
1. **Fork the repository** and create a feature branch
2. **Write tests** for new functionality
3. **Follow PEP 8** style guidelines
4. **Update documentation** as needed
5. **Submit a pull request** with detailed description

### Areas for Contribution
- New payload generation techniques
- Additional WAF bypass methods
- Enhanced AI/ML models
- Performance optimizations
- Documentation improvements

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Support

- **GitHub Issues**: [Report bugs or request features](https://github.com/yourusername/xghauri/issues)
- **Documentation**: [Full documentation](https://xghauri.readthedocs.io/)
- **Community**: [Join our Discord](https://discord.gg/xghauri)

## 🔗 Related Projects

- **SQLmap**: SQL injection exploitation tool
- **Ghauri**: Modern SQL injection tool
- **Burp Suite**: Web application security testing platform
- **OWASP ZAP**: Open-source security testing proxy

## 📈 Roadmap

### Version 1.1 (Planned)
- [ ] Web-based dashboard interface
- [ ] Real-time collaborative scanning
- [ ] Advanced AI model improvements
- [ ] Custom plugin system

### Version 1.2 (Future)
- [ ] Mobile application testing support
- [ ] API security testing features
- [ ] Cloud deployment options
- [ ] Enterprise reporting features

## 🏆 Acknowledgments

- **OWASP** for web security research and standards
- **PortSwigger** for Burp Suite integration capabilities
- **Security research community** for payload databases and techniques
- **Contributors** who help improve the tool

---

**⚠️ Disclaimer**: This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. The authors assume no liability for misuse of this tool.

**🚀 Happy Hunting!** - Find XSS vulnerabilities faster and smarter with XGhauri.