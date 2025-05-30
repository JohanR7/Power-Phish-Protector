# Phishing Detection Chrome Extension

A Chrome extension that analyzes email content and URLs for phishing indicators. The extension works with Gmail , extracting email content and analyzing URLs when users hover over on links.

## Features

- **Email Content Extraction**: Automatically extracts email subject, sender, content, and embedded URLs.

- **URL Analysis**: Analyzes URLs when users hover over or right-click on links to detect suspicious behavior.

- **Phishing Classification with BERT Deep Learning Models**: Leverages fine-tuned BERT-based deep learning models to classify the extracted email content and URLs as phishing or benign, enhancing detection accuracy through contextual understanding of text.

- **Real-time Processing**: Sends data to a Flask-based backend server for instant phishing analysis.

- **Dockerized Sandbox Environment**: Runs backend services in an isolated Docker container to ensure secure and reproducible operations.

- **Advanced Web Scraping with Playwright**: Utilizes Playwright inside the Docker sandbox to scrape and analyze webpage content and behavior for more accurate threat detection.

- **Privacy Protection with Proxy Support**: All scraping tasks are performed through a proxy server to preserve user privacy and avoid direct exposure to potentially harmful links.

- **Phish Website Screenshot (Base64 Encoded)**: Returns a base64 encoded screenshot of the suspicious website, allowing users to view the site without actually visiting it—mitigating any risk of executing malicious scripts locally.


## Project Structure

```
Power-Phish-Protector/
├── Backend/                  # Flask backend application
│   └── app.py
│   └── requirements.txt
├── ChromeExtension/          # Chrome extension frontend
│   ├── background.js
│   ├── content.js
│   ├── manifest.json
│   ├── popup.html
│   └── popup.js
│
├── Docker/                   # Docker setup for backend
│   ├── app.py
│   ├── Dockerfile
│   └── requirements.txt
│
├── .gitignore
├── README.md

```

## Setup Instructions

### Backend Setup

1. **Install Python Dependencies**
   ```bash
   cd Backend
   pip install -r requirements.txt
   ```

2. **Run the Flask Backend**
   ```bash
   python app.py
   ```
   
   The backend will start at `http://localhost:5000`

### Chrome Extension Setup

1. **Open Chrome Extension Management**
   - Go to `chrome://extensions/`
   - Enable "Developer mode" (toggle in top right)

2. **Load the Extension**
   - Click "Load unpacked"
   - Select the directory containing the extension files
   - The extension should appear in your extensions list

3. **Verify Installation**
   - Look for the extension icon in Chrome's toolbar
   - Click the icon to open the popup interface

### Docker Setup
   ```bash
   - cd Docker
   - docker build -t your_app_name .
   - docker run -d -p 5000:5000 --name your_app_name_container your_app_name

   ```

## Usage

### Automatic Email Analysis

1. **Navigate to Gmail or Outlook**
   - The extension automatically detects supported email platforms
   - Gmail: `mail.google.com`

2. **Email Scanning**
   - The extension automatically scans visible emails
   - Extracts subject, sender, content, and embedded URLs
   - Sends data to backend for analysis

### URL Analysis

1. **Hover Analysis**
   - Hover over any link in an email
   - The extension automatically analyzes the URL
   - Results are sent to backend and logged

### Popup Interface

- Click the extension icon to view:
  - Number of emails scanned
  - Number of URLs analyzed
  - Number of threats detected
  - Backend connection status
  - Manual scan trigger

### Email Analysis
- **Suspicious keywords** in subject lines (urgent, verify, etc.)
- **Sender patterns** (no-reply addresses)
- **URL patterns** (shorteners, suspicious domains)
- **Urgency indicators** in content
- **Risk scoring** based on multiple factors

### URL Analysis
- **URL shorteners** detection (bit.ly, tinyurl, etc.)
- **Suspicious paths** (login, verify, account)
- **IP addresses** instead of domain names
- **Excessive subdomains**
- **URL length** analysis

### 🐳 Docker Sandbox Environment
- **Isolated Execution**: All backend operations, including web scraping and phishing detection, are run inside a secure Docker container.
- **Safe Web Interaction**: Malicious webpages are loaded inside the container, preventing any direct contact with the user’s system.
- **Reproducible Setup**: Docker ensures consistent behavior across different machines and environments.
- **Easy Deployment**: The entire backend stack can be spun up quickly using `docker-compose` or a single Dockerfile.
- **Secure Script Execution**: Suspicious scripts embedded in web pages are neutralized, as they execute in an environment without access to the user’s OS or browser.

## Development Notes

### Scalability Considerations

- **Modular Architecture**: Components are separated for easy enhancement
- **Storage Ready**: Chrome storage APIs used for statistics
- **Backend Extensible**: Flask backend ready for ML model integration
- **Error Handling**: Comprehensive error handling throughout

### Future Enhancements

- **Machine Learning Models**: Replace rule-based analysis with ML
- **Database Integration**: Store analysis history and patterns
- **Advanced UI**: Enhanced popup with detailed threat information
- **Settings Panel**: User configuration options
- **Whitelist/Blacklist**: User-defined trusted/blocked domains
- **Real-time Notifications**: Push notifications for high-risk detections

## Contributors

@amanback


## License

This project is for educational and research purposes. Ensure compliance with email platform terms of service when using.
