# Phishing Detection Chrome Extension

A Chrome extension that analyzes email content and URLs for phishing indicators. The extension works with Gmail , extracting email content and analyzing URLs when users hover over on links.

## Features

- **Email Content Extraction**: Automatically extracts email subject, sender, content, and embedded URLs.

- **URL Analysis**: Analyzes URLs when users hover over or right-click on links to detect suspicious behavior.

- **Real-time Processing**: Sends data to a Flask-based backend server for instant phishing analysis.

- **Dockerized Sandbox Environment**: Runs backend services in an isolated Docker container to ensure secure and reproducible operations.

- **Advanced Web Scraping with Playwright**: Utilizes Playwright inside the Docker sandbox to scrape and analyze webpage content and behavior for more accurate threat detection.

- **Privacy Protection with Proxy Support**: All scraping tasks are performed through a proxy server to preserve user privacy and avoid direct exposure to potentially harmful links.

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

2. **Context Menu Analysis**
   - Right-click on any link
   - Select "Analyze Link for Phishing"
   - URL is analyzed and results displayed

### Popup Interface

- Click the extension icon to view:
  - Number of emails scanned
  - Number of URLs analyzed
  - Number of threats detected
  - Backend connection status
  - Manual scan trigger

## Backend API Endpoints

### Health Check
```
GET /health
```
Returns backend status and timestamp.

### Email Analysis
```
POST /analyze-email
Content-Type: application/json

{
  "subject": "Email subject",
  "sender": "sender@example.com",
  "content": "Email content text",
  "urls": [
    {
      "url": "https://example.com",
      "text": "Link text",
      "title": "Link title"
    }
  ],
  "platform": "gmail"
}
```

### URL Analysis
```
POST /analyze-url
Content-Type: application/json

{
  "url": "https://suspicious-site.com",
  "timestamp": "2025-05-22T10:30:00Z"
}
```

### Statistics
```
GET /stats
```
Returns analysis statistics.

## Current Analysis Logic

The backend includes basic phishing detection rules:

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

### Security Considerations

- **No Local Storage**: Uses Chrome storage APIs instead of localStorage
- **CORS Enabled**: Backend configured for extension requests
- **Input Validation**: Backend validates all incoming data
- **Error Sanitization**: Prevents information leakage in error messages

## Troubleshooting

### Extension Not Working
1. Check if extension is enabled in `chrome://extensions/`
2. Verify you're on a supported email platform
3. Check browser console for error messages
4. Reload the extension if needed

### Backend Connection Issues
1. Ensure Flask backend is running on `localhost:5000`
2. Check firewall settings
3. Verify CORS is enabled
4. Check backend logs for errors

### Email Content Not Extracted
1. Verify you're on Gmail or Outlook
2. Wait for page to fully load
3. Check if emails are visible on screen
4. Review browser console for content script errors

## Contributing

This extension is designed to be minimal but scalable. When adding features:

1. **Follow the established patterns** in existing code
2. **Add comprehensive comments** for new functionality  
3. **Test on both Gmail and Outlook**
4. **Update this README** with new features
5. **Consider security implications** of changes

## License

This project is for educational and research purposes. Ensure compliance with email platform terms of service when using.
