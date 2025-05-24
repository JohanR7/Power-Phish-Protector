// Content script for email platforms
// Extracts email content, detects URLs, and handles user interactions

class PhishingDetector {
  constructor() {
    this.init();
    this.hoveredUrls = new Set();
    this.analyzedEmails = new Set();
  }

  init() {
    console.log('Phishing Detector initialized');
    this.detectEmailPlatform();
    this.setupEventListeners();
    this.startEmailMonitoring();
  }

  // Detect which email platform we're on
  detectEmailPlatform() {
    const hostname = window.location.hostname;
    
    if (hostname.includes('mail.google.com')) {
      this.platform = 'gmail';
    } else if (hostname.includes('outlook.live.com') || hostname.includes('outlook.office.com')) {
      this.platform = 'outlook';
    } else {
      this.platform = 'unknown';
    }
    
    console.log('Detected email platform:', this.platform);
  }

  // Setup event listeners for link interactions
setupEventListeners() {
  // Listen for mouse hover on links
  document.addEventListener('mouseover', (event) => {
    if (event.target.tagName === 'A' && event.target.href) {
      this.handleLinkHover(event.target.href);
    }
  });

  // Listen for right-click on links
  document.addEventListener('contextmenu', (event) => {
    if (event.target.tagName === 'A' && event.target.href) {
      console.log('Right-clicked on link:', event.target.href);
    }
  });

  // Listen for any click (used to check for new emails after delay)
  document.addEventListener('click', () => {
    setTimeout(() => {
      this.checkForNewEmails();
    }, 1000);
  });

  // Listen for messages from background script
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'URL_ANALYSIS_RESULT') {
      this.displayUrlAnalysisResult(message.url, message.result);
    }

    if (message.type === 'EMAIL_ANALYSIS_RESULT') {
      this.displayEmailAnalysisResult(message.result);
    }

    if (message.type === 'URL_ANALYSIS_ERROR' || message.type === 'EMAIL_ANALYSIS_ERROR') {
      console.error('Analysis error:', message.error);
      this.showNotification('Analysis failed: ' + message.error, 'error');
    }

    if (message.type === 'PAGE_NAVIGATION_DETECTED') {
      console.log('Navigation detected, rescanning...');
      setTimeout(() => {
        this.analyzedEmails.clear();
        this.checkForNewEmails();
      }, 1000);
      sendResponse({ success: true });
      return;
    }

    if (message.type === 'TRIGGER_MANUAL_SCAN') {
      this.performManualScan();
      sendResponse({ success: true });
      return;
    }

    sendResponse({ received: true });
  });

  // Gmail-specific listeners
  if (this.platform === 'gmail') {
    // Detect hash changes (email navigation in Gmail)
    window.addEventListener('hashchange', () => {
      console.log('Gmail hash changed, checking for new emails...');
      setTimeout(() => {
        this.checkForNewEmails();
      }, 500);
    });

    // Detect keyboard shortcuts for Gmail navigation
    document.addEventListener('keydown', (event) => {
      if (['KeyJ', 'KeyK', 'KeyN', 'KeyP'].includes(event.code)) {
        setTimeout(() => {
          this.checkForNewEmails();
        }, 500);
      }
    });
  }
}

performManualScan() {
  console.log('Manual scan triggered');
  this.analyzedEmails.clear(); // Clear cache to re-analyze
  this.hoveredUrls.clear();
  this.checkForNewEmails();
  this.showNotification('Manual scan completed', 'info');
}
  // Handle link hover events
  handleLinkHover(url) {
    // Avoid analyzing the same URL multiple times in a short period
    if (this.hoveredUrls.has(url)) return;
    
    this.hoveredUrls.add(url);
    console.log('Hovered over URL:', url);
    
    // Send URL to background script for analysis
    chrome.runtime.sendMessage({
      type: 'ANALYZE_HOVERED_URL',
      url: url
    });

    // Clear the URL from cache after 5 seconds to allow re-analysis
    setTimeout(() => {
      this.hoveredUrls.delete(url);
    }, 5000);
  }

  // Start monitoring for new emails
  startEmailMonitoring() {
    // Use MutationObserver to detect new emails
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.addedNodes.length > 0) {
          this.checkForNewEmails();
        }
      });
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });

    // Initial check for existing emails
    this.checkForNewEmails();
  }

  // Check for new emails and extract content
checkForNewEmails() {
  let emailElements = [];

  if (this.platform === 'gmail') {
    // Try multiple selectors for different Gmail views and states
    const selectors = [
      // Conversation view
      '[role="main"] [data-message-id]',
      // Individual email view
      '.ii.gt',
      // Email list items
      '[gh="tl"] .zA',
      // Conversation items
      '.Cp .bog',
      // New Gmail interface
      '[data-thread-id]',
      // Expanded email content
      '.a3s.aiL'
    ];
    
    for (const selector of selectors) {
      const elements = document.querySelectorAll(selector);
      if (elements.length > 0) {
        emailElements = Array.from(elements);
        console.log(`Found ${elements.length} emails using selector: ${selector}`);
        break;
      }
    }
  } else if (this.platform === 'outlook') {
    emailElements = Array.from(document.querySelectorAll('[role="option"]'));
  }

  // Filter to get only visible and meaningful emails
  emailElements = emailElements.filter(el => {
    const rect = el.getBoundingClientRect();
    const hasContent = el.textContent && el.textContent.trim().length > 10;
    return rect.width > 0 && rect.height > 0 && hasContent;
  });

  console.log(`Processing ${emailElements.length} email elements`);

  emailElements.forEach((element, index) => {
    const emailId = this.generateEmailId(element);
    
    if (!this.analyzedEmails.has(emailId)) {
      this.analyzedEmails.add(emailId);
      console.log(`Analyzing new email ${index + 1}/${emailElements.length}`);
      this.extractEmailContent(element);
    }
  });
}


  // Generate unique ID for email element
  generateEmailId(element) {
  // Try to get Gmail's data-message-id first
  const messageId = element.getAttribute('data-message-id') || 
                   element.closest('[data-message-id]')?.getAttribute('data-message-id');
  
  if (messageId) {
    return messageId;
  }
  
  // Fallback to content-based hash
  const text = element.textContent || '';
  const position = element.getBoundingClientRect();
  const hash = `${text.substring(0, 100)}_${position.top}_${position.left}`;
  return btoa(hash).substring(0, 20);
}

  // Extract email content and URLs
extractEmailContent(emailElement) {
  try {
    const emailData = {
      subject: this.extractSubject(emailElement),
      sender: this.extractSender(emailElement),
      content: this.extractContent(emailElement),
      urls: this.extractUrls(emailElement),
      platform: this.platform
    };

    // Only analyze if we have meaningful content
    if (emailData.subject || emailData.content || emailData.urls.length > 0) {
      console.log('Extracted email data:', emailData);
      
      // Send to background script for analysis
      chrome.runtime.sendMessage({
        type: 'ANALYZE_EMAIL_CONTENT',
        data: emailData
      });

      // Update stats immediately
      this.updateStats('emailsScanned', 1);
      if (emailData.urls.length > 0) {
        this.updateStats('urlsAnalyzed', emailData.urls.length);
      }
    }
  } catch (error) {
    console.error('Error extracting email content:', error);
  }
}
updateStats(statName, increment) {
  chrome.storage.local.get([statName], (result) => {
    const currentValue = result[statName] || 0;
    chrome.storage.local.set({
      [statName]: currentValue + increment,
      lastScan: new Date().toISOString()
    });
  });
}
  // Extract email subject based on platform
  extractSubject(element) {
  let subject = '';
  
  if (this.platform === 'gmail') {
    // Try multiple selectors for Gmail subject
    const subjectSelectors = [
      '[data-thread-id] span[id]',
      '.bog .y6 span',
      '.hP span',
      'h2 span',
      '.ii.gt .hP'
    ];
    
    for (const selector of subjectSelectors) {
      const subjectElement = element.querySelector(selector) || 
                           document.querySelector(selector);
      if (subjectElement && subjectElement.textContent.trim()) {
        subject = subjectElement.textContent.trim();
        break;
      }
    }
  } else if (this.platform === 'outlook') {
    const subjectElement = element.querySelector('[title]');
    subject = subjectElement ? subjectElement.getAttribute('title') : '';
  }
  
  return subject;
}


  // Extract sender information
  extractSender(element) {
  let sender = '';
  
  if (this.platform === 'gmail') {
    // Try multiple selectors for Gmail sender
    const senderSelectors = [
      'span[email]',
      '.yW span',
      '.go span',
      '.qu span'
    ];
    
    for (const selector of senderSelectors) {
      const senderElement = element.querySelector(selector) || 
                          document.querySelector(selector);
      if (senderElement) {
        const email = senderElement.getAttribute('email') || 
                     senderElement.textContent.trim();
        if (email && email.includes('@')) {
          sender = email;
          break;
        }
      }
    }
  } else if (this.platform === 'outlook') {
    const senderElement = element.querySelector('[aria-label*="From"]');
    sender = senderElement ? senderElement.textContent.trim() : '';
  }
  
  return sender;
}

extractContent(element) {
  let fullContent = '';
  
  if (this.platform === 'gmail') {
    // Try multiple selectors for Gmail email body
    const bodyElement = element.querySelector('.ii.gt div[dir="ltr"]') ||
                       element.querySelector('.a3s.aiL') ||
                       element.querySelector('[role="listitem"] .y6 span') ||
                       element.querySelector('.adn');
    
    if (bodyElement) {
      // Get all text content including nested elements
      fullContent = this.extractAllTextContent(bodyElement);
    }
  } else {
    // Fallback for Outlook and other platforms
    fullContent = element.textContent || '';
  }
  
  return fullContent.replace(/\s+/g, ' ').trim();
}

// New helper method to recursively extract all text
extractAllTextContent(element) {
  let text = '';
  
  // Get direct text content
  for (let node of element.childNodes) {
    if (node.nodeType === Node.TEXT_NODE) {
      text += node.textContent + ' ';
    } else if (node.nodeType === Node.ELEMENT_NODE) {
      // Skip script and style elements
      if (!['SCRIPT', 'STYLE', 'NOSCRIPT'].includes(node.tagName)) {
        text += this.extractAllTextContent(node) + ' ';
      }
    }
  }
  
  return text;
}

  // Extract all URLs from email element
  extractUrls(element) {
    const urls = [];
    const links = element.querySelectorAll('a[href]');
    
    links.forEach(link => {
      const href = link.getAttribute('href');
      if (href && this.isValidUrl(href)) {
        urls.push({
          url: href,
          text: link.textContent.trim(),
          title: link.getAttribute('title') || ''
        });
      }
    });

    return urls;
  }

  // Validate if string is a proper URL
  isValidUrl(string) {
    try {
      const url = new URL(string);
      return url.protocol === 'http:' || url.protocol === 'https:';
    } catch (_) {
      return false;
    }
  }

  // Display URL analysis result
 displayEmailAnalysisResult(result) {
  console.log('Email Analysis Result:', result);
  
  // Update threat stats if threat detected
  if (result.risk_level === 'high' || result.risk_level === 'critical') {
    this.updateStats('threatsDetected', 1);
  }
  
  // Create detailed notification
  const riskColor = this.getRiskColor(result.risk_level);
  const message = `Email Analysis: ${result.status} (Risk: ${result.risk_level})`;
  
  this.showEnhancedNotification(message, result.risk_level, result);
}

displayUrlAnalysisResult(url, result) {
  console.log('URL Analysis Result:', { url, result });
  
  // Update threat stats if threat detected
  if (result.risk_level === 'high' || result.risk_level === 'critical') {
    this.updateStats('threatsDetected', 1);
  }
  
  const message = `URL Analysis: ${result.status} - ${url.substring(0, 30)}...`;
  this.showEnhancedNotification(message, result.risk_level, result);
}

  // Show notification to user
  showEnhancedNotification(message, riskLevel, analysisResult) {
    const notification = document.createElement('div');
    notification.className = `phishing-detector-notification phishing-detector-${riskLevel}`;
  
    const riskColor = this.getRiskColor(riskLevel);
  
    notification.innerHTML = `
      <div style="font-weight: bold; margin-bottom: 5px;">${message}</div>
      ${analysisResult.risk_factors && analysisResult.risk_factors.length > 0 ? 
        `<div style="font-size: 12px; opacity: 0.9;">Risk Factors: ${analysisResult.risk_factors.length}</div>` : ''}
      ${analysisResult.trust_factors && analysisResult.trust_factors.length > 0 ? 
        `<div style="font-size: 12px; opacity: 0.9;">Trust Factors: ${analysisResult.trust_factors.length}</div>` : ''}
    `;
  
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: ${riskColor};
      color: white;
      padding: 12px 20px;
      border-radius: 8px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      z-index: 10000;
      max-width: 350px;
      font-size: 14px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      cursor: pointer;
    `;
  
    notification.addEventListener('click', () => {
      this.showDetailedAnalysis(analysisResult);
    });
  
    document.body.appendChild(notification);
  
    const timeout = riskLevel === 'critical' ? 10000 : riskLevel === 'high' ? 8000 : 5000;
    setTimeout(() => {
      if (notification.parentNode) {
        notification.parentNode.removeChild(notification);
      }
    }, timeout);
  }

  getRiskColor(riskLevel) {
    const colors = {
      'safe': '#27ae60',
      'low': '#f39c12',
      'medium': '#e67e22',
      'high': '#e74c3c',
      'critical': '#8e44ad',
      'unknown': '#95a5a6'
    };
    return colors[riskLevel] || colors['unknown'];
  }

  showDetailedAnalysis(result) {
    const overlay = document.createElement('div');
    overlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0,0,0,0.7);
      z-index: 20000;
      display: flex;
      align-items: center;
      justify-content: center;
    `;
  
    const popup = document.createElement('div');
    popup.style.cssText = `
      background: white;
      padding: 20px;
      border-radius: 8px;
      max-width: 500px;
      max-height: 80vh;
      overflow-y: auto;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;
  
    popup.innerHTML = `
      <h3>Analysis Details</h3>
      <p><strong>Risk Level:</strong> ${result.risk_level}</p>
      <p><strong>Risk Score:</strong> ${result.risk_score}</p>
      ${result.risk_factors && result.risk_factors.length > 0 ? 
        `<h4>Risk Factors:</h4><ul>${result.risk_factors.map(f => `<li>${f}</li>`).join('')}</ul>` : ''}
      ${result.trust_factors && result.trust_factors.length > 0 ? 
        `<h4>Trust Factors:</h4><ul>${result.trust_factors.map(f => `<li>${f}</li>`).join('')}</ul>` : ''}
      <button style="margin-top: 15px; padding: 8px 16px; background: #3498db; color: white; border: none; border-radius: 4px; cursor: pointer;">
        Close
      </button>
    `;
  
    overlay.className = 'overlay';
    overlay.appendChild(popup);
    document.body.appendChild(overlay);
  
    // Close on overlay click or button
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay || e.target.tagName === 'BUTTON') {
        overlay.remove();
      }
    });
  }
}

// Initialize when page loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    new PhishingDetector();
  });
} else {
  new PhishingDetector();
}