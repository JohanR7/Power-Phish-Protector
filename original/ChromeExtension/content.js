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
      // Potentially trigger a specific scan or show context menu item here in future
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
      this.showEnhancedNotification('Analysis failed: ' + message.error, 'error', { error: message.error });
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
  this.showEnhancedNotification('Manual scan initiated. Results will appear shortly.', 'info', {});
}
  // Handle link hover events
  handleLinkHover(url) {
    if (this.hoveredUrls.has(url)) return;
    
    this.hoveredUrls.add(url);
    console.log('Hovered over URL:', url);
    
    chrome.runtime.sendMessage({
      type: 'ANALYZE_HOVERED_URL',
      url: url
    });

    setTimeout(() => {
      this.hoveredUrls.delete(url);
    }, 5000);
  }

  startEmailMonitoring() {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.addedNodes.length > 0) {
          // Debounce or smarter check might be needed if this fires too often
          this.checkForNewEmails();
        }
      });
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });

    this.checkForNewEmails();
  }

checkForNewEmails() {
  let emailElements = [];

  if (this.platform === 'gmail') {
    const selectors = [
      '[role="main"] [data-message-id]:not(.phishing-detector-processed)', // Gmail conversation view
      '.ii.gt:not(.phishing-detector-processed)', // Gmail individual email view
      '.a3s.aiL:not(.phishing-detector-processed)', // Gmail expanded email content
      '[data-thread-id]:not(.phishing-detector-processed)' // New Gmail UI
    ];
    
    for (const selector of selectors) {
      const elements = document.querySelectorAll(selector);
      if (elements.length > 0) {
        emailElements = Array.from(elements);
        // console.log(`Found ${elements.length} potential emails using selector: ${selector}`);
        break; 
      }
    }
  } else if (this.platform === 'outlook') {
    // Outlook selectors need to be robust
    emailElements = Array.from(document.querySelectorAll('[role="option"]:not(.phishing-detector-processed), [aria-label*="Message body"]:not(.phishing-detector-processed)'));
  }

  emailElements = emailElements.filter(el => {
    const rect = el.getBoundingClientRect();
    const hasContent = el.textContent && el.textContent.trim().length > 10;
    return rect.width > 0 && rect.height > 0 && hasContent && !el.classList.contains('phishing-detector-processed');
  });

  if (emailElements.length > 0) {
    // console.log(`Processing ${emailElements.length} new/updated email elements`);
  }

  emailElements.forEach((element, index) => {
    const emailId = this.generateEmailId(element);
    
    if (!this.analyzedEmails.has(emailId)) {
      this.analyzedEmails.add(emailId);
      element.classList.add('phishing-detector-processed'); // Mark as processed
      // console.log(`Analyzing new email ${index + 1}/${emailElements.length}, ID: ${emailId}`);
      this.extractEmailContent(element);
    }
  });
}


  generateEmailId(element) {
    const gmailMsgId = element.getAttribute('data-message-id') || 
                     element.closest('[data-message-id]')?.getAttribute('data-message-id');
    if (gmailMsgId) return `gmail-${gmailMsgId}`;

    const outlookItemId = element.getAttribute('data-convid') || element.getAttribute('data-itemid');
    if(outlookItemId) return `outlook-${outlookItemId}`;
  
    const text = (element.querySelector('h2')?.textContent || element.textContent || '').substring(0, 50);
    const rect = element.getBoundingClientRect();
    const simpleHash = `${text}_${Math.round(rect.top)}_${Math.round(rect.left)}`;
    let hash = 0;
    for (let i = 0; i < simpleHash.length; i++) {
        const char = simpleHash.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash |= 0; 
    }
    return `fallback-${Math.abs(hash).toString(16)}`;
  }

extractEmailContent(emailElement) {
  try {
    const emailData = {
      subject: this.extractSubject(emailElement),
      sender: this.extractSender(emailElement),
      content: this.extractContent(emailElement),
      urls: this.extractUrls(emailElement),
      platform: this.platform
    };

    if (emailData.subject || (emailData.content && emailData.content.length > 10) || emailData.urls.length > 0) {
      // console.log('Extracted email data for analysis:', emailData);
      
      chrome.runtime.sendMessage({
        type: 'ANALYZE_EMAIL_CONTENT',
        data: emailData
      });

      this.updateStats('emailsScanned', 1);
      if (emailData.urls.length > 0) {
        this.updateStats('urlsAnalyzed', emailData.urls.length); 
      }
    } else {
      // console.log('Skipping email analysis: Insufficient content.', emailElement);
    }
  } catch (error) {
    console.error('Error extracting email content:', error, emailElement);
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
  extractSubject(element) {
    let subject = '';
    if (this.platform === 'gmail') {
      const subjectSelectors = [
        '.hP', 
        '.bog .y6 span', 
        'h2.hP', 
        '[data-legacy-thread-id] h2.hP',
        '[data-legacy-message-id] .hP' 
      ];
      for (const selector of subjectSelectors) {
        const subjectEl = element.querySelector(selector) || document.querySelector(selector); 
        if (subjectEl && subjectEl.textContent.trim()) {
          subject = subjectEl.textContent.trim();
          break;
        }
      }
    } else if (this.platform === 'outlook') {
      const subjectEl = element.querySelector('[aria-label^="Subject"], [data-testid="subject-text"]');
      subject = subjectEl ? subjectEl.textContent.trim() : (element.getAttribute('title') || '');
    }
    return subject;
  }

  extractSender(element) {
    let sender = '';
    if (this.platform === 'gmail') {
      const senderSelectors = [
        'span[email].yP', 
        '.gD[email]', 
        '.go.D.E', 
        '.sender-info [email]' 
      ];
      for (const selector of senderSelectors) {
        const senderEl = element.querySelector(selector) || document.querySelector(selector);
        if (senderEl) {
          sender = senderEl.getAttribute('email') || senderEl.textContent.trim();
          if (sender && sender.includes('@')) break;
        }
      }
    } else if (this.platform === 'outlook') {
      const senderEl = element.querySelector('[aria-label*="From:"] span, [data-testid="persona"] span[title*="@"]');
      sender = senderEl ? (senderEl.getAttribute('title') || senderEl.textContent.trim()) : '';
    }
    return sender;
  }

extractContent(element) {
  let fullContent = '';
  if (this.platform === 'gmail') {
    const bodySelectors = [
        '.a3s.aiL', 
        '.ii.gt div[dir="ltr"]', 
        '.adn.ads [dir="ltr"]', 
        'div[data-message-id] > div > div:nth-child(2) > div:nth-child(3)', 
        '[role="listitem"] .zA', 
    ];
    for (const selector of bodySelectors) {
        const bodyElement = element.querySelector(selector);
        if (bodyElement) {
            fullContent = this.extractAllTextContent(bodyElement);
            if (fullContent.length > 50) break; 
        }
    }
     if (!fullContent) fullContent = this.extractAllTextContent(element); 
  } else if (this.platform === 'outlook') {
     const bodyElement = element.querySelector('[aria-label="Message body"], .rps_xxx, div[role="document"]');
     if (bodyElement) {
        fullContent = this.extractAllTextContent(bodyElement);
     } else {
        fullContent = this.extractAllTextContent(element); 
     }
  } else {
    fullContent = this.extractAllTextContent(element);
  }
  return fullContent.replace(/\s+/g, ' ').trim().substring(0, 5000); 
}

extractAllTextContent(element) {
  let text = '';
  if (!element) return text;

  for (let node of element.childNodes) {
    if (node.nodeType === Node.TEXT_NODE) {
      text += node.textContent + ' ';
    } else if (node.nodeType === Node.ELEMENT_NODE) {
      if (!['SCRIPT', 'STYLE', 'NOSCRIPT', 'BUTTON', 'INPUT', 'A'].includes(node.tagName.toUpperCase()) &&
          !node.closest('.gmail_signature')) { 
        text += this.extractAllTextContent(node) + ' ';
      }
    }
  }
  return text;
}

  extractUrls(element) {
    const urls = [];
    const links = element.querySelectorAll('a[href]');
    
    links.forEach(link => {
      let href = link.getAttribute('href');
      if (this.platform === 'gmail' && href && href.startsWith('/url?q=')) {
        const urlParams = new URLSearchParams(href.substring(href.indexOf('?') + 1));
        href = urlParams.get('q');
      }

      if (href && this.isValidUrl(href)) {
        urls.push({
          url: href,
          text: (link.textContent || link.innerText || '').trim(),
          title: link.getAttribute('title') || ''
        });
      }
    });
    return urls;
  }

  isValidUrl(string) {
    try {
      const url = new URL(string);
      return ['http:', 'https:'].includes(url.protocol);
    } catch (_) {
      return false;
    }
  }

 displayEmailAnalysisResult(result) {
  // console.log('Email Analysis Result:', result);
  
  if (result.risk_level === 'high' || result.risk_level === 'critical') {
    this.updateStats('threatsDetected', 1);
  }
  
  const message = `Email Scan: ${result.status} (Risk: ${result.risk_level})`;
  this.showEnhancedNotification(message, result.risk_level, result, 'email');
}

displayUrlAnalysisResult(url, result) {
  // console.log('URL Analysis Result:', { url, result });
  
  if (result.risk_level === 'high' || result.risk_level === 'critical') {
    this.updateStats('threatsDetected', 1);
  }
  
  const message = `URL Scan: ${result.status} - ${url.substring(0, 30)}...`;
  this.showEnhancedNotification(message, result.risk_level, result, 'url');
}

  showEnhancedNotification(message, riskLevel, analysisResult, type = 'general') {
    const notificationId = `phishing-detector-notif-${Date.now()}`;
    const notification = document.createElement('div');
    notification.id = notificationId;
    notification.className = `phishing-detector-notification phishing-detector-${riskLevel}`;
  
    const riskColor = this.getRiskColor(riskLevel);
    let detailsSummary = '';
    if (analysisResult.risk_factors && analysisResult.risk_factors.length > 0) {
        detailsSummary += `<div style="font-size: 12px; opacity: 0.9;">Risk Factors: ${analysisResult.risk_factors.length}</div>`;
    }
    if (analysisResult.trust_factors && analysisResult.trust_factors.length > 0) {
        detailsSummary += `<div style="font-size: 12px; opacity: 0.9;">Trust Factors: ${analysisResult.trust_factors.length}</div>`;
    }
    if (type === 'url' && analysisResult.playwright_scan_details && !analysisResult.playwright_scan_details.error) {
        detailsSummary += `<div style="font-size: 11px; opacity: 0.8; margin-top:3px;">(Deep scan performed)</div>`;
    }


    notification.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div style="font-weight: bold; margin-bottom: 5px; flex-grow: 1;">${message}</div>
        <button class="phishing-detector-close-btn" style="background:none; border:none; color:white; font-size:18px; cursor:pointer; margin-left:10px;">×</button>
      </div>
      ${detailsSummary}
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
      z-index: 200000 !important; 
      max-width: 350px;
      font-size: 14px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      cursor: pointer;
      opacity: 0;
      transform: translateX(100%);
      transition: opacity 0.5s ease, transform 0.5s ease;
    `;
  
    notification.addEventListener('click', (e) => {
        if (!e.target.classList.contains('phishing-detector-close-btn')) {
            this.showDetailedAnalysis(analysisResult, type);
        }
    });
    notification.querySelector('.phishing-detector-close-btn').addEventListener('click', (e) => {
        e.stopPropagation();
        notification.style.opacity = '0';
        notification.style.transform = 'translateX(100%)';
        setTimeout(() => {
          if (notification.parentNode) {
            notification.parentNode.removeChild(notification);
          }
        }, 500);
    });
  
    document.body.appendChild(notification);
    setTimeout(() => {
        notification.style.opacity = '1';
        notification.style.transform = 'translateX(0)';
    }, 50);
  
    const timeout = riskLevel === 'critical' ? 15000 : riskLevel === 'high' ? 10000 : 7000;
    setTimeout(() => {
      if (notification.parentNode && notification.style.opacity !== '0') { 
        notification.style.opacity = '0';
        notification.style.transform = 'translateX(100%)';
        setTimeout(() => {
          if (notification.parentNode) {
            notification.parentNode.removeChild(notification);
          }
        }, 500);
      }
    }, timeout);
  }

  getRiskColor(riskLevel) {
    const colors = {
      'safe': '#27ae60', 
      'low': '#f39c12',  
      'medium': '#e67e22', 
      'high': '#c0392b', 
      'critical': '#8e44ad', 
      'unknown': '#7f8c8d', 
      'error': '#d35400' 
    };
    return colors[riskLevel] || colors['unknown'];
  }

  showDetailedAnalysis(result, analysisType = 'general') {
    const existingOverlay = document.querySelector('.phishing-detector-overlay');
    if (existingOverlay) {
        existingOverlay.remove();
    }

    const overlay = document.createElement('div');
    overlay.className = 'phishing-detector-overlay';
    overlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0,0,0,0.7);
      z-index: 200001 !important;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      padding: 20px;
    `;
  
    const popup = document.createElement('div');
    popup.style.cssText = `
      background: white;
      padding: 25px;
      border-radius: 10px;
      width: 90%;
      max-width: 700px; /* Increased max-width for more content */
      max-height: 90vh;
      overflow-y: auto;
      box-shadow: 0 5px 15px rgba(0,0,0,0.3);
    `;

    let playwrightHtml = '';
    // --- Helper function to build list items ---
    const buildListItem = (label, value) => {
        if (value !== undefined && value !== null && value !== '') {
            return `<li><strong>${this.escapeHtml(label)}:</strong> ${this.escapeHtml(value)}</li>`;
        }
        return `<li><strong>${this.escapeHtml(label)}:</strong> N/A</li>`;
    };
     const buildBooleanListItem = (label, value) => {
        return `<li><strong>${this.escapeHtml(label)}:</strong> ${value ? 'Yes' : 'No'}</li>`;
    };


    // --- Playwright Section (URL or Email URL) ---
    const generatePlaywrightDetailsHtml = (ps, urlForScan) => {
        let html = '';
        if (urlForScan) { // For URLs within an email
             html += `<div style="margin-top:10px; padding:10px; border: 1px solid #eee; border-radius:5px;">
                        <h5>Deep Scan for URL: <small style="word-break:break-all;">${this.escapeHtml(urlForScan)}</small></h5>`;
        } else { // For direct URL scan
            html += `<h4>Deep Scan Details (Playwright):</h4>`;
        }

        if (ps.error) {
            html += `<p style="color:red;"><strong>Error:</strong> ${this.escapeHtml(ps.error)}</p>`;
            if(ps.details) html += `<p><small>Details: ${this.escapeHtml(ps.details)}</small></p>`;
        } else {
            html += `<div style="display: flex; flex-wrap: wrap; gap: 20px;">`; // Flex container for columns

            // Column 1: Basic Info & Screenshot
            html += `<div style="flex: 1; min-width: 280px;">`;
            html += `<h5>General:</h5><ul>`;
            html += buildListItem('Submitted URL', ps.original_url || ps.url_submitted_for_scan);
            html += buildListItem('Final URL', ps.final_url);
            html += buildListItem('Page Title', ps.page_title);
            html += buildListItem('Status Code', ps.status_code);
            html += `</ul>`;

            if (ps.screenshot_base64) {
                html += `<h5 style="margin-top:15px;">Screenshot:</h5>
                           <img src="data:image/png;base64,${ps.screenshot_base64}" alt="Page Screenshot" 
                                style="max-width: 100%; height: auto; border: 1px solid #ccc; margin-top: 5px; margin-bottom:10px; border-radius: 4px;">`;
            }
            html += `</div>`; // End Column 1

            // Column 2: Technical Details
            html += `<div style="flex: 1; min-width: 280px;">`;
            if (ps.domain_info) {
                html += `<h5>Domain & SSL:</h5><ul>`;
                html += buildListItem('Domain Age (Days)', ps.domain_info.domain_age_days);
                html += buildBooleanListItem('Hostname Matches SSL Cert', ps.domain_info.hostname_matches_ssl_cert);
                html += buildListItem('SSL Expiry (Days)', ps.domain_info.ssl_certificate_expiry_days);
                html += buildListItem('SSL Issuer', ps.domain_info.ssl_issuer);
                html += buildListItem('SSL Protocol', ps.domain_info.ssl_protocol);
                html += buildListItem('SSL Subject', ps.domain_info.ssl_subject_name);
                html += buildBooleanListItem('SSL Valid', ps.domain_info.ssl_valid);
                html += `</ul>`;
            }

            html += `<h5 style="margin-top:15px;">Page Structure & Content:</h5><ul>`;
            html += buildListItem('Number of Redirects', ps.number_of_redirects);
             if (ps.redirection_history && ps.redirection_history.length > 0) {
                html += `<li><strong>Redirect Path:</strong> <small>${ps.redirection_history.map(r => this.escapeHtml(r)).join(' → ')}</small></li>`;
            }
            html += buildBooleanListItem('Has Iframes', ps.has_iframes);
            html += buildBooleanListItem('Has Input Fields', ps.has_input_fields);
            html += buildBooleanListItem('Has Password Field', ps.has_password_field);
            html += buildListItem('Number of Forms', ps.number_of_forms);
            html += buildListItem('Number of Links', ps.number_of_links);
            html += buildListItem('Number of External Links', ps.number_of_external_links);
            html += buildListItem('Number of Script Tags', ps.number_of_script_tags);
            html += buildListItem('Page Content Length', ps.page_content_length);
            html += `</ul>`;
            
            html += `<h5 style="margin-top:15px;">URL Characteristics:</h5><ul>`;
            html += buildBooleanListItem('URL Contains IP', ps.url_contains_ip);
            html += buildListItem('URL Length', ps.url_length);
            html += buildListItem('URL Path Entropy', ps.url_path_entropy !== undefined ? ps.url_path_entropy.toFixed(3) : 'N/A');
            html += buildListItem('URL Query Entropy', ps.url_query_entropy !== undefined ? ps.url_query_entropy.toFixed(3) : 'N/A');
            html += `</ul>`;

            if (ps.alerts_found && ps.alerts_found.length > 0) {
                html += `<h5 style="margin-top:15px;">Alerts/Confirms Found:</h5><ul>${ps.alerts_found.map(a => `<li>Type: ${this.escapeHtml(a.type)}, Message: ${this.escapeHtml(a.message)}</li>`).join('')}</ul>`;
            }
            if (ps.form_targets && ps.form_targets.length > 0) {
                html += `<h5 style="margin-top:15px;">Form Submission Targets:</h5><p style="word-break:break-all;">${ps.form_targets.map(ft => this.escapeHtml(ft)).join(', ')}</p>`;
            }
             if (ps.suspicious_words_found && ps.suspicious_words_found.length > 0) {
                html += `<h5 style="margin-top:15px;">Suspicious Words Found:</h5><p>${ps.suspicious_words_found.map(w => this.escapeHtml(w)).join(', ')}</p>`;
            }
            html += `</div>`; // End Column 2
            html += `</div>`; // End Flex container
        }
        if (urlForScan) { // Closing div for email URL scan section
            html += `</div>`;
        }
        return html;
    };

    if (analysisType === 'url' && result.playwright_scan_details) {
        playwrightHtml = generatePlaywrightDetailsHtml(result.playwright_scan_details, null);
    }

    let emailUrlsPlaywrightHtml = '';
    if (analysisType === 'email' && result.url_analysis_summary && result.url_analysis_summary.analyzed_url_details) {
        const detailsArray = result.url_analysis_summary.analyzed_url_details
            .filter(urlDetail => urlDetail.playwright_scan) // Only process if playwright_scan exists
            .map(urlDetail => generatePlaywrightDetailsHtml(urlDetail.playwright_scan, urlDetail.url));
        
        if (detailsArray.length > 0) {
             emailUrlsPlaywrightHtml = `<h4>Deep Scan Details for URLs in Email:</h4>` + detailsArray.join('');
        }
    }
  
    popup.innerHTML = `
      <h3 style="margin-top:0; color: ${this.getRiskColor(result.risk_level || 'unknown')};">Analysis Details</h3>
      <p><strong>Overall Status:</strong> ${this.escapeHtml(result.status || 'N/A')}</p>
      <p><strong>Risk Level:</strong> <span style="font-weight:bold; color: ${this.getRiskColor(result.risk_level || 'unknown')}">${this.escapeHtml(result.risk_level || 'N/A')}</span></p>
      <p><strong>Risk Score:</strong> ${result.risk_score !== undefined ? result.risk_score : 'N/A'}</p>
      
      ${analysisType === 'email' && result.sender_analysis ? `
        <h4>Sender Analysis:</h4>
        <ul>
            <li><strong>Address:</strong> ${this.escapeHtml(result.sender_analysis.address || 'N/A')}</li>
            <li><strong>Trusted:</strong> ${result.sender_analysis.is_trusted ? 'Yes' : 'No'} ${result.sender_analysis.trusted_source ? `(Source: ${this.escapeHtml(result.sender_analysis.trusted_source)})` : ''}</li>
        </ul>` : ''}

      ${analysisType === 'email' && result.email_content_ml_analysis ? `
        <h4>Email Content ML:</h4>
        <ul>
            <li><strong>Prediction:</strong> ${this.escapeHtml(result.email_content_ml_analysis.model_prediction || 'Not run/Error')}</li>
            ${result.email_content_ml_analysis.confidence !== undefined ? `<li><strong>Confidence:</strong> ${(result.email_content_ml_analysis.confidence * 100).toFixed(2)}%</li>` : ''}
            ${result.email_content_ml_analysis.error ? `<li style="color:red;"><strong>Error:</strong> ${this.escapeHtml(result.email_content_ml_analysis.error)}</li>` : ''}
        </ul>` : ''}
      
      ${result.risk_factors && result.risk_factors.length > 0 ? 
        `<h4>Risk Factors:</h4><ul>${result.risk_factors.map(f => `<li>${this.escapeHtml(f)}</li>`).join('')}</ul>` : ''}
      ${result.trust_factors && result.trust_factors.length > 0 ? 
        `<h4>Trust Factors:</h4><ul>${result.trust_factors.map(f => `<li>${this.escapeHtml(f)}</li>`).join('')}</ul>` : ''}

      ${analysisType === 'email' && result.url_analysis_summary && result.url_analysis_summary.analyzed_url_details ? `
        <h4>ML Analysis for URLs in Email (${result.url_analysis_summary.total_urls || 0}):</h4>
        ${result.url_analysis_summary.analyzed_url_details.map(urlDet => `
            <div style="margin-bottom: 10px; padding: 8px; border: 1px solid #ddd; border-radius:4px;">
                <p style="word-break:break-all;"><strong>URL:</strong> ${this.escapeHtml(urlDet.url)}</p>
                <p><strong>Status:</strong> ${this.escapeHtml(urlDet.status)}
                   ${urlDet.trusted_domain ? ` (Domain: ${this.escapeHtml(urlDet.trusted_domain)})` : ''}
                   ${urlDet.pattern ? ` (Matched: ${this.escapeHtml(urlDet.pattern)})` : ''}
                </p>
                ${urlDet.ml_risk_level ? `<p><strong>ML Risk:</strong> ${this.escapeHtml(urlDet.ml_risk_level)} (Score: ${urlDet.ml_score !== undefined ? urlDet.ml_score : 'N/A'}, Label: ${this.escapeHtml(urlDet.ml_label || 'N/A')})</p>` : ''}
            </div>
        `).join('') || '<p>No URLs found or ML analyzed in detail.</p>'}
      ` : ''}
      
      ${playwrightHtml}
      ${emailUrlsPlaywrightHtml}

      <button class="phishing-detector-popup-close" style="margin-top: 20px; padding: 10px 18px; background: #3498db; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 15px;">
        Close
      </button>
    `;
  
    overlay.appendChild(popup);
    document.body.appendChild(overlay);
  
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay || e.target.classList.contains('phishing-detector-popup-close')) {
        overlay.remove();
      }
    });
  }

  escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') {
        if (unsafe === null || unsafe === undefined) return 'N/A';
        try {
            unsafe = String(unsafe);
        } catch (e) {
            console.error("Error during HTML escaping (non-string input):", e);
            return 'Error converting/escaping string';
        }
    }

    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}
}

// Initialize when page loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    window.phishingDetectorInstance = new PhishingDetector();
  });
} else {
  window.phishingDetectorInstance = new PhishingDetector();
}