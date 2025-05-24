// Background service worker for Chrome extension
// Handles context menus and communication between components
// 1. Add navigation listener to detect page changes
chrome.webNavigation.onCompleted.addListener((details) => {
  // Only trigger for main frame (not iframes)
  if (details.frameId === 0) {
    const url = details.url;
    
    // Check if it's an email platform
    if (url.includes('mail.google.com') || 
        url.includes('outlook.live.com') || 
        url.includes('outlook.office.com')) {
      
      // Wait a bit for page to load, then trigger scan
      setTimeout(() => {
        chrome.tabs.sendMessage(details.tabId, {
          type: 'PAGE_NAVIGATION_DETECTED'
        }).catch(err => console.log('Content script not ready yet'));
      }, 2000);
    }
  }
});
chrome.runtime.onInstalled.addListener(() => {
  console.log('Phishing Detection Extension installed');
  
  // Create context menu for link analysis
  chrome.contextMenus.create({
    id: "analyzeLink",
    title: "Analyze Link for Phishing",
    contexts: ["link"]
  });
});

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "analyzeLink" && info.linkUrl) {
    // Send URL to backend for analysis
    analyzeUrl(info.linkUrl, tab.id);
  }
});

// Function to analyze URL with backend
async function analyzeUrl(url, tabId) {
  try {
    console.log('Analyzing URL:', url);
    
    const response = await fetch('http://localhost:5123/analyze-url', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    url: url,
    timestamp: new Date().toISOString()
  })
}).catch(error => {
  throw new Error(`Network error: ${error.message}`);
});

if (!response.ok) {
  throw new Error(`HTTP error! status: ${response.status}`);
}
    
    const result = await response.json();
    console.log('Backend response:', result);
    
    // Send result to content script for display
    chrome.tabs.sendMessage(tabId, {
      type: 'URL_ANALYSIS_RESULT',
      url: url,
      result: result
    });
    
  } catch (error) {
    console.error('Error analyzing URL:', error);
    
    // Send error to content script
    chrome.tabs.sendMessage(tabId, {
      type: 'URL_ANALYSIS_ERROR',
      url: url,
      error: error.message
    });
  }
}

// Handle messages from content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'ANALYZE_EMAIL_CONTENT') {
    analyzeEmailContent(request.data, sender.tab.id);
    sendResponse({success: true});
  }
  
  if (request.type === 'ANALYZE_HOVERED_URL') {
    analyzeUrl(request.url, sender.tab.id);
    sendResponse({success: true});
  }
  
  if (request.type === 'GET_BACKEND_STATS') {
    getBackendStats(sender.tab.id);
    sendResponse({success: true});
  }
  
  return true; // Keep message channel open for async response
});

// Function to analyze email content with backend
async function analyzeEmailContent(emailData, tabId) {
  try {
    console.log('Analyzing email content:', emailData);
    
    const response = await fetch('http://localhost:5123/analyze-email', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        ...emailData,
        timestamp: new Date().toISOString()
      })
    }).catch(error => {
      throw new Error(`Network error: ${error.message}`);
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const result = await response.json();
    console.log('Email analysis result:', result);
    
    // Send result to content script
    chrome.tabs.sendMessage(tabId, {
      type: 'EMAIL_ANALYSIS_RESULT',
      result: result
    });
    
    // Update backend stats
    getBackendStats();
    
  } catch (error) {
    console.error('Error analyzing email:', error);
    
    chrome.tabs.sendMessage(tabId, {
      type: 'EMAIL_ANALYSIS_ERROR',
      error: error.message
    });
  }
}
async function getBackendStats() {
  try {
    const response = await fetch('http://localhost:5123/stats', {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      }
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const result = await response.json();
    console.log('Backend stats:', result);
    
    // Update local storage with backend stats
    chrome.storage.local.set({
      backendStats: result.stats,
      lastStatsUpdate: new Date().toISOString()
    });
    
    return result;
  } catch (error) {
    console.error('Error fetching backend stats:', error);
    return null;
  }
}