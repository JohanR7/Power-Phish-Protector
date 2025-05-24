// Popup script for Chrome extension
// Handles UI interactions and displays statistics

class PopupController {
  constructor() {
    this.init();
  }

  async init() {
  console.log('Popup initialized');
  await this.loadStoredData();
  await this.loadBackendStats(); // Add this line
  this.setupEventListeners();
  this.checkConnectionStatus();
  this.setupAutoRefresh(); // Add this line
}
async loadBackendStats() {
  try {
    // First try to get fresh stats from backend
    const response = await fetch('http://localhost:5123/stats', {
      method: 'GET',
      timeout: 3000
    });
    
    if (response.ok) {
      const data = await response.json();
      this.updateStatsFromBackend(data.stats);
    }
  } catch (error) {
    // Fall back to stored backend stats
    const stored = await chrome.storage.local.get(['backendStats']);
    if (stored.backendStats) {
      this.updateStatsFromBackend(stored.backendStats);
    }
  }
}
updateStatsFromBackend(backendStats) {
  if (backendStats) {
    document.getElementById('emails-scanned').textContent = 
      backendStats.emails_analyzed || 0;
    document.getElementById('urls-analyzed').textContent = 
      backendStats.urls_analyzed || 0;
    document.getElementById('threats-detected').textContent = 
      backendStats.threats_detected || 0;
  }
}
  // Load stored statistics from Chrome storage
  async loadStoredData() {
    try {
      const data = await chrome.storage.local.get([
        'emailsScanned',
        'urlsAnalyzed', 
        'threatsDetected',
        'lastScan'
      ]);

      // Update UI with stored data
      document.getElementById('emails-scanned').textContent = data.emailsScanned || 0;
      document.getElementById('urls-analyzed').textContent = data.urlsAnalyzed || 0;
      document.getElementById('threats-detected').textContent = data.threatsDetected || 0;
      
      if (data.lastScan) {
        const lastScanDate = new Date(data.lastScan);
        document.getElementById('last-scan').textContent = 
          `Last scan: ${this.formatRelativeTime(lastScanDate)}`;
      }
    } catch (error) {
      console.error('Error loading stored data:', error);
    }
  }
async triggerManualScan() {
  const button = document.getElementById('scan-now');
  const originalText = button.textContent;
  
  try {
    // Update button state
    button.textContent = 'Scanning...';
    button.disabled = true;
    
    // Get current active tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab) {
      throw new Error('No active tab found');
    }
    
    // Check if we're on a supported email platform
    const isEmailSite = this.isEmailSite(tab.url);
    
    if (!isEmailSite) {
      throw new Error('Please navigate to Gmail or Outlook to scan emails');
    }
    
    // Send message to content script to trigger scan
    await chrome.tabs.sendMessage(tab.id, {
      type: 'TRIGGER_MANUAL_SCAN'
    });
    
    // Update last scan time
    const now = new Date().toISOString();
    await chrome.storage.local.set({ lastScan: now });
    
    // Refresh stats after scan
    setTimeout(async () => {
      await this.loadBackendStats();
    }, 2000);
    
    // Show success feedback
    button.textContent = 'Scan Complete!';
    setTimeout(() => {
      button.textContent = originalText;
      button.disabled = false;
    }, 2000);
    
  } catch (error) {
    console.error('Manual scan failed:', error);
    
    // Show error feedback
    button.textContent = 'Scan Failed';
    setTimeout(() => {
      button.textContent = originalText;
      button.disabled = false;
    }, 2000);
    
    this.showErrorMessage(error.message);
  }
}
  // Setup event listeners for UI interactions
  setupEventListeners() {
    // Scan now button
    document.getElementById('scan-now').addEventListener('click', () => {
      this.triggerManualScan();
    });

    // Settings button (placeholder for now)
    document.getElementById('view-settings').addEventListener('click', () => {
      this.openSettings();
    });

    // Listen for storage changes to update stats in real-time
    chrome.storage.onChanged.addListener((changes, namespace) => {
      if (namespace === 'local') {
        this.updateStatsFromChanges(changes);
      }
    });
  }
setupAutoRefresh() {
  // Refresh stats every 30 seconds
  setInterval(async () => {
    await this.loadBackendStats();
  }, 30000);
}
  // Update statistics display when storage changes
  updateStatsFromChanges(changes) {
    if (changes.emailsScanned) {
      document.getElementById('emails-scanned').textContent = 
        changes.emailsScanned.newValue || 0;
    }
    
    if (changes.urlsAnalyzed) {
      document.getElementById('urls-analyzed').textContent = 
        changes.urlsAnalyzed.newValue || 0;
    }
    
    if (changes.threatsDetected) {
      document.getElementById('threats-detected').textContent = 
        changes.threatsDetected.newValue || 0;
    }
    
    if (changes.lastScan) {
      const lastScanDate = new Date(changes.lastScan.newValue);
      document.getElementById('last-scan').textContent = 
        `Last scan: ${this.formatRelativeTime(lastScanDate)}`;
    }
  }

  // Trigger manual scan of current page
  async triggerManualScan() {
    const button = document.getElementById('scan-now');
    const originalText = button.textContent;
    
    try {
      // Update button state
      button.textContent = 'Scanning...';
      button.disabled = true;
      
      // Get current active tab
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      
      if (!tab) {
        throw new Error('No active tab found');
      }
      
      // Check if we're on a supported email platform
      const isEmailSite = this.isEmailSite(tab.url);
      
      if (!isEmailSite) {
        throw new Error('Please navigate to Gmail or Outlook to scan emails');
      }
      
      // Send message to content script to trigger scan
      await chrome.tabs.sendMessage(tab.id, {
        type: 'TRIGGER_MANUAL_SCAN'
      });
      
      // Update last scan time
      const now = new Date().toISOString();
      await chrome.storage.local.set({ lastScan: now });
      
      // Show success feedback
      button.textContent = 'Scan Complete!';
      setTimeout(() => {
        button.textContent = originalText;
        button.disabled = false;
      }, 2000);
      
    } catch (error) {
      console.error('Manual scan failed:', error);
      
      // Show error feedback
      button.textContent = 'Scan Failed';
      setTimeout(() => {
        button.textContent = originalText;
        button.disabled = false;
      }, 2000);
      
      // You could show a more detailed error message here
      this.showErrorMessage(error.message);
    }
  }

  // Check if URL is a supported email site
  isEmailSite(url) {
    return url.includes('mail.google.com') || 
           url.includes('outlook.live.com') || 
           url.includes('outlook.office.com');
  }

  // Open settings (placeholder for future implementation)
  openSettings() {
    console.log('Settings clicked - placeholder for future implementation');
    
    // For now, just show an alert
    // In the future, this could open a dedicated settings page
    alert('Settings panel will be implemented in a future version');
  }

  // Check connection status to backend
  async checkConnectionStatus() {
  try {
    const response = await fetch('http://localhost:5123/health', {
      method: 'GET',
      timeout: 5000
    });
    
    if (response.ok) {
      const data = await response.json();
      this.updateConnectionStatus(true, data);
    } else {
      this.updateConnectionStatus(false);
    }
  } catch (error) {
    console.error('Backend connection failed:', error);
    this.updateConnectionStatus(false);
  }
}

  // Update connection status indicator
  uupdateConnectionStatus(isConnected, healthData = null) {
  const statusDot = document.getElementById('status-dot');
  const statusText = document.getElementById('status-text');
  
  if (isConnected) {
    statusDot.className = 'status-dot status-active';
    statusText.textContent = 'Protection Active';
    
    // Show model status if available
    if (healthData) {
      const emailModelStatus = healthData.email_model_loaded ? '✓' : '✗';
      const urlModelStatus = healthData.url_model_loaded ? '✓' : '✗';
      statusText.title = `Email Model: ${emailModelStatus} | URL Model: ${urlModelStatus}`;
    }
  } else {
    statusDot.className = 'status-dot status-inactive';
    statusText.textContent = 'Backend Disconnected';
    statusText.title = 'Unable to connect to analysis backend';
  }
}

  // Show error message to user
  showErrorMessage(message) {
    // Create a simple error display (could be enhanced with better styling)
    const errorDiv = document.createElement('div');
    errorDiv.style.cssText = `
      position: fixed;
      top: 10px;
      left: 10px;
      right: 10px;
      background: #e74c3c;
      color: white;
      padding: 8px;
      border-radius: 4px;
      font-size: 12px;
      z-index: 1000;
    `;
    errorDiv.textContent = message;
    
    document.body.appendChild(errorDiv);
    
    // Remove after 3 seconds
    setTimeout(() => {
      if (errorDiv.parentNode) {
        errorDiv.parentNode.removeChild(errorDiv);
      }
    }, 3000);
  }

  // Format relative time for last scan display
  formatRelativeTime(date) {
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);
    
    if (diffMins < 1) {
      return 'Just now';
    } else if (diffMins < 60) {
      return `${diffMins} min ago`;
    } else if (diffHours < 24) {
      return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
    } else {
      return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
    }
  }
}

// Initialize popup when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new PopupController();
});