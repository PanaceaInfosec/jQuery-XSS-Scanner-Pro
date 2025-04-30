/**
 * jQuery XSS Vulnerability Scanner Pro - Popup Interface
 * Handles user interaction with the extension popup
 */

document.addEventListener('DOMContentLoaded', function() {
    'use strict';
    
    // Define DOM elements
    const scanButton = document.getElementById('scanButton');
    const statusDiv = document.getElementById('status');
    const persistentIconToggle = document.getElementById('persistentIconToggle');
    const detailedReportsToggle = document.getElementById('detailedReportsToggle');
    const historyContainer = document.getElementById('historyContainer');
    
    // Add popup demonstration toggle
    let popupDemoToggle = document.getElementById('popupDemoToggle');
    if (!popupDemoToggle) {
      // Create the toggle if it doesn't exist
      const popupDemoRow = document.createElement('div');
      popupDemoRow.className = 'toggle-row';
      popupDemoRow.innerHTML = `
        <span class="toggle-label">Show popup alerts during testing</span>
        <label class="toggle-switch">
          <input type="checkbox" id="popupDemoToggle">
          <span class="slider"></span>
        </label>
      `;
      
      // Insert after detailed reports toggle
      if (detailedReportsToggle) {
        detailedReportsToggle.parentNode.parentNode.insertAdjacentElement('afterend', popupDemoRow);
        popupDemoToggle = document.getElementById('popupDemoToggle');
      }
    }
    
    // Initialize UI based on stored settings
    chrome.storage.local.get(['showPersistentIcon', 'detailedReports', 'showPopupAlerts'], function(data) {
      persistentIconToggle.checked = data.showPersistentIcon !== false; // Default to true
      detailedReportsToggle.checked = data.detailedReports !== false; // Default to true
      if (popupDemoToggle) {
        popupDemoToggle.checked = data.showPopupAlerts === true; // Default to false
      }
    });
    
    // Load scan history
    loadScanHistory();
    
    /**
     * Load and display scan history
     */
    function loadScanHistory() {
      chrome.storage.local.get('scanHistory', function(data) {
        const history = data.scanHistory || [];
        
        if (history.length === 0) {
          historyContainer.innerHTML = '<p style="font-size: 13px; color: #757575;">No scan history yet.</p>';
          return;
        }
        
        // Display last 5 scans
        historyContainer.innerHTML = '';
        const recentScans = history.slice(0, 5);
        
        recentScans.forEach(scan => {
          // Determine if the scan found vulnerabilities
          const isVulnerable = scan.result.vulnerableVersions && scan.result.vulnerableVersions.length > 0;
          
          // Format the timestamp
          const scanDate = new Date(scan.timestamp);
          const timeString = scanDate.toLocaleDateString() + ' ' + scanDate.toLocaleTimeString();
          
          // Create history item
          const historyItem = document.createElement('div');
          historyItem.className = `history-item ${isVulnerable ? 'vulnerable' : 'secure'}`;
          
          historyItem.innerHTML = `
            <div class="history-url">${formatUrl(scan.url)}</div>
            <div class="history-time">
              ${timeString} - 
              ${isVulnerable ? 
                `<span style="color: #d32f2f;">Vulnerable jQuery ${scan.result.vulnerableVersions.join(', ')}</span>` : 
                '<span style="color: #2e7d32;">No vulnerabilities found</span>'}
            </div>
          `;
          
          // Add click event to re-scan this URL
          historyItem.addEventListener('click', function() {
            chrome.tabs.create({ url: scan.url });
          });
          
          historyContainer.appendChild(historyItem);
        });
      });
    }
    
    /**
     * Format URL for display (limit length)
     */
    function formatUrl(url) {
      try {
        const urlObj = new URL(url);
        let displayUrl = urlObj.hostname + urlObj.pathname;
        
        // Limit the URL length
        if (displayUrl.length > 40) {
          displayUrl = displayUrl.substring(0, 37) + '...';
        }
        
        return displayUrl;
      } catch (e) {
        return url;
      }
    }
    
    /**
     * Update status message
     */
    function updateStatus(message, type = 'info') {
      statusDiv.className = `status ${type}`;
      statusDiv.textContent = message;
    }
    
    /**
     * Handle scan button click
     */
    scanButton.addEventListener('click', async function() {
      // Update the UI to show scanning state
      scanButton.disabled = true;
      scanButton.textContent = 'Scanning...';
      updateStatus('Initiating scan, please wait...', 'info');
      
      try {
        // Get popup alerts preference
        const showPopupAlerts = popupDemoToggle && popupDemoToggle.checked;
        
        // Set the preference in storage for the scanner to use
        await chrome.storage.local.set({ showPopupAlerts: showPopupAlerts });
        
        // Get the current active tab
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        
        if (!tab || !tab.id) {
          throw new Error('No active tab found');
        }
        
        // Inject the scanner script
        chrome.runtime.sendMessage(
          { action: 'scanPage' },
          function(response) {
            if (response && response.status === 'success') {
              updateStatus('Scanner launched on page. Check the results panel on the website.', 'success');
            } else {
              updateStatus('Error: ' + (response ? response.message : 'Unknown error'), 'error');
            }
            
            // Reset button state
            scanButton.disabled = false;
            scanButton.innerHTML = `
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                <line x1="12" y1="8" x2="12" y2="14"></line>
                <line x1="12" y1="16" x2="12" y2="16.01"></line>
              </svg>
              Scan This Page
            `;
          }
        );
      } catch (error) {
        updateStatus('Error: ' + error.message, 'error');
        
        // Reset button state
        scanButton.disabled = false;
        scanButton.innerHTML = `
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
            <line x1="12" y1="8" x2="12" y2="14"></line>
            <line x1="12" y1="16" x2="12" y2="16.01"></line>
          </svg>
          Scan This Page
        `;
      }
    });
    
    /**
     * Handle persistent icon toggle
     */
    persistentIconToggle.addEventListener('change', function() {
      const showIcon = this.checked;
      
      // Save the setting
      chrome.storage.local.set({ showPersistentIcon: showIcon });
      
      // Notify background script
      chrome.runtime.sendMessage(
        { action: 'togglePersistentIcon', value: showIcon },
        function(response) {
          if (response && response.status === 'success') {
            updateStatus(
              showIcon ? 'Persistent icon enabled.' : 'Persistent icon disabled.',
              'info'
            );
          }
        }
      );
    });
    
    /**
     * Handle detailed reports toggle
     */
    detailedReportsToggle.addEventListener('change', function() {
      const detailedReports = this.checked;
      
      // Save the setting
      chrome.storage.local.set({ detailedReports: detailedReports });
      
      updateStatus(
        detailedReports ? 'Detailed reports enabled.' : 'Detailed reports disabled.',
        'info'
      );
    });
    
    /**
     * Handle popup alerts toggle
     */
    if (popupDemoToggle) {
      popupDemoToggle.addEventListener('change', function() {
        const showPopupAlerts = this.checked;
        
        // Save the setting
        chrome.storage.local.set({ showPopupAlerts: showPopupAlerts });
        
        updateStatus(
          showPopupAlerts ? 'Popup demonstration mode enabled.' : 'Popup demonstration mode disabled.',
          'info'
        );
      });
    }
    
    // Listen for messages about scan completion
    chrome.runtime.onMessage.addListener(function(message) {
      if (message.action === 'scanComplete') {
        loadScanHistory(); // Refresh history
        updateStatus('Scan completed. ' + message.result, 'success');
      }
    });
  });