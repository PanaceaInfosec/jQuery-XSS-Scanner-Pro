/**
 * jQuery XSS Vulnerability Scanner Pro - Background Service Worker
 * Handles extension installation and communication between components
 */

// Extension installation event
chrome.runtime.onInstalled.addListener((details) => {
    if (details.reason === 'install') {
      console.log('jQuery XSS Vulnerability Scanner Pro installed');
      // Initialize storage with default settings
      chrome.storage.local.set({
        scanHistory: [],
        showPersistentIcon: true,
        detailedReports: true,
        autoScanEnabled: false
      });
      
      // Open onboarding page
      chrome.tabs.create({
        url: 'onboarding.html'
      });
    } else if (details.reason === 'update') {
      console.log(`Extension updated from ${details.previousVersion} to ${chrome.runtime.getManifest().version}`);
    }
  });
  
  // Handle messages from popup and content scripts
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'scanPage') {
      // Inject scanner into active tab
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs && tabs[0] && tabs[0].id) {
          chrome.scripting.executeScript({
            target: { tabId: tabs[0].id },
            files: ['scanner.js']
          }).then(() => {
            sendResponse({ status: 'success', message: 'Scanner initiated' });
          }).catch(error => {
            console.error('Error injecting scanner:', error);
            sendResponse({ status: 'error', message: `Injection failed: ${error.message}` });
          });
        } else {
          sendResponse({ status: 'error', message: 'No active tab found' });
        }
      });
      
      // Keep the message channel open for async response
      return true;
    }
    
    if (message.action === 'togglePersistentIcon') {
      chrome.storage.local.set({ showPersistentIcon: message.value }, () => {
        // Notify all tabs to update icon visibility
        chrome.tabs.query({}, (tabs) => {
          tabs.forEach(tab => {
            chrome.tabs.sendMessage(tab.id, { 
              action: 'updateIconVisibility',
              visible: message.value
            }).catch(() => {
              // Ignore errors for tabs where content script isn't loaded
            });
          });
        });
        sendResponse({ status: 'success' });
      });
      return true;
    }
    
    if (message.action === 'saveScanResult') {
      // Save scan result to history
      chrome.storage.local.get('scanHistory', (data) => {
        const history = data.scanHistory || [];
        history.unshift({
          url: message.data.url,
          timestamp: Date.now(),
          result: message.data
        });
        
        // Limit history to last 50 scans
        if (history.length > 50) {
          history.pop();
        }
        
        chrome.storage.local.set({ scanHistory: history }, () => {
          sendResponse({ status: 'success' });
        });
      });
      return true;
    }
  });