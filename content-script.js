/**
 * jQuery XSS Vulnerability Scanner Pro - Content Script
 * Injects scanner icon into page footers and handles page interaction
 */

(function() {
    'use strict';
    
    // Prevent multiple injections
    if (window.jqueryXssScannerInjected) return;
    window.jqueryXssScannerInjected = true;
    
    let scannerIcon = null;
    let iconVisible = true;
    
    /**
     * Find the footer element on the page
     * Looks for common footer selectors
     */
    function findFooterElement() {
      // Try common footer selectors in order of specificity
      const footerSelectors = [
        'footer',
        '.footer',
        '#footer',
        '.site-footer',
        '.page-footer',
        'div[role="contentinfo"]',
        '.bottom',
        '.bottom-bar',
        // Add more common footer selectors as needed
      ];
      
      for (const selector of footerSelectors) {
        const element = document.querySelector(selector);
        if (element && isVisible(element)) {
          return element;
        }
      }
      
      // If we can't find a specific footer, try to find the last major section
      const mainContent = document.querySelector('main') || document.body;
      if (mainContent.children.length > 0) {
        // Get the last major child that's visible
        for (let i = mainContent.children.length - 1; i >= 0; i--) {
          const child = mainContent.children[i];
          if (isVisible(child) && child.offsetHeight > 50) {
            return child;
          }
        }
      }
      
      // Fall back to body if we couldn't find anything specific
      return document.body;
    }
    
    /**
     * Check if an element is visible
     */
    function isVisible(element) {
      const style = window.getComputedStyle(element);
      return style.display !== 'none' && 
             style.visibility !== 'hidden' && 
             element.offsetWidth > 0 && 
             element.offsetHeight > 0;
    }
    
    /**
     * Override alert function to prevent disruption during testing
     */
    function setupAlertHandling() {
      // Store the original alert function
      if (!window._originalAlert) {
        window._originalAlert = window.alert;
      
        // Create a counter for tracking alert frequency
        window._alertCounter = 0;
        
        // Override the alert function
        window.alert = function(message) {
          // If the message is from our scanner test (contains marker)
          if (typeof message === 'string' && message.includes('XSS-SCANNER-TEST:')) {
            // Log instead of showing alert unless SHOW-ALERT is included
            if (!message.includes('SHOW-ALERT')) {
              console.log("[jQuery XSS Scanner] Alert suppressed:", message);
              // Increment the counter but don't show the alert
              window._alertCounter++;
              return;
            }
            // For testing mode with visible alerts, limit the number to prevent spamming
            if (window._alertCounter > 10) {
              console.log("[jQuery XSS Scanner] Too many alerts, suppressing:", message);
              return;
            }
            window._alertCounter++;
          }
          
          // Call the original alert for normal cases
          window._originalAlert.call(window, message);
        };
      }
    }
    
    /**
     * Restore original alert function
     */
    function restoreAlertHandling() {
      if (window._originalAlert) {
        window.alert = window._originalAlert;
        delete window._originalAlert;
        delete window._alertCounter;
      }
    }
    
    /**
     * Creates and injects the scanner icon
     * Will attempt to insert in footer first, then fall back to fixed position
     */
    function createScannerIcon() {
      // Check storage for visibility preference
      chrome.storage.local.get('showPersistentIcon', (data) => {
        iconVisible = data.showPersistentIcon !== false; // Default to true
        
        if (!iconVisible) return;
        
        // Create the icon container
        scannerIcon = document.createElement('div');
        scannerIcon.className = 'jquery-xss-scanner-icon';
        
        // Apply base styles that won't be affected by page CSS
        const baseStyles = {
          width: '36px',
          height: '36px',
          borderRadius: '50%',
          backgroundColor: '#ffffff',
          boxShadow: '0 2px 6px rgba(0,0,0,0.2)',
          cursor: 'pointer',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          transition: 'all 0.3s ease',
          border: '2px solid #1976d2',
          margin: '10px',
          zIndex: '9999',
          position: 'relative' // Default to relative for footer insertion
        };
        
        // Apply all base styles
        Object.assign(scannerIcon.style, baseStyles);
        
        // Add icon content (shield with exclamation mark)
        scannerIcon.innerHTML = `
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#1976d2" stroke-width="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
            <line x1="12" y1="8" x2="12" y2="14"></line>
            <line x1="12" y1="16" x2="12" y2="16.01"></line>
          </svg>
        `;
        
        // Add hover effect
        scannerIcon.addEventListener('mouseenter', () => {
          scannerIcon.style.transform = 'scale(1.1)';
        });
        
        scannerIcon.addEventListener('mouseleave', () => {
          scannerIcon.style.transform = 'scale(1)';
        });
        
        // Add click handler
        scannerIcon.addEventListener('click', () => {
          // Check if scanner is already running
          if (document.getElementById('jquery-xss-scanner-panel')) {
            alert('Scanner is already running on this page.');
            return;
          }
          
          // Inject scanner
          injectScanner();
        });
        
        // Add tooltip using title attribute
        scannerIcon.title = 'jQuery XSS Scanner - Click to scan this page';
        
        // First, try to add the icon to the page footer
        injectIconIntoFooter();
        
        // Also listen for DOM changes to handle dynamically loaded footers
        observeDOMForFooter();
      });
    }
    
    /**
     * Try to inject the icon into the page footer
     * Falls back to fixed position if no suitable footer is found
     */
    function injectIconIntoFooter() {
      // If icon doesn't exist yet, don't proceed
      if (!scannerIcon) return;
      
      // If icon is already in the document, remove it first
      if (scannerIcon.parentNode) {
        scannerIcon.parentNode.removeChild(scannerIcon);
      }
      
      try {
        // Find footer element
        const footer = findFooterElement();
        
        if (footer) {
          // Prepare a wrapper for the icon to control position in the footer
          const iconWrapper = document.createElement('div');
          iconWrapper.className = 'jquery-xss-scanner-wrapper';
          iconWrapper.style.cssText = 'display: flex; justify-content: flex-end; align-items: center;';
          
          iconWrapper.appendChild(scannerIcon);
          
          // Append to the footer
          footer.appendChild(iconWrapper);
          console.log('jQuery XSS Scanner icon added to footer');
        } else {
          // Fall back to fixed position if no footer found
          useFixedPosition();
        }
      } catch (error) {
        console.error('Error injecting scanner icon into footer:', error);
        // Fall back to fixed position
        useFixedPosition();
      }
    }
    
    /**
     * Fall back to fixed position in bottom right corner
     */
    function useFixedPosition() {
      // Apply fixed position styles
      Object.assign(scannerIcon.style, {
        position: 'fixed',
        bottom: '20px',
        right: '20px',
        margin: '0',
        zIndex: '2147483647' // Max z-index
      });
      
      // Add to body
      document.body.appendChild(scannerIcon);
      console.log('jQuery XSS Scanner icon added to fixed position');
    }
    
    /**
     * Observe DOM changes to handle dynamically loaded footers
     */
    function observeDOMForFooter() {
      // Create a MutationObserver to watch for changes to the body
      const observer = new MutationObserver((mutations) => {
        for (const mutation of mutations) {
          if (mutation.type === 'childList' && mutation.addedNodes.length) {
            // Check if any of the added nodes might be a footer
            for (const node of mutation.addedNodes) {
              if (node.nodeType === Node.ELEMENT_NODE) {
                if (node.tagName === 'FOOTER' || 
                    node.classList.contains('footer') || 
                    node.id === 'footer') {
                  // Re-inject the icon as a footer may have been added
                  setTimeout(injectIconIntoFooter, 500);
                  return;
                }
              }
            }
          }
        }
      });
      
      // Start observing
      observer.observe(document.body, { 
        childList: true, 
        subtree: true 
      });
      
      // Stop observing after 30 seconds to prevent performance issues
      setTimeout(() => observer.disconnect(), 30000);
    }
    
    /**
     * Injects the scanner script
     */
    function injectScanner() {
      // Check if scanner is already running
      if (document.getElementById('jquery-xss-scanner-panel')) {
        console.log('jQuery XSS Scanner is already running on this page.');
        return;
      }
      
      try {
        // Set up alert handling before injecting the scanner
        setupAlertHandling();
        
        // Load the scanner script
        const script = document.createElement('script');
        script.src = chrome.runtime.getURL('scanner.js');
        script.onload = function() {
          this.remove(); // Remove the script element after loading
        };
        document.head.appendChild(script);
        
        // Notify background that scan was initiated
        chrome.runtime.sendMessage({
          action: 'scanInitiated',
          url: window.location.href
        });
      } catch (error) {
        console.error('Error injecting scanner:', error);
        alert('Failed to inject scanner: ' + error.message);
        restoreAlertHandling();
      }
    }
    
    /**
     * Updates icon visibility based on storage preferences
     */
    function updateIconVisibility(visible) {
      iconVisible = visible;
      
      if (scannerIcon) {
        if (visible) {
          scannerIcon.style.display = 'flex';
        } else {
          scannerIcon.style.display = 'none';
        }
      } else if (visible) {
        // Create the icon if it doesn't exist yet
        createScannerIcon();
      }
    }
    
    // Listen for messages from background script
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.action === 'updateIconVisibility') {
        updateIconVisibility(message.visible);
        sendResponse({ status: 'success' });
      }
      
      if (message.action === 'triggerScan') {
        injectScanner();
        sendResponse({ status: 'success' });
      }
      
      if (message.action === 'cleanupScanner') {
        restoreAlertHandling();
        sendResponse({ status: 'success' });
      }
    });
    
    // Initialize when DOM is fully loaded
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', createScannerIcon);
    } else {
      createScannerIcon();
    }
    
    // Re-check for footer after window load to handle slow-loading pages
    window.addEventListener('load', () => {
      setTimeout(() => {
        if (scannerIcon && document.body.contains(scannerIcon)) {
          // If we're already using fixed position, try to move to footer again
          if (scannerIcon.style.position === 'fixed') {
            injectIconIntoFooter();
          }
        }
      }, 1000);
    });
    
    // Handle page unload to restore alert function
    window.addEventListener('beforeunload', restoreAlertHandling);
  })();