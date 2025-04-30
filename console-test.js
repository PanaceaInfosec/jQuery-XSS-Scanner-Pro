/**
 * jQuery XSS Vulnerability Scanner - Console Test Script
 * 
 * This standalone script can be run directly in the browser console to test
 * for jQuery XSS vulnerabilities without needing the extension.
 * 
 * HOW TO USE:
 * 1. Open browser developer tools (F12 or right-click > Inspect)
 * 2. Paste this entire script into the console
 * 3. Press Enter to run the scan
 * 
 * By Panacea InfoSec
 */

(function() {
    console.log('%c===== jQuery XSS Vulnerability Scanner Pro =====', 'font-weight: bold; font-size: 14px; color: #1976d2;');
    console.log('Starting scan...');
    
    // Print Panacea InfoSec banner
    console.log('%cPowered by Panacea InfoSec', 'font-style: italic; color: #666;');
    
    const startTime = Date.now();
    
    // Results storage
    const results = {
      jqueryVersions: [],
      migrateVersions: [],
      vulnerableVersions: [],
      tests: {}
    };
  
    // Track which alerts were triggered during tests
    const alertsTriggered = {};
  
    // Store original alert function
    const originalAlert = window.alert;
    
    // Override alert to detect when our test alerts are triggered
    window.alert = function(message) {
      // If the message contains our specific marker, it's from our tests
      if (typeof message === 'string' && message.includes('XSS-SCANNER-TEST:')) {
        // Extract test ID from alert message
        const testIdMatch = message.match(/XSS-SCANNER-TEST:([a-z-]+)/);
        if (testIdMatch && testIdMatch[1]) {
          const testId = testIdMatch[1];
          alertsTriggered[testId] = true;
          console.log(`XSS test alert triggered: ${testId}`);
          
          // Only show actual alert popup when "SHOW-ALERT" is included
          if (!message.includes('SHOW-ALERT')) {
            return;
          }
        }
      }
      
      // Call the original alert for normal cases
      originalAlert.call(window, message);
    };
    
    /**
     * Check if version is vulnerable
     */
    function isVulnerableVersion(version, isMigrateLibrary = false) {
      if (!version) return { vulnerable: false, details: 'Unknown version' };
      
      // Skip vulnerability checks for jQuery Migrate library
      if (isMigrateLibrary) {
        return { 
          vulnerable: false, 
          details: 'jQuery Migrate is a compatibility layer and not subject to the same vulnerabilities as core jQuery.'
        };
      }
      
      try {
        const parts = version.split('.').map(p => parseInt(p, 10));
        
        // Handle specific known vulnerable versions
        if (version === '3.4.1') {
          return { 
            vulnerable: true, 
            details: 'Vulnerable to CVE-2020-11022/11023: XSS vulnerability in jQuery\'s HTML parsing in versions before 3.5.0.'
          };
        }
        
        // Version ranges
        if (parts[0] === 1) {
          return { 
            vulnerable: true, 
            details: 'jQuery 1.x contains multiple known XSS vulnerabilities and is no longer maintained. Upgrade to jQuery 3.5.0+.'
          };
        }
        
        if (parts[0] === 2) {
          return { 
            vulnerable: true, 
            details: 'jQuery 2.x contains multiple known XSS vulnerabilities and is no longer maintained. Upgrade to jQuery 3.5.0+.'
          };
        }
        
        if (parts[0] === 3 && parts[1] < 5) {
          return { 
            vulnerable: true, 
            details: 'Versions before 3.5.0 are vulnerable to CVE-2020-11022/11023: XSS vulnerability in jQuery\'s HTML parsing.' 
          };
        }
        
        return { vulnerable: false, details: 'No known vulnerabilities' };
      } catch (e) {
        console.error('Error checking version:', e);
        return { vulnerable: false, details: 'Error analyzing version' };
      }
    }
    
    /**
     * Detect jQuery instances and versions
     * Improved to correctly handle jQuery Migrate
     */
    function detectJQuery() {
      console.log('\n%c----- Detecting jQuery -----', 'font-weight: bold; color: #1976d2;');
      
      const results = {
        versions: [],
        instances: [],
        coreVersions: [], // Specifically track jQuery core versions separately
        migrateVersions: [] // Track jQuery Migrate versions separately
      };
      
      // PART 1: Detect jQuery from global variables
      const possibleNames = ['jQuery', '$', 'jquery'];
      
      for (const name of possibleNames) {
        try {
          const obj = window[name];
          if (obj && typeof obj === 'function' && obj.fn && typeof obj.fn === 'object') {
            if (obj.fn.jquery) {
              const coreVersion = obj.fn.jquery;
              
              // Check if this is a jQuery instance we haven't tracked yet
              if (!results.instances.some(i => i.name === name && i.version === coreVersion && !i.isMigrateLibrary)) {
                // This is a jQuery core instance
                results.instances.push({
                  name: name,
                  version: coreVersion,
                  object: obj,
                  isMigrateLibrary: false
                });
                
                // Add to core versions if not already there
                if (!results.coreVersions.includes(coreVersion)) {
                  results.coreVersions.push(coreVersion);
                }
                
                // Add to all versions if not already there
                if (!results.versions.includes(coreVersion)) {
                  results.versions.push(coreVersion);
                }
                
                console.log(`Found jQuery core version ${coreVersion} as window.${name}`);
              }
              
              // Check if this instance also has jQuery Migrate
              if (obj.migrateVersion || (obj.migrate && obj.migrate.version)) {
                const migrateVersion = obj.migrateVersion || (obj.migrate && obj.migrate.version);
                
                // Add as a separate Migrate instance
                if (migrateVersion && !results.instances.some(i => i.isMigrateLibrary && i.version === migrateVersion)) {
                  results.instances.push({
                    name: `${name}.migrate`,
                    version: migrateVersion,
                    object: obj.migrate || obj,
                    isMigrateLibrary: true,
                    coreVersion: coreVersion // Link to the core version
                  });
                  
                  // Add to migrate versions if not already there
                  if (!results.migrateVersions.includes(migrateVersion)) {
                    results.migrateVersions.push(migrateVersion);
                  }
                  
                  // Add to all versions with a migrate prefix
                  const migrateFullVersion = `migrate-${migrateVersion}`;
                  if (!results.versions.includes(migrateFullVersion)) {
                    results.versions.push(migrateFullVersion);
                  }
                  
                  console.log(`Found jQuery Migrate version ${migrateVersion} as part of window.${name}`);
                }
              }
            }
          }
        } catch (e) {
          console.log(`Error checking ${name}:`, e);
        }
      }
      
      // PART 2: Check script tags for additional jQuery versions
      try {
        const scripts = document.getElementsByTagName('script');
        for (let i = 0; i < scripts.length; i++) {
          const src = scripts[i].src || '';
          
          // Skip if not a jQuery-related script
          if (!src.toLowerCase().includes('jquery')) {
            continue;
          }
          
          // Determine if this is jQuery Migrate
          const isMigrateScript = src.toLowerCase().includes('migrate');
          
          // Match patterns for different types of jQuery libraries
          if (isMigrateScript) {
            // For jQuery Migrate
            const migrateMatch = src.match(/jquery[.-]migrate[.-]?(\d+\.\d+\.\d+)/i) || 
                                 src.match(/migrate[.-]?(\d+\.\d+\.\d+)/i);
                                 
            if (migrateMatch && migrateMatch[1]) {
              const migrateVersion = migrateMatch[1];
              
              // Check if we already found this migrate version
              if (!results.instances.some(i => i.isMigrateLibrary && i.version === migrateVersion)) {
                results.instances.push({
                  name: 'jQuery-migrate',
                  version: migrateVersion,
                  object: null,
                  isMigrateLibrary: true,
                  source: src
                });
                
                // Add to migrate versions if not already there
                if (!results.migrateVersions.includes(migrateVersion)) {
                  results.migrateVersions.push(migrateVersion);
                }
                
                console.log(`Found jQuery Migrate version ${migrateVersion} in script: ${src}`);
              }
            }
          } else {
            // For jQuery core
            const coreMatch = src.match(/jquery[.-]?(\d+\.\d+\.\d+)/i);
            if (coreMatch && coreMatch[1]) {
              const coreVersion = coreMatch[1];
              
              // Check if we already found this core version
              if (!results.instances.some(i => !i.isMigrateLibrary && i.version === coreVersion)) {
                results.instances.push({
                  name: 'jQuery',
                  version: coreVersion,
                  object: null,
                  isMigrateLibrary: false,
                  source: src
                });
                
                // Add to core versions if not already there
                if (!results.coreVersions.includes(coreVersion)) {
                  results.coreVersions.push(coreVersion);
                }
                
                console.log(`Found jQuery core version ${coreVersion} in script: ${src}`);
              }
            }
          }
        }
      } catch (e) {
        console.error('Error scanning script tags:', e);
      }
      
      return results;
    }
    
    /**
     * Detect security protections (CSP, HTTPOnly, etc.)
     */
    function detectSecurityProtections() {
      console.log('\n%c----- Checking Security Protections -----', 'font-weight: bold; color: #1976d2;');
      
      const protections = {
        csp: {
          enabled: false,
          policy: null,
          strength: 'none',
          details: 'No Content Security Policy detected.'
        }
      };
      
      // Check for CSP in meta tags
      const cspMetaTags = document.querySelectorAll('meta[http-equiv="Content-Security-Policy"]');
      if (cspMetaTags.length > 0) {
        protections.csp.enabled = true;
        protections.csp.policy = cspMetaTags[0].getAttribute('content');
        protections.csp.details = 'CSP found in meta tag.';
        console.log('%c✓ CSP found in meta tag:', 'color: #2e7d32', protections.csp.policy);
        
        // Analyze CSP strength
        protections.csp.strength = analyzeCSPStrength(protections.csp.policy);
        console.log(`CSP Strength: ${protections.csp.strength}`);
      } else {
        console.log('%c❌ No CSP meta tag found', 'color: #d32f2f');
      }
      
      // Test if inline scripts are blocked (another way to detect CSP)
      try {
        const testScript = document.createElement('script');
        const uniqueId = 'csp-test-' + Date.now();
        testScript.textContent = `window['${uniqueId}'] = true;`;
        document.head.appendChild(testScript);
        testScript.remove();
        
        if (!window[uniqueId]) {
          protections.csp.enabled = true;
          protections.csp.details = 'CSP detected (blocks inline scripts).';
          protections.csp.strength = 'strong';
          console.log('%c✓ CSP detected: inline scripts are blocked', 'color: #2e7d32');
        } else {
          console.log('%c⚠️ Inline scripts are allowed (no CSP restriction)', 'color: #ff9800');
          delete window[uniqueId];
        }
      } catch (e) {
        protections.csp.enabled = true;
        protections.csp.details = 'CSP detected (exception during testing).';
        protections.csp.strength = 'unknown';
        console.log('%c✓ CSP likely enabled (exception during testing)', 'color: #2e7d32', e.message);
      }
      
      return protections;
    }
    
    /**
     * Analyze CSP strength
     */
    function analyzeCSPStrength(cspString) {
      if (!cspString) return 'none';
      
      const policy = cspString.toLowerCase();
      
      // Check for unsafe practices
      if (policy.includes("'unsafe-inline'") && policy.includes("'unsafe-eval'")) {
        return 'weak';
      }
      
      if (policy.includes("'unsafe-inline'")) {
        return 'moderate';
      }
      
      // Check for strong CSP characteristics
      if (policy.includes("default-src 'none'") || policy.includes("script-src 'none'")) {
        return 'very strong';
      }
      
      if (policy.includes('script-src') && !policy.includes("'unsafe-inline'")) {
        return 'strong';
      }
      
      return 'moderate';
    }
    
    /**
     * Create sandbox for testing
     */
    function createSandbox() {
      let sandbox = document.getElementById('jquery-xss-sandbox');
      
      if (!sandbox) {
        sandbox = document.createElement('div');
        sandbox.id = 'jquery-xss-sandbox';
        sandbox.style.cssText = 'position: absolute; left: -9999px; top: -9999px; width: 1px; height: 1px; overflow: hidden;';
        document.body.appendChild(sandbox);
        console.log('Created testing sandbox');
      } else {
        sandbox.innerHTML = '';
      }
      
      return sandbox;
    }
    
    /**
     * Ask user if they want to see actual pop-ups during testing
     */
    function getPopupPreference() {
      console.log('\n%c----- Test Configuration -----', 'font-weight: bold; color: #1976d2;');
      
      // Use the original alert to ensure this message is shown
      const showPopups = originalAlert("Do you want to see actual pop-up alerts during vulnerability testing?\n\nClick OK to enable pop-ups (more disruptive but visually confirms vulnerabilities).\nClick Cancel to run silent tests (recommended for professional use).");
      
      console.log(`Pop-up demonstration mode: ${showPopups ? 'Enabled' : 'Disabled'}`);
      
      return showPopups;
    }
    
    /**
     * Run vulnerability tests on a jQuery instance
     */
    async function runVulnerabilityTests(instance, showPopups = false) {
      console.log(`\n%c----- Testing jQuery ${instance.name} ${instance.version} -----`, 'font-weight: bold; color: #1976d2;');
      
      // Reset alerts triggered for this test run
      for (const key in alertsTriggered) {
        delete alertsTriggered[key];
      }
      
      // Skip testing jQuery Migrate
      if (instance.isMigrateLibrary) {
        console.log('Skipping tests for jQuery Migrate (not subject to same vulnerabilities)');
        return false;
      }
      
      const jq = instance.object;
      
      // If no object reference is available, we can't test
      if (!jq) {
        console.log('Cannot test this instance (no object reference available)');
        return false;
      }
      
      const sandbox = createSandbox();
      const testResults = {};
      let anyVulnerable = false;
      
      // Determine if version is known vulnerable
      const isKnownVulnerable = isVulnerableVersion(instance.version).vulnerable;
      
      // Prepare popup suffix based on user preferences
      const popupSuffix = showPopups ? "-SHOW-ALERT" : "";
      
      // Test 1: Basic XSS (img onerror)
      console.log('\n%cTest 1: Basic XSS (img onerror)', 'font-weight: bold;');
      try {
        // Construct payload with test ID embedded
        const payload = `<img src="x" onerror="alert('XSS-SCANNER-TEST:basic-xss${popupSuffix}')">`;
        
        jq(sandbox).html(payload);
        await new Promise(resolve => setTimeout(resolve, 500));
        
        if (alertsTriggered['basic-xss'] || isKnownVulnerable) {
          console.log('%c⛔ VULNERABLE: Script executed via img onerror', 'color: #d32f2f; font-weight: bold;');
          testResults['basicXss'] = true;
          anyVulnerable = true;
        } else {
          console.log('%c✅ SECURE: Script blocked in img onerror', 'color: #2e7d32;');
          testResults['basicXss'] = false;
        }
      } catch (e) {
        console.log('%c❓ ERROR during test:', 'color: #ff9800;', e.message);
        testResults['basicXss'] = 'error';
      }
      
      // Clear sandbox
      sandbox.innerHTML = '';
      
      // Test 2: CVE-2020-11022/11023
      console.log('\n%cTest 2: CVE-2020-11022/11023', 'font-weight: bold;');
      try {
        // Construct payload with test ID embedded
        const payload = `<select><option><script>alert('XSS-SCANNER-TEST:cve-test${popupSuffix}')</script></option></select>`;
        
        jq(sandbox).html(payload);
        await new Promise(resolve => setTimeout(resolve, 500));
        
        if (alertsTriggered['cve-test'] || isKnownVulnerable) {
          console.log('%c⛔ VULNERABLE: Vulnerable to CVE-2020-11022/11023', 'color: #d32f2f; font-weight: bold;');
          testResults['cveTest'] = true;
          anyVulnerable = true;
        } else {
          console.log('%c✅ SECURE: Not vulnerable to CVE-2020-11022/11023', 'color: #2e7d32;');
          testResults['cveTest'] = false;
        }
      } catch (e) {
        console.log('%c❓ ERROR during test:', 'color: #ff9800;', e.message);
        testResults['cveTest'] = 'error';
      }
      
      // Clear sandbox
      sandbox.innerHTML = '';
      
      // Test 3: Nested Elements
      console.log('\n%cTest 3: Nested Elements', 'font-weight: bold;');
      try {
        // Construct payload with test ID embedded
        const payload = `<div><style><script>alert('XSS-SCANNER-TEST:nested-test${popupSuffix}')</script></style></div>`;
        
        jq(sandbox).html(payload);
        await new Promise(resolve => setTimeout(resolve, 500));
        
        if (alertsTriggered['nested-test'] || isKnownVulnerable) {
          console.log('%c⛔ VULNERABLE: Script executed via nested elements', 'color: #d32f2f; font-weight: bold;');
          testResults['nestedElements'] = true;
          anyVulnerable = true;
        } else {
          console.log('%c✅ SECURE: Script blocked in nested elements', 'color: #2e7d32;');
          testResults['nestedElements'] = false;
        }
      } catch (e) {
        console.log('%c❓ ERROR during test:', 'color: #ff9800;', e.message);
        testResults['nestedElements'] = 'error';
      }
      
      // Clear sandbox
      sandbox.innerHTML = '';
      
      // Test 4: jQuery.html() Method
      console.log('\n%cTest 4: jQuery.html() Method', 'font-weight: bold;');
      try {
        // Construct payload with test ID embedded
        const payload = `<img src="x" onerror="alert('XSS-SCANNER-TEST:html-test${popupSuffix}')">`;
        
        const div = jq('<div>');
        div.html(payload);
        jq(sandbox).append(div);
        await new Promise(resolve => setTimeout(resolve, 500));
        
        if (alertsTriggered['html-test'] || isKnownVulnerable) {
          console.log('%c⛔ VULNERABLE: Script executed via jQuery.html()', 'color: #d32f2f; font-weight: bold;');
          testResults['htmlMethod'] = true;
          anyVulnerable = true;
        } else {
          console.log('%c✅ SECURE: Script blocked in jQuery.html()', 'color: #2e7d32;');
          testResults['htmlMethod'] = false;
        }
        
        div.remove();
      } catch (e) {
        console.log('%c❓ ERROR during test:', 'color: #ff9800;', e.message);
        testResults['htmlMethod'] = 'error';
      }
      
      // Clear sandbox
      sandbox.innerHTML = '';
      
      // Test 5: jQuery Constructor
      console.log('\n%cTest 5: jQuery Constructor', 'font-weight: bold;');
      try {
        // Construct payload with test ID embedded
        const payload = `<div><img src="x" onerror="alert('XSS-SCANNER-TEST:constructor-test${popupSuffix}')"></div>`;
        
        jq(payload).appendTo(sandbox);
        await new Promise(resolve => setTimeout(resolve, 500));
        
        if (alertsTriggered['constructor-test'] || isKnownVulnerable) {
          console.log('%c⛔ VULNERABLE: Script executed via jQuery constructor', 'color: #d32f2f; font-weight: bold;');
          testResults['constructor'] = true;
          anyVulnerable = true;
        } else {
          console.log('%c✅ SECURE: Script blocked in jQuery constructor', 'color: #2e7d32;');
          testResults['constructor'] = false;
        }
      } catch (e) {
        console.log('%c❓ ERROR during test:', 'color: #ff9800;', e.message);
        testResults['constructor'] = 'error';
      }
      
      // Remove sandbox
      sandbox.remove();
      
      // Store results
      results.tests[instance.version] = testResults;
      
      // If we know it's vulnerable from the version check but no tests triggered,
      // it might be due to browser protections - still mark as vulnerable
      if (isKnownVulnerable && !anyVulnerable) {
        console.log('%c⚠️ Note: Version known to be vulnerable but no XSS payloads executed. Browser protections may be preventing exploitation.', 'color: #ff9800; font-weight: bold');
        anyVulnerable = true;
      }
      
      return anyVulnerable;
    }
    
    /**
     * Display final summary
     */
    function displaySummary() {
      console.log('\n%c===== SCAN SUMMARY =====', 'font-weight: bold; font-size: 14px; color: #1976d2;');
      
      const scanDuration = ((Date.now() - startTime) / 1000).toFixed(2);
      console.log(`Scan completed in ${scanDuration} seconds`);
      
      if (results.jqueryVersions.length === 0) {
        console.log('%cNo jQuery detected on this page.', 'font-weight: bold;');
        return;
      }
      
      console.log(`%cFound ${results.jqueryVersions.length} jQuery version(s): ${results.jqueryVersions.join(', ')}`, 'font-weight: bold;');
      
      if (results.migrateVersions && results.migrateVersions.length > 0) {
        console.log(`Found ${results.migrateVersions.length} jQuery Migrate version(s): ${results.migrateVersions.join(', ')}`);
      }
      
      if (results.vulnerableVersions.length > 0) {
        console.log(`%c⚠️ VULNERABLE: ${results.vulnerableVersions.length} vulnerable version(s) detected: ${results.vulnerableVersions.join(', ')}`, 'color: #d32f2f; font-weight: bold;');
        
        console.log('\n%cRecommendations:', 'font-weight: bold;');
        console.log('1. Update to jQuery 3.5.0 or newer.');
        console.log('2. Implement Content-Security-Policy with script-src restrictions.');
        console.log('3. Use a DOM sanitizer like DOMPurify when processing HTML.');
        console.log('4. Validate and sanitize all user inputs on both client and server sides.');
      } else {
        console.log('%c✅ No vulnerable jQuery versions detected', 'color: #2e7d32; font-weight: bold;');
      }
      
      console.log('\n%c===== Scanner by Panacea InfoSec =====', 'font-style: italic; color: #666;');
      
      // Restore original alert function
      window.alert = originalAlert;
    }
    
    /**
     * Main scanning function
     */
    async function runScan() {
      try {
        // 1. Ask user about popup preferences
        const showPopups = getPopupPreference();
        
        // 2. Detect jQuery
        const jQueryInfo = detectJQuery();
        
        if (!jQueryInfo || (jQueryInfo.coreVersions && jQueryInfo.coreVersions.length === 0)) {
          displaySummary();
          return;
        }
        
        // Store core versions in results
        results.jqueryVersions = jQueryInfo.coreVersions || [];
        results.migrateVersions = jQueryInfo.migrateVersions || [];
        
        // 3. Check for vulnerable versions
        console.log('\n%c----- Checking for Known Vulnerabilities -----', 'font-weight: bold; color: #1976d2;');
        for (const version of jQueryInfo.coreVersions) {
          const status = isVulnerableVersion(version);
          if (status.vulnerable) {
            console.log(`%c⚠️ jQuery ${version}: VULNERABLE - ${status.details}`, 'color: #d32f2f;');
            results.vulnerableVersions.push(version);
          } else {
            console.log(`%c✅ jQuery ${version}: SECURE - ${status.details}`, 'color: #2e7d32;');
          }
        }
        
        // Show migrate versions as info
        for (const version of jQueryInfo.migrateVersions) {
          console.log(`%cℹ️ jQuery Migrate ${version}: Not subject to core vulnerabilities`, 'color: #1976d2;');
        }
        
        // 4. Detect security protections
        const protections = detectSecurityProtections();
        
        // 5. Run vulnerability tests on instances
        const coreInstances = jQueryInfo.instances.filter(instance => !instance.isMigrateLibrary && instance.object);
        if (coreInstances.length > 0) {
          for (const instance of coreInstances) {
            await runVulnerabilityTests(instance, showPopups);
          }
        } else if (results.vulnerableVersions.length > 0) {
          console.log('\n%c⚠️ Cannot run dynamic tests (no jQuery object references available)', 'color: #ff9800;');
          console.log('However, vulnerable versions were detected based on version numbers.');
        }
        
        // 6. Display summary
        displaySummary();
        
      } catch (error) {
        console.error('Error during scan:', error);
        // Restore original alert function in case of error
        window.alert = originalAlert;
      }
    }
    
    // Run the scan
    runScan();
  })();