
# ![](https://avatars.githubusercontent.com/u/208623228?v=4&size=35) jQuery XSS Scanner Pro  

Protect your websites from Cross-Site Scripting (XSS) vulnerabilities with ease!

---

## 🔍 About This Extension

The **jQuery XSS Vulnerability Scanner Pro** is a browser extension developed to help developers and security professionals detect and analyze potential **XSS vulnerabilities** in web pages that use jQuery.

> 📢 In April 2020, jQuery 3.5.0 patched critical XSS vulnerabilities (CVE-2020-11022, CVE-2020-11023). Many websites are still using vulnerable versions!

This tool is **for educational and authorized testing purposes only**. Always ensure you have permission before scanning any website you don’t own.

---

## ✨ Key Features

- 🔍 **jQuery Detection**  
  Detects all versions of jQuery used on a webpage (CDN or local).

- ⚠️ **Vulnerability Analysis**  
  Identifies vulnerable jQuery versions and actively tests for real-world XSS.

- 🛡️ **Security Protection Detection**  
  Finds CSP and other built-in protections against XSS.

- 📊 **Detailed Reports**  
  Displays comprehensive reports with findings and recommendations.

---

## 🛠️ How to Use

1. 🖱️ Click the extension icon in your browser toolbar.  
2. 🔎 Press **"Scan This Page"** to begin analysis.  
3. 📄 Review detailed results in the panel injected into the page.  
4. ✅ Follow suggested remediation steps if vulnerabilities are found.

> 💡 **Pro Tip:** Use the persistent corner icon (bottom right of the page) for one-click scans!

---

## 💡 Understanding XSS

**Cross-Site Scripting (XSS)** allows attackers to inject malicious scripts into web pages viewed by others. jQuery versions before **3.5.0** contain known XSS flaws that attackers can exploit.

### 🚨 Common jQuery XSS Vectors
- Unsafe use of `$.html()` with untrusted input  
- CVE-2020-11022 / CVE-2020-11023  
- Improper HTML parsing and nested elements  
- Unsafe selector/constructor usage with dynamic input

---


---

## 🚀 Get Started

> 🔧 Install the `.crx` file from the [Releases](https://github.com/PanaceaInfosec/jQuery-XSS-Scanner-Pro/releases) section and follow the usage guide above.

---
