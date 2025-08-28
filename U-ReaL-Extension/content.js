// U-ReaL Scanner Content Script - Fixed Lifecycle Management
class UReaLURLScanner {
  constructor() {
    this.scannedUrls = new Set();
    this.maliciousUrls = new Map();
    this.processedElements = new WeakSet();
    this.observers = [];
    this.intervals = [];
    this.settings = { threshold: 0.4, enableNotifications: true };
    this.isInitialized = false;
    this.isDestroyed = false;
    
    // Bind methods to preserve context
    this.handleVisibilityChange = this.handleVisibilityChange.bind(this);
    this.handleFocus = this.handleFocus.bind(this);
    this.handleBeforeUnload = this.handleBeforeUnload.bind(this);
    
    this.init();
  }

  async init() {
    if (this.isInitialized) {
      console.log('🔧 Scanner already initialized, skipping...');
      return;
    }

    console.log('🔧 U-ReaL Scanner initializing...');
    this.isDestroyed = false;
    
    // Setup lifecycle event handlers
    this.setupLifecycleHandlers();
    
    try {
      // Load stored data
      await this.loadStoredData();
      
      // Wait for U-ReaL and start scanning
      await this.waitForUReaL();
      
      if (!this.isDestroyed) {
        console.log('📧 U-ReaL loaded, starting URL scanner');
        this.startScanning();
        this.isInitialized = true;
      }
    } catch (error) {
      console.error('❌ Error initializing scanner:', error);
      this.cleanup();
    }
  }

  // Setup event handlers for page lifecycle
  setupLifecycleHandlers() {
    // Handle tab visibility changes
    document.addEventListener('visibilitychange', this.handleVisibilityChange);
    
    // Handle window focus/blur
    window.addEventListener('focus', this.handleFocus);
    window.addEventListener('blur', this.handleBlur);
    
    // Handle page unload
    window.addEventListener('beforeunload', this.handleBeforeUnload);
    
    // Handle U-ReaL navigation (pushstate/popstate)
    window.addEventListener('popstate', () => {
      console.log('📍 Browser navigation detected');
      this.reinitialize();
    });
    
    // Monitor for pushstate changes (U-ReaL navigation)
    const originalPushState = history.pushState;
    const originalReplaceState = history.replaceState;
    
    history.pushState = (...args) => {
      originalPushState.apply(history, args);
      console.log('📍 U-ReaL pushState navigation detected');
      this.handleNavigation();
    };
    
    history.replaceState = (...args) => {
      originalReplaceState.apply(history, args);
      console.log('📍 U-ReaL replaceState navigation detected');
      this.handleNavigation();
    };
  }

  // Handle visibility changes (tab switching)
  handleVisibilityChange() {
    if (document.hidden) {
      console.log('👁️ Tab hidden, pausing scanner');
      this.pauseScanning();
    } else {
      console.log('👁️ Tab visible, resuming scanner');
      this.resumeScanning();
    }
  }

  // Handle window focus
  handleFocus() {
    console.log('🎯 Window focused, ensuring scanner is active');
    if (!this.isInitialized || this.isDestroyed) {
      this.reinitialize();
    } else {
      this.resumeScanning();
    }
  }

  // Handle window blur
  handleBlur() {
    console.log('🎯 Window blurred');
    // Don't pause on blur as U-ReaL might still be processing
  }

  // Handle before page unload
  handleBeforeUnload() {
    console.log('📤 Page unloading, cleaning up scanner');
    this.cleanup();
  }

  // Handle U-ReaL navigation
  handleNavigation() {
    setTimeout(() => {
      if (this.shouldReinitialize()) {
        console.log('🔄 U-ReaL navigation completed, reinitializing...');
        this.reinitialize();
      }
    }, 1000);
  }

  // Check if we should reinitialize
  shouldReinitialize() {
    // Check if we're still on U-ReaL
    if (window.location.hostname !== 'mail.google.com') {
      return false;
    }
    
    // Check if U-ReaL interface is present
    const urealInterface = document.querySelector('[role="main"]') || 
                          document.querySelector('.nH') || 
                          document.querySelector('[jsname]');
    
    return !!urealInterface;
  }

  // Reinitialize the scanner
  async reinitialize() {
    console.log('🔄 Reinitializing scanner...');
    
    // Cleanup existing instance
    this.cleanup(false); // Don't remove event listeners
    
    // Reset state
    this.isInitialized = false;
    this.isDestroyed = false;
    this.processedElements = new WeakSet();
    
    // Reinitialize
    try {
      await this.waitForUReaL();
      
      if (!this.isDestroyed && this.shouldReinitialize()) {
        console.log('📧 U-ReaL reloaded, restarting scanner');
        this.startScanning();
        this.isInitialized = true;
      }
    } catch (error) {
      console.error('❌ Error reinitializing scanner:', error);
    }
  }

  // Start all scanning activities
  startScanning() {
    this.observeEmailChanges();
    this.scanExistingEmails();
    this.setupPeriodicScan();
  }

  // Pause scanning activities
  pauseScanning() {
    // Clear intervals
    this.intervals.forEach(interval => clearInterval(interval));
    this.intervals = [];
    
    // Disconnect observers but keep them for resume
    this.observers.forEach(observer => {
      if (observer.disconnect) observer.disconnect();
    });
  }

  // Resume scanning activities
  resumeScanning() {
    if (this.isDestroyed) return;
    
    // Only resume if we're still on U-ReaL
    if (!this.shouldReinitialize()) {
      this.reinitialize();
      return;
    }
    
    // Restart observers
    this.observeEmailChanges();
    
    // Restart periodic scanning
    this.setupPeriodicScan();
    
    // Immediate scan
    setTimeout(() => this.scanExistingEmails(), 500);
  }

  // Load stored data
  async loadStoredData() {
    return new Promise((resolve) => {
      chrome.storage.local.get(['maliciousUrls', 'scannedUrls', 'settings'], (data) => {
        if (chrome.runtime.lastError) {
          console.error('Storage error:', chrome.runtime.lastError);
          resolve();
          return;
        }

        if (data.maliciousUrls) {
          data.maliciousUrls.forEach(item => {
            this.maliciousUrls.set(item.url, {
              is_malicious: true,
              confidence: item.confidence,
              timestamp: item.timestamp
            });
            this.scannedUrls.add(item.url);
          });
          console.log(`📚 Loaded ${this.maliciousUrls.size} known malicious URLs from storage`);
        }

        if (data.scannedUrls) {
          data.scannedUrls.forEach(url => this.scannedUrls.add(url));
          console.log(`📚 Loaded ${data.scannedUrls?.length || 0} previously scanned URLs`);
        }

        if (data.settings) {
          this.settings = { ...this.settings, ...data.settings };
        }

        resolve();
      });
    });
  }

  // Wait for U-ReaL interface
  waitForUReaL() {
    return new Promise((resolve, reject) => {
      let attempts = 0;
      const maxAttempts = 20;
      
      const checkUReaL = () => {
        if (this.isDestroyed) {
          reject(new Error('Scanner destroyed while waiting for U-ReaL'));
          return;
        }

        attempts++;
        
        const urealMain = document.querySelector('[role="main"]') || 
                         document.querySelector('.nH') || 
                         document.querySelector('[jsname]');
        
        if (urealMain) {
          console.log('✅ U-ReaL interface detected');
          resolve();
        } else if (attempts >= maxAttempts) {
          reject(new Error('U-ReaL interface not found after maximum attempts'));
        } else {
          console.log(`⏳ Waiting for U-ReaL to load... (${attempts}/${maxAttempts})`);
          setTimeout(checkUReaL, 1000);
        }
      };
      
      checkUReaL();
    });
  }

  // Setup periodic scanning with proper cleanup
  setupPeriodicScan() {
    // Clear any existing intervals
    this.intervals.forEach(interval => clearInterval(interval));
    this.intervals = [];
    
    if (this.isDestroyed) return;
    
    // Scan every 5 seconds for new content
    const quickScanInterval = setInterval(() => {
      if (!this.isDestroyed && !document.hidden) {
        this.scanExistingEmails(true);
      }
    }, 5000);
    
    // Full rescan every 30 seconds
    const fullScanInterval = setInterval(() => {
      if (!this.isDestroyed && !document.hidden) {
        console.log('🔄 Performing periodic full rescan...');
        this.processedElements = new WeakSet(); // Reset processed elements
        this.scanExistingEmails();
      }
    }, 30000);
    
    this.intervals.push(quickScanInterval, fullScanInterval);
  }

  // Observe email changes with proper cleanup
  observeEmailChanges() {
    // Disconnect existing observers
    this.observers.forEach(observer => {
      if (observer.disconnect) observer.disconnect();
    });
    this.observers = [];
    
    if (this.isDestroyed) return;

    const observer = new MutationObserver((mutations) => {
      if (this.isDestroyed) return;
      
      let shouldScan = false;
      
      mutations.forEach((mutation) => {
        if (mutation.addedNodes.length > 0) {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === Node.ELEMENT_NODE) {
              if (this.containsEmailContent(node)) {
                shouldScan = true;
              }
            }
          });
        }
      });

      if (shouldScan) {
        console.log('🔍 New email content detected, scanning...');
        setTimeout(() => {
          if (!this.isDestroyed) {
            this.scanExistingEmails();
          }
        }, 500);
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: false,
      characterData: false
    });
    
    this.observers.push(observer);
  }

  // Check if element contains email content
  containsEmailContent(element) {
    const emailSelectors = [
      '.a3s', '.ii', '.adn', '.Am', '[role="listitem"]'
    ];

    for (const selector of emailSelectors) {
      if (element.matches && element.matches(selector)) {
        return true;
      }
      if (element.querySelector && element.querySelector(selector)) {
        return true;
      }
    }
    return false;
  }

  // Scan existing emails
  scanExistingEmails(silent = false) {
    if (this.isDestroyed) return;
    
    if (!silent) console.log('🔍 Scanning existing emails...');
    
    const emailBodySelectors = [
      '.a3s.aiL', '.a3s.aXjCH', '.a3s',
      '.ii.gt .a3s', '.ii .a3s', '.gs .a3s',
      '.adn.ads', '.Am.Al.editable', '[role="listitem"] .a3s',
      'div[dir="ltr"] .a3s', 'div[dir="rtl"] .a3s',
      '[jsname] .a3s', '.Ar .a3s',
      '[role="main"] .a3s', '.nH .a3s'
    ];

    let totalFound = 0;
    let totalScanned = 0;

    emailBodySelectors.forEach(selector => {
      if (this.isDestroyed) return;
      
      const emailBodies = document.querySelectorAll(selector);
      if (!silent && emailBodies.length > 0) {
        console.log(`📧 Found ${emailBodies.length} elements for selector: ${selector}`);
      }
      
      emailBodies.forEach(body => {
        if (this.isDestroyed) return;
        
        if (!this.processedElements.has(body) && this.isValidEmailContent(body)) {
          totalFound++;
          this.processedElements.add(body);
          const urlCount = this.scanEmailContent(body, silent);
          totalScanned += urlCount;
        }
      });
    });

    if (!silent && !this.isDestroyed) {
      console.log(`📊 Scanned ${totalFound} email bodies, found ${totalScanned} URLs`);
    }
  }

  // Rest of the methods remain the same...
  isValidEmailContent(element) {
    if (!element) return false;

    const skipSelectors = [
      '.nH.if', '.G-Ni', '.aic', '.ar.as', '.zA.yW', '.Cp',
      '[role="navigation"]', '[role="toolbar"]', '.gb_',
      '.D.E', '.Bs', '.aqL'
    ];

    for (const skipSelector of skipSelectors) {
      if (element.closest(skipSelector)) {
        return false;
      }
    }

    const textContent = element.textContent?.trim();
    if (!textContent || textContent.length < 10) {
      return false;
    }

    const emailIndicators = [
      /\b\w+@\w+\.\w+\b/, /https?:\/\//, /Dear\s+/i,
      /Best\s+regards/i, /Thanks?/i, /Please/i,
      /Subject:/i, /From:/i
    ];

    return emailIndicators.some(pattern => pattern.test(textContent)) || 
           textContent.length > 50;
  }

  scanEmailContent(container, silent = false) {
    if (!container || this.isDestroyed) return 0;

    const links = container.querySelectorAll('a[href]');
    if (!silent) console.log(`🔗 Found ${links.length} links in email content`);
    
    let processedCount = 0;
    
    links.forEach(link => {
      if (this.isDestroyed) return;
      
      if (this.isEmailLink(link)) {
        this.processLink(link, silent);
        processedCount++;
      }
    });

    return processedCount;
  }

  isEmailLink(linkElement) {
    const href = linkElement.href;
    if (!href) return false;

    const skipPatterns = [
      /mail\.google\.com/, /accounts\.google\.com/, /support\.google\.com/,
      /google\.com\/search/, /gmail/i, /^mailto:/, /^tel:/, /^#/, /javascript:/
    ];

    if (skipPatterns.some(pattern => pattern.test(href))) {
      return false;
    }

    const emailContentSelectors = [
      '.a3s', '.ii.gt', '.Am.Al', '[role="listitem"]'
    ];

    return emailContentSelectors.some(selector => 
      linkElement.closest(selector)
    );
  }

  async processLink(linkElement, silent = false) {
    if (this.isDestroyed) return;
    
    const href = linkElement.href;
    if (!href) return;

    if (this.maliciousUrls.has(href)) {
      if (!silent) console.log(`🚨 Re-blocking known malicious URL: ${href}`);
      const result = this.maliciousUrls.get(href);
      this.applyMaliciousStyle(linkElement, href, result);
      return;
    }

    if (this.scannedUrls.has(href)) {
      return;
    }

    if (!silent) console.log(`🔍 Processing new URL: ${href}`);
    this.scannedUrls.add(href);
    
    this.addScanningIndicator(linkElement);
    
    try {
      const result = await this.checkURL(href);
      
      if (this.isDestroyed) return;
      
      if (result.is_malicious && result.confidence >= this.settings.threshold) {
        console.log(`🚨 MALICIOUS URL DETECTED: ${href}`);
        this.maliciousUrls.set(href, result);
        this.handleMaliciousURL(linkElement, href, result);
      } else {
        this.removeScanningIndicator(linkElement);
        linkElement.classList.add('benign-link');
      }
    } catch (error) {
      if (!this.isDestroyed) {
        console.error('❌ Error checking URL:', href, error);
        this.removeScanningIndicator(linkElement);
      }
    }
  }

  applyMaliciousStyle(linkElement, url, result) {
    this.removeScanningIndicator(linkElement);
    
    linkElement.style.cssText = `
      pointer-events: none !important;
      text-decoration: line-through !important;
      color: #dc2626 !important;
      background-color: #fef2f2 !important;
      padding: 2px 4px !important;
      border-radius: 4px !important;
      border: 1px solid #fca5a5 !important;
      cursor: help !important;
    `;
    
    linkElement.removeAttribute('href');
    
    if (!linkElement.querySelector('.malicious-warning')) {
      const warningIcon = document.createElement('span');
      warningIcon.className = 'malicious-warning';
      warningIcon.innerHTML = ' ✖';
      warningIcon.style.color = '#dc2626';
      warningIcon.title = `Malicious link blocked (${(result.confidence * 100).toFixed(1)}% confidence)`;
      linkElement.appendChild(warningIcon);
    }
    
    linkElement.addEventListener('click', (e) => {
      e.preventDefault();
      this.showURLDetails(url, result);
    });
  }

  addScanningIndicator(linkElement) {
    if (linkElement.querySelector('.url-scanning-indicator') || 
        linkElement.querySelector('.malicious-warning')) {
      return;
    }

    const indicator = document.createElement('span');
    indicator.className = 'url-scanning-indicator';
    indicator.innerHTML = ' 🔍';
    indicator.style.cssText = 'animation: pulse 1s infinite; color: #3b82f6;';
    linkElement.appendChild(indicator);
  }

  removeScanningIndicator(linkElement) {
    const indicator = linkElement.querySelector('.url-scanning-indicator');
    if (indicator) {
      indicator.remove();
    }
  }

  async checkURL(url) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({
        action: 'checkURL',
        url: url
      }, (response) => {
        if (chrome.runtime.lastError) {
          resolve({ is_malicious: false, confidence: 0 });
        } else {
          resolve(response || { is_malicious: false, confidence: 0 });
        }
      });
    });
  }

  handleMaliciousURL(linkElement, url, result) {
    this.applyMaliciousStyle(linkElement, url, result);
    this.storeMaliciousURL(url, result);
  }

  showURLDetails(url, result) {
    const existingModal = document.querySelector('.url-scanner-modal');
    if (existingModal) existingModal.remove();

    const modal = document.createElement('div');
    modal.className = 'url-scanner-modal';
    modal.innerHTML = `
      <div class="modal-content">
        <h3>✖ Security Warning</h3>
        <p><strong>Malicious URL blocked:</strong></p>
        <p class="url-text">${url}</p>
        <p><strong>Confidence:</strong> ${(result.confidence * 100).toFixed(1)}%</p>
        <div class="modal-buttons">
          <button class="close-btn">Close</button>
          <button class="extension-btn">Open Extension</button>
        </div>
      </div>
    `;

    modal.querySelector('.close-btn').addEventListener('click', () => modal.remove());
    modal.querySelector('.extension-btn').addEventListener('click', () => {
      chrome.runtime.sendMessage({ action: 'openExtension' });
      modal.remove();
    });

    document.body.appendChild(modal);
  }

  storeMaliciousURL(url, result) {
    chrome.storage.local.get(['maliciousUrls'], (data) => {
      const maliciousUrls = data.maliciousUrls || [];
      const urlData = {
        url: url,
        confidence: result.confidence,
        timestamp: Date.now(),
        source: 'gmail-email'
      };

      const existingIndex = maliciousUrls.findIndex(item => item.url === url);
      if (existingIndex >= 0) {
        maliciousUrls[existingIndex] = urlData;
      } else {
        maliciousUrls.push(urlData);
      }
      
      if (maliciousUrls.length > 100) {
        maliciousUrls.splice(0, maliciousUrls.length - 100);
      }
      
      chrome.storage.local.set({ maliciousUrls: maliciousUrls });
    });
  }

  // Cleanup method
  cleanup(removeEventListeners = true) {
    console.log('🧹 Cleaning up scanner...');
    this.isDestroyed = true;
    
    // Clear intervals
    this.intervals.forEach(interval => clearInterval(interval));
    this.intervals = [];
    
    // Disconnect observers
    this.observers.forEach(observer => {
      if (observer.disconnect) observer.disconnect();
    });
    this.observers = [];
    
    // Remove event listeners if requested
    if (removeEventListeners) {
      document.removeEventListener('visibilitychange', this.handleVisibilityChange);
      window.removeEventListener('focus', this.handleFocus);
      window.removeEventListener('blur', this.handleBlur);
      window.removeEventListener('beforeunload', this.handleBeforeUnload);
    }
  }
}

// Global scanner management
let globalScanner = null;

function initializeScanner() {
  // Only initialize if we're on U-ReaL
  if (window.location.hostname !== 'mail.google.com') {
    return;
  }
  
  // Cleanup existing scanner if any
  if (globalScanner) {
    globalScanner.cleanup();
    globalScanner = null;
  }
  
  // Create new scanner
  globalScanner = new UReaLURLScanner();
  window.UReaLURLScanner = globalScanner; // For debugging
  console.log('🔧 U-ReaL URL Scanner initialized with lifecycle management');
}

// Initialize scanner
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initializeScanner);
} else {
  initializeScanner();
}

// Also initialize on window load for safety
window.addEventListener('load', initializeScanner);

// Handle page refresh/reload
window.addEventListener('beforeunload', () => {
  if (globalScanner) {
    globalScanner.cleanup();
  }
});
