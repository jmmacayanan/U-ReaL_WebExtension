class UReaLURLScanner {
  constructor() {
    // --- State Tracking ---
    this.scannedUrls = new Set();     // Stores already-checked URLs -> avoids duplicate scans
    this.maliciousUrls = new Map();   // Maps malicious URLs -> detection results

    // --- Observers & Intervals ---
    this.observers = [];              // Holds MutationObservers (DOM change watchers)
    this.intervals = [];              // Holds setInterval handles (for periodic rescans)

    // --- Scanner settings ---
    this.settings = { 
      threshold: 0.5,
      enableNotifications: true
    };

    // --- State flags ---
    this.isInitialized = false;       // Prevents duplicate init
    this.isDestroyed = false;         // Used to stop scanning cleanly

    this.init(); // Start initialization immediately
  }

  // --- Initialization ---
  async init() {
    if (this.isInitialized) return;   // Already initialized -> skip
    console.log("Initializing U-ReaL Scanner...");
    this.isDestroyed = false;

    try {
      // Wait until Gmail has rendered an email body
      await this.waitForGmailBody();

      if (!this.isDestroyed) {
        this.startScanning();         // Start scanning lifecycle
        this.isInitialized = true;
        console.log("Scanner ready.");
      }
    } catch (err) {
      console.error("Init error:", err);
      this.cleanup();                 // Clean up if init fails
    }
  }

  // --- Gmail body detection (polling loop until email body is ready) ---
  async waitForGmailBody() {
    return new Promise((resolve, reject) => {
      let attempts = 0;
      const check = () => {
        if (this.isDestroyed) return reject(new Error("Destroyed"));
        if (document.querySelector("div.a3s.aiL")) return resolve(); // Found body
        if (++attempts >= 20) return reject(new Error("Gmail body not found")); // Timeout
        setTimeout(check, 1000); // Retry every second
      };
      check();
    });
  }

  // --- Scanner lifecycle ---
  startScanning() {
    this.observeEmailChanges();   // Watch for Gmail DOM updates
    this.scanExistingEmails();    // First scan (already-opened email)
    this.setupPeriodicScan();     // Safety net -> periodic rescans
  }

  setupPeriodicScan() {
    this.pauseScanning(); // Clear previous intervals
    if (this.isDestroyed) return;

    // Periodically rescan (every 5 seconds)
    this.intervals.push(
      setInterval(() => !this.isDestroyed && this.scanExistingEmails(true), 5000)
    );
  }

  pauseScanning() {
    // Clear all timers + observers
    this.intervals.forEach(clearInterval);
    this.intervals = [];
    this.observers.forEach(o => o.disconnect?.());
    this.observers = [];
  }

  // --- MutationObserver: watch for Gmail email body updates ---
  observeEmailChanges() {
    this.observers.forEach(o => o.disconnect?.());
    this.observers = [];
    if (this.isDestroyed) return;

    const observer = new MutationObserver(mutations => {
      let bodyChanged = false;

      for (const m of mutations) {
        // Detect newly added email body or quoted section
        if ([...m.addedNodes].some(n => n.querySelector?.("div.a3s.aiL, blockquote.gmail_quote"))) {
          bodyChanged = true;
          break;
        }

        // Detect changes inside an existing email body
        if (m.target && (m.target.matches?.("div.a3s.aiL, blockquote.gmail_quote") || 
                         m.target.closest?.("div.a3s.aiL, blockquote.gmail_quote"))) {
          bodyChanged = true;
          break;
        }
      }

      // Rescan when new content detected
      if (bodyChanged) {
        console.log("Email body changed -> forcing rescan.");
        this.forceRescan();
      }
    });

    // Observe full Gmail DOM for changes
    observer.observe(document.body, {
      childList: true,     // New nodes added/removed
      subtree: true,       // Observe entire subtree
      characterData: true  // Catch inline text/link changes
    });

    this.observers.push(observer);
  }

  // --- Scan all visible Gmail email bodies ---
  scanExistingEmails(silent = false) {
    if (this.isDestroyed) return;
    let total = 0;

    // Scan emails
    document.querySelectorAll("div.a3s.aiL, blockquote.gmail_quote").forEach(body => {
      total += this.scanEmailContent(body, silent);
    });

    if (!silent) console.log(`Scanned ${total} URLs inside div.a3s.aiL and blockquote.gmail_quote`);
  }

  // --- Extract & process links from one container ---
  scanEmailContent(container, silent = false) {
    const links = container.querySelectorAll("a[href]");
    if (!silent) console.log(`Found ${links.length} links in email body`);

    let count = 0;
    links.forEach(link => {
      this.processLink(link, silent); // Send link to processor
      count++;
    });
    return count;
  }

  // --- Handle each link individually ---
  async processLink(link, silent = false) {
    const href = link.href;
    if (!href || this.scannedUrls.has(href)) return; // Skip duplicates
    this.scannedUrls.add(href);

    this.addIndicator(link); // Show scanning indicator
    try {
      const result = await this.checkURL(href); // Ask background script
      if (result.is_malicious && result.confidence >= this.settings.threshold) {
        console.log(`Malicious URL blocked: ${href}`);
        this.maliciousUrls.set(href, result);
        this.applyMaliciousStyle(link, href, result); // Apply block styling
      } else {
        this.removeIndicator(link);  // Remove scanning animation
        link.classList.add("benign-link");
      }
    } catch {
      this.removeIndicator(link); // Fail-safe
    }
  }

  // --- Send URL to background script for classification ---
  async checkURL(url) {
    return new Promise(resolve => {
      chrome.runtime.sendMessage({ action: "checkURL", url }, res => {
        if (chrome.runtime.lastError) 
          return resolve({ is_malicious: false, confidence: 0 });
        resolve(res || { is_malicious: false, confidence: 0 });
      });
    });
  }

  // --- Apply malicious styling to bad links ---
  applyMaliciousStyle(link, url, result) {
    this.removeIndicator(link);

    // Visual changes to block interaction (Strike-through)
    link.style.cssText = `
      pointer-events:none; text-decoration:line-through; color:#dc2626;
      background:#fef2f2; padding:2px 4px; border-radius:4px;
      border:1px solid #fca5a5; cursor:help;
    `;
    link.removeAttribute("href"); // Disable clicking

    // Add warning marker
    if (!link.querySelector(".malicious-warning")) {
      const warn = document.createElement("span");
      warn.className = "malicious-warning";
      warn.textContent = " ✖";
      warn.style.color = "#dc2626";
      warn.title = `Blocked (${(result.confidence * 100).toFixed(1)}% confidence)`;
      link.appendChild(warn);
    }

    // --- Save detection result per email ---
    const emailId = location.href; // Use Gmail URL as unique email ID
    chrome.storage.local.get(["emails"], (data) => {
      const emails = data.emails || {};
      if (!emails[emailId]) emails[emailId] = [];

      // Avoid duplicates
      if (!emails[emailId].some(item => item.url === url)) {
        emails[emailId].push({
          url,
          confidence: result.confidence,
          timestamp: Date.now()
        });
        chrome.storage.local.set({ emails });
      }
    });
  }
  
  // --- Add small icon while scanning ---
  addIndicator(link) {
    if (link.querySelector(".url-scanning-indicator,.malicious-warning")) return;
    const span = document.createElement("span");
    span.className = "url-scanning-indicator";
    span.textContent = " 🔍";
    span.style.cssText = "animation:pulse 1s infinite; color:#3b82f6;";
    link.appendChild(span);
  }

  // --- Remove scanning indicator ---
  removeIndicator(link) {
    link.querySelector(".url-scanning-indicator")?.remove();
  }

  // --- Clear state and force a fresh scan ---
  forceRescan() {
    if (this.isDestroyed) return;
    console.log("Forcing full rescan of all email bodies.");
    this.scannedUrls.clear();
    this.maliciousUrls.clear();
    this.scanExistingEmails(false);
  }

  // --- Cleanup scanner instance ---
  cleanup() {
    console.log("Cleaning up scanner instance.");
    this.isDestroyed = true;
    this.pauseScanning();
  }  
}

// --- Bootstrapping ---
let globalScanner = null;
function initializeScanner() {
  if (window.location.hostname !== "mail.google.com") return;
  globalScanner?.cleanup();
  globalScanner = new UReaLURLScanner();
  console.log("U-ReaL Scanner initialized.");
}

// Ensure scanner starts once Gmail is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initializeScanner);
} else {
  initializeScanner();
}

// This detects navigation and forces rescan.
let lastUrl = location.href;
setInterval(() => {
  if (location.href !== lastUrl) {
    lastUrl = location.href;
    console.log("Gmail navigation detected -> force rescan.");
    globalScanner?.forceRescan();
  }
}, 1000);
