// Extension Popup Logic (shows only URLs from the currently opened email)

// When popup opens, load data for the active Gmail tab
document.addEventListener("DOMContentLoaded", function () {
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    const tab = tabs[0];
    if (!tab || !tab.url.includes("mail.google.com")) {
      displayMessage("Not in Gmail tab.");
      return;
    }

    const emailId = tab.url; // use full Gmail URL as key
    loadMaliciousURLs(emailId);
  });
});

// --- Load & Display ---
function loadMaliciousURLs(emailId) {
  chrome.storage.local.get(["emails"], function (data) {
    const emails = data.emails || {};
    const maliciousUrls = emails[emailId] || [];
    displayMaliciousURLs(maliciousUrls);
    updateStats(maliciousUrls);
  });
}

function displayMaliciousURLs(urls) {
  const content = document.getElementById("content");

  if (urls.length === 0) {
    content.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">✅</div>
        <div>No malicious URLs detected in this email.</div>
        <div style="font-size: 12px; margin-top: 5px; opacity: 0.7;">
          This email appears safe.
        </div>
      </div>
    `;
    return;
  }

  content.innerHTML = urls
    .map(
      (item) => `
    <div class="malicious-url">
      <div class="url-text">${truncateURL(item.url)}</div>
      <div class="url-meta">
        <span>⚠️ ${(item.confidence * 100).toFixed(1)}% confidence</span>
        <span>${formatTime(item.timestamp)}</span>
      </div>
    </div>
  `
    )
    .join("");
}

// --- Stats ---
function updateStats(urls) {
  document.getElementById("maliciousFound").textContent = urls.length;

  // For now, total scanned = malicious count (extend if you track total separately)
  const estimatedTotal = Math.max(urls.length, 0);
  document.getElementById("totalScanned").textContent = estimatedTotal;
}

// --- Helpers ---
function truncateURL(url, maxLength = 50) {
  if (url.length <= maxLength) return url;
  return url.substring(0, maxLength - 3) + "...";
}

function formatTime(timestamp) {
  const now = Date.now();
  const diff = now - timestamp;
  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (days > 0) return `${days}d ago`;
  if (hours > 0) return `${hours}h ago`;
  if (minutes > 0) return `${minutes}m ago`;
  return "Just now";
}

function displayMessage(msg) {
  const content = document.getElementById("content");
  content.innerHTML = `
    <div class="empty-state">
      <div class="empty-icon">ℹ️</div>
      <div>${msg}</div>
    </div>
  `;
}
