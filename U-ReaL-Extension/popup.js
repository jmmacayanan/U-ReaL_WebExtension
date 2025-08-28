// Extension Popup Logic
document.addEventListener('DOMContentLoaded', function() {
  loadMaliciousURLs();
  updateStats();
});

function loadMaliciousURLs() {
  chrome.storage.local.get(['maliciousUrls'], function(data) {
    const maliciousUrls = data.maliciousUrls || [];
    displayMaliciousURLs(maliciousUrls);
    updateStats(maliciousUrls);
  });
}

function displayMaliciousURLs(urls) {
  const content = document.getElementById('content');
  
  if (urls.length === 0) {
    content.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">✅</div>
        <div>No malicious URLs detected</div>
        <div style="font-size: 12px; margin-top: 5px; opacity: 0.7;">Your emails are safe!</div>
      </div>
    `;
    return;
  }

  content.innerHTML = urls.map(item => `
    <div class="malicious-url">
      <div class="url-text">${truncateURL(item.url)}</div>
      <div class="url-meta">
        <span>⚠️ ${(item.confidence * 100).toFixed(1)}% confidence</span>
        <span>${formatTime(item.timestamp)}</span>
      </div>
      <!-- Removed Visit Anyway button -->
    </div>
  `).join('');
}

function updateStats(urls = null) {
  if (urls === null) {
    chrome.storage.local.get(['maliciousUrls'], function(data) {
      const maliciousUrls = data.maliciousUrls || [];
      updateStatsDisplay(maliciousUrls);
    });
  } else {
    updateStatsDisplay(urls);
  }
}

function updateStatsDisplay(urls) {
  document.getElementById('maliciousFound').textContent = urls.length;
  
  // For total scanned, we'll estimate based on malicious findings
  // In a real implementation, you'd track this separately
  const estimatedTotal = Math.max(urls.length * 10, 0);
  document.getElementById('totalScanned').textContent = estimatedTotal;
}

function visitURL(url) {
  if (confirm(`Are you sure you want to visit this potentially malicious URL?\n\n${url}\n\nThis could be dangerous!`)) {
    chrome.tabs.create({ url: url });
  }
}

function truncateURL(url, maxLength = 50) {
  if (url.length <= maxLength) return url;
  return url.substring(0, maxLength - 3) + '...';
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
  return 'Just now';
}

// Refresh data every 30 seconds
setInterval(loadMaliciousURLs, 30000);