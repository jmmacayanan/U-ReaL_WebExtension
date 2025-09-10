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
        <div>No malicious URLs detected.</div>
        <div style="font-size: 12px; margin-top: 5px; opacity: 0.7;">Your emails are safe!</div>
      </div>
    `;
    return;
  }

  content.innerHTML = urls.map((item, idx) => `
    <div class="malicious-url">
      <div class="url-text">${truncateURL(item.url)}</div>
      <div class="url-meta">
        <span>${formatTime(item.timestamp)}</span>
        <button class="open-anyway-btn" data-url="${encodeURIComponent(item.url)}" style="margin-left:10px;">Open Anyway</button>
      </div>
    </div>
  `).join('');


  document.querySelectorAll('.open-anyway-btn').forEach(btn => {
    btn.addEventListener('click', function(e) {
      const url = decodeURIComponent(this.getAttribute('data-url'));
      if (confirm('This link was flagged as malicious. Are you sure you want to open it anyway?')) {
        chrome.tabs.create({ url });
      }
    });
  });
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
  
  const estimatedTotal = Math.max(urls.length, 0);
  document.getElementById('totalScanned').textContent = estimatedTotal;
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

