// Extension Popup Logic
document.addEventListener('DOMContentLoaded', function() {
  loadMaliciousURLs();
  setupSettings();
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
      <button class="visit-btn" onclick="visitURL('${item.url}')">
        Visit Anyway
      </button>
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

function setupSettings() {
  const settingsBtn = document.getElementById('settingsBtn');
  const settingsPanel = document.getElementById('settingsPanel');
  const thresholdSlider = document.getElementById('threshold');
  const thresholdValue = document.getElementById('thresholdValue');
  const notificationsCheckbox = document.getElementById('notifications');

  // Toggle settings panel
  settingsBtn.addEventListener('click', () => {
    settingsPanel.style.display = 
      settingsPanel.style.display === 'none' ? 'block' : 'none';
  });

  // Load current settings
  chrome.storage.local.get(['settings'], function(data) {
    const settings = data.settings || { threshold: 0.4, enableNotifications: true };
    thresholdSlider.value = settings.threshold;
    thresholdValue.textContent = Math.round(settings.threshold * 100) + '%';
    notificationsCheckbox.checked = settings.enableNotifications;
  });

  // Update threshold display
  thresholdSlider.addEventListener('input', function() {
    const value = Math.round(this.value * 100);
    thresholdValue.textContent = value + '%';
  });

  // Save settings on change
  thresholdSlider.addEventListener('change', saveSettings);
  notificationsCheckbox.addEventListener('change', saveSettings);
}

function saveSettings() {
  const threshold = parseFloat(document.getElementById('threshold').value);
  const enableNotifications = document.getElementById('notifications').checked;

  chrome.storage.local.set({
    settings: {
      threshold: threshold,
      enableNotifications: enableNotifications
    }
  });
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