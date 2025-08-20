# Gmail URL Scanner Chrome Extension

A Chrome extension that automatically scans URLs in Gmail emails for potential security threats using machine learning.

## 🚀 Features

- **Real-time URL Scanning**: Automatically scans all URLs in Gmail emails
- **Machine Learning Detection**: Uses XGBoost model for malicious URL detection
- **Smart Whitelisting**: Trusted domains bypass scanning for better performance
- **Visual Indicators**: Malicious URLs are disabled and marked with warning icons
- **Extension Dashboard**: View detected threats and manage settings
- **Safe Access**: Option to visit flagged URLs through extension popup

## 📋 Requirements

- Python 3.8+
- Chrome Browser
- Your trained XGBoost model (`url_xgb_model_v2.json`)
- Whitelist CSV file (`raw_datasets/benign-urls.csv`)

## 🛠️ Setup Instructions

### 1. Backend Setup

1. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Prepare your files**:
   - Place your trained model: `url_xgb_model.json`
   - Place your whitelist: `raw_datasets/benign-urls.csv`
   - Ensure `feature_extractor.py` is in the same directory

3. **Start the Flask server**:
   ```bash
   python flask_server.py
   ```
   
   Server will start on `http://localhost:5000`

4. **Test the backend** (optional):
   ```bash
   python test_server.py
   ```

### 2. Chrome Extension Setup

1. **Open Chrome Extensions**:
   - Go to `chrome://extensions/`
   - Enable "Developer mode" (top right toggle)

2. **Load the extension**:
   - Click "Load unpacked"
   - Select the folder containing all the extension files:
     - `manifest.json`
     - `content.js`
     - `background.js`
     - `popup.html`
     - `popup.js`
     - `styles.css`

3. **Pin the extension**:
   - Click the extensions icon in Chrome toolbar
   - Pin "Gmail URL Security Scanner"

### 3. Usage

1. **Open Gmail** in Chrome
2. **Open any email** with URLs
3. The extension will **automatically scan** all URLs
4. **Malicious URLs** will be:
   - Disabled (cannot be clicked)
   - Marked with ⚠️ warning icon
   - Styled with red strikethrough
5. Click the **extension icon** to view detected threats
6. Use **"Visit Anyway"** button to access flagged URLs if needed

## 🔧 Configuration

### Backend Configuration

Edit `flask_server.py` to adjust:
- Server port (default: 5000)
- Detection threshold (default: 0.4)
- Batch processing limits

### Extension Settings

Click the extension icon and use the ⚙️ settings button to adjust:
- **Detection Threshold**: Confidence level for malicious classification
- **Enable Notifications**: Show alerts when threats are detected

## 📊 API Endpoints

The backend provides these endpoints:

- `GET /health` - Health check and status
- `POST /check-url` - Check single URL
- `POST /check-urls` - Check multiple URLs (batch)

### Example API Usage

```bash
# Check single URL
curl -X POST http://localhost:5000/check-url \
     -H "Content-Type: application/json" \
     -d '{"url": "http://suspicious-site.com", "threshold": 0.4}'

# Response
{
  "url": "http://suspicious-site.com",
  "is_malicious": true,
  "confidence": 0.87,
  "status": "success",
  "message": "Malicious (87.00% confidence)"
}
```

## 🔒 Security Features

- **Whitelist Protection**: Trusted domains skip expensive ML inference
- **DNS Caching**: Reduces lookup times for repeated domains  
- **Safe Defaults**: Unknown URLs default to safe when backend unavailable
- **User Control**: Users can override decisions through extension popup
- **Privacy**: No URL data is stored permanently, only cached during session

## 🐛 Troubleshooting

### Backend Issues

1. **Model not loading**:
   - Verify `url_xgb_model.json` exists and is valid
   - Check XGBoost version compatibility

2. **Whitelist not loading**:
   - Verify `raw_datasets/benign-urls.csv` exists
   - Check CSV format matches expected structure

3. **DNS resolution errors**:
   - Check internet connection
   - Some corporate networks may block DNS queries

### Extension Issues

1. **URLs not being scanned**:
   - Refresh Gmail page
   - Check if backend server is running
   - Look for errors in Chrome Developer Tools

2. **Extension not loading**:
   - Verify all files are in the same directory
   - Check `manifest.json` syntax
   - Enable Developer mode in Chrome extensions

## 📝 File Structure

```
gmail-url-scanner/
├── feature_extractor.py    # Your existing feature extraction
├── main.py                 # Your existing prediction script  
├── flask_server.py         # New Flask API server
├── test_server.py          # Backend testing script
├── requirements.txt        # Python dependencies
├── manifest.json           # Extension manifest
├── content.js              # Gmail content scanner
├── background.js           # Extension service worker
├── popup.html              # Extension popup UI
├── popup.js                # Popup functionality
├── styles.css              # Content script styles
├── url_xgb_model.json      # Your trained model
└── raw_datasets/
    └── benign-urls.csv     # Your whitelist
```

## 🚀 Next Steps

1. **Test thoroughly** with various email types
2. **Monitor performance** with large inboxes
3. **Update whitelist** regularly with new trusted domains  
4. **Retrain model** periodically with new threat data
5. **Consider publishing** to Chrome Web Store

## ⚠️ Important Notes

- Keep your model and whitelist updated for best protection
- The extension only works on Gmail (mail.google.com)
- Backend must be running for real-time protection
- Extension falls back to safe mode if backend is unavailable