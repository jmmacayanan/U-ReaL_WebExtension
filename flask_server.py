from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import xgboost as xgb
from feature_extractor import URLFeatureExtractor
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)  # Enable CORS for Chrome extension

# -----------------------------
# Load Trained Model
# -----------------------------
try:
    model = xgb.XGBClassifier()
    model.load_model("url_xgb_model.json")
    logger.info("✅ XGBoost model loaded successfully")
except Exception as e:
    logger.error(f"❌ Failed to load model: {e}")
    model = None

# -----------------------------
# Load Whitelist
# -----------------------------
try:
    URLFeatureExtractor.load_whitelist("raw_datasets/benign-urls.csv")
    logger.info(f"✅ Whitelist loaded with {len(URLFeatureExtractor.WHITELIST)} domains")
except Exception as e:
    logger.error(f"❌ Failed to load whitelist: {e}")

# -----------------------------
# Feature order must match training
# -----------------------------
FEATURE_ORDER = [
    'url_len', 'dot_count', 'hyphen_count', 'has_ip',
    'suspicious_total', 'subdomain_count', 'tld_length',
    'url_entropy', 'has_a', 'has_mx', 'has_ns', 'ip_count'
]

def predict_url(url, threshold=0.4):
    """
    Predict if URL is malicious
    
    Args:
        url (str): URL to check
        threshold (float): Confidence threshold for malicious classification
        
    Returns:
        dict: Prediction result
    """
    try:
        extractor = URLFeatureExtractor(url)
        
        # If whitelisted, immediately return as benign
        if extractor.is_whitelisted():
            return {
                'url': url,
                'is_malicious': False,
                'confidence': 0.0,
                'status': 'whitelisted',
                'message': 'Domain is whitelisted'
            }
        
        # Extract features
        feat_dict = extractor.extract_features()
        if feat_dict is None:
            return {
                'url': url,
                'is_malicious': False,
                'confidence': 0.0,
                'status': 'error',
                'message': 'Feature extraction failed'
            }
        
        # Check for missing model
        if model is None:
            return {
                'url': url,
                'is_malicious': False,
                'confidence': 0.0,
                'status': 'error',
                'message': 'Model not loaded'
            }
        
        # Prepare DataFrame
        df = pd.DataFrame([[feat_dict[f] for f in FEATURE_ORDER]], columns=FEATURE_ORDER)
        
        # Check for NaN values
        if df.isnull().any().any():
            return {
                'url': url,
                'is_malicious': False,
                'confidence': 0.0,
                'status': 'error',
                'message': 'Invalid features detected'
            }
        
        # Make prediction
        proba = model.predict_proba(df)[0][1]  # Get probability of malicious class
        is_malicious = proba >= threshold
        
        return {
            'url': url,
            'is_malicious': bool(is_malicious),  # Convert numpy.bool_ to Python bool
            'confidence': float(proba),
            'status': 'success',
            'message': f'{"Malicious" if is_malicious else "Benign"} ({proba * 100:.2f}% confidence)'
        }
        
    except Exception as e:
        logger.error(f"Error predicting URL {url}: {str(e)}")
        return {
            'url': url,
            'is_malicious': False,
            'confidence': 0.0,
            'status': 'error',
            'message': f'Prediction failed: {str(e)}'
        }

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'model_loaded': model is not None,
        'whitelist_size': len(URLFeatureExtractor.WHITELIST)
    })

@app.route('/check-url', methods=['POST'])
def check_url():
    """
    Check if URL is malicious
    
    Expected JSON payload:
    {
        "url": "http://example.com",
        "threshold": 0.4  # optional, defaults to 0.4
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'error': 'Missing URL in request',
                'is_malicious': False,
                'confidence': 0.0
            }), 400
        
        url = data['url']
        threshold = data.get('threshold', 0.4)
        
        # Validate threshold
        if not 0.0 <= threshold <= 1.0:
            threshold = 0.4
        
        logger.info(f"Checking URL: {url}")
        
        result = predict_url(url, threshold)
        
        # Log result
        if result['is_malicious']:
            logger.warning(f"🔴 MALICIOUS: {url} ({result['confidence']*100:.2f}%)")
        else:
            logger.info(f"🟢 BENIGN: {url} ({result['confidence']*100:.2f}%)")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in check_url endpoint: {str(e)}")
        return jsonify({
            'error': str(e),
            'is_malicious': False,
            'confidence': 0.0,
            'status': 'error'
        }), 500

@app.route('/check-urls', methods=['POST'])
def check_multiple_urls():
    """
    Check multiple URLs at once
    
    Expected JSON payload:
    {
        "urls": ["http://example1.com", "http://example2.com"],
        "threshold": 0.4  # optional
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'urls' not in data:
            return jsonify({'error': 'Missing URLs in request'}), 400
        
        urls = data['urls']
        threshold = data.get('threshold', 0.4)
        
        if not isinstance(urls, list):
            return jsonify({'error': 'URLs must be a list'}), 400
        
        if len(urls) > 100:  # Limit batch size
            return jsonify({'error': 'Maximum 100 URLs per request'}), 400
        
        results = []
        for url in urls:
            result = predict_url(url, threshold)
            results.append(result)
        
        return jsonify({
            'results': results,
            'total_checked': len(results),
            'malicious_count': sum(1 for r in results if r['is_malicious'])
        })
        
    except Exception as e:
        logger.error(f"Error in check_multiple_urls endpoint: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/stats', methods=['GET'])
def get_stats():
    """Get server statistics"""
    return jsonify({
        'model_loaded': model is not None,
        'whitelist_domains': len(URLFeatureExtractor.WHITELIST),
        'feature_count': len(FEATURE_ORDER),
        'dns_cache_size': len(URLFeatureExtractor.dns_cache)
    })

if __name__ == '__main__':
    print("🚀 Starting Gmail URL Scanner Backend Server...")
    print("📊 Server Status:")
    print(f"   Model Loaded: {'✅' if model else '❌'}")
    print(f"   Whitelist Size: {len(URLFeatureExtractor.WHITELIST)} domains")
    print(f"   Features: {len(FEATURE_ORDER)}")
    print("\n🔗 API Endpoints:")
    print("   GET  /health          - Health check")
    print("   POST /check-url       - Check single URL")
    print("   POST /check-urls      - Check multiple URLs")
    print("   GET  /stats           - Server statistics")
    print("\n🌐 Server starting on http://localhost:5000")
    
    app.run(host='0.0.0.0', port=5000, debug=True)