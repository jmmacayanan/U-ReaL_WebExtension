from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import xgboost as xgb
from feature_extractor import URLFeatureExtractor
import logging
import requests

# -----------------------------
# Setup logging
# -----------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)  # Enable CORS for Chrome extension


# -----------------------------
# Load Trained Model
# -----------------------------
try:
    model = xgb.XGBClassifier()
    model.load_model("url_xgb_model_v2.json")
    logger.info("XGBoost model loaded successfully")
except Exception as e:
    logger.error(f"Failed to load model: {e}")
    model = None

# -----------------------------
# Load Whitelist
# -----------------------------
try:
    URLFeatureExtractor.load_whitelist("raw_datasets/benign-urls.csv")
    logger.info(f"Whitelist loaded with {len(URLFeatureExtractor.WHITELIST)} domains")
except Exception as e:
    logger.error(f"Failed to load whitelist: {e}")

# -----------------------------
# Feature order (MUST match training!)
# -----------------------------
FEATURE_ORDER = [
    'URL_length',
    'Domain_length',
    'No_of_dots',
    'token_count',
    'largest_token',
    'domain_token_count',
    'largest_domain',
    'path_token_count',
    'largest_path',
    'sec_sen_word_cnt',
    'IPaddress_presence',
    'exe_in_url',
    'hyphen_count_url',
]

def unshorten_url(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=10)
        return response.url
    except requests.RequestException as e:
        return url
    

# -----------------------------
# Prediction function
# -----------------------------
def predict_url(url):
    threshold = 0.5
    url = unshorten_url(url)
    try:
        extractor = URLFeatureExtractor(url)

        # STEP 1: Whitelist check
        if extractor.is_whitelisted():
            logger.info(f"WHITELISTED: {url}")
            return {
                'url': url,
                'is_malicious': False,
                'confidence': 0.0,
                'status': 'whitelisted',
                'message': 'Domain is whitelisted - trusted'
            }

        # STEP 2: Extract features
        feat_dict = extractor.extract_features()
        if feat_dict is None:
            return {
                'url': url,
                'is_malicious': False,
                'confidence': 0.0,
                'status': 'error',
                'message': 'Feature extraction failed'
            }

        df = pd.DataFrame([[feat_dict[f] for f in FEATURE_ORDER]], columns=FEATURE_ORDER)
        if df.isnull().any().any():
            return {
                'url': url,
                'is_malicious': False,
                'confidence': 0.0,
                'status': 'error',
                'message': 'Invalid features detected'
            }

        # STEP 3: Model prediction
        proba = model.predict_proba(df)[0][1]
        is_malicious = proba >= threshold

        result = {
            'url': url,
            'is_malicious': bool(is_malicious),
            'confidence': float(proba),
            'status': 'analyzed',
            'message': f'{"Malicious" if is_malicious else "Benign"} ({proba * 100:.2f}% confidence)'
        }

        if is_malicious:
            logger.warning(f"MALICIOUS: {url} ({proba*100:.2f}%)")
        else:
            logger.info(f"BENIGN: {url} ({proba*100:.2f}%)")

        return result

    except Exception as e:
        logger.error(f"Error predicting URL {url}: {str(e)}")
        return {
            'url': url,
            'is_malicious': False,
            'confidence': 0.0,
            'status': 'error',
            'message': f'Prediction failed: {str(e)}'
        }

# -----------------------------
# Flask Endpoints
# -----------------------------
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'model_loaded': model is not None,
        'whitelist_size': len(URLFeatureExtractor.WHITELIST),
        'features_count': len(FEATURE_ORDER),
        'features': FEATURE_ORDER
    })

@app.route('/check-url', methods=['POST'])
def check_url():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing URL in request'}), 400

    url = data['url']

    result = predict_url(url)
    return jsonify(result)

if __name__ == '__main__':
    print("🚀 Starting Gmail URL Scanner Backend Server...")
    print(f"   Model Loaded: {'Yes' if model else 'No'}")
    print(f"   Whitelist Size: {len(URLFeatureExtractor.WHITELIST)} domains")
    print(f"   Features: {len(FEATURE_ORDER)} ({', '.join(FEATURE_ORDER)})")
    app.run(host='127.0.0.1', port=5000, debug=True)
