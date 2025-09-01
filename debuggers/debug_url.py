#!/usr/bin/env python3

import pandas as pd
import xgboost as xgb
from feature_extractor import URLFeatureExtractor
import traceback

# Load model
model = xgb.XGBClassifier()
model.load_model("url_xgb_model.json")

# Load whitelist
URLFeatureExtractor.load_whitelist("raw_datasets/benign-urls.csv")

# Feature order
FEATURE_ORDER = [
    'url_len', 'dot_count', 'hyphen_count', 'has_ip',
    'suspicious_total', 'subdomain_count', 'tld_length',
    'url_entropy', 'has_a', 'has_mx', 'has_ns', 'ip_count'
]

def debug_url(url):
    print(f"\n🔍 Debugging URL: {url}")
    
    try:
        # Step 1: Create extractor
        print("  Step 1: Creating extractor...")
        extractor = URLFeatureExtractor(url)
        print(f"    Domain: {extractor.domain}")
        print(f"    Main domain: {extractor.main_domain}")
        
        # Step 2: Check whitelist
        print("  Step 2: Checking whitelist...")
        is_whitelisted = extractor.is_whitelisted()
        print(f"    Whitelisted: {is_whitelisted}")
        
        if is_whitelisted:
            print("  ✅ Whitelisted - skipping ML prediction")
            return
        
        # Step 3: Extract features
        print("  Step 3: Extracting features...")
        feat_dict = extractor.extract_features()
        
        if feat_dict is None:
            print("  ❌ Feature extraction returned None")
            return
            
        print(f"    Features extracted: {len(feat_dict)} features")
        for key, value in feat_dict.items():
            print(f"      {key}: {value}")
        
        # Step 4: Create DataFrame
        print("  Step 4: Creating DataFrame...")
        df = pd.DataFrame([[feat_dict[f] for f in FEATURE_ORDER]], columns=FEATURE_ORDER)
        print(f"    DataFrame shape: {df.shape}")
        print(f"    Has NaN values: {df.isnull().any().any()}")
        
        if df.isnull().any().any():
            print("    NaN values found:")
            for col in df.columns:
                if df[col].isnull().any():
                    print(f"      {col}: NaN")
        
        # Step 5: Make prediction
        print("  Step 5: Making prediction...")
        proba = model.predict_proba(df)[0][1]
        print(f"    Probability: {proba}")
        print(f"    Is malicious (>0.4): {proba >= 0.4}")
        
        print("  ✅ Success!")
        
    except Exception as e:
        print(f"  ❌ Error: {e}")
        print(f"    Error type: {type(e).__name__}")
        traceback.print_exc()

if __name__ == '__main__':
    # Test the problematic URLs
    test_urls = [
        "https://www.google.com",
        "http://secure-login-update.com", 
        "http://free-money-now.ru"
    ]
    
    for url in test_urls:
        debug_url(url)