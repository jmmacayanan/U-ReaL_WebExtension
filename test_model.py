#!/usr/bin/env python3

print("🔍 Testing model loading dependencies...")

try:
    import sklearn
    print(f"✅ scikit-learn version: {sklearn.__version__}")
except ImportError as e:
    print(f"❌ scikit-learn import failed: {e}")

try:
    import xgboost as xgb
    print(f"✅ XGBoost version: {xgb.__version__}")
except ImportError as e:
    print(f"❌ XGBoost import failed: {e}")

try:
    import pandas as pd
    print(f"✅ Pandas version: {pd.__version__}")
except ImportError as e:
    print(f"❌ Pandas import failed: {e}")

# Test XGBoost model creation
try:
    model = xgb.XGBClassifier()
    print("✅ XGBoost model creation successful")
except Exception as e:
    print(f"❌ XGBoost model creation failed: {e}")

# Test model loading with your file
try:
    model = xgb.XGBClassifier()
    model.load_model("url_xgb_model.json")
    print("✅ Model loaded successfully!")
except FileNotFoundError:
    print("❌ Model file 'url_xgb_model.json' not found")
except Exception as e:
    print(f"❌ Model loading failed: {e}")
    print(f"   Error type: {type(e).__name__}")

print("\n🔍 Python environment info:")
import sys
print(f"Python version: {sys.version}")
print(f"Python executable: {sys.executable}")