import xgboost as xgb

# Path to your trained model JSON or binary file
MODEL_PATH = "url_xgb_model_v2.json"

try:
    model = xgb.XGBClassifier()
    model.load_model(MODEL_PATH)

    # Extract feature names from the underlying booster
    feature_names = model.get_booster().feature_names
    print(f"📊 Model expects {len(feature_names)} features:\n")
    for i, name in enumerate(feature_names, start=1):
        print(f"{i:2d}. {name}")

except Exception as e:
    print(f"❌ Failed to load model or read features: {e}")
