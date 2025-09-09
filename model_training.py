if __name__ == '__main__':
    import pandas as pd
    import xgboost as xgb
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score, roc_auc_score, confusion_matrix
    import concurrent.futures
    from tqdm import tqdm
    from feature_extractor import URLFeatureExtractor
    import numpy as np
    import matplotlib.pyplot as plt

    # -------- Feature extraction helper --------
    def safe_extract_features(index_url):
        i, url = index_url
        try:
            extractor = URLFeatureExtractor(url)
            features = extractor.extract_features()
            if features is None:
                return None
            return i, features
        except Exception:
            return None

    # -------- Load dataset --------
    df = pd.read_csv("url_dataset_balanced.csv")
    print("Label distribution:\n", df['label'].value_counts())


    # -------- Function for learning curve visualization --------
    def plot_learning_curve(evals_result):
        train_rmse = evals_result['train']['rmse']
        val_rmse = evals_result['validation']['rmse']
        plt.figure(figsize=(8, 5))
        plt.plot(train_rmse, label='Training rmse')
        plt.plot(val_rmse, label='Validation rmse')
        plt.xlabel('Boosting Rounds')
        plt.ylabel('rmse')
        plt.title('XGBoost Training vs Validation rmse')
        plt.legend()
        plt.grid(True)
        plt.tight_layout()
        plt.savefig("learning_curve.png")
        plt.show()

    # -------- Extract features concurrently --------
    print("Extracting features...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(tqdm(executor.map(safe_extract_features, enumerate(df['url'])), total=len(df)))

    valid_results = [res for res in results if res is not None]
    if not valid_results:
        raise Exception("No valid URLs were processed. Check your dataset.")

    indices, feature_rows = zip(*valid_results)
    features_df = pd.DataFrame(feature_rows)
    labels = df.loc[list(indices), 'label'].reset_index(drop=True)


    # -------- Train-Test Split --------
    X_train, X_test, y_train, y_test = train_test_split(
        features_df, labels, test_size=0.2, random_state=42, stratify=labels
    )

    # -------- Convert to DMatrix for xgboost.train --------
    dtrain = xgb.DMatrix(X_train, label=y_train)
    dtest = xgb.DMatrix(X_test, label=y_test)

        # -------- Training parameters --------
    params = {
        "objective": "binary:logistic",   # Use logistic regression for binary classification (output = probability of class 1)
        "eval_metric": "rmse",            # Evaluation metric = Root Mean Squared Error
        "max_depth": 6,                   # Maximum depth of trees (higher = more complex model, risk of overfitting)
        "learning_rate": 0.1,             # Step size shrinkage (controls contribution of each tree; smaller = slower but more accurate training)
    }


    print("Training model...")
    evals = [(dtrain, "train"), (dtest, "validation")]
    evals_result = {}

    bst = xgb.train(
        params=params,
        dtrain=dtrain,
        num_boost_round=10000, 
        evals=evals,
        evals_result=evals_result,
        verbose_eval=100,      
        early_stopping_rounds=50
    )


    # -------- Evaluate on training set --------
    y_train_pred_prob = bst.predict(dtrain)
    y_train_pred = (y_train_pred_prob > 0.5).astype(int)

    print("\nTraining Performance")
    print("Accuracy:", accuracy_score(y_train, y_train_pred))
    print(classification_report(y_train, y_train_pred, digits=2))
    print("ROC-AUC:", roc_auc_score(y_train, y_train_pred_prob))
    print("Confusion Matrix:\n", confusion_matrix(y_train, y_train_pred))

    # -------- Evaluate on validation/test set --------
    y_test_pred_prob = bst.predict(dtest)
    y_test_pred = (y_test_pred_prob > 0.5).astype(int)

    print("\nValidation Performance")
    print("Accuracy:", accuracy_score(y_test, y_test_pred))
    print(classification_report(y_test, y_test_pred, digits=2))
    print("ROC-AUC:", roc_auc_score(y_test, y_test_pred_prob))
    print("Confusion Matrix:\n", confusion_matrix(y_test, y_test_pred))

    # -------- Save model --------
    bst.save_model("url_xgb_model_v2.json")
    print("Model saved as url_xgb_model_v2.json")
    plot_learning_curve(evals_result)