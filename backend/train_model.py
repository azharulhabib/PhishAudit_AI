import pickle
import os
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, classification_report
)

TRAINING_FEATURES = [
    'url_len', '@', '?', '-', '=', '.', '#', '%',
    '+', '$', '!', '*', ',', '//', 'digits', 'letters',
    'https', 'having_ip_address', 'abnormal_url',
    'Shortining_Service', 'phish_has_brand',
    'phish_brand_in_subdomain', 'phish_brand_in_path',
    'phish_hyphen_count', 'phish_digit_count',
    'phish_long_domain', 'phish_many_subdomains',
    'phish_suspicious_tld', 'phish_keyword_count',
    'phish_has_redirect', 'phish_param_count',
    'phish_encoded_chars', 'adv_domain_ngram_entropy',
    'adv_path_entropy', 'adv_digit_ratio',
    'adv_subdomain_count', 'adv_token_count',
]


def train():
    print("Loading dataset.")
    df = pd.read_csv("data/dataset_with_all_features v2.csv")
    print(f"Rows loaded: {len(df)}")

    df = df[df['type'].isin(['benign', 'phishing'])]
    print(f"Rows after class filter: {len(df)}")

    df['binary_label'] = df['type'].map(
        {'benign': 0, 'phishing': 1}
    )
    print(f"Label distribution:\n{df['binary_label'].value_counts()}")

    df = df.dropna(subset=TRAINING_FEATURES + ['binary_label'])
    print(f"Rows after null removal: {len(df)}")

    X = df[TRAINING_FEATURES]
    y = df['binary_label']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )
    print(f"Train size: {len(X_train)} | Test size: {len(X_test)}")

    print("Fitting RandomForestClassifier.")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced'
    )
    model.fit(X_train, y_train)
    print("Model fitting complete.")

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    print("\n-- Evaluation Metrics --")
    print(f"Accuracy:  {accuracy_score(y_test, y_pred):.4f}")
    print(f"Precision: {precision_score(y_test, y_pred):.4f}")
    print(f"Recall:    {recall_score(y_test, y_pred):.4f}")
    print(f"F1-Score:  {f1_score(y_test, y_pred):.4f}")
    print(f"ROC-AUC:   {roc_auc_score(y_test, y_prob):.4f}")

    print("\n-- Classification Report --")
    print(classification_report(
        y_test, y_pred,
        target_names=['Benign', 'Phishing']
    ))

    importance = pd.Series(
        model.feature_importances_,
        index=TRAINING_FEATURES
    ).sort_values(ascending=False)
    print("\n-- Top 10 Features by Importance --")
    print(importance.head(10))

    os.makedirs("models", exist_ok=True)
    model_path = "models/rf_model.pkl"
    features_path = "models/feature_columns.pkl"

    with open(model_path, "wb") as f:
        pickle.dump(model, f)

    with open(features_path, "wb") as f:
        pickle.dump(TRAINING_FEATURES, f)

    print(f"\nModel serialized to {model_path}")
    print(f"Feature list serialized to {features_path}")


if __name__ == "__main__":
    train()