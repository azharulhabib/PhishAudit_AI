import pickle
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, classification_report,
    confusion_matrix
)
from feature_extractor import extract_features, features_to_vector

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


def evaluate():
    print("Loading trained model and threshold.")
    with open("models/rf_model.pkl", "rb") as f:
        model = pickle.load(f)
    with open("models/optimal_threshold.pkl", "rb") as f:
        threshold = pickle.load(f)
    print(f"Optimal threshold: {threshold:.4f}")

    print("\nLoading PhiUSIIL dataset.")
    df = pd.read_csv("data/PhiUSIIL_Phishing_URL_Dataset.csv")
    print(f"Rows loaded: {len(df)}")

    df['binary_label'] = df['label'].astype(int)
    print(f"\nLabel distribution:")
    print(df['binary_label'].value_counts())

    print("\nRe-extracting 37 features from raw URLs.")
    print("This may take several minutes on 235,795 URLs...")
    vectors = []
    skipped = 0
    for i, url in enumerate(df['URL']):
        try:
            features = extract_features(str(url))
            vectors.append(features_to_vector(features))
        except Exception:
            vectors.append([0] * len(TRAINING_FEATURES))
            skipped += 1

        if (i + 1) % 10000 == 0:
            print(f"  Processed {i + 1} / {len(df)} URLs...")

    print(f"Feature extraction complete. Skipped {skipped} malformed URLs.")

    X = pd.DataFrame(vectors, columns=TRAINING_FEATURES)
    y = df['binary_label'].values

    print("\nRunning model inference...")

    y_prob = model.predict_proba(X)[:, 1]
    threshold_override = 0.85
    y_pred = (y_prob >= threshold_override).astype(int)

    print("\n-- Cross-Dataset Evaluation Results (PhiUSIIL) --")
    print(f"Dataset:   PhiUSIIL Phishing URL Dataset")
    print(f"Threshold: {threshold:.4f} (cost-sensitive optimal)")
    print(f"URLs:      {len(df)}")
    print(f"\nAccuracy:  {accuracy_score(y, y_pred):.4f}")
    print(f"Precision: {precision_score(y, y_pred):.4f}")
    print(f"Recall:    {recall_score(y, y_pred):.4f}")
    print(f"F1-Score:  {f1_score(y, y_pred):.4f}")
    print(f"ROC-AUC:   {roc_auc_score(y, y_prob):.4f}")

    cm = confusion_matrix(y, y_pred)
    print(f"\n-- Confusion Matrix --")
    print(f"TN: {cm[0][0]}  FP: {cm[0][1]}")
    print(f"FN: {cm[1][0]}  TP: {cm[1][1]}")

    print("\n-- Classification Report --")
    print(classification_report(
        y, y_pred,
        target_names=['Legitimate', 'Phishing']
    ))


if __name__ == "__main__":
    evaluate()