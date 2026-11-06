import pickle
import pandas as pd
import numpy as np
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, classification_report,
    confusion_matrix, precision_recall_curve
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
        primary_threshold = pickle.load(f)
    print(f"Primary dataset optimal threshold: {primary_threshold:.4f}")

    print("\nLoading PhiUSIIL dataset.")
    df = pd.read_csv("data/PhiUSIIL_Phishing_URL_Dataset.csv")
    print(f"Rows loaded: {len(df)}")

    df['binary_label'] = df['label'].apply(lambda x: 0 if int(x) == 1 else 1)
    print(f"\nLabel distribution after remapping:")
    print(df['binary_label'].value_counts())

    print("\nRe-extracting 37 features from raw URLs.")
    print("This may take several minutes...")
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
    y_prob_raw = model.predict_proba(X)[:, 1]
    y_prob = 1 - y_prob_raw

    auc = roc_auc_score(y, y_prob)
    print(f"\nROC-AUC (corrected direction): {auc:.4f}")

    # Find optimal threshold on PhiUSIIL
    precisions, recalls, thresholds = precision_recall_curve(y, y_prob)
    f1s = np.where(
        (precisions + recalls) == 0, 0,
        2 * precisions * recalls / (precisions + recalls)
    )
    best_idx = np.argmax(f1s[:-1])
    best_threshold = thresholds[best_idx]
    print(f"Optimal threshold on PhiUSIIL: {best_threshold:.4f}")
    print(f"Primary dataset threshold:     {primary_threshold:.4f}")
    print(f"Threshold difference:          {abs(best_threshold - primary_threshold):.4f}")

    # Predictions at PhiUSIIL optimal threshold
    y_pred = (y_prob >= best_threshold).astype(int)

    print("\n-- Cross-Dataset Evaluation Results (PhiUSIIL) --")
    print(f"Dataset:   PhiUSIIL Phishing URL Dataset")
    print(f"URLs:      {len(df)}")
    print(f"\nAccuracy:  {accuracy_score(y, y_pred):.4f}")
    print(f"Precision: {precision_score(y, y_pred):.4f}")
    print(f"Recall:    {recall_score(y, y_pred):.4f}")
    print(f"F1-Score:  {f1_score(y, y_pred):.4f}")
    print(f"ROC-AUC:   {auc:.4f}")

    cm = confusion_matrix(y, y_pred)
    print(f"\n-- Confusion Matrix (at PhiUSIIL optimal threshold {best_threshold:.4f}) --")
    print(f"TN: {cm[0][0]}  FP: {cm[0][1]}")
    print(f"FN: {cm[1][0]}  TP: {cm[1][1]}")

    print("\n-- Classification Report --")
    print(classification_report(y, y_pred, target_names=['Legitimate', 'Phishing']))

    y_pred_primary = (y_prob >= primary_threshold).astype(int)
    print(f"\n-- At Primary Dataset Threshold ({primary_threshold:.4f}) --")
    print(f"Accuracy:  {accuracy_score(y, y_pred_primary):.4f}")
    print(f"Precision: {precision_score(y, y_pred_primary, zero_division=0):.4f}")
    print(f"Recall:    {recall_score(y, y_pred_primary, zero_division=0):.4f}")
    print(f"F1-Score:  {f1_score(y, y_pred_primary, zero_division=0):.4f}")
    cm2 = confusion_matrix(y, y_pred_primary)
    print(f"TN: {cm2[0][0]}  FP: {cm2[0][1]}")
    print(f"FN: {cm2[1][0]}  TP: {cm2[1][1]}")


if __name__ == "__main__":
    evaluate()