import pickle
import os
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, classification_report,
    confusion_matrix, precision_recall_curve
)
from urllib.parse import urlparse

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


def get_domain(url):
    try:
        return urlparse(str(url)).hostname or ""
    except:
        return ""



def find_optimal_threshold(y_true, y_prob):
    """
    Finds the classification threshold that maximises F1 score.
    Addresses the concern that 0.5 is arbitrary — in phishing
    detection, false negatives and false positives have
    different operational costs.
    """
    precisions, recalls, thresholds = precision_recall_curve(
        y_true, y_prob
    )
    f1_scores = np.where(
        (precisions + recalls) == 0,
        0,
        2 * (precisions * recalls) / (precisions + recalls)
    )
    optimal_idx = np.argmax(f1_scores[:-1])
    return thresholds[optimal_idx], f1_scores[optimal_idx]


def train():
    print("Loading dataset.")
    df = pd.read_csv("data/dataset_with_all_features v2.csv")
    print(f"Rows loaded: {len(df)}")

    print("\nFiltering to benign and phishing only.")
    df = df[df['type'].isin(['benign', 'phishing'])].copy()
    print(f"Rows after class filter: {len(df)}")

    print("\nRemoving duplicate URLs.")
    before = len(df)
    df = df.drop_duplicates(subset=['url'])
    print(f"Removed {before - len(df)} duplicates. Rows remaining: {len(df)}")

    print("\nDropping rows with missing feature values.")
    df = df.dropna(subset=TRAINING_FEATURES + ['type'])
    print(f"Rows after null removal: {len(df)}")

    df['binary_label'] = df['type'].map({'benign': 0, 'phishing': 1})

    print(f"\nLabel distribution:")
    print(df['binary_label'].value_counts())
    print(f"Phishing ratio: {df['binary_label'].mean()*100:.2f}%")

    X = df[TRAINING_FEATURES]
    y = df['binary_label']

    print("\nApplying stratified row-level train/test split.")
    print("Domain-level split was evaluated but caused severe class")
    print("imbalance due to low benign domain diversity (311 unique")
    print("benign domains vs 12,105 phishing domains). Row-level")
    print("split with documented domain overlap check is used instead.")


    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )
    print(f"\nTrain size: {len(X_train)} rows")
    print(f"Test size:  {len(X_test)} rows")

    print("\nChecking domain overlap between train and test sets...")
    df_split = df.copy()
    df_split['_domain'] = df_split['url'].apply(get_domain)
    train_domains = set(df_split.loc[X_train.index, '_domain'])
    test_domains  = set(df_split.loc[X_test.index, '_domain'])
    overlap       = train_domains.intersection(test_domains)
    print(f"Train domains: {len(train_domains)}")
    print(f"Test domains:  {len(test_domains)}")
    print(f"Overlapping:   {len(overlap)} ({len(overlap)/len(test_domains)*100:.2f}%)")
    print("Note: Overlap documented as known limitation in report.")


    print(f"\nTrain label distribution:")
    print(y_train.value_counts())
    print(f"\nTest label distribution:")
    print(y_test.value_counts())

    print("\nFitting RandomForestClassifier.")

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

    print("\n-- Evaluation Metrics (Test Set) --")
    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec  = recall_score(y_test, y_pred)
    f1   = f1_score(y_test, y_pred)
    auc  = roc_auc_score(y_test, y_prob)

    print(f"Accuracy:  {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print(f"ROC-AUC:   {auc:.4f}")

    print("\n-- Confusion Matrix --")
    cm = confusion_matrix(y_test, y_pred)
    print(f"True Negatives  (TN): {cm[0][0]}")
    print(f"False Positives (FP): {cm[0][1]}")
    print(f"False Negatives (FN): {cm[1][0]}")
    print(f"True Positives  (TP): {cm[1][1]}")


    print("\n-- Classification Report --")
    print(classification_report(
        y_test, y_pred,
        target_names=['Benign', 'Phishing']
    ))

    print("\n-- Cost-Sensitive Threshold Analysis --")
    optimal_thresh, optimal_f1 = find_optimal_threshold(
        y_test, y_prob
    )
    print(f"Default threshold (0.50) F1:  {f1:.4f}")
    print(f"Optimal threshold:             {optimal_thresh:.4f}")
    print(f"Optimal threshold F1:          {optimal_f1:.4f}")

    y_pred_optimal = (y_prob >= optimal_thresh).astype(int)
    print(f"Precision at optimal threshold: {precision_score(y_test, y_pred_optimal):.4f}")
    print(f"Recall at optimal threshold:    {recall_score(y_test, y_pred_optimal):.4f}")

    print("\n-- Top 10 Features by Importance --")


    importance = pd.Series(
        model.feature_importances_,
        index=TRAINING_FEATURES
    ).sort_values(ascending=False)

    print(importance.head(10))

    print("\n-- 5-Fold Cross-Validation --")
    print("Running on full dataset (this may take several minutes)...")
    X_full = df[TRAINING_FEATURES]
    y_full = df['binary_label']

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_results = cross_validate(
        RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        ),
        X, y,
        cv=cv,
        scoring=['accuracy', 'precision', 'recall', 'f1', 'roc_auc'],
        return_train_score=False
    )

    print(f"\nCross-Validation Results (5-Fold):")
    print(f"Accuracy:  {cv_results['test_accuracy'].mean():.4f} +/- {cv_results['test_accuracy'].std():.4f}")
    print(f"Precision: {cv_results['test_precision'].mean():.4f} +/- {cv_results['test_precision'].std():.4f}")
    print(f"Recall:    {cv_results['test_recall'].mean():.4f} +/- {cv_results['test_recall'].std():.4f}")
    print(f"F1-Score:  {cv_results['test_f1'].mean():.4f} +/- {cv_results['test_f1'].std():.4f}")
    print(f"ROC-AUC:   {cv_results['test_roc_auc'].mean():.4f} +/- {cv_results['test_roc_auc'].std():.4f}")



    os.makedirs("models", exist_ok=True)
    model_path     = "models/rf_model.pkl"
    features_path  = "models/feature_columns.pkl"
    threshold_path = "models/optimal_threshold.pkl"


    with open(model_path, "wb") as f:
        pickle.dump(model, f)

    with open(features_path, "wb") as f:
        pickle.dump(TRAINING_FEATURES, f)

    with open(threshold_path, "wb") as f:
        pickle.dump(float(optimal_thresh), f)



    print(f"\nModel serialized to {model_path}")
    print(f"Feature list serialized to {features_path}")
    print(f"Optimal threshold saved to {threshold_path}")



if __name__ == "__main__":
    train()