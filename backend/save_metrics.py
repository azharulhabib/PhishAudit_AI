import pickle
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score,
    recall_score, f1_score, roc_auc_score
)
from feature_extractor import features_to_vector, extract_features
from connection import SessionLocal
from database.models import ModelMetrics

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


def evaluate_and_save(model_version: str = "rf_v1.0"):
    print("Loading dataset for evaluation...")
    df = pd.read_csv("data/dataset_with_all_features v2.csv")
    df = df[df['type'].isin(['benign', 'phishing'])]
    df['binary_label'] = df['type'].map({'benign': 0, 'phishing': 1})
    df = df.dropna(subset=TRAINING_FEATURES + ['binary_label'])

    print("Loading trained model...")
    with open("models/rf_model.pkl", "rb") as f:
        model = pickle.load(f)

    X = df[TRAINING_FEATURES].values
    y = df['binary_label'].values

    print("Running evaluation on full dataset...")
    y_pred = model.predict(X)
    y_prob = model.predict_proba(X)[:, 1]

    acc  = round(accuracy_score(y, y_pred), 4)
    prec = round(precision_score(y, y_pred), 4)
    rec  = round(recall_score(y, y_pred), 4)
    f1   = round(f1_score(y, y_pred), 4)
    auc  = round(roc_auc_score(y, y_prob), 4)

    print(f"\nAccuracy:  {acc}")
    print(f"Precision: {prec}")
    print(f"Recall:    {rec}")
    print(f"F1-Score:  {f1}")
    print(f"ROC-AUC:   {auc}")

    db = SessionLocal()
    record = ModelMetrics(
        model_version=model_version,
        precision=prec,
        recall=rec,
        f1_score=f1,
        roc_auc=auc,
        urls_audited=len(df)
    )
    db.add(record)
    db.commit()
    db.close()

    print(f"\nMetrics saved to database as version: {model_version}")


if __name__ == "__main__":
    evaluate_and_save()