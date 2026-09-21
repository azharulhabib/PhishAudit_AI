import pickle
import pandas as pd
from feature_extractor import extract_features, features_to_vector

try:
    with open("models/rf_model.pkl", "rb") as f:
        MODEL = pickle.load(f)

    with open("models/feature_columns.pkl", "rb") as f:
        FEATURE_COLUMNS = pickle.load(f)

    with open("models/optimal_threshold.pkl", "rb") as f:
        THRESHOLD = pickle.load(f)

except FileNotFoundError as e:
    raise RuntimeError(
        "Model files not found. Run train_model.py before starting the server."
    ) from e


def predict(url: str) -> dict:
    try:
        features = extract_features(url)
        vector = features_to_vector(features)

        df = pd.DataFrame([vector], columns=FEATURE_COLUMNS)
        score = float(MODEL.predict_proba(df)[0][1])
        status = "Phishing" if score >= THRESHOLD else "Safe"

        return {
            "status":    status,
            "score":     round(score, 4),
            "threshold": round(THRESHOLD, 4),
            "features":  features,
            "error":     None
        }

    except Exception as e:
        return {
            "status":    "Error",
            "score":     0.0,
            "threshold": THRESHOLD,
            "features":  {},
            "error":     "Prediction failed."
        }