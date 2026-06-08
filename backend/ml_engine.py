import pickle
from feature_extractor import extract_features, features_to_vector

try:
    with open("models/rf_model.pkl", "rb") as f:
        MODEL = pickle.load(f)

    with open("models/feature_columns.pkl", "rb") as f:
        FEATURE_COLUMNS = pickle.load(f)

except FileNotFoundError as e:
    raise RuntimeError(
        "Model files not found."
    ) from e


def predict(url: str) -> dict:
    if MODEL is None:
        return {
            "status": "Error",
            "score": 0.0,
            "features": {},
            "error": "Model unavailable."
        }

    try:
        features = extract_features(url)
        vector = features_to_vector(features)
        score = float(MODEL.predict_proba([vector])[0][1])
        status = "Phishing" if score >= 0.5 else "Safe"

        return {
            "status": status,
            "score": round(score, 4),
            "features": features,
            "error": None
        }

    except Exception as e:
        print(f"Prediction failed for URL '{url}': {e}")
        return {
            "status": "Error",
            "score": 0.0,
            "features": {},
            "error": "Prediction failed."
        }