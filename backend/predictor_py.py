import joblib
import pandas as pd
import numpy as np
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent
MODEL_DIR = CURRENT_DIR / "Model"

model = joblib.load(MODEL_DIR / "model1.pkl")
explainer = joblib.load(MODEL_DIR / "explainer1.pkl")
feature_order = joblib.load(MODEL_DIR / "feature_order1.pkl")

def predict_url(features_df: pd.DataFrame) -> dict:

    # Ensure correct feature order
    features_df = features_df[feature_order]

    # -------- model prediction --------
    prediction   = model.predict(features_df)[0]
    probabilities = model.predict_proba(features_df)[0]

    # class 0 = phishing, class 1 = legitimate
    phishing_prob  = float(probabilities[0])
    legit_prob     = float(probabilities[1])

    # Return the probability of the PREDICTED class
    probability = legit_prob if prediction == 1 else phishing_prob

    # -------- SHAP explanation --------
    shap_values = explainer.shap_values(features_df)

    if isinstance(shap_values, list):
        shap_vals = shap_values[1][0]
    elif len(shap_values.shape) == 3:
        shap_vals = shap_values[0, :, 1]
    elif len(shap_values.shape) == 2:
        shap_vals = shap_values[0]
    else:
        shap_vals = shap_values[0]

    importance = pd.Series(np.abs(shap_vals), index=features_df.columns)

    # Top 4 as percentage of ALL features (not just top 4)
    top4 = importance.sort_values(ascending=False).head(4)
    total_importance = importance.sum()

    top_features_percent = {
        feature: round(float((value / total_importance) * 100), 2)
        for feature, value in top4.items()
    }

    return {
        "prediction":  "phishing" if prediction == 0 else "legitimate",
        "probability": round(probability, 4),
        "top_features": top_features_percent
    }