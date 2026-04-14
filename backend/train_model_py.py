from ucimlrepo import fetch_ucirepo
import pandas as pd
import joblib
import shap

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

# fetch dataset
phiusiil_phishing_url_website = fetch_ucirepo(id=967)

# data (as pandas dataframes)
X = phiusiil_phishing_url_website.data.features
y = phiusiil_phishing_url_website.data.targets

X = X.drop(['URL','Domain','TLD','Title'],axis=1)

X = X.drop(['URLSimilarityIndex', "LineOfCode", 
            "LargestLineLength", 
            "NoOfPopup", 
            "Robots" , "TLDLegitimateProb", 
            "URLSimilarityIndex",   "DomainTitleMatchScore", 
            "URLTitleMatchScore",  "Bank", 
            "Pay", 
            "Crypto", 
            "HasSocialNet", 
            "HasCopyrightInfo"],axis=1)

X = X.astype(float)

pd.set_option('display.max_columns', None)

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

model = RandomForestClassifier(
    n_estimators=300,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

print("\nEvaluating model...")

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print("Accuracy:", accuracy)
print("\nClassification Report:\n")
print(classification_report(y_test, y_pred,digits=6))

print("\nTop global features:")

feature_importance = pd.Series(
    model.feature_importances_,
    index=X.columns
).sort_values(ascending=False)

print(feature_importance.head(10))

print("\nCreating SHAP explainer...")

explainer = shap.TreeExplainer(model)


# -------- save artifacts --------
print("\nSaving model artifacts...")

joblib.dump(model, "model.pkl")
joblib.dump(explainer, "explainer.pkl")
joblib.dump(list(X.columns), "feature_order.pkl")

print("Saved files:")
print("- model.pkl")
print("- explainer.pkl")
print("- feature_order.pkl")


print("\nTraining complete.")



