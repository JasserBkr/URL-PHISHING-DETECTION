# 🛡️ Phishing URL Detector

A Machine Learning project that identifies malicious URLs using a **Random Forest Classifier**. This tool uses a dataset from the UCI Machine Learning Repository and provides "Explainable AI" insights using **SHAP** to show which URL features contributed most to the prediction.

---

## 📁 Project Structure

* **`train_model_py.py`**: Fetches the UCI dataset (ID: 967), trains the Random Forest model, and saves the artifacts.
* **`predictor_py.py`**: The main script for making predictions. It loads the model and processes URL features.
* **`Model/`**: Contains the saved model artifacts:
    * `model.pkl`: The trained classifier.
    * `explainer.pkl`: The SHAP explainer for transparency.
    * `feature_order.pkl`: Ensures correct feature alignment.
* **`Datasets/`**: Local CSV files used for training and testing.
* **`requirements.txt`**: List of dependencies for easy installation.

---

## 🚀 Getting Started

### 1. Installation
Clone this repository and install the necessary libraries:

```bash
pip install -r requirements.txt