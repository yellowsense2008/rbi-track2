import sys
import os

# Force Python to look at the root 'rbi-track2' directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib
import warnings

# Suppress the pandas mixed DtypeWarning for clean output
warnings.filterwarnings('ignore')

from ml.features import MASTER_PERMISSIONS

def train_static_apk_model(csv_path="/home/Hp/rbi-track2/data/malware_permissions_dataset.csv", output_path="xgboost_permissions.joblib"):
    print(f"Loading dataset from {csv_path}...")
    if not os.path.exists(csv_path):
        print("ERROR: Dataset not found.")
        return

    # Load the Kaggle dataset
    df = pd.read_csv(csv_path)

    # Convert Kaggle's 'class' column (S/B) to 1s and 0s
    target_col = 'class' 
    if target_col in df.columns:
        df[target_col] = df[target_col].map({'S': 1, 'B': 0})
    else:
        print(f"ERROR: Target column '{target_col}' not found.")
        return

    # --- THE FIX: SMART COLUMN MAPPING ---
    # The CSV uses short names (INTERNET) instead of full names (android.permission.INTERNET)
    actual_columns_in_csv = []
    rename_mapping = {}

    for master_perm in MASTER_PERMISSIONS:
        short_name = master_perm.split('.')[-1] # Extracts 'INTERNET' from 'android.permission.INTERNET'
        
        if master_perm in df.columns:
            actual_columns_in_csv.append(master_perm)
        elif short_name in df.columns:
            actual_columns_in_csv.append(short_name)
            rename_mapping[short_name] = master_perm # Save the mapping so we can rename it back
            
    print(f"Found {len(actual_columns_in_csv)} out of {len(MASTER_PERMISSIONS)} master permissions in the CSV.")

    if len(actual_columns_in_csv) == 0:
        print("CRITICAL ERROR: Still cannot find matching columns. The CSV structure is entirely different.")
        return

    # Filter the dataset
    X = df[actual_columns_in_csv]
    y = df[target_col]

    # Rename the short columns back to the official Android 'android.permission.X' format
    # This guarantees the trained model perfectly matches your FastAPI backend
    if rename_mapping:
        X = X.rename(columns=rename_mapping)

    # Fill missing data
    X = X.fillna(0)

    print("Splitting data for evaluation...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    print("Training XGBoost Classifier...")
    model = xgb.XGBClassifier(
        n_estimators=100,
        learning_rate=0.1,
        max_depth=4,
        random_state=42,
        eval_metric='logloss'
    )

    model.fit(X_train, y_train)

    print("\n--- Model Evaluation ---")
    predictions = model.predict(X_test)
    print(f"Accuracy: {accuracy_score(y_test, predictions):.4f}")
    print(classification_report(y_test, predictions))

    print(f"\nSaving model to {output_path}...")
    joblib.dump(model, output_path)
    print("Training complete. The AI engine is ready.")

if __name__ == "__main__":
    train_static_apk_model()