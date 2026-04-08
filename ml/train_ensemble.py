import sys
import os
import warnings

# Force Python to look at the root 'rbi-track2' directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier

# Suppress the pandas mixed DtypeWarning for clean output
warnings.filterwarnings('ignore')

from ml.features import MASTER_PERMISSIONS

def train_ensemble_model(csv_path="/home/Hp/rbi-track2/data/malware_permissions_dataset.csv", output_path="/home/Hp/rbi-track2/ml/ensemble_permissions.joblib"):
    print(f"Loading dataset from {csv_path}...")
    if not os.path.exists(csv_path):
        print("ERROR: Dataset not found.")
        return

    # Load the Kaggle dataset
    df = pd.read_csv(csv_path, low_memory=False)

    # Convert Kaggle's 'class' column (S/B) to 1s and 0s
    target_col = 'class' 
    if target_col in df.columns:
        df[target_col] = df[target_col].map({'S': 1, 'B': 0})
    else:
        print(f"ERROR: Target column '{target_col}' not found.")
        return

    # --- SMART COLUMN MAPPING (From your original train.py) ---
    actual_columns_in_csv = []
    rename_mapping = {}

    for master_perm in MASTER_PERMISSIONS:
        short_name = master_perm.split('.')[-1] 
        
        if master_perm in df.columns:
            actual_columns_in_csv.append(master_perm)
        elif short_name in df.columns:
            actual_columns_in_csv.append(short_name)
            rename_mapping[short_name] = master_perm 
            
    print(f"Found {len(actual_columns_in_csv)} out of {len(MASTER_PERMISSIONS)} master permissions in the CSV.")

    if len(actual_columns_in_csv) == 0:
        print("CRITICAL ERROR: Cannot find matching columns.")
        return

    # Filter the dataset to only what we need
    X = df[actual_columns_in_csv]
    y = df[target_col]

    # Drop any rows where the target answer is missing
    valid_indices = y.dropna().index
    X = X.loc[valid_indices]
    y = y.loc[valid_indices]

    # Rename short columns back to 'android.permission.X'
    if rename_mapping:
        X = X.rename(columns=rename_mapping)

    # Security Check: Ensure X has ALL 30 MASTER_PERMISSIONS
    # If the CSV didn't have one of our 30, add it as zeros so the math shapes match perfectly
    for perm in MASTER_PERMISSIONS:
        if perm not in X.columns:
            X[perm] = 0
            
    # Force the exact column order required by the FastAPI backend
    X = X[MASTER_PERMISSIONS]
    X = X.fillna(0).astype(int)
    y = y.astype(int)

    print("Splitting data for training...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    print("Initializing the ML models...")
    model_1 = XGBClassifier(eval_metric='logloss', random_state=42)
    model_2 = RandomForestClassifier(n_estimators=100, random_state=42)
    model_3 = LogisticRegression(max_iter=1000, random_state=42)

    # Wrap them in the Voting Ensemble
    ensemble = VotingClassifier(
        estimators=[('xgb', model_1), ('rf', model_2), ('lr', model_3)],
        voting='soft' # 'soft' averages the probability percentages
    )

    print("Training the multi-model ensemble. This might take a minute...")
    ensemble.fit(X_train, y_train)

    print(f"Saving model to {output_path}...")
    joblib.dump(ensemble, output_path)
    print("Success! Multi-model ensemble is ready.")

if __name__ == "__main__":
    train_ensemble_model()