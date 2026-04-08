import joblib
import os
import numpy as np

# Resolve the absolute path to the new ensemble model file
MODEL_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'ml', 'ensemble_permissions.joblib'))

# Keep the model in memory so we don't reload it on every single API ping
_model = None

def load_ensemble_model():
    """Loads the VotingClassifier into global memory if it isn't already there."""
    global _model
    if _model is None:
        if os.path.exists(MODEL_PATH):
            _model = joblib.load(MODEL_PATH)
            print("Ensemble ML (XGBoost + RF + LR) loaded into memory.")
        else:
            print(f"WARNING: Model not found at {MODEL_PATH}. Run ml/train_ensemble.py first.")
    return _model

def predict_apk_risk(feature_vector: np.ndarray) -> dict:
    """
    Takes a 2D numpy array of permissions, runs them through the 3-model 
    VotingClassifier, and returns the consensus AI risk score.
    """
    model = load_ensemble_model()
    
    if model is None:
        return {"error": "AI Model not initialized", "risk_score": 0.0, "verdict": "UNKNOWN"}

    try:
        # predict_proba returns [[probability_of_safe, probability_of_malware]]
        # We want index 1 (Malware)
        probabilities = model.predict_proba(feature_vector)
        malware_probability = float(probabilities[0][1])

        # Align with the RBI risk thresholds
        if malware_probability >= 0.60:
            verdict = "HIGH"
        elif malware_probability >= 0.30:
            verdict = "MEDIUM"
        else:
            verdict = "LOW"

        return {
            "status": "success",
            "risk_score": round(malware_probability, 3),
            "verdict": verdict,
            "engines_used": "Ensemble ML (XGBoost + Random Forest + Logistic Regression)"
        }
        
    except Exception as e:
        return {"status": "error", "message": str(e), "risk_score": 0.0, "verdict": "ERROR"}

# Load the model immediately when the server starts
load_ensemble_model()