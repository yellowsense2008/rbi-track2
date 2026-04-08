import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import os

MODEL_PATH = "ml/anomaly_model.joblib"

# Training data — known legitimate app patterns
# [installs, rating, ratings_count, description_length]
LEGITIMATE_PATTERNS = [
    [215960334, 4.27, 1200000, 2500],  # SBI YONO
    [55405959,  4.64, 890000,  1800],  # mPokket (high installs = legitimate pattern)
    [10000000,  4.5,  500000,  2000],  # typical large app
    [5000000,   4.3,  200000,  1500],
    [8000000,   4.1,  300000,  1200],
    [50000000,  4.6,  1000000, 2200],
    [20000000,  4.4,  600000,  1900],
    [15000000,  4.2,  400000,  1600],
    [30000000,  4.5,  800000,  2100],
    [100000,    3.9,  5000,    800],   # smaller legitimate app
    [500000,    4.0,  20000,   1000],
    [1000000,   4.2,  50000,   1200],
    [2000000,   4.3,  80000,   1400],
    [3000000,   4.1,  100000,  1300],
    [200000,    4.0,  8000,    900],
]

# Known suspicious patterns
SUSPICIOUS_PATTERNS = [
    [500,   4.9, 10,   150],   # very few installs, perfect rating
    [100,   5.0, 3,    80],    # brand new fake app
    [1000,  4.8, 15,   200],
    [50,    4.9, 2,    50],
    [200,   5.0, 5,    100],
    [800,   4.7, 8,    120],
    [300,   4.9, 4,    90],
    [150,   5.0, 3,    60],
    [400,   4.8, 6,    110],
    [600,   4.9, 9,    130],
]

def train_anomaly_model():
    X = np.array(LEGITIMATE_PATTERNS + SUSPICIOUS_PATTERNS)
    # Log transform installs to handle scale difference
    X[:, 0] = np.log1p(X[:, 0])
    X[:, 2] = np.log1p(X[:, 2])

    model = IsolationForest(
        n_estimators=100,
        contamination=0.3,
        random_state=42
    )
    model.fit(X)
    joblib.dump(model, MODEL_PATH)
    print(f"Anomaly model saved to {MODEL_PATH}")
    return model

def detect_anomaly(installs: int, rating: float,
                   ratings_count: int, description_length: int) -> dict:
    if not os.path.exists(MODEL_PATH):
        train_anomaly_model()

    model = joblib.load(MODEL_PATH)
    X = np.array([[
        np.log1p(installs),
        rating,
        np.log1p(ratings_count),
        description_length
    ]])

    score = model.decision_function(X)[0]
    prediction = model.predict(X)[0]  # -1 = anomaly, 1 = normal

    return {
        "is_anomaly": prediction == -1,
        "anomaly_score": round(float(score), 4),
        "interpretation": "suspicious pattern" if prediction == -1 else "normal pattern"
    }

if __name__ == "__main__":
    train_anomaly_model()
    # Test
    print(detect_anomaly(215960334, 4.27, 1200000, 2500))  # SBI - normal
    print(detect_anomaly(500, 4.9, 10, 150))               # fake - anomaly