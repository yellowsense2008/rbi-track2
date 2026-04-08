import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import os

MODEL_PATH = "ml/anomaly_model.joblib"

LEGITIMATE_PATTERNS = [
    [10000000,  4.5,  500000,  2000],
    [5000000,   4.3,  200000,  1500],
    [8000000,   4.1,  300000,  1200],
    [50000000,  4.6,  1000000, 2200],
    [20000000,  4.4,  600000,  1900],
    [15000000,  4.2,  400000,  1600],
    [30000000,  4.5,  800000,  2100],
    [100000,    3.8,  5000,    800],
    [500000,    3.9,  20000,   1000],
    [1000000,   4.0,  50000,   1200],
    [2000000,   4.1,  80000,   1400],
    [3000000,   4.0,  100000,  1300],
    [200000,    3.7,  8000,    900],
    [400000,    3.9,  15000,   950],
    [700000,    4.0,  30000,   1100],
    [900000,    4.1,  40000,   1050],
    [1500000,   4.2,  60000,   1350],
    [2500000,   4.0,  90000,   1250],
    [4000000,   4.2,  150000,  1450],
    [6000000,   4.3,  250000,  1550],
]

def train_anomaly_model():
    X = np.array(LEGITIMATE_PATTERNS).astype(float)
    X[:, 0] = np.log1p(X[:, 0])
    X[:, 2] = np.log1p(X[:, 2])

    model = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        random_state=42
    )
    model.fit(X)
    joblib.dump(model, MODEL_PATH)
    print(f"Anomaly model trained on {len(LEGITIMATE_PATTERNS)} legitimate patterns")
    return model

def detect_anomaly(installs: int, rating: float,
                   ratings_count: int, description_length: int) -> dict:
    # High installs = legitimate, skip anomaly check
    if installs > 1000000:
        return {
            "is_anomaly": False,
            "anomaly_score": 0.5,
            "interpretation": "high install count — legitimate"
        }

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
    prediction = model.predict(X)[0]

    return {
        "is_anomaly": bool(prediction == -1),
        "anomaly_score": round(float(score), 4),
        "interpretation": "suspicious pattern" if prediction == -1 else "normal pattern"
    }

if __name__ == "__main__":
    train_anomaly_model()
    tests = [
        (215960334, 4.27, 1200000, 2500, "SBI YONO"),
        (55405959,  4.64, 890000,  1800, "mPokket"),
        (1000000,   4.0,  50000,   1200, "normal small app"),
        (500,       4.9,  10,      150,  "fake app"),
        (100,       5.0,  3,       80,   "brand new fake"),
        (800,       4.8,  8,       120,  "suspicious"),
        (200000,    3.8,  8000,    900,  "legit small app"),
    ]
    for installs, rating, ratings_count, desc_len, name in tests:
        result = detect_anomaly(installs, rating, ratings_count, desc_len)
        print(f"{name}: anomaly={result['is_anomaly']} | {result['interpretation']}")
