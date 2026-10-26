"""
Cybersecurity Anomaly Detection Model using Isolation Forest & Feature Engineering
Trains an unsupervised Isolation Forest on synthetic network telemetry and saves the pipeline.
"""
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_FILE = os.path.join(MODEL_DIR, "anomaly_model.joblib")
SCALER_FILE = os.path.join(MODEL_DIR, "scaler.joblib")

FEATURES = [
    "request_rate_per_min",
    "failed_logins_last_10m",
    "payload_size_kb",
    "geo_deviation_score",
    "unique_ports_scanned",
    "error_rate_percent"
]

def generate_synthetic_training_data(n_samples=5000, contamination=0.08):
    """
    Generates synthetic network traffic behavior:
    - Normal behavior: baseline traffic
    - Anomalous behavior: brute-force bursts, large payload injections, port scans, high geo deviation
    """
    np.random.seed(42)
    n_normal = int(n_samples * (1 - contamination))
    n_anom = n_samples - n_normal

    # Normal traffic distributions
    normal_data = {
        "request_rate_per_min": np.clip(np.random.normal(loc=30, scale=12, size=n_normal), 1, 120),
        "failed_logins_last_10m": np.random.choice([0, 1, 2], p=[0.85, 0.12, 0.03], size=n_normal),
        "payload_size_kb": np.clip(np.random.exponential(scale=15, size=n_normal), 0.5, 150),
        "geo_deviation_score": np.clip(np.random.beta(a=1, b=5, size=n_normal) * 20, 0, 30),
        "unique_ports_scanned": np.random.choice([1, 2], p=[0.95, 0.05], size=n_normal),
        "error_rate_percent": np.clip(np.random.normal(loc=2.0, scale=1.5, size=n_normal), 0, 10)
    }

    # Anomalous traffic distributions
    anom_data = {
        "request_rate_per_min": np.random.uniform(150, 1500, size=n_anom),
        "failed_logins_last_10m": np.random.randint(5, 50, size=n_anom),
        "payload_size_kb": np.random.uniform(200, 5000, size=n_anom),
        "geo_deviation_score": np.random.uniform(50, 100, size=n_anom),
        "unique_ports_scanned": np.random.randint(5, 120, size=n_anom),
        "error_rate_percent": np.random.uniform(25, 95, size=n_anom)
    }

    df_normal = pd.DataFrame(normal_data)
    df_anom = pd.DataFrame(anom_data)
    df = pd.concat([df_normal, df_anom], ignore_index=True)
    return df

def train_and_save_model():
    print("[*] Generating synthetic telemetry training dataset...")
    df = generate_synthetic_training_data()
    X = df[FEATURES].values

    print("[*] Fitting StandardScaler...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    print("[*] Training Isolation Forest detector...")
    model = IsolationForest(
        n_estimators=150,
        contamination=0.08,
        random_state=42,
        bootstrap=False
    )
    model.fit(X_scaled)

    joblib.dump(model, MODEL_FILE)
    joblib.dump(scaler, SCALER_FILE)
    print(f"[+] Model saved to {MODEL_FILE}")
    print(f"[+] Scaler saved to {SCALER_FILE}")
    return model, scaler

def load_or_train():
    if os.path.exists(MODEL_FILE) and os.path.exists(SCALER_FILE):
        try:
            model = joblib.load(MODEL_FILE)
            scaler = joblib.load(SCALER_FILE)
            return model, scaler
        except Exception as e:
            print(f"[-] Error loading model: {e}. Retraining...")
    return train_and_save_model()

if __name__ == "__main__":
    train_and_save_model()
