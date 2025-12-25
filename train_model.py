import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

def train_anomaly_detector():
    df = pd.read_csv("training_data.csv")
    
    features = ["proto", "len", "sport", "dport"]
    X = df[features]
    
    print(f"[!] Training on {len(X)} samples...")
    
    # We increase n_estimators for better accuracy 
    # and adjust contamination to be more sensitive
    model = IsolationForest(
        n_estimators=200,
        contamination=0.01,
        max_samples='auto',
        random_state=42
    )
    
    model.fit(X)
    
    joblib.dump(model, "anomaly_detector.pkl")
    print("[!] Model retrained with higher sensitivity.")

if __name__ == "__main__":
    train_anomaly_detector()