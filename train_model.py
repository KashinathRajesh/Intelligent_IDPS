import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

def train_anomaly_detector():
    df = pd.read_csv("training_data.csv")
    X = df[["proto", "len", "sport", "dport"]]
    
    model = IsolationForest(
        n_estimators=100,
        contamination=0.1, 
        random_state=42
    )
    
    model.fit(X)
    joblib.dump(model, "anomaly_detector.pkl")
    print("[+] Model retrained with 10% sensitivity.")

if __name__ == "__main__":
    train_anomaly_detector()