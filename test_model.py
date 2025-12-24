import joblib
import pandas as pd

model = joblib.load("anomaly_detector.pkl")

test_data = pd.DataFrame([
    {"proto": 6, "len": 64, "sport": 443, "dport": 52101},   # Should be Normal
    {"proto": 255, "len": 65535, "sport": 9999, "dport": 0} # Extreme: Invalid Proto + Max Length
])

predictions = model.predict(test_data)

for i, pred in enumerate(predictions):
    status = "Normal" if pred == 1 else "ANOMALY"
    print(f"Sample {i+1}: {status}")