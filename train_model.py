import pandas as pd
from pyod.models.iforest import IForest  # Isolation Forest
from sklearn.preprocessing import StandardScaler
import joblib

df = pd.read_csv("normal_traffic.csv")

# Features for the model
X = df[["src_port", "dst_port", "len"]]

# Normalize the data
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train the model
clf = IForest()
clf.fit(X_scaled)

# Save model and scaler
joblib.dump(clf, "anomaly_model.pkl")
joblib.dump(scaler, "scaler.pkl")

print("Model and scaler saved.")
