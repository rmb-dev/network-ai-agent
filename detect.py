# scapy.all: used to sniff and inspect TCP/IP packets
from scapy.all import sniff, IP, TCP
# joblib: loads a pre-trained ML model and scaler from disk
import joblib
# pandas: creates structured data from packets
import pandas as pd
# time: imported but unused in this version
import time
# Load a pre-trained anomaly detection model (e.g., Isolation Forest, One-Class SVM)
clf = joblib.load("anomaly_model.pkl")
# Load a scaler (e.g., StandardScaler) to normalize feature input for the model
scaler = joblib.load("scaler.pkl")
# Call for each packet
def detect(packet):
    # Process TCP over IP packets
    if IP in packet and TCP in packet:
        # Creat a single-row DataFrame with Source, Destination ports and packet length
        data = pd.DataFrame([{
            "src_port": packet[TCP].sport,
            "dst_port": packet[TCP].dport,
            "len": len(packet),
        }])
# 
        X_scaled = scaler.transform(data)
        prediction = clf.predict(X_scaled)

        if prediction[0] == 1:
            print(f"[!] Anomaly detected: {packet[IP].src} -> {packet[IP].dst}")

print("Monitoring for anomalies. Press CTRL+C to stop.")
try:
    sniff(filter="tcp", prn=detect, store=0)
except KeyboardInterrupt:
    pass
