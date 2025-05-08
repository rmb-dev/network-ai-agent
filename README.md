# 🛡️ Network AI Agent - Anomaly-Based Intrusion Detector

This is a Python project that builds a simple AI-powered agent to monitor network traffic and flag anomalies using machine learning.

## 🔧 Features

- Captures TCP traffic from your home network
- Trains an unsupervised anomaly detection model (Isolation Forest)
- Detects unusual network behavior in real time
- Prints alerts to the console

## 📦 Dependencies:

Install the required Python libraries:

```bash
sudo apt install -r requirements.txt
```

## 🛠 Set Up Your Python Environment:
Install Python (3.10+ recommended), and set up a virtual environment:
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv -y
mkdir ~/network-ai-agent
cd ~/network-ai-agent
python3 -m venv venv
source venv/bin/activate
```

Install the required packages:
```bash
sudo apt update
sudo apt install python3-sklearn python3-pandas python3-scapy
```

Set up a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
pip install pyod joblib scikit-learn
python detect.py
```

## 📥 Capture and Save Network Traffic:
Create a script: sniff_packets.py
Run it and let it capture traffic while you browse the web, stream a video, etc. (to simulate "normal" usage):
```bash
sudo python3 sniff_packets.py
```

## 📊 Train an Anomaly Detection Model:
Create train_model.py
Run it:
```bash
sudo python3 train_model.py
```

## ⚠️ Real-Time Anomaly Detection:
Create detect.py
Run the detection script:
```bash
sudo python3 detect.py
sudo ./venv/bin/python detect.py
```
Try generating unusual traffic (e.g., scanning ports from another device, using nmap) and observe alerts.

## Great — your anomaly detector is working now! 🎉
```yaml
[!] Anomaly detected: 151.101.125.91 -> 192.168.2.87
```
mean that your model is flagging certain network packets as anomalies — that is, they differ from the "normal" traffic pattern the model was trained on.
What does each part mean?

    151.101.125.91 is the source IP address (likely external).

    192.168.2.87 is your local device IP.

    The arrow -> shows the direction of the traffic.

So, for example:
```yaml
151.101.125.91 -> 192.168.2.87
```
means: an external IP sent a packet to your machine, and the model thinks it’s unusual or suspicious.
What should you do next?

Here are a few practical next steps:
🔍 1. Identify the IP addresses

You can look up IPs using tools like:
```yaml
whois 151.101.125.91
```
That IP belongs to Fastly CDN (used by GitHub, StackOverflow, etc.) — so it's likely benign.
📈 2. Log anomalies to a file

Update detect.py to log events like this:
```python
with open("anomaly_log.txt", "a") as log_file:
    log_file.write(f"Anomaly detected: {src} -> {dst}\n")
```
Place it inside your detect() function, after a detection is triggered.
🧠 3. Tune the model or thresholds

If too many "normal" events are flagged, the model might need:

    More normal training data

    Different algorithm/hyperparameters

    Threshold adjustment