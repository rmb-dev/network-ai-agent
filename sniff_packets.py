# Import the necessary Scapy functions and layers to capture packets (sniff) and access IP/TCP headers
from scapy.all import sniff, IP, TCP
# Imports Pandas for data manipulation and time to timestamp packets
import pandas as pd
import time
# Initializes an empty list to store packet data
packets = []
# function is called for each captured packet, checks if the packet contains both IP and TCP layers
def packet_callback(packet):
    if IP in packet and TCP in packet:
        # Extract source/destination IPs and ports, total packet length, and timestamp, and appends it as a dictionary to the packets list
        packets.append({
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "src_port": packet[TCP].sport,
            "dst_port": packet[TCP].dport,
            "len": len(packet),
           "time": time.time()
        })
# Begin sniffing TCP packets
print("Sniffing... Press CTRL+C to stop.")
try:
    # prn=packet_callback: each packet triggers the callback function
    # store=0: does not keep packets in memory (other than what's manually appended)
    # timeout=60: stops after 60 seconds
    sniff(filter="tcp", prn=packet_callback, store=0, timeout=60)
# Allows manual interruption via CTRL+C without crashing
except KeyboardInterrupt:
    pass
# Convert the list of packet dictionaries to a Pandas DataFrame
df = pd.DataFrame(packets)
# Save the data to a CSV file named normal_traffic.csv
df.to_csv("normal_traffic.csv", index=False)
print("Saved to normal_traffic.csv")
