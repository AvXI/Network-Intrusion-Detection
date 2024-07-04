from scapy.all import *
import suricata

# Define a function to handle each packet
def handle_packet(packet):
    # Extract the packet payload
    payload = bytes(packet[TCP].payload)
    
    # Send the payload to Suricata for signature-based detection
    alert = suricata.detect(payload)
    
    if alert:
        # Alert on detected signatures
        print('ALERT: Signature detected!')
        print(alert)
    else:
        # Perform anomaly detection on the packet
        # Here we can define custom rules to detect anomalies based on packet fields
        if packet[TCP].dport == 80 and len(payload) > 10000:
            print('ALERT: Anomaly detected!')
            print('HTTP request with unusually large payload')
        
        # Print a message for normal packets (without detection or anomalies)
        else:
            print('Normal packet')

# Define a filter for the monitored network interface (change to your specific interface)
filter_str = 'tcp and (host 192.168.1.100 or host 192.168.1.101)'

# Start the packet capture loop
sniff(filter=filter_str, prn=handle_packet)