import scapy.all as scapy
import json
import logging
import yaml
from datetime import datetime

with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

logging.basicConfig(filename=config["log_file"], level=logging.INFO, format='%(message)s')

def log_alert(alert_type, src_ip, dst_ip, src_port, dst_port, severity="Low"):
    alert_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": alert_type,
        "severity": severity,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port
    }
    
    logging.info(json.dumps(alert_data))
    
    if config["alerts"]["enable_console_output"]:
        print(f"[LOGGED] {alert_type}: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        
        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            log_alert("TCP_TRAFFIC", src_ip, dst_ip, src_port, dst_port)

        elif packet.haslayer(scapy.UDP):
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            log_alert("UDP_TRAFFIC", src_ip, dst_ip, src_port, dst_port)

def main():
    if isinstance(config["interface"], int):
        interface = scapy.dev_from_index(config["interface"])
    else:
        interface = config["interface"]

    print(f"\n[+] Loading configuration from config.yaml...")
    print(f"[+] Starting capture on: {interface}\n")
    
    try:
        scapy.sniff(iface=interface, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[!] Stopping IDS.")

if __name__ == "__main__":
    main()