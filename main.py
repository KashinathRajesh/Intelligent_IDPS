import scapy.all as scapy
import json
import logging
import yaml
from datetime import datetime

# Load Config
with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

# Load Rules
with open("rules.json", "r") as f:
    rules = json.load(f)

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
        print(f"[ALERT] {alert_type}: {src_ip} -> {dst_ip} ({severity})")

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        
        # Check Source IP against Blacklist
        if src_ip in rules["blacklist_ips"]:
            src_port = packet.sport if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP) else 0
            dst_port = packet.dport if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP) else 0
            log_alert("BLACKLIST_IP_DETECTED", src_ip, dst_ip, src_port, dst_port, severity="High")

        if packet.haslayer(scapy.TCP):
            pass

        elif packet.haslayer(scapy.UDP):
            pass

def main():
    if isinstance(config["interface"], int):
        interface = scapy.dev_from_index(config["interface"])
    else:
        interface = config["interface"]

    print(f"\n[+] Rules loaded: {len(rules['blacklist_ips'])} IPs in blacklist.")
    print(f"[+] Starting capture on: {interface}\n")
    
    try:
        scapy.sniff(iface=interface, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[!] Stopping IDS.")

if __name__ == "__main__":
    main()