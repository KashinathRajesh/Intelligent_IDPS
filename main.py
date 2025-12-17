import scapy.all as scapy
import json
import logging
import yaml
import time
from datetime import datetime
from urllib.parse import unquote

with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

with open("rules.json", "r") as f:
    rules = json.load(f)

logging.basicConfig(filename=config["log_file"], level=logging.INFO, format='%(message)s')

scan_tracker = {}

def log_alert(alert_type, src_ip, dst_ip, src_port, dst_port, severity="Low", payload=""):
    alert_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": alert_type,
        "severity": severity,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "payload_snippet": payload
    }
    
    logging.info(json.dumps(alert_data))
    
    if config["alerts"]["enable_console_output"]:
        print(f"[ALERT] {alert_type}: {src_ip} -> {dst_ip} ({severity})")

def detect_port_scan(src_ip, dst_port):
    current_time = time.time()
    
    if src_ip not in scan_tracker:
        scan_tracker[src_ip] = {
            "ports": set(),
            "start_time": current_time,
            "alerted": False
        }

    tracker = scan_tracker[src_ip]

    if current_time - tracker["start_time"] > 60:
        tracker["ports"] = set()
        tracker["start_time"] = current_time
        tracker["alerted"] = False
    
    tracker["ports"].add(dst_port)

    if len(tracker["ports"]) > 15 and not tracker["alerted"]:
        log_alert("PORT_SCAN_DETECTED", src_ip, "Multiple", 0, 0, severity="Medium")
        tracker["alerted"] = True

def check_payload(packet, src_ip, dst_ip, src_port, dst_port):
    if packet.haslayer(scapy.Raw):
        try:
            # 1. Decode bytes to string
            raw_payload = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
            
            # 2. Decode URL encoding (turns %20 back into space)
            decoded_payload = unquote(raw_payload)

            for signature in rules["payload_signatures"]:
                # Check BOTH the raw and the decoded version
                if signature in raw_payload or signature in decoded_payload:
                    log_alert(f"MALICIOUS_PAYLOAD_MATCH: {signature}", 
                              src_ip, dst_ip, src_port, dst_port, 
                              severity="Critical", payload=decoded_payload[:100])
                    return
        except Exception:
            pass

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        
        if src_ip in rules["blacklist_ips"]:
            src_port = packet.sport if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP) else 0
            dst_port = packet.dport if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP) else 0
            log_alert("BLACKLIST_IP_DETECTED", src_ip, dst_ip, src_port, dst_port, severity="High")

        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            detect_port_scan(src_ip, dst_port)
            check_payload(packet, src_ip, dst_ip, src_port, dst_port)

        elif packet.haslayer(scapy.UDP):
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            detect_port_scan(src_ip, dst_port)

def main():
    if isinstance(config["interface"], int):
        interface = scapy.dev_from_index(config["interface"])
    else:
        interface = config["interface"]

    print(f"\n[+] Rules loaded: {len(rules['blacklist_ips'])} IPs, {len(rules['payload_signatures'])} Signatures.")
    print(f"[+] Starting capture on: {interface}\n")
    
    try:
        scapy.sniff(iface=interface, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[!] Stopping IDS.")

if __name__ == "__main__":
    main()