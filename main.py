import scapy.all as scapy
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNSQR
import json
import logging
import yaml
import time
import geoip2.database
from datetime import datetime
from urllib.parse import unquote

with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

with open("rules.json", "r") as f:
    rules = json.load(f)

logging.basicConfig(filename=config["log_file"], level=logging.INFO, format='%(message)s')

try:
    geoip_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
    print("[+] GeoIP Database loaded successfully.")
except FileNotFoundError:
    print("[!] Error: GeoLite2-City.mmdb not found. GeoIP features disabled.")
    geoip_reader = None

scan_tracker = {}

def get_country(ip):
    if geoip_reader is None:
        return "Unknown"
    try:
        response = geoip_reader.city(ip)
        return response.country.name if response.country.name else "Unknown"
    except Exception:
        return "Internal/Private"

def log_alert(alert_type, src_ip, dst_ip, src_port, dst_port, severity="Low", payload=""):
    src_country = get_country(src_ip)
    alert_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": alert_type,
        "severity": severity,
        "src_ip": src_ip,
        "src_country": src_country,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "payload_snippet": payload
    }
    logging.info(json.dumps(alert_data))
    if config["alerts"]["enable_console_output"]:
        print(f"[ALERT] {alert_type}: {src_ip} ({src_country}) -> {dst_ip} ({severity})")

def process_http_packet(packet, src_ip, dst_ip, src_port, dst_port):
    try:
        if packet.haslayer(HTTPRequest):
            host = packet[HTTPRequest].Host.decode('utf-8', errors='ignore')
            path = packet[HTTPRequest].Path.decode('utf-8', errors='ignore')
            method = packet[HTTPRequest].Method.decode('utf-8', errors='ignore')
            
            # --- NEW: User-Agent Check ---
            user_agent = packet[HTTPRequest].User_Agent.decode('utf-8', errors='ignore').lower()
            for agent in rules.get("suspicious_user_agents", []):
                if agent in user_agent:
                    log_alert(f"SUSPICIOUS_USER_AGENT: {agent}", src_ip, dst_ip, src_port, dst_port, severity="High", payload=user_agent)
            
            url = f"http://{host}{path}"
            if "/admin" in path or "/login" in path:
                log_alert("SENSITIVE_PATH_ACCESS", src_ip, dst_ip, src_port, dst_port, severity="Medium", payload=url)
    except Exception:
        pass

def process_dns_packet(packet, src_ip, dst_ip, src_port, dst_port):
    if packet.haslayer(DNSQR):
        try:
            query_name = packet[DNSQR].qname.decode('utf-8').rstrip('.')
            if query_name in rules["blacklist_domains"]:
                log_alert(f"MALICIOUS_DNS_QUERY: {query_name}", src_ip, dst_ip, src_port, dst_port, severity="Critical", payload=query_name)
        except Exception:
            pass

def detect_port_scan(src_ip, dst_port):
    current_time = time.time()
    if src_ip not in scan_tracker:
        scan_tracker[src_ip] = {"ports": set(), "start_time": current_time, "alerted": False}
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
            raw_payload = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
            decoded_payload = unquote(raw_payload)
            for signature in rules["payload_signatures"]:
                if signature in raw_payload or signature in decoded_payload:
                    log_alert(f"MALICIOUS_PAYLOAD_MATCH: {signature}", src_ip, dst_ip, src_port, dst_port, severity="Critical", payload=decoded_payload[:100])
                    return
        except Exception:
            pass

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        
        if src_ip in rules["blacklist_ips"]:
            log_alert("BLACKLIST_IP_DETECTED", src_ip, dst_ip, 0, 0, severity="High")

        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            detect_port_scan(src_ip, dst_port)
            check_payload(packet, src_ip, dst_ip, src_port, dst_port)
            process_http_packet(packet, src_ip, dst_ip, src_port, dst_port)

        elif packet.haslayer(scapy.UDP):
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            detect_port_scan(src_ip, dst_port)
            if dst_port == 53:
                process_dns_packet(packet, src_ip, dst_ip, src_port, dst_port)

def main():
    if isinstance(config["interface"], int):
        interface = scapy.dev_from_index(config["interface"])
    else:
        interface = config["interface"]

    print(f"\n[+] Rules loaded: {len(rules['blacklist_ips'])} IPs, {len(rules['blacklist_domains'])} Domains.")
    print(f"[+] Starting capture on: {interface}\n")
    
    try:
        scapy.sniff(iface=interface, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[!] Stopping IDS.")

if __name__ == "__main__":
    main()