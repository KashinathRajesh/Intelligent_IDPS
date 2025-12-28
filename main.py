import scapy.all as scapy
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNSQR
import json
import yaml
import time
import geoip2.database
import joblib
import pandas as pd
import mysql.connector
from datetime import datetime
from urllib.parse import unquote
from scapy.all import conf

# Force Scapy to use Npcap for Windows support
conf.use_pcap = True
conf.use_npcap = True

class IntelligentIDPS:
    def __init__(self, config_path="config.yaml", rules_path="rules.json"):
        """Initializes configurations, ML models, GeoIP, and MySQL connection."""
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)
        with open(rules_path, "r") as f:
            self.rules = json.load(f)

        self.scan_tracker = {}
        self._load_models()
        self._connect_db()

    def _connect_db(self):
        """Establishes a persistent connection to the MySQL database."""
        try:
            self.db = mysql.connector.connect(
                host=self.config['mysql']['host'],
                user=self.config['mysql']['user'],
                password=self.config['mysql']['password'],
                database=self.config['mysql']['database']
            )
            self.cursor = self.db.cursor()
            print("[+] MySQL Database connected successfully.")
        except Exception as e:
            print(f"[!] MySQL Connection Failed: {e}")
            self.db = None

    def _load_models(self):
        """Loads the Isolation Forest model and GeoIP database."""
        try:
            self.ml_model = joblib.load("anomaly_detector.pkl")
            print("[+] ML Anomaly Detector loaded successfully.")
        except:
            self.ml_model = None
            print("[!] ML Model not found. Anomaly detection disabled.")

        try:
            self.geoip_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
            print("[+] GeoIP Database loaded successfully.")
        except:
            self.geoip_reader = None

    def get_country(self, ip):
        """Resolves the geographic location of an IP address."""
        if self.geoip_reader is None: return "Unknown"
        try:
            response = self.geoip_reader.city(ip)
            return response.country.name if response.country.name else "Unknown"
        except:
            return "Internal/Private"

    def log_alert(self, alert_type, src_ip, dst_ip, src_port, dst_port, severity="Low", payload=""):
        """Inserts security alerts into MySQL and prints to console."""
        src_country = self.get_country(src_ip)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if self.db:
            try:
                query = """INSERT INTO alerts (timestamp, alert_type, severity, src_ip, src_country, dst_ip, src_port, dst_port, payload_snippet) 
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"""
                values = (timestamp, alert_type, severity, src_ip, src_country, dst_ip, src_port, dst_port, payload[:500])
                self.cursor.execute(query, values)
                self.db.commit()
            except Exception as e:
                print(f"[!] Database Insert Error: {e}")

        if self.config["alerts"]["enable_console_output"]:
            print(f"[ALERT] {alert_type}: {src_ip} ({src_country}) -> {dst_ip} ({severity})")

    def predict_anomaly(self, proto, length, sport, dport, src_ip, dst_ip):
        """Uses ML to detect statistically unusual packets."""
        if self.ml_model:
            if dport in [5353, 1900] or sport in [5353, 1900]:
                return

            df = pd.DataFrame([{"proto": proto, "len": length, "sport": sport, "dport": dport}])
            prediction = self.ml_model.predict(df)[0]
            
            if prediction == -1:
                self.log_alert("ML_ANOMALY_DETECTED", src_ip, dst_ip, sport, dport, 
                               severity="Medium", payload=f"Size:{length}, Proto:{proto}")

    def detect_port_scan(self, src_ip, dport):
        """Tracks unique ports to detect reconnaissance activity."""
        current_time = time.time()
        if src_ip not in self.scan_tracker:
            self.scan_tracker[src_ip] = {"ports": set(), "start_time": current_time, "alerted": False}
        
        tracker = self.scan_tracker[src_ip]
        if current_time - tracker["start_time"] > 60:
            tracker.update({"ports": set(), "start_time": current_time, "alerted": False})
        
        tracker["ports"].add(dport)
        if len(tracker["ports"]) > 15 and not tracker["alerted"]:
            self.log_alert("PORT_SCAN_DETECTED", src_ip, "Multiple", 0, 0, severity="Medium")
            tracker["alerted"] = True

    def check_dns(self, packet, src_ip, dst_ip):
        """Inspects DNS queries against the domain blacklist."""
        if packet.haslayer(scapy.DNSQR):
            query_name = packet[scapy.DNSQR].qname.decode('utf-8', errors='ignore').strip('.')
            for domain in self.rules.get("blacklist_domains", []):
                if domain.lower() in query_name.lower():
                    self.log_alert("BLACKLIST_DOMAIN_ACCESS", src_ip, dst_ip, 0, 53, 
                                   severity="High", payload=query_name)

    def check_payload(self, packet, src_ip, dst_ip, src_port, dst_port):
        """DPI module for SQLi, XSS, and custom signatures."""
        if packet.haslayer(scapy.Raw):
            try:
                raw_data = packet[scapy.Raw].load
                decoded_variants = [
                    raw_data.decode('utf-8', errors='ignore').lower(),
                    unquote(raw_data.decode('utf-8', errors='ignore')).lower()
                ]
                for sig in self.rules.get("payload_signatures", []):
                    sig_lower = sig.lower()
                    for variant in decoded_variants:
                        if sig_lower in variant:
                            self.log_alert("MALICIOUS_PAYLOAD_MATCH", src_ip, dst_ip, src_port, dst_port, 
                                           severity="Critical", payload=sig)
            except: pass

    def packet_callback(self, packet):
        """Main processing engine for network traffic."""
        if not packet.haslayer(scapy.IP):
            return

        src_ip, dst_ip = packet[scapy.IP].src, packet[scapy.IP].dst
        proto, length = packet[scapy.IP].proto, len(packet)
        sport, dport = 0, 0

        # LOW SEVERITY: ICMP Detection
        if packet.haslayer(scapy.ICMP):
            self.log_alert("ICMP_TRAFFIC_DETECTED", src_ip, dst_ip, 0, 0, severity="Low")

        # HIGH SEVERITY: DNS Blacklist Check
        self.check_dns(packet, src_ip, dst_ip)

        if packet.haslayer(scapy.TCP):
            sport, dport = packet[scapy.TCP].sport, packet[scapy.TCP].dport
        elif packet.haslayer(scapy.UDP):
            sport, dport = packet[scapy.UDP].sport, packet[scapy.UDP].dport

        # NOISE FILTER
        if dport == 443 or sport == 443:
            return

        # WHITELIST
        if src_ip in self.config.get("whitelist", []): 
            return

        # CORE DETECTION
        self.predict_anomaly(proto, length, sport, dport, src_ip, dst_ip)
        self.detect_port_scan(src_ip, dport)
        self.check_payload(packet, src_ip, dst_ip, sport, dport)

        if src_ip in self.rules.get("blacklist_ips", []):
            self.log_alert("BLACKLIST_IP_DETECTED", src_ip, dst_ip, sport, dport, severity="High")

    def start(self):
        """Starts the IDPS engine in promiscuous mode."""
        iface_config = self.config["interface"]
        interface = scapy.conf.ifaces.dev_from_index(iface_config) if isinstance(iface_config, int) else iface_config
        
        print(f"\n[+] Starting Intelligent IDPS on: {interface}")
        try:
            scapy.sniff(iface=interface, prn=self.packet_callback, store=False, promisc=True)
        except KeyboardInterrupt:
            print("\n[!] Stopping IDPS Engine.")

if __name__ == "__main__":
    idps = IntelligentIDPS()
    idps.start()