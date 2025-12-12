import scapy.all as scapy
import json
import logging
from datetime import datetime

logging.basicConfig(filename="alerts.log", level=logging.INFO, format='%(message)s')

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

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        
        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            # For now, let's log every TCP connection as a "General Traffic" event
            log_alert("TCP_TRAFFIC", src_ip, dst_ip, src_port, dst_port)
            print(f"[LOGGED] TCP: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        elif packet.haslayer(scapy.UDP):
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            log_alert("UDP_TRAFFIC", src_ip, dst_ip, src_port, dst_port)
            print(f"[LOGGED] UDP: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

def main():
    print("Available Interfaces:")
    scapy.show_interfaces()
    choice = input("\nEnter the 'Index' of the interface: ")
    
    if choice.isdigit():
        interface = scapy.dev_from_index(int(choice))
    else:
        interface = choice

    print(f"\n[+] Monitoring and logging to alerts.log...\n")
    
    try:
        scapy.sniff(iface=interface, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[!] Stopping IDS.")

if __name__ == "__main__":
    main()