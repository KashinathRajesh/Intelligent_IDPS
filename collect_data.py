import scapy.all as scapy
import pandas as pd
import time
import os

data_list = []

def packet_handler(packet):
    if packet.haslayer(scapy.IP):
        data = {
            "timestamp": time.time(),
            "src_ip": packet[scapy.IP].src,
            "dst_ip": packet[scapy.IP].dst,
            "proto": packet[scapy.IP].proto,
            "len": len(packet),
            "sport": 0,
            "dport": 0
        }
        
        if packet.haslayer(scapy.TCP):
            data["sport"] = packet[scapy.TCP].sport
            data["dport"] = packet[scapy.TCP].dport
        elif packet.haslayer(scapy.UDP):
            data["sport"] = packet[scapy.UDP].sport
            data["dport"] = packet[scapy.UDP].dport
            
        data_list.append(data)
        
        if len(data_list) % 50 == 0:
            print(f"[+] Captured {len(data_list)} packets...")

def main():
    print("[!] Starting Normal Traffic Collection...")
    print("[!] Please browse websites, watch a video, or work normally.")
    
    try:
        scapy.sniff(prn=packet_handler, store=False, timeout=300)
    except KeyboardInterrupt:
        pass
    
    df = pd.DataFrame(data_list)
    df.to_csv("training_data.csv", index=False)
    print(f"\n[!] Collection complete. Saved {len(df)} rows to training_data.csv")

if __name__ == "__main__":
    main()