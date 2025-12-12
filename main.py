import scapy.all as scapy

def packet_callback(packet):
    # Check if the packet has an IP layer (IPv4)
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        # Check if it is a TCP packet
        if packet.haslayer(scapy.TCP):
            try:
                src_port = packet[scapy.TCP].sport
                dst_port = packet[scapy.TCP].dport
                print(f"[TCP] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            except AttributeError:
                pass # Skip malformed packets

        # Check if it is a UDP packet
        elif packet.haslayer(scapy.UDP):
            try:
                src_port = packet[scapy.UDP].sport
                dst_port = packet[scapy.UDP].dport
                print(f"[UDP] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            except AttributeError:
                pass
        
        # Other IP packets (ICMP, etc.)
        else:
             print(f"[IP]  {src_ip} -> {dst_ip} | Protocol: {protocol}")

def main():
    print("Available Interfaces:")
    scapy.show_interfaces()
    
    choice = input("\nEnter the 'Index' (e.g. 23) of the interface to sniff: ")
    
    if choice.isdigit():
        interface = scapy.dev_from_index(int(choice))
    else:
        interface = choice

    print(f"\n[+] Starting capture on: {interface}...\n")
    
    try:
        scapy.sniff(iface=interface, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[!] Stopping capture.")
    except Exception as e:
        print(f"\n[!] Error: {e}")

if __name__ == "__main__":
    main()