import scapy.all as scapy

def packet_callback(packet):
    print(packet.summary())

def main():
    print("Available Interfaces:")
    scapy.show_interfaces()
    
    # Get user input
    choice = input("\nEnter the 'Index' (e.g. 23) of the interface to sniff: ")
    
    # Logic to handle Index (number) vs Name (string)
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