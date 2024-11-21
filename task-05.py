import scapy.all as scapy

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {protocol}")

        if packet.haslayer(scapy.TCP):
            if packet.haslayer(scapy.Raw):
                try:
                    payload = packet[scapy.Raw].load
                    decoded_payload = payload.decode('utf-8', 'ignore')
                    print(f"TCP Payload: {decoded_payload}")  # Print decoded payload
                except (IndexError, UnicodeDecodeError) as e:
                    print(f"Unable to decode TCP payload: {e}")

        elif packet.haslayer(scapy.UDP):
            if packet.haslayer(scapy.Raw):
                try:
                    payload = packet[scapy.Raw].load
                    decoded_payload = payload.decode('utf-8', 'ignore')
                    print(f"UDP Payload: {decoded_payload}")  # Print decoded payload
                except (IndexError, UnicodeDecodeError) as e:
                    print(f"Unable to decode UDP payload: {e}")

def start_sniffing():
    scapy.sniff(count=120, store=False, prn=packet_callback)
    input("Press Enter to exit...")  # Keep the window open

start_sniffing()