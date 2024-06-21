from scapy.all import sniff, IP, TCP, UDP, conf

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\nNew Packet: {packet.summary()}")
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Protocol: TCP")
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
            print(f"Payload: {tcp_layer.payload.load if tcp_layer.payload else 'None'}")
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"Protocol: UDP")
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
            print(f"Payload: {udp_layer.payload.load if udp_layer.payload else 'None'}")

print("Starting packet sniffing... Press Ctrl+C to stop.")

# Set the socket to Layer 3
conf.L3socket

try:
    sniff(prn=packet_callback, filter="ip", store=0)
except KeyboardInterrupt:
    print("\nPacket sniffing stopped.")
except Exception as e:
    print(f"An error occurred: {e}")
