pip install scapy
from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP
import socket
import os

# Function to get protocol name
def get_protocol_name(proto):
    if proto == 1:
        return 'ICMP'
    elif proto == 6:
        return 'TCP'
    elif proto == 17:
        return 'UDP'
    else:
        return 'Others'

# Function to analyze packets
def analyze_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = get_protocol_name(packet[IP].proto)

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"[{protocol}] {ip_src}:{src_port} -> {ip_dst}:{dst_port}")
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"[{protocol}] {ip_src}:{src_port} -> {ip_dst}:{dst_port}")
        elif ICMP in packet:
            print(f"[ICMP] {ip_src} -> {ip_dst}")
        else:
            print(f"[{protocol}] {ip_src} -> {ip_dst}")

    elif ARP in packet:
        arp_src = packet[ARP].psrc
        arp_dst = packet[ARP].pdst
        print(f"[ARP] {arp_src} -> {arp_dst}")

    else:
        print("Non-IP/Non-ARP Packet")

# Function to start sniffing
def start_sniffing():
    print("Starting the network sniffer...")
    sniff(prn=analyze_packet, store=0)

if __name__ == "__main__":
    # Check if running as root
    if os.geteuid() != 0:
        print("Please run the script with root privileges.")
        exit()

