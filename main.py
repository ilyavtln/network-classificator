from scapy.all import sniff, get_if_list
from scapy.interfaces import ifaces
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.utils import hexdump

interfaces = get_if_list()
target_interface = 'en0'

if target_interface not in interfaces:
    exit(1)


def classify_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        if packet.haslayer(TCP):
            sport, dport = packet[TCP].sport, packet[TCP].dport
            if dport == 80 or sport == 80:
                traffic_type = "HTTP"
            elif dport == 443 or sport == 443:
                traffic_type = "HTTPS"
            elif dport == 22 or sport == 22:
                traffic_type = "SSH"
            else:
                traffic_type = "TCP"

        elif packet.haslayer(UDP):
            sport, dport = packet[UDP].sport, packet[UDP].dport
            if dport == 53 or sport == 53:
                traffic_type = "DNS"
            else:
                traffic_type = "UDP"

        elif packet.haslayer(ICMP):
            traffic_type = "ICMP (Ping)"

        else:
            traffic_type = "Other"

        print(f"[{traffic_type}] {src_ip} -> {dst_ip} (Protocol: {proto})")
        print("Hexdump:")
        hexdump(packet)


print("Начало захвата трафика...")
sniff(filter="ip", iface=target_interface, prn=classify_packet, count=3)