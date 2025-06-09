from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP


def packet_callback(packet):
    print(packet)


print("Starting packet capture...")
sniff(iface="Беспроводная сеть", prn=packet_callback, count=10)
