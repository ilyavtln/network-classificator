from scapy.all import wrpcap, sniff
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import rdpcap

# Захватить 100 пакетов и сохранить в файл
packets = sniff(count=10)
wrpcap("captured.pcap", packets)

packets = rdpcap("captured.pcap")
for pkt in packets:
    if pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto
        print(f"Пакет: {src} -> {dst} | Протокол: {proto}")

    if pkt.haslayer(TCP):
        print(f"TCP: Порт {pkt[TCP].sport} -> {pkt[TCP].dport}")

    if pkt.haslayer(Raw):  # Полезно для HTTP
        print("Данные:", pkt[Raw].load[:50])  # Первые 50 байт