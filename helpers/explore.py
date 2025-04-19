from dpkt import hexdump
from scapy.all import sniff

def packet_handler(packet):
    packet.show()

sniff(prn=packet_handler, count=1)  # Захватывает 5 пакетов

print(socket.addr)