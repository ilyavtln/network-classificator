import requests
import csv
from io import StringIO
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import matplotlib.pyplot as plt

KNOWN_PORTS = 0
UNKNOWN_PORTS = 0

def update_port_map(address):
    response = requests.get(address)
    maps = {}

    if response.status_code == 200:
        csv_data = StringIO(response.text)
        reader = csv.DictReader(csv_data)

        for row in reader:
            if row['Port Number'] and '-' not in row['Port Number']:
                try:
                    port = int(row['Port Number'])
                    protocol = row['Transport Protocol']
                    service = row['Service Name']

                    if protocol in ['tcp', 'udp'] and service:
                        maps[port] = service
                except ValueError:
                    continue

    return maps


def port_classification(port):
    return port_map.get(port, "Unknown")


def print_classification(proto_type, raw, protocol):
    print(f"{proto_type} пакет: {raw.src} -> {raw.dst} | Порт: {raw.dport} | Протокол: {protocol}")


def packet_handler(packet):
    global KNOWN_PORTS, UNKNOWN_PORTS

    if packet.haslayer(IP):
        protocol = None

        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            protocol = port_classification(dst_port)
            print_classification("TCP", packet[IP], protocol)
        elif packet.haslayer(UDP):
            dst_port = packet[UDP].dport
            protocol = port_classification(dst_port)
            print_classification("UDP", packet[IP], protocol)

        if protocol == "Unknown":
            UNKNOWN_PORTS += 1
        else:
            KNOWN_PORTS += 1


URL = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"
port_map = update_port_map(URL)

print("Классификация пакетов по порту")
sniff(prn=packet_handler, timeout=600)
print(KNOWN_PORTS / (KNOWN_PORTS + UNKNOWN_PORTS), UNKNOWN_PORTS / (KNOWN_PORTS + UNKNOWN_PORTS))

labels = ['Известные порты', 'Неизвестные порты']
sizes = [KNOWN_PORTS, UNKNOWN_PORTS]

plt.figure(figsize=(8, 8))
plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
plt.axis('equal')
plt.savefig("../images/port_classificator.png")
plt.show()
