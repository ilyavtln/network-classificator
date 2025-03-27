from scapy.all import sniff

def port_based_classification(port):
    port_mapping = {
        80: "HTTP",
        443: "HTTPS",
        21: "FTP",
        22: "SSH",
        53: "DNS",
    }
    return port_mapping.get(port, "Unknown")

def packet_handler(packet):
    if packet.haslayer("IP"):
        if packet.haslayer("TCP"):
            dst_port = packet["TCP"].dport
            protocol = port_based_classification(dst_port)
            print(f"TCP Пакет: {packet['IP'].src} -> {packet['IP'].dst} | Порт: {dst_port} | Протокол: {protocol}")
        elif packet.haslayer("UDP"):
            dst_port = packet["UDP"].dport
            protocol = port_based_classification(dst_port)
            print(f"UDP Пакет: {packet['IP'].src} -> {packet['IP'].dst} | Порт: {dst_port} | Протокол: {protocol}")


print("Классификация пакетов по порту")
sniff(prn=packet_handler, filter="tcp or udp", store=False)
