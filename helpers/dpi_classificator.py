import re
from scapy.all import sniff, raw
from scapy.layers.inet import IP, TCP

SIGNATURES = {
    "HTTP": [
        rb"GET /", rb"POST /", rb"HEAD /", rb"PUT /",
        rb"DELETE /", rb"OPTIONS /", rb"HTTP/1\.[01]"
    ]
}


def dpi_classification(payload):
    found_patterns = []

    for pattern in SIGNATURES["HTTP"]:
        if re.search(pattern, payload, re.DOTALL):
            found_patterns.append(pattern)

    return found_patterns if found_patterns else None


def packet_handler(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        payload = raw(packet[TCP])

        if payload:
            matched_patterns = dpi_classification(payload)

            if matched_patterns:
                print(f"Пакет: {packet[IP].src} -> {packet[IP].dst} | протокол: HTTP")
                print(f"Сигнатуры: {matched_patterns}")


sniff(prn=packet_handler, timeout=10)
