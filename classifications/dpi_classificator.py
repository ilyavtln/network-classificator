import socket
import dpkt

# Сигнатуры для классификации сетевого трафика
SIGNATURES = {
    b"HTTP/1.1": "HTTP",
    b"Host: youtube.com": "YouTube",
    b"SSH-": "SSH",
    b"GET /video": "VideoStream",
    b"ClientHello": "TLS",
    b"ServerHello": "TLS",
    b"MAIL FROM": "SMTP",
    b"220 FTP": "FTP",
    b"PASS ": "FTP-Auth",
    b"USER ": "FTP-Auth",
    b"GET ": "HTTP",
    b"POST ": "HTTP",
    b"PUT ": "HTTP",
    b"DELETE ": "HTTP",
    b"CONNECT ": "HTTP-Tunnel",
    b"Content-Type: application/json": "API Request",
    b"Bitcoin": "Bitcoin",
    b"Ethereum": "Ethereum",
    b"DNS": "DNS",
}

def dpi_classification(packet_payload):
    """
    Классифицирует сетевой пакет на основе сигнатур.
    """
    for signature, category in SIGNATURES.items():
        if signature in packet_payload:
            return category
    return "Unknown"

def process_pcap(file_path):
    """
    Обрабатывает pcap-файл и классифицирует пакеты.
    """
    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for timestamp, raw_packet in pcap:
            eth = dpkt.ethernet.Ethernet(raw_packet)
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                if isinstance(ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                    payload = ip.data.data
                    category = dpi_classification(payload)
                    print(f"Packet Timestamp: {timestamp}, Category: {category}")


def capture_live_traffic():
    # Создание RAW-сокета для захвата пакетов (только IPv4)
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP) as sock:
        sock.bind(("en0", 0))
  # Замените "en0" на имя сетевого интерфейса (на Windows это может быть "Wi-Fi")
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # Windows: включаем режим промискуитета (Linux/macOS не требуется)
        try:
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        except AttributeError:
            pass  # SIO_RCVALL отсутствует на macOS

        print("Захват трафика начался... (нажмите Ctrl+C для остановки)")
        try:
            while True:
                raw_packet, _ = sock.recvfrom(65535)
                print(f"Пакет получен: {raw_packet[:50]}...")  # Вывод первых 50 байт пакета
        except KeyboardInterrupt:
            print("Захват трафика остановлен.")

        # Windows: выключаем режим промискуитета
        try:
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except AttributeError:
            pass

# Пример обработки pcap-файла
# process_pcap("traffic.pcap")

# Пример захвата живого трафика (необходимы root-права)
capture_live_traffic()
