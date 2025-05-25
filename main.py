from scapy.all import sniff, wrpcap
import socket
import datetime
import sys

# Список доменов для захвата
DOMAINS = ["spotify.com", "music.yandex.ru"]
PORTS = [443]  # HTTPS-порт для стриминга


def resolve_domains(domains):
    """Разрешает домены в IP-адреса."""
    ip_list = []
    for domain in domains:
        try:
            ip = socket.gethostbyname(domain)
            ip_list.append(ip)
            print(f"Разрешен домен {domain} -> {ip}")
        except socket.gaierror:
            print(f"Не удалось разрешить домен {domain}")
    return ip_list


def create_bpf_filter(ip_list):
    """Создает BPF-фильтр для scapy на основе IP-адресов и портов."""
    if not ip_list:
        return ""
    ip_filter = " or ".join(f"host {ip}" for ip in ip_list)
    port_filter = " or ".join(f"tcp port {port}" for port in PORTS)
    return f"({port_filter}) and ({ip_filter})"


def packet_callback(packet):
    """Callback-функция для обработки каждого захваченного пакета."""
    packets.append(packet)
    print(f"Захвачен пакет: {packet.summary()}")


def start_capture(interface, output_file, duration=60):
    """Захват трафика для Spotify и Яндекс.Музыки и сохранение в PCAP-файл."""
    global packets
    packets = []  # Список для хранения пакетов

    # Разрешение доменов в IP-адреса
    ip_list = resolve_domains(DOMAINS)
    if not ip_list:
        print("Не удалось разрешить ни один из доменов. Проверьте подключение или доменные имена.")
        sys.exit(1)

    # Создание BPF-фильтра
    bpf_filter = create_bpf_filter(ip_list)
    if not bpf_filter:
        print("Не удалось создать фильтр для захвата трафика.")
        sys.exit(1)

    print(f"BPF-фильтр: {bpf_filter}")
    print(f"Начало захвата трафика на интерфейсе {interface}...")

    try:
        # Захват трафика
        sniff(iface=interface, prn=packet_callback, timeout=duration, filter=bpf_filter)

        # Сохранение пакетов в PCAP-файл
        print(f"Сохранение {len(packets)} пакетов в файл {output_file}...")
        wrpcap(output_file, packets)
        print(f"Захват завершен. Файл сохранен: {output_file}")

    except Exception as e:
        print(f"Ошибка при захвате трафика: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Имя сетевого интерфейса (узнайте через `scapy.all.get_working_ifaces()`)
    INTERFACE = "Беспроводная сеть"  # Замените на ваш интерфейс (например, 'Wi-Fi')

    # Имя выходного файла с меткой времени
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    OUTPUT_FILE = f"music_traffic_{timestamp}.pcap"

    # Длительность захвата (в секундах)
    DURATION = 60  # 1 минута

    # Запуск захвата
    start_capture(INTERFACE, OUTPUT_FILE, DURATION)