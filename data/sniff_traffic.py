#!/usr/bin/env python
# coding: utf-8

# In[697]:


import socket
import sys
import platform
import os


# In[698]:


from scapy.all import sniff, wrpcap


# In[699]:


CATEGORIES = {
    'games',
    'music',
    'social_network',
    'video_hosting',
    'cloud_service',
    'e-mail',
    'other'
}


# In[700]:


DOMAINS = {
    'games': ["music.yandex.ru"],
    'music': ["spotify.com", "open.spotify.com"],
    'social_network': ["vk.com", "ok.ru", "web.telegram.org", "telegram.org", "t.me"],
    'video_hosting': ["twitch.tv", "youtube.com", "rutube.ru", "vkvideo.ru"],
    'cloud_service': ["disk.yandex.ru", "cloud.mail.ru", "drive.google.com"],
    'e-mail': ["mail.google.com", "mail.yandex.ru", "mail.ru", "outlook.live.com"],
    'other': ["wikipedia.org", "nstu.ru", "ngs.ru", "gismeteo.ru", "habr.com", "tass.ru"]
}


# In[701]:


PORTS = {
    'games': [80],
}


# In[702]:


CURRENT_CATEGORY = 'other'
DURATION = 60


# In[703]:


print(f"Сбор трафика для {CURRENT_CATEGORY} с продолжительностью {DURATION}c.")


# In[704]:


system = platform.system().lower()

if not system:
    exit(1)

print(f"Текущая ОС {system}")


# In[705]:


if system == "windows":
    INTERFACE = "Беспроводная сеть"
else:
    INTERFACE = "<UNK> <UNK>"

print(INTERFACE)


# In[706]:


def resolve_domains(domains):
    """Разрешает домены в список всех IP-адресов (IPv4 и IPv6)."""
    ip_list = []
    for domain in domains:
        try:
            # Запрашиваем все адреса
            addr_info = socket.getaddrinfo(
                domain,
                None,
                family=0,
                type=socket.SOCK_STREAM,
                flags=socket.AI_ALL | socket.AI_V4MAPPED
            )
            # Извлекаем уникальные IP-адреса
            ip_set = set()
            for info in addr_info:
                ip = info[4][0]
                ip_set.add(ip)
            ip_list.extend(ip_set)

            print(f"Разрешен домен {domain} -> {list(ip_set)}")
        except socket.gaierror:
            print(f"Не удалось разрешить домен {domain}")
    return list(set(ip_list))  # Удаляем дубликаты


# In[707]:


def create_bpf_filter():
    """Создает BPF-фильтр для scapy на основе IP-адресов и портов."""

    # Получение ip адресов по доменному имени
    ip_list = resolve_domains(DOMAINS.get(CURRENT_CATEGORY))
    if not ip_list:
        return ""

    ip_filter = " or ".join(f"host {ip}" for ip in ip_list)

    # key_words = KEY_WORDS.get(CURRENT_CATEGORY)
    #
    # key_words_filter = " or ".join(f"http.host contains {key_word}" for key_word in key_words)

    ports = PORTS.get(CURRENT_CATEGORY)
    if not ports:
        return ip_filter

    port_filter = " or ".join(f"tcp port {port}" for port in ports)

    return f"({port_filter}) and ({ip_filter})"


# In[708]:


def start_capture(interface, output_file, duration=60):
    """Захват трафика и сохранение в PCAP-файл."""
    packets = []

    # Создание BPF-фильтра
    bpf_filter = create_bpf_filter()

    print(bpf_filter)

    if not bpf_filter:
        print("Не удалось создать фильтр для захвата трафика.")
        sys.exit(1)

    print(f"BPF-фильтр: {bpf_filter}")
    print(f"Начало захвата трафика на интерфейсе {interface}...")

    def packet_callback(packet):
        packets.append(packet)
        print(f"Захвачен пакет: {packet.summary()}")

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


# In[709]:


# Имя выходного файла
RAW_PATH = f'raw/{ CURRENT_CATEGORY }'
FILENAME = f"{ len(os.listdir(RAW_PATH)) + 1 }_{ system }.pcap"
OUTPUT_FILE = f"{RAW_PATH}/{FILENAME}"


# In[710]:


start_capture(INTERFACE, OUTPUT_FILE, DURATION)


# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:




