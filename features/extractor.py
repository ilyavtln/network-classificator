import numpy as np
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from collections import defaultdict

def extract_features_from_pcap(pcap_file, category=""):
    """Извлекает признаки из PCAP-файла."""
    try:
        packets = rdpcap(pcap_file)
        if not packets:
            print(f"Файл {pcap_file} пустой")
            return []

        # Группировка пакетов по потокам
        flows = defaultdict(list)
        for pkt in packets:
            if IP in pkt:
                try:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    proto = pkt[IP].proto
                    src_port = dst_port = 0

                    if TCP in pkt:
                        src_port = pkt[TCP].sport
                        dst_port = pkt[TCP].dport
                    elif UDP in pkt:
                        src_port = pkt[UDP].sport
                        dst_port = pkt[UDP].dport
                    elif ICMP in pkt:
                        proto = 1  # ICMP

                    flow_key = tuple(sorted([
                        (src_ip, src_port, dst_ip, dst_port, proto),
                        (dst_ip, dst_port, src_ip, src_port, proto)
                    ]))[0]
                    flows[flow_key].append(pkt)
                except Exception as e:
                    print(f"Ошибка обработки пакета в {pcap_file}: {e}")
                    continue

        # Список для хранения признаков всех потоков
        all_features = []

        # Обработка каждого потока
        for flow_key, packets in flows.items():
            (src_ip, src_port, dst_ip, dst_port, proto) = flow_key
            features = compute_flow_features(packets, category, dst_port)
            if features:
                all_features.append(features)

        print(f"Успешно обработан файл {pcap_file}: {len(packets)} пакетов, {len(all_features)} потоков")
        return all_features

    except Exception as e:
        print(f"Ошибка обработки {pcap_file}: {e}")
        return []

def compute_flow_features(packets, category, dst_port):
    """Вычисляет признаки для одного потока, включая Destination Port из пакетов."""
    # Инициализация переменных
    total_fwd_packets = total_bwd_packets = 0
    total_fwd_bytes = total_bwd_bytes = 0
    fwd_packet_sizes = []
    bwd_packet_sizes = []
    inter_packet_times = []
    fwd_inter_packet_times = []
    bwd_inter_packet_times = []
    tcp_count = udp_count = icmp_count = 0
    syn_count = ack_count = fin_count = rst_count = psh_count = urg_count = cwe_count = ece_count = 0
    fwd_psh_flags = bwd_psh_flags = fwd_urg_flags = bwd_urg_flags = 0
    fwd_header_length = bwd_header_length = 0
    min_seg_size_forward = float('inf')
    init_win_bytes_forward = init_win_bytes_backward = 0
    act_data_pkt_fwd = 0
    active_times = []
    idle_times = []
    prev_time = start_time = last_active_time = None
    is_active = False
    fwd_bulk_bytes = bwd_bulk_bytes = 0
    fwd_bulk_packets = bwd_bulk_packets = 0
    last_bulk_time = None
    bulk_threshold = 0.1  # Порог для bulk
    idle_threshold = 0.01  # Порог для простоя

    # Определение направления первого пакета как Fwd
    first_pkt = packets[0]
    src_ip = src_port = None
    if IP in first_pkt:
        try:
            src_ip = first_pkt[IP].src
            src_port = first_pkt[TCP].sport if TCP in first_pkt else (first_pkt[UDP].sport if UDP in first_pkt else 0)
        except Exception as e:
            print(f"Ошибка определения направления: {e}")
            return {}

    # Обработка пакетов в потоке
    for pkt in packets:
        try:
            pkt_time = pkt.time
            if start_time is None:
                start_time = pkt_time

            pkt_size = len(pkt)
            inter_packet_time = float(pkt_time - prev_time) if prev_time is not None else None

            # Определение направления
            is_forward = False
            if IP in pkt:
                pkt_src_ip = pkt[IP].src
                pkt_src_port = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
                is_forward = (pkt_src_ip == src_ip and pkt_src_port == src_port) or (
                    pkt_src_ip != src_ip and pkt_src_port == 0 and ICMP in pkt)

            # Обработка IAT и активности
            if inter_packet_time is not None and inter_packet_time >= 0:
                inter_packet_times.append(inter_packet_time)
                if is_forward:
                    fwd_inter_packet_times.append(inter_packet_time)
                else:
                    bwd_inter_packet_times.append(inter_packet_time)

                if inter_packet_time > idle_threshold:
                    if is_active and last_active_time is not None:
                        active_duration = float(pkt_time - last_active_time)
                        if active_duration > 0:
                            active_times.append(active_duration)
                        is_active = False
                        idle_times.append(inter_packet_time)
                    else:
                        idle_times.append(inter_packet_time)
                else:
                    is_active = True
                    last_active_time = pkt_time

            prev_time = pkt_time

            # Подсчёт метрик
            if is_forward:
                total_fwd_packets += 1
                total_fwd_bytes += pkt_size
                fwd_packet_sizes.append(pkt_size)
            else:
                total_bwd_packets += 1
                total_bwd_bytes += pkt_size
                bwd_packet_sizes.append(pkt_size)

            if TCP in pkt:
                tcp_count += 1
                if is_forward:
                    fwd_header_length += len(pkt[TCP].options) + 20
                    if hasattr(pkt[TCP], 'window'):
                        init_win_bytes_forward = max(init_win_bytes_forward, pkt[TCP].window)
                    min_seg_size_forward = min(min_seg_size_forward, len(pkt[TCP]))
                    if hasattr(pkt[TCP], 'payload') and len(pkt[TCP].payload) > 0:
                        act_data_pkt_fwd += 1
                        if last_bulk_time is None or (pkt_time - last_bulk_time) < bulk_threshold:
                            fwd_bulk_bytes += len(pkt[TCP].payload)
                            fwd_bulk_packets += 1
                        last_bulk_time = pkt_time
                    if pkt[TCP].flags & 0x08:  # PSH
                        fwd_psh_flags += 1
                    if pkt[TCP].flags & 0x20:  # URG
                        fwd_urg_flags += 1
                else:
                    bwd_header_length += len(pkt[TCP].options) + 20
                    if hasattr(pkt[TCP], 'window'):
                        init_win_bytes_backward = max(init_win_bytes_backward, pkt[TCP].window)
                    if hasattr(pkt[TCP], 'payload') and len(pkt[TCP].payload) > 0:
                        if last_bulk_time is None or (pkt_time - last_bulk_time) < bulk_threshold:
                            bwd_bulk_bytes += len(pkt[TCP].payload)
                            bwd_bulk_packets += 1
                        last_bulk_time = pkt_time
                    if pkt[TCP].flags & 0x08:  # PSH
                        bwd_psh_flags += 1
                    if pkt[TCP].flags & 0x20:  # URG
                        bwd_urg_flags += 1

                if pkt[TCP].flags & 0x02:  # SYN
                    syn_count += 1
                if pkt[TCP].flags & 0x10:  # ACK
                    ack_count += 1
                if pkt[TCP].flags & 0x01:  # FIN
                    fin_count += 1
                if pkt[TCP].flags & 0x04:  # RST
                    rst_count += 1
                if pkt[TCP].flags & 0x08:  # PSH
                    psh_count += 1
                if pkt[TCP].flags & 0x20:  # URG
                    urg_count += 1
                if pkt[TCP].flags & 0x80:  # CWE
                    cwe_count += 1
                if pkt[TCP].flags & 0x40:  # ECE
                    ece_count += 1
            elif UDP in pkt:
                udp_count += 1
                if is_forward and hasattr(pkt[UDP], 'payload') and len(pkt[UDP].payload) > 0:
                    act_data_pkt_fwd += 1
                    if last_bulk_time is None or (pkt_time - last_bulk_time) < bulk_threshold:
                        fwd_bulk_bytes += len(pkt[UDP].payload)
                        fwd_bulk_packets += 1
                    last_bulk_time = pkt_time
                elif not is_forward and hasattr(pkt[UDP], 'payload') and len(pkt[UDP].payload) > 0:
                    if last_bulk_time is None or (pkt_time - last_bulk_time) < bulk_threshold:
                        bwd_bulk_bytes += len(pkt[UDP].payload)
                        bwd_bulk_packets += 1
                    last_bulk_time = pkt_time
            elif ICMP in pkt:
                icmp_count += 1

        except Exception as e:
            print(f"Ошибка обработки пакета: {e}")
            continue

    # Длительность потока
    flow_duration = float(prev_time - start_time) if start_time is not None and prev_time is not None else 1e-6

    # Вычисление признаков
    total_packets = total_fwd_packets + total_bwd_packets
    total_bytes = total_fwd_bytes + total_bwd_bytes
    packet_sizes = fwd_packet_sizes + bwd_packet_sizes

    features = {
        'Destination Port': dst_port,
        'Flow Duration': flow_duration,
        'Total Fwd Packets': total_fwd_packets,
        'Total Backward Packets': total_bwd_packets,
        'Total Length of Fwd Packets': total_fwd_bytes,
        'Total Length of Bwd Packets': total_bwd_bytes,
        'Fwd Packet Length Max': max(fwd_packet_sizes) if fwd_packet_sizes else 0,
        'Fwd Packet Length Min': min(fwd_packet_sizes) if fwd_packet_sizes else 0,
        'Fwd Packet Length Mean': np.mean(fwd_packet_sizes) if fwd_packet_sizes else 0,
        'Fwd Packet Length Std': np.std(fwd_packet_sizes) if fwd_packet_sizes else 0,
        'Bwd Packet Length Max': max(bwd_packet_sizes) if bwd_packet_sizes else 0,
        'Bwd Packet Length Min': min(bwd_packet_sizes) if bwd_packet_sizes else 0,
        'Bwd Packet Length Mean': np.mean(bwd_packet_sizes) if bwd_packet_sizes else 0,
        'Bwd Packet Length Std': np.std(bwd_packet_sizes) if bwd_packet_sizes else 0,
        'Flow Bytes/s': total_bytes / flow_duration if flow_duration > 0 else 0,
        'Flow Packets/s': total_packets / flow_duration if flow_duration > 0 else 0,
        'Flow IAT Mean': np.mean(inter_packet_times) if inter_packet_times else 0,
        'Flow IAT Std': np.std(inter_packet_times) if inter_packet_times else 0,
        'Flow IAT Max': max(inter_packet_times) if inter_packet_times else 0,
        'Flow IAT Min': min(inter_packet_times) if inter_packet_times else 0,
        'Fwd IAT Total': sum(fwd_inter_packet_times) if fwd_inter_packet_times else 0,
        'Fwd IAT Mean': np.mean(fwd_inter_packet_times) if fwd_inter_packet_times else 0,
        'Fwd IAT Std': np.std(fwd_inter_packet_times) if fwd_inter_packet_times else 0,
        'Fwd IAT Max': max(fwd_inter_packet_times) if fwd_inter_packet_times else 0,
        'Fwd IAT Min': min(fwd_inter_packet_times) if fwd_inter_packet_times else 0,
        'Bwd IAT Total': sum(bwd_inter_packet_times) if bwd_inter_packet_times else 0,
        'Bwd IAT Mean': np.mean(bwd_inter_packet_times) if bwd_inter_packet_times else 0,
        'Bwd IAT Std': np.std(bwd_inter_packet_times) if bwd_inter_packet_times else 0,
        'Bwd IAT Max': max(bwd_inter_packet_times) if bwd_inter_packet_times else 0,
        'Bwd IAT Min': min(bwd_inter_packet_times) if bwd_inter_packet_times else 0,
        'Fwd PSH Flags': fwd_psh_flags,
        'Bwd PSH Flags': bwd_psh_flags,
        'Fwd URG Flags': fwd_urg_flags,
        'Bwd URG Flags': bwd_urg_flags,
        'Fwd Header Length': fwd_header_length,
        'Bwd Header Length': bwd_header_length,
        'Fwd Packets/s': total_fwd_packets / flow_duration if flow_duration > 0 else 0,
        'Bwd Packets/s': total_bwd_packets / flow_duration if flow_duration > 0 else 0,
        'Min Packet Length': min(packet_sizes) if packet_sizes else 0,
        'Max Packet Length': max(packet_sizes) if packet_sizes else 0,
        'Packet Length Mean': np.mean(packet_sizes) if packet_sizes else 0,
        'Packet Length Std': np.std(packet_sizes) if packet_sizes else 0,
        'Packet Length Variance': np.var(packet_sizes) if packet_sizes else 0,
        'FIN Flag Count': fin_count,
        'SYN Flag Count': syn_count,
        'RST Flag Count': rst_count,
        'PSH Flag Count': psh_count,
        'ACK Flag Count': ack_count,
        'URG Flag Count': urg_count,
        'CWE Flag Count': cwe_count,
        'ECE Flag Count': ece_count,
        'Down/Up Ratio': total_bwd_packets / total_fwd_packets if total_fwd_packets > 0 else 0,
        'Average Packet Size': np.mean(packet_sizes) if packet_sizes else 0,
        'Avg Fwd Segment Size': np.mean(fwd_packet_sizes) if fwd_packet_sizes else 0,
        'Avg Bwd Segment Size': np.mean(bwd_packet_sizes) if bwd_packet_sizes else 0,
        'Fwd Avg Bytes/Bulk': fwd_bulk_bytes / fwd_bulk_packets if fwd_bulk_packets > 0 else 0,
        'Fwd Avg Packets/Bulk': fwd_bulk_packets / total_fwd_packets if total_fwd_packets > 0 else 0,
        'Fwd Avg Bulk Rate': fwd_bulk_bytes / flow_duration if flow_duration > 0 else 0,
        'Bwd Avg Bytes/Bulk': bwd_bulk_bytes / bwd_bulk_packets if bwd_bulk_packets > 0 else 0,
        'Bwd Avg Packets/Bulk': bwd_bulk_packets / total_bwd_packets if total_bwd_packets > 0 else 0,
        'Bwd Avg Bulk Rate': bwd_bulk_bytes / flow_duration if flow_duration > 0 else 0,
        'Subflow Fwd Packets': total_fwd_packets,
        'Subflow Fwd Bytes': total_fwd_bytes,
        'Subflow Bwd Packets': total_bwd_packets,
        'Subflow Bwd Bytes': total_bwd_bytes,
        'Init_Win_bytes_forward': init_win_bytes_forward,
        'Init_Win_bytes_backward': init_win_bytes_backward,
        'act_data_pkt_fwd': act_data_pkt_fwd,
        'min_seg_size_forward': min_seg_size_forward if min_seg_size_forward != float('inf') else 0,
        'Active Mean': np.mean(active_times) if active_times else 0,
        'Active Std': np.std(active_times) if active_times else 0,
        'Active Max': max(active_times) if active_times else 0,
        'Active Min': min(active_times) if active_times else 0,
        'Idle Mean': np.mean(idle_times) if idle_times else 0,
        'Idle Std': np.std(idle_times) if idle_times else 0,
        'Idle Max': max(idle_times) if idle_times else 0,
        'Idle Min': min(idle_times) if idle_times else 0,
    }

    if category:
        features['Label'] = category

    return features