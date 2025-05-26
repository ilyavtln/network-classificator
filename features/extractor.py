import numpy as np
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP


def extract_features_from_pcap(pcap_file, category=""):
    """Извлекает признаки из PCAP-файла, исключая порты и IP-адреса."""
    try:
        packets = rdpcap(pcap_file)
        if not packets:
            print(f"Файл {pcap_file} пустой.")
            return None

        # Инициализация переменных
        total_fwd_packets = 0
        total_bwd_packets = 0
        total_fwd_bytes = 0
        total_bwd_bytes = 0
        fwd_packet_sizes = []
        bwd_packet_sizes = []
        inter_packet_times = []
        fwd_inter_packet_times = []
        bwd_inter_packet_times = []
        tcp_count = 0
        udp_count = 0
        syn_count = 0
        ack_count = 0
        fin_count = 0
        rst_count = 0
        psh_count = 0
        urg_count = 0
        cwe_count = 0
        ece_count = 0
        fwd_psh_flags = 0
        bwd_psh_flags = 0
        fwd_urg_flags = 0
        bwd_urg_flags = 0
        fwd_header_length = 0
        bwd_header_length = 0
        min_seg_size_forward = float('inf')
        init_win_bytes_forward = 0
        init_win_bytes_backward = 0
        act_data_pkt_fwd = 0
        active_times = []
        idle_times = []
        prev_time = None
        start_time = None
        last_active_time = None
        is_active = False

        # Обработка пакетов
        for pkt in packets:
            # Время
            pkt_time = pkt.time
            if start_time is None:
                start_time = pkt_time

            # Размер пакета
            pkt_size = len(pkt)

            # Вычисление межпакетного интервала
            inter_packet_time = None
            if prev_time is not None:
                inter_packet_time = float(pkt_time - prev_time)
                inter_packet_times.append(inter_packet_time)

                # Активность и простой
                if inter_packet_time > 1.0:  # Порог для простоя (1 сек)
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

            # Протоколы и флаги
            if IP in pkt:
                if TCP in pkt:
                    tcp_count += 1
                    # Условное разделение на Fwd/Bwd
                    if pkt[TCP].flags & 0x02:  # SYN
                        total_fwd_packets += 1
                        total_fwd_bytes += pkt_size
                        fwd_packet_sizes.append(pkt_size)
                        if inter_packet_time is not None:
                            fwd_inter_packet_times.append(inter_packet_time)
                        syn_count += 1
                        if pkt[TCP].flags & 0x08:  # PSH
                            fwd_psh_flags += 1
                        if pkt[TCP].flags & 0x20:  # URG
                            fwd_urg_flags += 1
                        fwd_header_length += len(pkt[TCP].options) + 20
                        if pkt[TCP].window:
                            init_win_bytes_forward = max(init_win_bytes_forward, pkt[TCP].window)
                        min_seg_size_forward = min(min_seg_size_forward, len(pkt[TCP]))
                        if len(pkt[TCP].payload) > 0:
                            act_data_pkt_fwd += 1
                    else:
                        total_bwd_packets += 1
                        total_bwd_bytes += pkt_size
                        bwd_packet_sizes.append(pkt_size)
                        if inter_packet_time is not None:
                            bwd_inter_packet_times.append(inter_packet_time)
                        if pkt[TCP].flags & 0x08:  # PSH
                            bwd_psh_flags += 1
                        if pkt[TCP].flags & 0x20:  # URG
                            bwd_urg_flags += 1
                        bwd_header_length += len(pkt[TCP].options) + 20
                        if pkt[TCP].window:
                            init_win_bytes_backward = max(init_win_bytes_backward, pkt[TCP].window)

                    # Флаги
                    if pkt[TCP].flags & 0x01:  # FIN
                        fin_count += 1
                    if pkt[TCP].flags & 0x10:  # ACK
                        ack_count += 1
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
                    if total_fwd_packets <= total_bwd_packets:
                        total_fwd_packets += 1
                        total_fwd_bytes += pkt_size
                        fwd_packet_sizes.append(pkt_size)
                        if inter_packet_time is not None:
                            fwd_inter_packet_times.append(inter_packet_time)
                    else:
                        total_bwd_packets += 1
                        total_bwd_bytes += pkt_size
                        bwd_packet_sizes.append(pkt_size)
                        if inter_packet_time is not None:
                            bwd_inter_packet_times.append(inter_packet_time)

        # Длительность потока
        flow_duration = float(pkt_time - start_time) if start_time is not None else 0

        # Вычисление признаков
        total_packets = total_fwd_packets + total_bwd_packets
        total_bytes = total_fwd_bytes + total_bwd_bytes
        packet_sizes = fwd_packet_sizes + bwd_packet_sizes

        features = {
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
            'Flow Bytes/s': (total_bytes / flow_duration) if flow_duration else 0,
            'Flow Packets/s': (total_packets / flow_duration) if flow_duration else 0,
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
            'Fwd Packets/s': (total_fwd_packets / flow_duration) if flow_duration else 0,
            'Bwd Packets/s': (total_bwd_packets / flow_duration) if flow_duration else 0,
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
            'Down/Up Ratio': (total_bwd_packets / total_fwd_packets) if total_fwd_packets else 0,
            'Average Packet Size': np.mean(packet_sizes) if packet_sizes else 0,
            'Avg Fwd Segment Size': np.mean(fwd_packet_sizes) if fwd_packet_sizes else 0,
            'Avg Bwd Segment Size': np.mean(bwd_packet_sizes) if bwd_packet_sizes else 0,
            'Fwd Header Length.1': fwd_header_length,
            'Fwd Avg Bytes/Bulk': 0,
            'Fwd Avg Packets/Bulk': 0,
            'Fwd Avg Bulk Rate': 0,
            'Bwd Avg Bytes/Bulk': 0,
            'Bwd Avg Packets/Bulk': 0,
            'Bwd Avg Bulk Rate': 0,
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
            'Label': category,
        }

        print(f"Успешно обработан файл {pcap_file}: {len(packets)} пакетов")
        return features

    except Exception as e:
        print(f"Ошибка при обработке {pcap_file}: {e}")
        return None
