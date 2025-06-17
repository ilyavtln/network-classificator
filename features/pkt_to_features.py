from collections import defaultdict
import numpy as np
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Глобальное хранилище состояний потоков
flow_states = defaultdict(lambda: {
    'packets': [], 'start_time': None, 'prev_time': None, 'is_active': False,
    'last_active_time': None, 'last_bulk_time': None, 'total_fwd_packets': 0,
    'total_bwd_packets': 0, 'total_fwd_bytes': 0, 'total_bwd_bytes': 0,
    'fwd_packet_sizes': [], 'bwd_packet_sizes': [], 'inter_packet_times': [],
    'fwd_inter_packet_times': [], 'bwd_inter_packet_times': [], 'tcp_count': 0,
    'udp_count': 0, 'icmp_count': 0, 'syn_count': 0, 'ack_count': 0, 'fin_count': 0,
    'rst_count': 0, 'psh_count': 0, 'urg_count': 0, 'cwe_count': 0, 'ece_count': 0,
    'fwd_psh_flags': 0, 'bwd_psh_flags': 0, 'fwd_urg_flags': 0, 'bwd_urg_flags': 0,
    'fwd_header_length': 0, 'bwd_header_length': 0, 'min_seg_size_forward': float('inf'),
    'init_win_bytes_forward': 0, 'init_win_bytes_backward': 0, 'act_data_pkt_fwd': 0,
    'active_times': [], 'idle_times': [], 'fwd_bulk_bytes': 0, 'bwd_bulk_bytes': 0,
    'fwd_bulk_packets': 0, 'bwd_bulk_packets': 0, 'src_ip': None, 'src_port': None
})


def update_flow_state(pkt):
    if not IP in pkt:
        return None

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
            proto = 1

        flow_key = tuple(sorted([
            (src_ip, src_port, dst_ip, dst_port, proto),
            (dst_ip, dst_port, src_ip, src_port, proto)
        ]))[0]
        state = flow_states[flow_key]

        pkt_time = pkt.time
        if state['start_time'] is None:
            state['start_time'] = pkt_time

        pkt_size = len(pkt)
        inter_packet_time = float(pkt_time - state['prev_time']) if state['prev_time'] is not None else None

        # Определение направления
        is_forward = (state['src_ip'] is None and src_ip == pkt[IP].src) or (
                state['src_ip'] == src_ip and state['src_port'] == src_port)
        if state['src_ip'] is None:
            state['src_ip'] = src_ip
            state['src_port'] = src_port

        # Обновление IAT и активности
        if inter_packet_time is not None and inter_packet_time >= 0:
            state['inter_packet_times'].append(inter_packet_time)
            if is_forward:
                state['fwd_inter_packet_times'].append(inter_packet_time)
            else:
                state['bwd_inter_packet_times'].append(inter_packet_time)

        state['prev_time'] = pkt_time

        # Подсчёт метрик
        if is_forward:
            state['total_fwd_packets'] += 1
            state['total_fwd_bytes'] += pkt_size
            state['fwd_packet_sizes'].append(pkt_size)
        else:
            state['total_bwd_packets'] += 1
            state['total_bwd_bytes'] += pkt_size
            state['bwd_packet_sizes'].append(pkt_size)

        if TCP in pkt:
            state['tcp_count'] += 1
            if is_forward:
                state['fwd_header_length'] += len(pkt[TCP].options) + 20
                if hasattr(pkt[TCP], 'window'):
                    state['init_win_bytes_forward'] = max(state['init_win_bytes_forward'], pkt[TCP].window)
                state['min_seg_size_forward'] = min(state['min_seg_size_forward'], len(pkt[TCP]))
                if hasattr(pkt[TCP], 'payload') and len(pkt[TCP].payload) > 0:
                    state['act_data_pkt_fwd'] += 1
                    if state['last_bulk_time'] is None or (pkt_time - state['last_bulk_time']) < 0.1:
                        state['fwd_bulk_bytes'] += len(pkt[TCP].payload)
                        state['fwd_bulk_packets'] += 1
                    state['last_bulk_time'] = pkt_time
                if pkt[TCP].flags & 0x08:  # PSH
                    state['fwd_psh_flags'] += 1
                if pkt[TCP].flags & 0x20:  # URG
                    state['fwd_urg_flags'] += 1
            else:
                state['bwd_header_length'] += len(pkt[TCP].options) + 20
                if hasattr(pkt[TCP], 'window'):
                    state['init_win_bytes_backward'] = max(state['init_win_bytes_backward'], pkt[TCP].window)
                if hasattr(pkt[TCP], 'payload') and len(pkt[TCP].payload) > 0:
                    if state['last_bulk_time'] is None or (pkt_time - state['last_bulk_time']) < 0.1:
                        state['bwd_bulk_bytes'] += len(pkt[TCP].payload)
                        state['bwd_bulk_packets'] += 1
                    state['last_bulk_time'] = pkt_time
                if pkt[TCP].flags & 0x08:  # PSH
                    state['bwd_psh_flags'] += 1
                if pkt[TCP].flags & 0x20:  # URG
                    state['bwd_urg_flags'] += 1

            if pkt[TCP].flags & 0x02:  # SYN
                state['syn_count'] += 1
            if pkt[TCP].flags & 0x10:  # ACK
                state['ack_count'] += 1
            if pkt[TCP].flags & 0x01:  # FIN
                state['fin_count'] += 1
            if pkt[TCP].flags & 0x04:  # RST
                state['rst_count'] += 1
            if pkt[TCP].flags & 0x08:  # PSH
                state['psh_count'] += 1
            if pkt[TCP].flags & 0x20:  # URG
                state['urg_count'] += 1
            if pkt[TCP].flags & 0x80:  # CWE
                state['cwe_count'] += 1
            if pkt[TCP].flags & 0x40:  # ECE
                state['ece_count'] += 1
        elif UDP in pkt:
            state['udp_count'] += 1
            if is_forward and hasattr(pkt[UDP], 'payload') and len(pkt[UDP].payload) > 0:
                state['act_data_pkt_fwd'] += 1
                if state['last_bulk_time'] is None or (pkt_time - state['last_bulk_time']) < 0.1:
                    state['fwd_bulk_bytes'] += len(pkt[UDP].payload)
                    state['fwd_bulk_packets'] += 1
                state['last_bulk_time'] = pkt_time
            elif not is_forward and hasattr(pkt[UDP], 'payload') and len(pkt[UDP].payload) > 0:
                if state['last_bulk_time'] is None or (pkt_time - state['last_bulk_time']) < 0.1:
                    state['bwd_bulk_bytes'] += len(pkt[UDP].payload)
                    state['bwd_bulk_packets'] += 1
                state['last_bulk_time'] = pkt_time
        elif ICMP in pkt:
            state['icmp_count'] += 1

        # Проверка на завершение потока
        if state['fin_count'] > 0 or state['total_fwd_packets'] + state['total_bwd_packets'] >= 2:  # Уменьшен порог
            result = compute_final_features(state, flow_key[3])
            return result
        return None

    except Exception as e:
        print(f"Ошибка обработки пакета: {e}")
        return None


def compute_final_features(state, dst_port):
    """
    Вычисляет финальные признаки потока на основе собранных данных.

    Args:
        state (dict): Состояние потока из flow_states.
        dst_port (int): Порт назначения.

    Returns:
        dict: Словарь с вычисленными признаками потока.
    """
    flow_duration = float(state['prev_time'] - state['start_time']) if state['start_time'] and state[
        'prev_time'] else 1e-6
    total_packets = state['total_fwd_packets'] + state['total_bwd_packets']
    total_bytes = state['total_fwd_bytes'] + state['total_bwd_bytes']
    packet_sizes = state['fwd_packet_sizes'] + state['bwd_packet_sizes']

    features = {
        'Destination Port': dst_port,
        'Flow Duration': flow_duration,
        'Total Fwd Packets': state['total_fwd_packets'],
        'Total Backward Packets': state['total_bwd_packets'],
        'Total Length of Fwd Packets': state['total_fwd_bytes'],
        'Total Length of Bwd Packets': state['total_bwd_bytes'],
        'Fwd Packet Length Max': max(state['fwd_packet_sizes']) if state['fwd_packet_sizes'] else 0,
        'Fwd Packet Length Min': min(state['fwd_packet_sizes']) if state['fwd_packet_sizes'] else 0,
        'Fwd Packet Length Mean': np.mean(state['fwd_packet_sizes']) if state['fwd_packet_sizes'] else 0,
        'Fwd Packet Length Std': np.std(state['fwd_packet_sizes']) if state['fwd_packet_sizes'] else 0,
        'Bwd Packet Length Max': max(state['bwd_packet_sizes']) if state['bwd_packet_sizes'] else 0,
        'Bwd Packet Length Min': min(state['bwd_packet_sizes']) if state['bwd_packet_sizes'] else 0,
        'Bwd Packet Length Mean': np.mean(state['bwd_packet_sizes']) if state['bwd_packet_sizes'] else 0,
        'Bwd Packet Length Std': np.std(state['bwd_packet_sizes']) if state['bwd_packet_sizes'] else 0,
        'Flow Bytes/s': total_bytes / flow_duration if flow_duration > 0 else 0,
        'Flow Packets/s': total_packets / flow_duration if flow_duration > 0 else 0,
        'Flow IAT Mean': np.mean(state['inter_packet_times']) if state['inter_packet_times'] else 0,
        'Flow IAT Std': np.std(state['inter_packet_times']) if state['inter_packet_times'] else 0,
        'Flow IAT Max': max(state['inter_packet_times']) if state['inter_packet_times'] else 0,
        'Flow IAT Min': min(state['inter_packet_times']) if state['inter_packet_times'] else 0,
        'Fwd IAT Total': sum(state['fwd_inter_packet_times']) if state['fwd_inter_packet_times'] else 0,
        'Fwd IAT Mean': np.mean(state['fwd_inter_packet_times']) if state['fwd_inter_packet_times'] else 0,
        'Fwd IAT Std': np.std(state['fwd_inter_packet_times']) if state['fwd_inter_packet_times'] else 0,
        'Fwd IAT Max': max(state['fwd_inter_packet_times']) if state['fwd_inter_packet_times'] else 0,
        'Fwd IAT Min': min(state['fwd_inter_packet_times']) if state['fwd_inter_packet_times'] else 0,
        'Bwd IAT Total': sum(state['bwd_inter_packet_times']) if state['bwd_inter_packet_times'] else 0,
        'Bwd IAT Mean': np.mean(state['bwd_inter_packet_times']) if state['bwd_inter_packet_times'] else 0,
        'Bwd IAT Std': np.std(state['bwd_inter_packet_times']) if state['bwd_inter_packet_times'] else 0,
        'Bwd IAT Max': max(state['bwd_inter_packet_times']) if state['bwd_inter_packet_times'] else 0,
        'Bwd IAT Min': min(state['bwd_inter_packet_times']) if state['bwd_inter_packet_times'] else 0,
        'Fwd PSH Flags': state['fwd_psh_flags'],
        'Bwd PSH Flags': state['bwd_psh_flags'],
        'Fwd URG Flags': state['fwd_urg_flags'],
        'Bwd URG Flags': state['bwd_urg_flags'],
        'Fwd Header Length': state['fwd_header_length'],
        'Bwd Header Length': state['bwd_header_length'],
        'Fwd Packets/s': state['total_fwd_packets'] / flow_duration if flow_duration > 0 else 0,
        'Bwd Packets/s': state['total_bwd_packets'] / flow_duration if flow_duration > 0 else 0,
        'Min Packet Length': min(packet_sizes) if packet_sizes else 0,
        'Max Packet Length': max(packet_sizes) if packet_sizes else 0,
        'Packet Length Mean': np.mean(packet_sizes) if packet_sizes else 0,
        'Packet Length Std': np.std(packet_sizes) if packet_sizes else 0,
        'Packet Length Variance': np.var(packet_sizes) if packet_sizes else 0,
        'FIN Flag Count': state['fin_count'],
        'SYN Flag Count': state['syn_count'],
        'RST Flag Count': state['rst_count'],
        'PSH Flag Count': state['psh_count'],
        'ACK Flag Count': state['ack_count'],
        'URG Flag Count': state['urg_count'],
        'CWE Flag Count': state['cwe_count'],
        'ECE Flag Count': state['ece_count'],
        'Down/Up Ratio': state['total_bwd_packets'] / state['total_fwd_packets'] if state[
                                                                                        'total_fwd_packets'] > 0 else 0,
        'Average Packet Size': np.mean(packet_sizes) if packet_sizes else 0,
        'Avg Fwd Segment Size': np.mean(state['fwd_packet_sizes']) if state['fwd_packet_sizes'] else 0,
        'Avg Bwd Segment Size': np.mean(state['bwd_packet_sizes']) if state['bwd_packet_sizes'] else 0,
        'Fwd Avg Bytes/Bulk': state['fwd_bulk_bytes'] / state['fwd_bulk_packets'] if state[
                                                                                         'fwd_bulk_packets'] > 0 else 0,
        'Fwd Avg Packets/Bulk': state['fwd_bulk_packets'] / state['total_fwd_packets'] if state[
                                                                                              'total_fwd_packets'] > 0 else 0,
        'Fwd Avg Bulk Rate': state['fwd_bulk_bytes'] / flow_duration if flow_duration > 0 else 0,
        'Bwd Avg Bytes/Bulk': state['bwd_bulk_bytes'] / state['bwd_bulk_packets'] if state[
                                                                                         'bwd_bulk_packets'] > 0 else 0,
        'Bwd Avg Packets/Bulk': state['bwd_bulk_packets'] / state['total_bwd_packets'] if state[
                                                                                              'total_bwd_packets'] > 0 else 0,
        'Bwd Avg Bulk Rate': state['bwd_bulk_bytes'] / flow_duration if flow_duration > 0 else 0,
        'Subflow Fwd Packets': state['total_fwd_packets'],
        'Subflow Fwd Bytes': state['total_fwd_bytes'],
        'Subflow Bwd Packets': state['total_bwd_packets'],
        'Subflow Bwd Bytes': state['total_bwd_bytes'],
        'Init_Win_bytes_forward': state['init_win_bytes_forward'],
        'Init_Win_bytes_backward': state['init_win_bytes_backward'],
        'act_data_pkt_fwd': state['act_data_pkt_fwd'],
        'min_seg_size_forward': state['min_seg_size_forward'] if state['min_seg_size_forward'] != float('inf') else 0,
        'Active Mean': np.mean(state['active_times']) if state['active_times'] else 0,
        'Active Std': np.std(state['active_times']) if state['active_times'] else 0,
        'Active Max': max(state['active_times']) if state['active_times'] else 0,
        'Active Min': min(state['active_times']) if state['active_times'] else 0,
        'Idle Mean': np.mean(state['idle_times']) if state['idle_times'] else 0,
        'Idle Std': np.std(state['idle_times']) if state['idle_times'] else 0,
        'Idle Max': max(state['idle_times']) if state['idle_times'] else 0,
        'Idle Min': min(state['idle_times']) if state['idle_times'] else 0,
        'Fwd Header Length.1': state['fwd_header_length']
    }
    return features