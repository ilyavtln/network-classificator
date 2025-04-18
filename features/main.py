import numpy as np
from scapy.all import rdpcap
from tqdm import tqdm
import pandas as pd
from scapy.layers.inet import IP, TCP, UDP

def parse_packet(packet):
    if IP in packet and (TCP in packet or UDP in packet):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        if TCP in packet:
            transport_layer = packet[TCP]
            protocol = 'TCP'
        else:
            transport_layer = packet[UDP]
            protocol = 'UDP'

        src_port = transport_layer.sport
        dst_port = transport_layer.dport

        direction = 'fwd' if src_port < dst_port else 'bwd'

        parsed = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'direction': direction,
            'timestamp': float(packet.time),
            'length': len(packet),
            'header_len': transport_layer.len if UDP in packet else transport_layer.dataofs * 4,
            'tcp_flags': {
                'FIN': int((TCP in packet) and (transport_layer.flags & 0x01 != 0)),
                'SYN': int((TCP in packet) and (transport_layer.flags & 0x02 != 0)),
                'RST': int((TCP in packet) and (transport_layer.flags & 0x04 != 0)),
                'PSH': int((TCP in packet) and (transport_layer.flags & 0x08 != 0)),
                'ACK': int((TCP in packet) and (transport_layer.flags & 0x10 != 0)),
                'URG': int((TCP in packet) and (transport_layer.flags & 0x20 != 0)),
                'ECE': int((TCP in packet) and (transport_layer.flags & 0x40 != 0)),
                'CWR': int((TCP in packet) and (transport_layer.flags & 0x80 != 0)),
            },
            'init_win_bytes_fwd': transport_layer.window if TCP in packet else 0,
            'act_data_pkt_fwd': 1 if len(transport_layer.payload) > 0 else 0,
            'min_seg_size_fwd': transport_layer.dataofs * 4 if TCP in packet else 0,
        }

        flow_key = (src_ip, src_port, dst_ip, dst_port, protocol)
        return flow_key, parsed

    return None, None


def extract_features(flow_packets):
    if len(flow_packets) < 2:
        return None

    fwd = [p for p in flow_packets if p['direction'] == 'fwd']
    bwd = [p for p in flow_packets if p['direction'] == 'bwd']

    times = [p['timestamp'] for p in flow_packets]
    times.sort()

    duration = times[-1] - times[0]
    total_packets = len(flow_packets)
    total_bytes = sum(p['length'] for p in flow_packets)
    fwd_bytes = sum(p['length'] for p in fwd)
    bwd_bytes = sum(p['length'] for p in bwd)

    flow_iats = np.diff(times)
    fwd_times = [p['timestamp'] for p in fwd]
    bwd_times = [p['timestamp'] for p in bwd]
    fwd_iats = np.diff(fwd_times) if len(fwd_times) > 1 else [0]
    bwd_iats = np.diff(bwd_times) if len(bwd_times) > 1 else [0]

    def packet_stats(packets):
        lengths = [p['length'] for p in packets]
        return [
            max(lengths) if lengths else 0,
            min(lengths) if lengths else 0,
            np.mean(lengths) if lengths else 0,
            np.std(lengths) if lengths else 0,
        ]

    fwd_stats = packet_stats(fwd)
    bwd_stats = packet_stats(bwd)

    flow_bytes_per_s = total_bytes / duration if duration > 0 else 0
    flow_pkts_per_s = total_packets / duration if duration > 0 else 0

    feature_vector = {
        # 1-2
        "Destination Port": int(flow_packets[0].get("dst_port", 0)),
        "Flow Duration": duration,

        # 3-6
        "Total Fwd Packets": len(fwd),
        "Total Backward Packets": len(bwd),
        "Total Length of Fwd Packets": fwd_bytes,
        "Total Length of Bwd Packets": bwd_bytes,

        # 7-10
        "Fwd Packet Length Max": fwd_stats[0],
        "Fwd Packet Length Min": fwd_stats[1],
        "Fwd Packet Length Mean": fwd_stats[2],
        "Fwd Packet Length Std": fwd_stats[3],

        # 11-14
        "Bwd Packet Length Max": bwd_stats[0],
        "Bwd Packet Length Min": bwd_stats[1],
        "Bwd Packet Length Mean": bwd_stats[2],
        "Bwd Packet Length Std": bwd_stats[3],

        # 15-16
        "Flow Bytes/s": flow_bytes_per_s,
        "Flow Packets/s": flow_pkts_per_s,

        # 17-20
        "Flow IAT Mean": np.mean(flow_iats) if len(flow_iats) > 0 else 0,
        "Flow IAT Std": np.std(flow_iats) if len(flow_iats) > 0 else 0,
        "Flow IAT Max": np.max(flow_iats) if len(flow_iats) > 0 else 0,
        "Flow IAT Min": np.min(flow_iats) if len(flow_iats) > 0 else 0,

        # 21-25
        "Fwd IAT Total": sum(fwd_iats),
        "Fwd IAT Mean": np.mean(fwd_iats),
        "Fwd IAT Std": np.std(fwd_iats),
        "Fwd IAT Max": np.max(fwd_iats),
        "Fwd IAT Min": np.min(fwd_iats),

        # 26-30
        "Bwd IAT Total": sum(bwd_iats),
        "Bwd IAT Mean": np.mean(bwd_iats),
        "Bwd IAT Std": np.std(bwd_iats),
        "Bwd IAT Max": np.max(bwd_iats),
        "Bwd IAT Min": np.min(bwd_iats),

        # 31-34 (flags)
        "Fwd PSH Flags": sum(p['tcp_flags']['PSH'] for p in fwd),
        "Bwd PSH Flags": sum(p['tcp_flags']['PSH'] for p in bwd),
        "Fwd URG Flags": sum(p['tcp_flags']['URG'] for p in fwd),
        "Bwd URG Flags": sum(p['tcp_flags']['URG'] for p in bwd),

        # 35-36 (header length)
        "Fwd Header Length": sum(p['header_len'] for p in fwd),
        "Bwd Header Length": sum(p['header_len'] for p in bwd),

        # 37-38
        "Fwd Packets/s": len(fwd) / duration if duration > 0 else 0,
        "Bwd Packets/s": len(bwd) / duration if duration > 0 else 0,

        # 39-43 (length stats)
        "Min Packet Length": min(p['length'] for p in flow_packets),
        "Max Packet Length": max(p['length'] for p in flow_packets),
        "Packet Length Mean": np.mean([p['length'] for p in flow_packets]),
        "Packet Length Std": np.std([p['length'] for p in flow_packets]),
        "Packet Length Variance": np.var([p['length'] for p in flow_packets]),

        # 44-51 (TCP flags)
        "FIN Flag Count": sum(p['tcp_flags']['FIN'] for p in flow_packets),
        "SYN Flag Count": sum(p['tcp_flags']['SYN'] for p in flow_packets),
        "RST Flag Count": sum(p['tcp_flags']['RST'] for p in flow_packets),
        "ACK Flag Count": sum(p['tcp_flags']['ACK'] for p in flow_packets),
        "PSH Flag Count": sum(p['tcp_flags']['PSH'] for p in flow_packets),
        "URG Flag Count": sum(p['tcp_flags']['URG'] for p in flow_packets),
        "CWE Flag Count": sum(p['tcp_flags']['CWR'] for p in flow_packets),
        "ECE Flag Count": sum(p['tcp_flags']['ECE'] for p in flow_packets),

        # 52-55
        "Down/Up Ratio": len(bwd) / len(fwd) if len(fwd) > 0 else 0,
        "Average Packet Size": total_bytes / total_packets,
        "Avg Fwd Segment Size": fwd_bytes / len(fwd) if len(fwd) > 0 else 0,
        "Avg Bwd Segment Size": bwd_bytes / len(bwd) if len(bwd) > 0 else 0,

        # 56
        "Fwd Header Length.1": sum(p['header_len'] for p in fwd),

        # 57-62
        "Fwd Avg Bytes/Bulk": 0,
        "Fwd Avg Packets/Bulk": 0,
        "Fwd Avg Bulk Rate": 0,
        "Bwd Avg Bytes/Bulk": 0,
        "Bwd Avg Packets/Bulk": 0,
        "Bwd Avg Bulk Rate": 0,

        # 63-66 (subflows)
        "Subflow Fwd Packets": len(fwd),
        "Subflow Fwd Bytes": fwd_bytes,
        "Subflow Bwd Packets": len(bwd),
        "Subflow Bwd Bytes": bwd_bytes,

        # 67-70
        "Init_Win_bytes_forward": fwd[0]['init_win_bytes_fwd'] if fwd else 0,
        "Init_Win_bytes_backward": bwd[0]['init_win_bytes_fwd'] if bwd else 0,
        "act_data_pkt_fwd": sum(p['act_data_pkt_fwd'] for p in fwd),
        "min_seg_size_forward": min(p['min_seg_size_fwd'] for p in fwd) if fwd else 0,

        # 71-78
        "Active Mean": 0, "Active Std": 0, "Active Max": 0, "Active Min": 0,
        "Idle Mean": 0, "Idle Std": 0, "Idle Max": 0, "Idle Min": 0,
    }

    return feature_vector


def parse_pcap_to_flows(pcap_path):
    packets = rdpcap(pcap_path)
    flows = {}

    for packet in tqdm(packets, desc="Parsing packets"):
        flow_key, parsed = parse_packet(packet)
        if flow_key and parsed:
            rev_flow_key = (flow_key[2], flow_key[3], flow_key[0], flow_key[1], flow_key[4])
            if flow_key in flows:
                flows[flow_key].append(parsed)
            elif rev_flow_key in flows:
                parsed['direction'] = 'bwd' if parsed['direction'] == 'fwd' else 'fwd'
                flows[rev_flow_key].append(parsed)
            else:
                flows[flow_key] = [parsed]

    return list(flows.values())

flows = parse_pcap_to_flows("new.pcap")
features_list = []

for flow in flows:
    features = extract_features(flow)
    if features:
        features_list.append(features)

features_df = pd.DataFrame(features_list)
features_df.to_csv("features.csv", index=False)