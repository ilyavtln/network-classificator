import os
import sys
from scapy.all import rdpcap, wrpcap

def estimate_packet_size(packet):
    """Estimate the size of a packet in bytes."""
    try:
        # Convert packet to bytes and get its size
        return len(packet.build())
    except Exception:
        return 0

def compress_pcap(input_file, output_file, target_size_mb=100):
    """Compress a PCAP file to approximately target_size_mb MB by sampling packets."""
    # Convert target size to bytes
    target_size = target_size_mb * 1024 * 1024  # MB to bytes

    try:
        # Read all packets from the input PCAP file
        print(f"Reading PCAP file: {input_file}")
        packets = rdpcap(input_file)
        total_packets = len(packets)
        print(f"Total packets: {total_packets}")

        if total_packets == 0:
            print("Error: No packets found in the input file.")
            sys.exit(1)

        # Estimate total size of the input file
        total_size = sum(estimate_packet_size(pkt) for pkt in packets)
        print(f"Estimated original file size: {total_size / (1024 * 1024):.2f} MB")

        if total_size <= target_size:
            print("Input file is already smaller than or equal to the target size. Copying as is.")
            wrpcap(output_file, packets)
            print(f"File saved: {output_file}")
            return

        # Calculate the target number of packets to keep
        target_packet_ratio = target_size / total_size
        target_packet_count = int(total_packets * target_packet_ratio)
        if target_packet_count == 0:
            print("Error: Target size is too small to keep any packets.")
            sys.exit(1)

        # Sample packets evenly to meet the target size
        step = max(1, total_packets // target_packet_count)
        selected_packets = packets[::step][:target_packet_count]
        print(f"Selected {len(selected_packets)} packets for the compressed file.")

        # Estimate size of selected packets
        selected_size = sum(estimate_packet_size(pkt) for pkt in selected_packets)
        print(f"Estimated compressed file size: {selected_size / (1024 * 1024):.2f} MB")

        # Save the selected packets to a new PCAP file
        print(f"Saving compressed PCAP to: {output_file}")
        wrpcap(output_file, selected_packets)
        print(f"Compression complete. File saved: {output_file}")

    except Exception as e:
        print(f"Error during compression: {e}")
        sys.exit(1)


input_file = "../data/raw/cloud_service/15_darwin_300.pcap"
output_file = "../data/raw/cloud_service/15_darwin_300.pcap"
target_size_mb = 70

if not os.path.exists(input_file):
    print(f"Error: Input file {input_file} does not exist.")
    sys.exit(1)

compress_pcap(input_file, output_file, target_size_mb)