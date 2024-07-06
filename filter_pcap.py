from scapy.all import rdpcap, wrpcap
import os
import argparse

def filter_packets(ignored_sizes, input_file, output_file):
    """
    Read a pcap file, filter out packets with specific sizes, and save the result.
    """
    packets = rdpcap(input_file)
    filtered_packets = [pkt for pkt in packets if len(pkt) not in ignored_sizes]
    wrpcap(output_file, filtered_packets)

def process_directory(ignored_sizes, input_dir, output_dir):
    """
    Recursively process directories to filter pcap files and save results with the same structure.
    """
    for root, dirs, files in os.walk(input_dir):
        for file in files:
            if file.endswith(".pcap"):
                input_file_path = os.path.join(root, file)
                output_file_path = os.path.join(output_dir, os.path.relpath(input_file_path, input_dir))
                os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
                filter_packets(ignored_sizes, input_file_path, output_file_path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Filter out packets with certain sizes and save results into a new directory with the same structure.")
    parser.add_argument("input_dir", help="Input directory containing pcap files.")
    parser.add_argument("output_dir", help="Output directory for the filtered pcap files.")
    parser.add_argument("ignored_sizes", help="Comma-separated list of packet sizes to be filtered out.")
    args = parser.parse_args()
    ignored_sizes = list(map(int, args.ignored_sizes.split(',')))
    
    process_directory(ignored_sizes, args.input_dir, args.output_dir)
