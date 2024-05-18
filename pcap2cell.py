import argparse
from scapy.all import rdpcap, IP
import os

class PacketDirection:
    def __init__(self):
        self.source_ip = None
        self.destination_ip = None

    def is_outgoing_packet(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            if self.source_ip is None and self.destination_ip is None:
                self.source_ip = src_ip
                self.destination_ip = dst_ip
            return src_ip == self.source_ip and dst_ip == self.destination_ip
        return None

def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def pcap_to_cell(pcap_file, output_dir_original, output_dir_modified, label, sample_index):
    packets = rdpcap(pcap_file)
    packet_direction = PacketDirection()

    cell_filename_original = f"{label}-{sample_index}.cell"
    cell_filename_modified = f"{label}-{sample_index}.cell"

    ensure_dir(output_dir_original)
    ensure_dir(output_dir_modified)

    with open(os.path.join(output_dir_original, cell_filename_original), 'w') as f_original, \
         open(os.path.join(output_dir_modified, cell_filename_modified), 'w') as f_modified:
        for packet in packets:
            direction = packet_direction.is_outgoing_packet(packet)
            if direction is not None:
                size = len(packet)
                time = packet.time
                direction_str = '1' if direction else '-1'
                modified_size = size if direction else -size

                f_original.write(f'{time} {direction_str} {size}\n')
                f_modified.write(f'{time}\t{modified_size}\n')

def convert_and_save(input_dir, output_dir):
    label_count = {}
    class_index = 0
    class_map = {}
    for root, dirs, files in os.walk(input_dir):
        if files: 
            label = os.path.basename(root)
            print(label) 
            if label not in class_map:
                class_map[label] = class_index
                class_index += 1
            for file in files:
                if file.endswith(".pcap"):
                    if label not in label_count:
                        label_count[label] = 0
                    sample_index = label_count[label]
                    label_count[label] += 1

                    output_dir_original = os.path.join(output_dir, "directional_cell")
                    output_dir_modified = os.path.join(output_dir, "signed_size_cell")

                    input_file_path = os.path.join(root, file)
                    pcap_to_cell(input_file_path, output_dir_original, output_dir_modified, class_map[label], sample_index)
                    print(f"Converted and saved: Class {class_map[label]}, Sample {sample_index} - {file}")
    print("Class label to index mapping:")
    for label, index in class_map.items():
        print(f"Label '{label}' is assigned to index {index}")
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert pcap files to two versions of cell format with class labels.")
    parser.add_argument("input_dir", help="Input directory containing pcap files.")
    parser.add_argument("output_dir", help="Output directory for the converted cell files.")
    args = parser.parse_args()

    convert_and_save(args.input_dir, args.output_dir)