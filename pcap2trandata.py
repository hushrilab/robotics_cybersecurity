import os
import numpy as np
from scapy.all import rdpcap
import argparse
from sklearn.preprocessing import LabelEncoder

def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def save_as_npz(data_dict, output_dir, filename):
    ensure_dir(output_dir)
    np.savez(os.path.join(output_dir, filename), **data_dict)

def pad_sequences(sequences, padding_value=0):
    max_len = max(len(seq) for seq in sequences)
    padded_seqs = np.full((len(sequences), max_len), padding_value, dtype='float32')
    for i, seq in enumerate(sequences):
        padded_seqs[i, :len(seq)] = seq
    return padded_seqs

def process_and_save_data(timings, sizes, directions, labels, output_dir):
    labels = np.array(labels)
    print("All data shapes: timings={}, sizes={}, directions={}, labels={}".format(
        timings.shape, sizes.shape, directions.shape, labels.shape))
    
    data_dict = {
        'direction': directions,
        'time': timings,
        'size': sizes,
        'label': labels
    }
    save_as_npz(data_dict, output_dir, 'processed_data.npz')

def process_pcap_files(base_dir, local_ip, output_dir,
                       ignored_packet_sizes_incoming=[], ignored_packet_sizes_outgoing=[]):
    all_timings = []
    all_sizes = []
    labels = []
    all_directions = []

    for folder in os.listdir(base_dir):
        folder_path = os.path.join(base_dir, folder)
        if os.path.isdir(folder_path):
            for file in os.listdir(folder_path):
                if file.endswith('.pcap'):
                    file_path = os.path.join(folder_path, file)
                    packets = rdpcap(file_path)

                    raw_timings = []
                    packet_sizes = []
                    for i in range(1, len(packets)):
                        if 'IP' in packets[i]:
                            packet_time = packets[i].time
                            packet_size = len(packets[i])
                            if packets[i]['IP'].dst == local_ip and packet_size not in ignored_packet_sizes_incoming:
                                packet_sizes.append(-1 * packet_size)
                                raw_timings.append(-1 * packet_time)
                            elif packets[i]['IP'].src == local_ip and packet_size not in ignored_packet_sizes_outgoing:
                                packet_sizes.append(packet_size)
                                raw_timings.append(packet_time)
                    if raw_timings:
                        all_timings.append(raw_timings[:len(packet_sizes)])
                        all_sizes.append(packet_sizes)
                        all_directions.append(np.sign(packet_sizes))
                        labels.append(folder)
                        if len(packet_sizes) > 40000:
                            print("Number of packet sizes in current file:", len(packet_sizes))
                print(f"Processed {file} successfully.")

    timings_padded = pad_sequences(all_timings)
    sizes_padded = pad_sequences(all_sizes)
    directions_padded = pad_sequences(all_directions)
    le = LabelEncoder()
    labels = le.fit_transform(labels)
    labels_one_hot = np.eye(len(le.classes_))[labels]

    process_and_save_data(timings_padded, sizes_padded, directions_padded, labels_one_hot, output_dir)
    print("All datasets saved successfully.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert pcap files to deep learning dataset.")
    parser.add_argument("input_dir", help="Input directory containing pcap files.")
    parser.add_argument("output_dir", help="Output directory for the converted cell files.")
    parser.add_argument("src_ip", help="Source IP address.")

    args = parser.parse_args()

    process_pcap_files(args.input_dir, args.src_ip, args.output_dir)
