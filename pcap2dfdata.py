import os
import pandas as pd
from scapy.all import rdpcap
from sklearn.model_selection import train_test_split
import pickle
import numpy as np
import argparse

def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def save_as_pickle(data, output_dir, filename):
    ensure_dir(output_dir)  
    with open(os.path.join(output_dir, filename), 'wb') as f:
        pickle.dump(data, f)


def pad_sequences(sequences, padding_value=0):
    max_len = max(len(seq) for seq in sequences) 
    padded_seqs = np.full((len(sequences), max_len), padding_value, dtype='float32') 
    for i, seq in enumerate(sequences):
        padded_seqs[i, :len(seq)] = seq  
    return padded_seqs
    
def process_and_split_data(all_data, labels, output_dir, data_type):
    labels = np.array(labels)
    print("X_train shape:", all_data.shape)

    X_train, X_temp, y_train, y_temp = train_test_split(all_data, labels, test_size=0.4, random_state=42)
    X_valid, X_test, y_valid, y_test = train_test_split(X_temp, y_temp, test_size=0.5, random_state=42)
    print("X_train shape:", X_train.shape)
    print("X_train sample data:", X_train[:1])
    print("y_train shape:", y_train.shape)
    print("y_train sample data:", y_train[:1])

    save_as_pickle(X_train, os.path.join(output_dir, data_type), f'X_train_NoDef.pkl')
    save_as_pickle(y_train, os.path.join(output_dir, data_type), f'y_train_NoDef.pkl')
    save_as_pickle(X_valid, os.path.join(output_dir, data_type), f'X_valid_NoDef.pkl')
    save_as_pickle(y_valid, os.path.join(output_dir, data_type), f'y_valid_NoDef.pkl')
    save_as_pickle(X_test, os.path.join(output_dir, data_type), f'X_test_NoDef.pkl')
    save_as_pickle(y_test, os.path.join(output_dir, data_type), f'y_test_NoDef.pkl')

def process_pcap_files(base_dir, local_ip, output_dir,
                       ignored_packet_sizes_incoming=[], ignored_packet_sizes_outgoing=[]):
    all_timings = []
    all_sizes = []
    labels = []

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
                        labels.append(folder)  
                        if len(packet_sizes) > 40000:
                          print("Number of packet sizes in current file:", len(packet_sizes))
                print(f"Processed {file} successfully.")

    timings_padded = pad_sequences(all_timings)
    sizes_padded = pad_sequences(all_sizes)

    directions_padded = np.sign(sizes_padded) 
    sizes_padded_abs = np.abs(sizes_padded)  
    timings_padded_abs = np.abs(timings_padded)  

    merged_padded = np.stack((timings_padded_abs, sizes_padded_abs, directions_padded), axis=-1)

    process_and_split_data(merged_padded, labels, output_dir, "Merged")
    process_and_split_data(timings_padded, labels, output_dir, "Timings")
    process_and_split_data(sizes_padded, labels, output_dir, "Sizes")

    print("Datasets for timings, sizes, and their merger split and saved in separate subdirectories successfully.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert pcap files to deep learning dataset.")
    parser.add_argument("input_dir", help="Input directory containing pcap files.")
    parser.add_argument("output_dir", help="Output directory for the converted cell files.")
    parser.add_argument("src_ip", help="Source IP address.")

    args = parser.parse_args()

    process_pcap_files(args.input_dir, args.src_ip, args.output_dir)
