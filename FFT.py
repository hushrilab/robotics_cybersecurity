import os
import sys
import collections
import dpkt
import socket
import numpy as np
from scipy.signal import stft
from scipy.stats import kurtosis, skew
import pywt
import pandas as pd

def preprocess_pcap(file_path, dest_ip, source_ip, padded):
    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        
        packet_sizes = []
        timestamps = []
        
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip_hdr = eth.data

            try:
                src_ip = socket.inet_ntoa(ip_hdr.src)
                dst_ip = socket.inet_ntoa(ip_hdr.dst)
                
                if ((dst_ip == source_ip and src_ip == dest_ip) or (src_ip == source_ip and dst_ip == dest_ip)):
                    pkt_size = len(buf)
                    remainder = pkt_size % padded
                    if remainder != 0:
                        pkt_size += (padded - remainder)
                    
                    packet_sizes.append(pkt_size)
                    timestamps.append(ts)
            except:
                continue
        
        return packet_sizes, timestamps

def compute_spectral_features(packet_sizes):
    _, _, spectrogram = stft(packet_sizes, fs=1.0, nperseg=256)
    return np.abs(spectrogram).flatten()

def compute_wavelet_features(packet_sizes):
    coeffs = pywt.wavedec(packet_sizes, 'db1', level=5)
    return np.hstack([np.abs(c).flatten() for c in coeffs])

def extract_features(packet_sizes):
    spectral_features = compute_spectral_features(packet_sizes)
    wavelet_features = compute_wavelet_features(packet_sizes)
    return np.hstack([spectral_features, wavelet_features])

def save_features_to_csv(features, labels, file_name):
    df = pd.DataFrame(features)
    df['label'] = labels
    df.to_csv(file_name, index=False)

def process_pcap_files(base_dir, dest_ip, source_ip, dst_folder, padded=1):
    actions = os.listdir(base_dir)
    
    for action in actions:
        action_dir = os.path.join(base_dir, action)
        if not os.path.isdir(action_dir):
            continue
        
        output_file = os.path.join(dst_folder, f"{action}_features.csv")
        all_features = []
        all_labels = []
        
        for sample in os.listdir(action_dir):
            if sample.endswith('.pcap'):
                sample_path = os.path.join(action_dir, sample)
                packet_sizes, _ = preprocess_pcap(sample_path, dest_ip, source_ip, padded)
                features = extract_features(packet_sizes)
                all_features.append(features)
                all_labels.append(action)
        
        save_features_to_csv(all_features, all_labels, output_file)

def main():
    base_dir = 'path/to/pcap/files'
    dest_ip = '192.168.1.1'
    source_ip = '192.168.1.2'
    dst_folder = 'path/to/output/csv/files'
    
    if not os.path.exists(dst_folder):
        os.makedirs(dst_folder)
    
    process_pcap_files(base_dir, dest_ip, source_ip, dst_folder)

if __name__ == '__main__':
    main()
