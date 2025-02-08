import os
import sys
import collections
import dpkt
import socket
import numpy as np
from scipy.fft import fft
from scipy.stats import kurtosis, skew
import pywt
import pandas as pd
import argparse

def preprocess_pcap(file_path, dest_ip, source_ip, padded):
    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        
        packet_sizes = []
        timestamps = []
        
        for ts, buf in pcap:
            if len(buf) < 14:
                continue
        
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
    fft_result = fft(packet_sizes)
    return np.abs(fft_result).flatten()

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
        
        feature_set_folder_stats = os.path.join(dst_folder, action, 'traff_stats')
        if not os.path.exists(feature_set_folder_stats):
            os.makedirs(feature_set_folder_stats)
        
        for sample in os.listdir(action_dir):
            if sample.endswith('.pcap'):
                sample_path = os.path.join(action_dir, sample)
                packet_sizes, timestamps = preprocess_pcap(sample_path, dest_ip, source_ip, padded)
                
                if packet_sizes:
                    features = extract_features(packet_sizes)
                    all_features = features.tolist()
                    
                    # Generate descriptive headers
                    spectral_feature_count = len(compute_spectral_features(packet_sizes))
                    wavelet_feature_count = len(compute_wavelet_features(packet_sizes))
                    headers = [f'spectral_feature_{i+1}' for i in range(spectral_feature_count)] + \
                              [f'wavelet_feature_{i+1}' for i in range(wavelet_feature_count)]
                    headers.append('Class')
                    
                    # Append the class label to features
                    all_features.append(action)
                    
                    # Convert to DataFrame
                    df = pd.DataFrame([all_features], columns=headers)
                    output_file_features = os.path.join(feature_set_folder_stats, f"{sample[:-5]}_features.csv")
                    
                    # Write to CSV with headers
                    df.to_csv(output_file_features, index=False)

def main():
    parser = argparse.ArgumentParser(description="Run Feature Extraction for FFT.")
    parser.add_argument("base_dir", help="Input directory containing pcap files to be extracted.")
    parser.add_argument("dest_ip", help="Destination IP address.")
    parser.add_argument("source_ip", help="Source IP address.")
    parser.add_argument("dst_folder", help="Output directory for the extracted features to be.")
    args = parser.parse_args()

    if not os.path.exists(args.dst_folder):
        os.makedirs(args.dst_folder)
    
    process_pcap_files(args.base_dir, args.dest_ip, args.source_ip, args.dst_folder)

if __name__ == '__main__':
    main()
