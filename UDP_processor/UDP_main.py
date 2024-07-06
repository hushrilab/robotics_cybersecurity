import os
from feature_extraction import FeatureExtractionCombined
import argparse
def main(base_dir, dest_ip, source_ip, dst_folder, all_actions, padded=None):
    for action in all_actions:
        FeatureExtractionCombined(base_dir, dest_ip, source_ip, dst_folder, action, padded)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Feature Extraction.")
    parser.add_argument("base_dir", help="Input directory containing pcap files to be extracted.")
    parser.add_argument("dest_ip", help="Destiation IP address.")
    parser.add_argument("source_ip", help="Source IP address.")
    parser.add_argument("dst_folder", help="Output directory for the extracted features to be.")
    parser.add_argument("actions", nargs='+', help="List of the names of the actions.")
    parser.add_argument("--padded", type=int, default=None, help="Packet padding for defense.")
    args = parser.parse_args()
    main(args.base_dir, args.dest_ip, args.source_ip, args.dst_folder, args.actions, padded=None)