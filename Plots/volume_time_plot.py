import dpkt
import matplotlib.pyplot as plt
import datetime
import argparse

def read_pcap(pcap_file):
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        packet_counts = {}
        start_time = None  # Initialize start time
        for ts, buf in pcap:
            packet_time = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
            if start_time is None:
                start_time = packet_time  # Set the start time based on the first packet
            elif (packet_time - start_time).total_seconds() > 5:
                break  # Stop processing after the first 5 seconds
            rounded_seconds = round(packet_time.microsecond / 100000.0) / 10
            time_key = packet_time.replace(microsecond=0) + datetime.timedelta(seconds=rounded_seconds)
            if time_key in packet_counts:
                packet_counts[time_key] += 1
            else:
                packet_counts[time_key] = 1
        return packet_counts

def plot_packet_counts(packet_counts, output_file):
    times = sorted(packet_counts.keys())
    counts = [packet_counts[time] for time in times]
    plt.figure(figsize=(10, 5))
    plt.plot(times, counts, marker='o')
    plt.title('Number of Packets Over Time')
    plt.xlabel('Time')
    plt.ylabel('Packet Count')
    plt.xticks(rotation=45)
    plt.tight_layout()
    # Save the plot to a file
    plt.savefig(output_file)
    plt.close() 

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plot packet sizes over time from a pcap file.")
    parser.add_argument("pcap_file", help="Path to the input pcap file.")
    parser.add_argument("output_file", help="Path to save the output plot.")
    args = parser.parse_args()
    packet_counts = read_pcap(args.pcap_file)
    plot_packet_counts(packet_counts, args.output_file)