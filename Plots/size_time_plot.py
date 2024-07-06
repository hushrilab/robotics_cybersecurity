import argparse
import dpkt
import matplotlib.pyplot as plt
import socket

def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def plot_pcap(pcap_file, output_file, local_ip, target_ip, ignored_packet_sizes):
    ingoing_packets = []
    outgoing_packets = []
    first_timestamp = None

    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for timestamp, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue

                if first_timestamp is None:
                    first_timestamp = timestamp

                relative_time = timestamp - first_timestamp

                ip = eth.data
                src_ip = inet_to_str(ip.src)
                dst_ip = inet_to_str(ip.dst)
                packet_size = len(buf)

                # Filter out specified packet sizes
                if packet_size in ignored_packet_sizes:
                    continue

                if src_ip == local_ip:
                    outgoing_packets.append((relative_time, packet_size))
                else:
                    ingoing_packets.append((relative_time, -packet_size))

            except Exception as e:
                print(f"Error parsing packet: {e}")

    ingoing_times, ingoing_sizes = zip(*ingoing_packets) if ingoing_packets else ([], [])
    outgoing_times, outgoing_sizes = zip(*outgoing_packets) if outgoing_packets else ([], [])

    plt.figure(figsize=(10, 6))
    if ingoing_packets:
        plt.bar(ingoing_times, ingoing_sizes, color='blue', label='Ingoing Packets', alpha=0.5, width=0.1)
    if outgoing_packets:
        plt.bar(outgoing_times, outgoing_sizes, color='red', label='Outgoing Packets', alpha=0.5, width=0.1)
    plt.xlabel('Time (seconds from first packet)')
    plt.ylabel('Packet Size (bytes)')
    plt.legend()

    plt.tight_layout()
    plt.savefig(output_file)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plot packet sizes over time from a pcap file.")
    parser.add_argument("pcap_file", help="Path to the input pcap file.")
    parser.add_argument("output_file", help="Path to save the output plot.")
    parser.add_argument("--local_ip", required=True, help="Local IP address for direction determination.")
    parser.add_argument("--target_ip", required=True, help="Destination IP address for direction determination.")
    parser.add_argument("--ignored_packet_sizes", nargs='+', type=int, default=[], help="List of packet sizes to ignore.")
    args = parser.parse_args()

    plot_pcap(args.pcap_file, args.output_file, args.local_ip, args.target_ip, args.ignored_packet_sizes)
