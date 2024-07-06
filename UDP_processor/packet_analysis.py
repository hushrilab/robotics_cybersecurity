import dpkt
import socket
import io
import numpy as np
from scipy.stats import kurtosis, skew
from utils import RoundToNearest
import os
def read_pcap(sampleFolder, sample):
    with open(os.path.join(sampleFolder, sample), 'rb') as f:
        pcap_data = f.read()
        
    pcap_io = io.BytesIO(pcap_data)
    return dpkt.pcap.Reader(pcap_io)

def analyze_packets(pcap, source_ip, dest_ip, padded):
    stats = {
        'totalPackets': 0,
        'totalPacketsIn': 0,
        'totalPacketsOut': 0,
        'totalBytes': 0,
        'totalBytesIn': 0,
        'totalBytesOut': 0,
        'packetSizes': [],
        'packetSizesIn': [],
        'packetSizesOut': [],
        'packetTimes': [],
        'packetTimesIn': [],
        'packetTimesOut': [],
        'bin_dict': {i: 0 for i in range(0, 2000, 5)},
        'bin_dict2': {i: 0 for i in range(0, 2000, 5)},
        'packetBurstsOut': [],
        'packetBurstSizesOut': [],
        'packetBurstTimesOut': [],
        'packetBurstsIn': [],
        'packetBurstSizesIn': [],
        'packetBurstTimesIn': [],
        'absTimesOut': []
    }

    out_current_burst = 0
    out_current_burst_start = 0
    out_current_burst_size = 0
    in_current_burst = 0
    in_current_burst_start = 0
    in_current_burst_size = 0
    prev_ts = 0
    setFirst = False

    for ts, buf in pcap:
        if not setFirst:
            firstTime = ts
            setFirst = True
        if len(buf) < 14:
            continue
        
        eth = dpkt.ethernet.Ethernet(buf)
        ip_hdr = eth.data

        try:
            src_ip_addr_str = socket.inet_ntoa(ip_hdr.src)
            dst_ip_addr_str = socket.inet_ntoa(ip_hdr.dst)
            udp_hdr = ip_hdr.data

            if ip_hdr.p == 17 and ((dst_ip_addr_str == source_ip and src_ip_addr_str == dest_ip) or (src_ip_addr_str == source_ip and dst_ip_addr_str == dest_ip)):
                stats['totalPackets'] += 1
                pkt_size = len(buf)
                if padded:
                    pkt_size = RoundToNearest(pkt_size, padded)

                if src_ip_addr_str == dest_ip:
                    stats['totalPacketsIn'] += 1
                    stats['packetSizesIn'].append(pkt_size)
                    binned = RoundToNearest(pkt_size, 5)
                    stats['bin_dict2'][binned] += 1
                    if prev_ts != 0:
                        ts_difference = max(0, ts - prev_ts)
                        stats['packetTimesIn'].append(ts_difference * 1000)

                    if out_current_burst != 0:
                        if out_current_burst > 1:
                            stats['packetBurstsOut'].append(out_current_burst)
                            stats['packetBurstSizesOut'].append(out_current_burst_size)
                            stats['packetBurstTimesOut'].append(ts - out_current_burst_start)
                        out_current_burst = 0
                        out_current_burst_size = 0
                        out_current_burst_start = 0
                    if in_current_burst == 0:
                        in_current_burst_start = ts
                    in_current_burst += 1
                    in_current_burst_size += pkt_size
                else:
                    stats['totalPacketsOut'] += 1
                    stats['absTimesOut'].append(ts)
                    stats['packetSizesOut'].append(pkt_size)
                    binned = RoundToNearest(pkt_size, 5)
                    stats['bin_dict'][binned] += 1
                    if prev_ts != 0:
                        ts_difference = max(0, ts - prev_ts)
                        stats['packetTimesOut'].append(ts_difference * 1000)
                    if out_current_burst == 0:
                        out_current_burst_start = ts
                    out_current_burst += 1
                    out_current_burst_size += pkt_size

                    if in_current_burst != 0:
                        if in_current_burst > 1:
                            stats['packetBurstsIn'].append(in_current_burst)
                            stats['packetBurstSizesIn'].append(in_current_burst_size)
                            stats['packetBurstTimesIn'].append(ts - in_current_burst_start)
                        in_current_burst = 0
                        in_current_burst_size = 0
                        in_current_burst_start = 0
                    if out_current_burst == 0:
                        out_current_burst_start = ts
                    out_current_burst += 1
                    out_current_burst_size += pkt_size

                stats['totalBytes'] += pkt_size
                if src_ip_addr_str == dest_ip:
                    stats['totalBytesIn'] += pkt_size
                else:
                    stats['totalBytesOut'] += pkt_size

                stats['packetSizes'].append(pkt_size)
                if prev_ts != 0:
                    ts_difference = max(0, ts - prev_ts)
                    stats['packetTimes'].append(ts_difference * 1000)

                prev_ts = ts
        except:
            pass
        # except Exception as e:
        #     print("Error when processing: {}".format(e))
    # print(stats['packetBurstsIn'])
    # print(stats['packetBurstsOut'])
    # print(stats['packetBurstSizesIn'])
    # print(stats['packetBurstSizesOut'])
    # print(stats['packetBurstTimesIn'])
    # print(stats['packetBurstTimesOut'])


    return stats
