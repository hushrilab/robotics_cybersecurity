import sys
import collections
import dpkt
import socket
import os
import random
import math
import numpy as np
from scipy.stats import kurtosis, skew
from termcolor import colored 
from joblib import Parallel, delayed
import codecs
import io
from tsfresh import extract_features

def PrintColored(string, color):
    print(colored(string, color))

def PrintDynamic(string):
    sys.stdout.flush()
    
def RoundToNearest(n, m):
        r = n % m
        return n + m - r if r + r >= m else n - r

def FeatureExtractionCombined(base_dir, dest_ip, source_ip, dst_folder, action, padded=None):
    sampleFolder = base_dir+"/"+action
    samples = os.listdir(sampleFolder)

    feature_set_folder_stats = dst_folder + '/' + action + '/traff_stats'
    if not os.path.exists(feature_set_folder_stats):
        os.makedirs(feature_set_folder_stats)

    feature_set_folder_pl = dst_folder + '/' + action + '/pkt_len'
    if not os.path.exists(feature_set_folder_pl):
        os.makedirs(feature_set_folder_pl)
        
    for i, sample in enumerate(samples):
        if (".DS_Store" in sample):
            continue
        if not os.path.exists(sampleFolder + "/" + sample):
            print("Corresponding .pcap does not exist")
            continue

        arff_path_stats = feature_set_folder_stats + '/' + sample[:-5]  + '.csv'
        arff_path_pl = feature_set_folder_pl + '/' + sample[:-5]  + '.csv'

        arff_stats = open(arff_path_stats, 'wb')
        arff_pl = open(arff_path_pl, 'wb')

        written_header_stats = False
        written_header_pl = False

        tcp_protocols_seen = set()
        statinfo = os.stat(sampleFolder + "/" + sample)
        
        PrintDynamic(sampleFolder + "/" + sample + " " + str(i))
        with open(sampleFolder + "/" + sample, 'rb') as f:
            pcap_data = f.read()
            
        pcap_io = io.BytesIO(pcap_data)
        pcap = dpkt.pcap.Reader(pcap_io)
#         pcap = dpkt.pcap.Reader(f, encoding='latin-1')

        # Analyse packets transmited
        totalPackets = 0
        totalPacketsIn = 0
        totalPacketsOut = 0

        # Analyse bytes transmitted
        totalBytes = 0
        totalBytesIn = 0
        totalBytesOut = 0

        # Analyse packet sizes
        packetSizes = []
        packetSizesIn = []
        packetSizesOut = []

        bin_dict = {}
        bin_dict2 = {}
        binWidth = 5
        # Generate the set of all possible bins
        for i in range(0, 1000, binWidth):
            bin_dict[i] = 0
            bin_dict2[i] = 0

        # Analyse inter packet timing
        packetTimes = []
        packetTimesIn = []
        packetTimesOut = []

        # Analyse outcoming bursts
        out_bursts_packets = []
        out_burst_sizes = []
        out_burst_times = []
        out_burst_start = 0
        out_current_burst = 0
        out_current_burst_start = 0
        out_current_burst_size = 0
        out_current_burst_time = 0

        # Analyse incoming bursts
        in_bursts_packets = []
        in_burst_sizes = []
        in_burst_times = []
        in_burst_start = 0
        in_current_burst = 0
        in_current_burst_start = 0
        in_current_burst_size = 0
        in_current_burst_time = 0

        prev_ts = 0
        absTimesOut = []
        setFirst = False
        for ts, buf in pcap:

            if (not (setFirst)):
                firstTime = ts
                setFirst = True

            eth = dpkt.ethernet.Ethernet(buf)
            ip_hdr = eth.data

            try:
                src_ip_addr_str = socket.inet_ntoa(ip_hdr.src)
                dst_ip_addr_str = socket.inet_ntoa(ip_hdr.dst)
                tcp_hdr = ip_hdr.data

                # Target TCP communication between both cluster machines
                if (ip_hdr.p == 6 and ((dst_ip_addr_str == source_ip and src_ip_addr_str == dest_ip) or (src_ip_addr_str == source_ip and dst_ip_addr_str == dest_ip))):
                    # General packet statistics
                    for byte in tcp_hdr.data:
                        tcp_protocols_seen.add(str(byte) + " ")

                    totalPackets += 1
                    pkt_size = len(buf)
                    if padded and len(buf) < padded:
                        pkt_size = padded
                    # If source is recipient
                    if (src_ip_addr_str == dest_ip):
                        totalPacketsIn += 1
                        packetSizesIn.append(pkt_size)
                        binned = RoundToNearest(packetSizesIn, binWidth)
                        bin_dict2[binned] += 1
                        if (prev_ts != 0):
                            ts_difference = max(0, ts - prev_ts)
                            packetTimesIn.append(ts_difference * 1000)

                        if (out_current_burst != 0):
                            if (out_current_burst > 1):
                                out_bursts_packets.append(out_current_burst)  # packets on burst
                                out_burst_sizes.append(out_current_burst_size)  # total bytes on burst
                                out_burst_times.append(ts - out_current_burst_start)
                            out_current_burst = 0
                            out_current_burst_size = 0
                            out_current_burst_start = 0
                        if (in_current_burst == 0):
                            in_current_burst_start = ts
                        in_current_burst += 1
                        in_current_burst_size += pkt_size
                    # If source is caller
                    else:
                        totalPacketsOut += 1
                        absTimesOut.append(ts)
                        packetSizesOut.append(pkt_size)
                        binned = RoundToNearest(pkt_size, binWidth)
                        bin_dict[binned] += 1
                        if (prev_ts != 0):
                            ts_difference = max(0, ts - prev_ts)
                            packetTimesOut.append(ts_difference * 1000)
                        if (out_current_burst == 0):
                            out_current_burst_start = ts
                        out_current_burst += 1
                        out_current_burst_size += pkt_size

                        if (in_current_burst != 0):
                            if (in_current_burst > 1):
                                in_bursts_packets.append(out_current_burst)  # packets on burst
                                in_burst_sizes.append(out_current_burst_size)  # total bytes on burst
                                in_burst_times.append(ts - out_current_burst_start)
                            in_current_burst = 0
                            in_current_burst_size = 0
                            in_current_burst_start = 0

                    # Bytes transmitted statistics
                    totalBytes += pkt_size
                    if (src_ip_addr_str == dest_ip):
                        totalBytesIn += pkt_size
                    else:
                        totalBytesOut += pkt_size

                    # Packet Size statistics
                    packetSizes.append(pkt_size)
                    # Packet Times statistics
                    if (prev_ts != 0):
                        # print "{0:.6f}".format(ts)
                        ts_difference = max(0, ts - prev_ts)
                        packetTimes.append(ts_difference * 1000)

                    prev_ts = ts
            except:
                pass
        f.close()
        ################################################################
        ####################Compute statistics#####################
        ################################################################
        try:
            ##########################################################
            # Statistical indicators for packet sizes (total)
            meanPacketSizes = np.mean(packetSizes)
            medianPacketSizes = np.median(packetSizes)
            stdevPacketSizes = np.std(packetSizes)
            variancePacketSizes = np.var(packetSizes)
            kurtosisPacketSizes = kurtosis(packetSizes)
            skewPacketSizes = skew(packetSizes)
            maxPacketSize = np.amax(packetSizes)
            minPacketSize = np.amin(packetSizes)
            p10PacketSizes = np.percentile(packetSizes, 10)
            p20PacketSizes = np.percentile(packetSizes, 20)
            p30PacketSizes = np.percentile(packetSizes, 30)
            p40PacketSizes = np.percentile(packetSizes, 40)
            p50PacketSizes = np.percentile(packetSizes, 50)
            p60PacketSizes = np.percentile(packetSizes, 60)
            p70PacketSizes = np.percentile(packetSizes, 70)
            p80PacketSizes = np.percentile(packetSizes, 80)
            p90PacketSizes = np.percentile(packetSizes, 90)

            ##########################################################
            # Statistical indicators for packet sizes (in)
            meanPacketSizesIn = np.mean(packetSizesIn)
            medianPacketSizesIn = np.median(packetSizesIn)
            stdevPacketSizesIn = np.std(packetSizesIn)
            variancePacketSizesIn = np.var(packetSizesIn)
            kurtosisPacketSizesIn = kurtosis(packetSizesIn)
            skewPacketSizesIn = skew(packetSizesIn)
            maxPacketSizeIn = np.amax(packetSizesIn)
            minPacketSizeIn = np.amin(packetSizesIn)
            p10PacketSizesIn = np.percentile(packetSizesIn, 10)
            p20PacketSizesIn = np.percentile(packetSizesIn, 20)
            p30PacketSizesIn = np.percentile(packetSizesIn, 30)
            p40PacketSizesIn = np.percentile(packetSizesIn, 40)
            p50PacketSizesIn = np.percentile(packetSizesIn, 50)
            p60PacketSizesIn = np.percentile(packetSizesIn, 60)
            p70PacketSizesIn = np.percentile(packetSizesIn, 70)
            p80PacketSizesIn = np.percentile(packetSizesIn, 80)
            p90PacketSizesIn = np.percentile(packetSizesIn, 90)

            ##########################################################
            # Statistical indicators for packet sizes (out)
            meanPacketSizesOut = np.mean(packetSizesOut)
            medianPacketSizesOut = np.median(packetSizesOut)
            stdevPacketSizesOut = np.std(packetSizesOut)
            variancePacketSizesOut = np.var(packetSizesOut)
            kurtosisPacketSizesOut = kurtosis(packetSizesOut)
            skewPacketSizesOut = skew(packetSizesOut)
            maxPacketSizeOut = np.amax(packetSizesOut)
            minPacketSizeOut = np.amin(packetSizesOut)
            p10PacketSizesOut = np.percentile(packetSizesOut, 10)
            p20PacketSizesOut = np.percentile(packetSizesOut, 20)
            p30PacketSizesOut = np.percentile(packetSizesOut, 30)
            p40PacketSizesOut = np.percentile(packetSizesOut, 40)
            p50PacketSizesOut = np.percentile(packetSizesOut, 50)
            p60PacketSizesOut = np.percentile(packetSizesOut, 60)
            p70PacketSizesOut = np.percentile(packetSizesOut, 70)
            p80PacketSizesOut = np.percentile(packetSizesOut, 80)
            p90PacketSizesOut = np.percentile(packetSizesOut, 90)

            ##################################################################
            # Statistical indicators for Inter-Packet Times (total)

            meanPacketTimes = np.mean(packetTimes)
            medianPacketTimes = np.median(packetTimes)
            stdevPacketTimes = np.std(packetTimes)
            variancePacketTimes = np.var(packetTimes)
            kurtosisPacketTimes = kurtosis(packetTimes)
            skewPacketTimes = skew(packetTimes)
            maxIPT = np.amax(packetTimes)
            minIPT = np.amin(packetTimes)
            p10PacketTimes = np.percentile(packetTimes, 10)
            p20PacketTimes = np.percentile(packetTimes, 20)
            p30PacketTimes = np.percentile(packetTimes, 30)
            p40PacketTimes = np.percentile(packetTimes, 40)
            p50PacketTimes = np.percentile(packetTimes, 50)
            p60PacketTimes = np.percentile(packetTimes, 60)
            p70PacketTimes = np.percentile(packetTimes, 70)
            p80PacketTimes = np.percentile(packetTimes, 80)
            p90PacketTimes = np.percentile(packetTimes, 90)

            ##################################################################
            # Statistical indicators for Inter-Packet Times (in)
            meanPacketTimesIn = np.mean(packetTimesIn)
            medianPacketTimesIn = np.median(packetTimesIn)
            stdevPacketTimesIn = np.std(packetTimesIn)
            variancePacketTimesIn = np.var(packetTimesIn)
            kurtosisPacketTimesIn = kurtosis(packetTimesIn)
            skewPacketTimesIn = skew(packetTimesIn)
            maxPacketTimesIn = np.amax(packetTimesIn)
            minPacketTimesIn = np.amin(packetTimesIn)
            p10PacketTimesIn = np.percentile(packetTimesIn, 10)
            p20PacketTimesIn = np.percentile(packetTimesIn, 20)
            p30PacketTimesIn = np.percentile(packetTimesIn, 30)
            p40PacketTimesIn = np.percentile(packetTimesIn, 40)
            p50PacketTimesIn = np.percentile(packetTimesIn, 50)
            p60PacketTimesIn = np.percentile(packetTimesIn, 60)
            p70PacketTimesIn = np.percentile(packetTimesIn, 70)
            p80PacketTimesIn = np.percentile(packetTimesIn, 80)
            p90PacketTimesIn = np.percentile(packetTimesIn, 90)

            ##################################################################
            # Statistical indicators for Inter-Packet Times (out)
            meanPacketTimesOut = np.mean(packetTimesOut)
            medianPacketTimesOut = np.median(packetTimesOut)
            stdevPacketTimesOut = np.std(packetTimesOut)
            variancePacketTimesOut = np.var(packetTimesOut)
            kurtosisPacketTimesOut = kurtosis(packetTimesOut)
            skewPacketTimesOut = skew(packetTimesOut)
            maxPacketTimesOut = np.amax(packetTimesOut)
            minPacketTimesOut = np.amin(packetTimesOut)
            p10PacketTimesOut = np.percentile(packetTimesOut, 10)
            p20PacketTimesOut = np.percentile(packetTimesOut, 20)
            p30PacketTimesOut = np.percentile(packetTimesOut, 30)
            p40PacketTimesOut = np.percentile(packetTimesOut, 40)
            p50PacketTimesOut = np.percentile(packetTimesOut, 50)
            p60PacketTimesOut = np.percentile(packetTimesOut, 60)
            p70PacketTimesOut = np.percentile(packetTimesOut, 70)
            p80PacketTimesOut = np.percentile(packetTimesOut, 80)
            p90PacketTimesOut = np.percentile(packetTimesOut, 90)

            ########################################################################
            # Statistical indicators for Outgoing bursts

            out_totalBursts = len(out_bursts_packets)
            out_meanBurst = np.mean(out_bursts_packets)
            out_medianBurst = np.median(out_bursts_packets)
            out_stdevBurst = np.std(out_bursts_packets)
            out_varianceBurst = np.var(out_bursts_packets)
            out_maxBurst = np.amax(out_bursts_packets)
            out_kurtosisBurst = kurtosis(out_bursts_packets)
            out_skewBurst = skew(out_bursts_packets)
            out_p10Burst = np.percentile(out_bursts_packets, 10)
            out_p20Burst = np.percentile(out_bursts_packets, 20)
            out_p30Burst = np.percentile(out_bursts_packets, 30)
            out_p40Burst = np.percentile(out_bursts_packets, 40)
            out_p50Burst = np.percentile(out_bursts_packets, 50)
            out_p60Burst = np.percentile(out_bursts_packets, 60)
            out_p70Burst = np.percentile(out_bursts_packets, 70)
            out_p80Burst = np.percentile(out_bursts_packets, 80)
            out_p90Burst = np.percentile(out_bursts_packets, 90)

            ########################################################################
            # Statistical indicators for Outgoing bytes (sliced intervals)
            out_meanBurstBytes = np.mean(out_burst_sizes)
            out_medianBurstBytes = np.median(out_burst_sizes)
            out_stdevBurstBytes = np.std(out_burst_sizes)
            out_varianceBurstBytes = np.var(out_burst_sizes)
            out_kurtosisBurstBytes = kurtosis(out_burst_sizes)
            out_skewBurstBytes = skew(out_burst_sizes)
            out_maxBurstBytes = np.amax(out_burst_sizes)
            out_minBurstBytes = np.amin(out_burst_sizes)
            out_p10BurstBytes = np.percentile(out_burst_sizes, 10)
            out_p20BurstBytes = np.percentile(out_burst_sizes, 20)
            out_p30BurstBytes = np.percentile(out_burst_sizes, 30)
            out_p40BurstBytes = np.percentile(out_burst_sizes, 40)
            out_p50BurstBytes = np.percentile(out_burst_sizes, 50)
            out_p60BurstBytes = np.percentile(out_burst_sizes, 60)
            out_p70BurstBytes = np.percentile(out_burst_sizes, 70)
            out_p80BurstBytes = np.percentile(out_burst_sizes, 80)
            out_p90BurstBytes = np.percentile(out_burst_sizes, 90)
            print(sample)

        except Exception as e:
            print("Error when processing {}: {}".format(sampleFolder + "/" + sample, e))
            continue

        # Write sample features to the csv file
        f_names_stats = []
        f_values_stats = []

        f_names_pl = []
        f_values_pl = []

        od_dict = collections.OrderedDict(sorted(bin_dict.items(), key=lambda t: float(t[0])))
        bin_list = []
        for i in od_dict:
            bin_list.append(od_dict[i])
        od_dict2 = collections.OrderedDict(sorted(bin_dict2.items(), key=lambda t: float(t[0])))
        bin_list2 = []
        for i in od_dict2:
            bin_list2.append(od_dict2[i])

        ###################################################################
        # Global Packet Features
        f_names_stats.append('TotalPackets')
        f_values_stats.append(totalPackets)
        f_names_stats.append('totalPacketsIn')
        f_values_stats.append(totalPacketsIn)
        f_names_stats.append('totalPacketsOut')
        f_values_stats.append(totalPacketsOut)
        f_names_stats.append('totalBytes')
        f_values_stats.append(totalBytes)
        f_names_stats.append('totalBytesIn')
        f_values_stats.append(totalBytesIn)
        f_names_stats.append('totalBytesOut')
        f_values_stats.append(totalBytesOut)

        ###################################################################
        # Packet Length Features
        f_names_stats.append('minPacketSize')
        f_values_stats.append(minPacketSize)
        f_names_stats.append('maxPacketSize')
        f_values_stats.append(maxPacketSize)
        # f_names_stats.append('medianPacketSizes')
        # f_values_stats.append(medianPacketSizes)
        f_names_stats.append('meanPacketSizes')
        f_values_stats.append(meanPacketSizes)
        f_names_stats.append('stdevPacketSizes')
        f_values_stats.append(stdevPacketSizes)
        f_names_stats.append('variancePacketSizes')
        f_values_stats.append(variancePacketSizes)
#         f_names_stats.append('kurtosisPacketSizes')
#         f_values_stats.append(kurtosisPacketSizes)
#         f_names_stats.append('skewPacketSizes')
#         f_values_stats.append(skewPacketSizes)

        f_names_stats.append('p10PacketSizes')
        f_values_stats.append(p10PacketSizes)
        f_names_stats.append('p20PacketSizes')
        f_values_stats.append(p20PacketSizes)
        f_names_stats.append('p30PacketSizes')
        f_values_stats.append(p30PacketSizes)
        f_names_stats.append('p40PacketSizes')
        f_values_stats.append(p40PacketSizes)
        f_names_stats.append('p50PacketSizes')
        f_values_stats.append(p50PacketSizes)
        f_names_stats.append('p60PacketSizes')
        f_values_stats.append(p60PacketSizes)
        f_names_stats.append('p70PacketSizes')
        f_values_stats.append(p70PacketSizes)
        f_names_stats.append('p80PacketSizes')
        f_values_stats.append(p80PacketSizes)
        f_names_stats.append('p90PacketSizes')
        f_values_stats.append(p90PacketSizes)

        ###################################################################
        # Packet Length Features (in)
        f_names_stats.append('minPacketSizeIn')
        f_values_stats.append(minPacketSizeIn)
        f_names_stats.append('maxPacketSizeIn')
        f_values_stats.append(maxPacketSizeIn)
        # f_names_stats.append('medianPacketSizesIn')
        # f_values_stats.append(medianPacketSizesIn)
        f_names_stats.append('meanPacketSizesIn')
        f_values_stats.append(meanPacketSizesIn)
        f_names_stats.append('stdevPacketSizesIn')
        f_values_stats.append(stdevPacketSizesIn)
        f_names_stats.append('variancePacketSizesIn')
        f_values_stats.append(variancePacketSizesIn)
#         f_names_stats.append('skewPacketSizesIn')
#         f_values_stats.append(skewPacketSizesIn)
#         f_names_stats.append('kurtosisPacketSizesIn')
#         f_values_stats.append(kurtosisPacketSizesIn)

        f_names_stats.append('p10PacketSizesIn')
        f_values_stats.append(p10PacketSizesIn)
        f_names_stats.append('p20PacketSizesIn')
        f_values_stats.append(p20PacketSizesIn)
        f_names_stats.append('p30PacketSizesIn')
        f_values_stats.append(p30PacketSizesIn)
        f_names_stats.append('p40PacketSizesIn')
        f_values_stats.append(p40PacketSizesIn)
        f_names_stats.append('p50PacketSizesIn')
        f_values_stats.append(p50PacketSizesIn)
        f_names_stats.append('p60PacketSizesIn')
        f_values_stats.append(p60PacketSizesIn)
        f_names_stats.append('p70PacketSizesIn')
        f_values_stats.append(p70PacketSizesIn)
        f_names_stats.append('p80PacketSizesIn')
        f_values_stats.append(p80PacketSizesIn)
        f_names_stats.append('p90PacketSizesIn')
        f_values_stats.append(p90PacketSizesIn)

        ###################################################################
        # Packet Length Features (out)
        f_names_stats.append('minPacketSizeOut')
        f_values_stats.append(minPacketSizeOut)
        f_names_stats.append('maxPacketSizeOut')
        f_values_stats.append(maxPacketSizeOut)
        # f_names_stats.append('medianPacketSizesOut')
        # f_values_stats.append(medianPacketSizesOut)
        f_names_stats.append('meanPacketSizesOut')
        f_values_stats.append(meanPacketSizesOut)
        f_names_stats.append('stdevPacketSizesOut')
        f_values_stats.append(stdevPacketSizesOut)
        f_names_stats.append('variancePacketSizesOut')
        f_values_stats.append(variancePacketSizesOut)
#         f_names_stats.append('skewPacketSizesOut')
#         f_values_stats.append(skewPacketSizesOut)
#         f_names_stats.append('kurtosisPacketSizesOut')
#         f_values_stats.append(kurtosisPacketSizesOut)

        f_names_stats.append('p10PacketSizesOut')
        f_values_stats.append(p10PacketSizesOut)
        f_names_stats.append('p20PacketSizesOut')
        f_values_stats.append(p20PacketSizesOut)
        f_names_stats.append('p30PacketSizesOut')
        f_values_stats.append(p30PacketSizesOut)
        f_names_stats.append('p40PacketSizesOut')
        f_values_stats.append(p40PacketSizesOut)
        f_names_stats.append('p50PacketSizesOut')
        f_values_stats.append(p50PacketSizesOut)
        f_names_stats.append('p60PacketSizesOut')
        f_values_stats.append(p60PacketSizesOut)
        f_names_stats.append('p70PacketSizesOut')
        f_values_stats.append(p70PacketSizesOut)
        f_names_stats.append('p80PacketSizesOut')
        f_values_stats.append(p80PacketSizesOut)
        f_names_stats.append('p90PacketSizesOut')
        f_values_stats.append(p90PacketSizesOut)

        ###################################################################
        # Packet Timing Features
        f_names_stats.append('maxIPT')
        f_values_stats.append(maxIPT)
        f_names_stats.append('minIPT')
        f_values_stats.append(minIPT)
        # f_names_stats.append('medianPacketTimes')
        # f_values_stats.append(medianPacketTimes)
        f_names_stats.append('meanPacketTimes')
        f_values_stats.append(meanPacketTimes)
        f_names_stats.append('stdevPacketTimes')
        f_values_stats.append(stdevPacketTimes)
        f_names_stats.append('variancePacketTimes')
        f_values_stats.append(variancePacketTimes)
#         f_names_stats.append('kurtosisPacketTimes')
#         f_values_stats.append(kurtosisPacketTimes)
#         f_names_stats.append('skewPacketTimes')
#         f_values_stats.append(skewPacketTimes)

        f_names_stats.append('p10PacketTimes')
        f_values_stats.append(p10PacketTimes)
        f_names_stats.append('p20PacketTimes')
        f_values_stats.append(p20PacketTimes)
        f_names_stats.append('p30PacketTimes')
        f_values_stats.append(p30PacketTimes)
        f_names_stats.append('p40PacketTimes')
        f_values_stats.append(p40PacketTimes)
        f_names_stats.append('p50PacketTimes')
        f_values_stats.append(p50PacketTimes)
        f_names_stats.append('p60PacketTimes')
        f_values_stats.append(p60PacketTimes)
        f_names_stats.append('p70PacketTimes')
        f_values_stats.append(p70PacketTimes)
        f_names_stats.append('p80PacketTimes')
        f_values_stats.append(p80PacketTimes)
        f_names_stats.append('p90PacketTimes')
        f_values_stats.append(p90PacketTimes)

        ###################################################################
        # Packet Timing Features (in)
        f_names_stats.append('minPacketTimesIn')
        f_values_stats.append(minPacketTimesIn)
        f_names_stats.append('maxPacketTimesIn')
        f_values_stats.append(maxPacketTimesIn)
        # f_names_stats.append('medianPacketTimesIn')
        # f_values_stats.append(medianPacketTimesIn)
        f_names_stats.append('meanPacketTimesIn')
        f_values_stats.append(meanPacketTimesIn)
        f_names_stats.append('stdevPacketTimesIn')
        f_values_stats.append(stdevPacketTimesIn)
        f_names_stats.append('variancePacketTimesIn')
        f_values_stats.append(variancePacketTimesIn)
#         f_names_stats.append('skewPacketTimesIn')
#         f_values_stats.append(skewPacketTimesIn)
#         f_names_stats.append('kurtosisPacketTimesIn')
#         f_values_stats.append(kurtosisPacketTimesIn)

        f_names_stats.append('p10PacketTimesIn')
        f_values_stats.append(p10PacketTimesIn)
        f_names_stats.append('p20PacketTimesIn')
        f_values_stats.append(p20PacketTimesIn)
        f_names_stats.append('p30PacketTimesIn')
        f_values_stats.append(p30PacketTimesIn)
        f_names_stats.append('p40PacketTimesIn')
        f_values_stats.append(p40PacketTimesIn)
        f_names_stats.append('p50PacketTimesIn')
        f_values_stats.append(p50PacketTimesIn)
        f_names_stats.append('p60PacketTimesIn')
        f_values_stats.append(p60PacketTimesIn)
        f_names_stats.append('p70PacketTimesIn')
        f_values_stats.append(p70PacketTimesIn)
        f_names_stats.append('p80PacketTimesIn')
        f_values_stats.append(p80PacketTimesIn)
        f_names_stats.append('p90PacketTimesIn')
        f_values_stats.append(p90PacketTimesIn)

        ###################################################################
        # Packet Timing Features (out)
        f_names_stats.append('minPacketTimesOut')
        f_values_stats.append(minPacketTimesOut)
        f_names_stats.append('maxPacketTimesOut')
        f_values_stats.append(maxPacketTimesOut)
        # f_names_stats.append('medianPacketTimesOut')
        # f_values_stats.append(medianPacketTimesOut)
        f_names_stats.append('meanPacketTimesOut')
        f_values_stats.append(meanPacketTimesOut)
        f_names_stats.append('stdevPacketTimesOut')
        f_values_stats.append(stdevPacketTimesOut)
        f_names_stats.append('variancePacketTimesOut')
        f_values_stats.append(variancePacketTimesOut)
#         f_names_stats.append('skewPacketTimesOut')
#         f_values_stats.append(skewPacketTimesOut)
#         f_names_stats.append('kurtosisPacketTimesOut')
#         f_values_stats.append(kurtosisPacketTimesOut)

        f_names_stats.append('p10PacketTimesOut')
        f_values_stats.append(p10PacketTimesOut)
        f_names_stats.append('p20PacketTimesOut')
        f_values_stats.append(p20PacketTimesOut)
        f_names_stats.append('p30PacketTimesOut')
        f_values_stats.append(p30PacketTimesOut)
        f_names_stats.append('p40PacketTimesOut')
        f_values_stats.append(p40PacketTimesOut)
        f_names_stats.append('p50PacketTimesOut')
        f_values_stats.append(p50PacketTimesOut)
        f_names_stats.append('p60PacketTimesOut')
        f_values_stats.append(p60PacketTimesOut)
        f_names_stats.append('p70PacketTimesOut')
        f_values_stats.append(p70PacketTimesOut)
        f_names_stats.append('p80PacketTimesOut')
        f_values_stats.append(p80PacketTimesOut)
        f_names_stats.append('p90PacketTimesOut')
        f_values_stats.append(p90PacketTimesOut)

        # Write Stats csv
        f_names_stats.append('Class')
        f_values_stats.append(action)

        if (not written_header_stats):
            arff_stats.write(','.join(f_names_stats).encode('utf-8'))
            arff_stats.write('\n'.encode('utf-8'))
            written_header_stats = True

        l = []
        for v in f_values_stats:
            l.append(str(v))
        arff_stats.write(','.join(l).encode('utf-8'))
        arff_stats.write('\n'.encode('utf-8'))


        # Write PL csv
        f_names_pl = []
        f_values_pl = []
        for i, b in enumerate(bin_list):
            f_names_pl.append('packetLengthBin_' + str(i))
            f_values_pl.append(b)

        for i, b in enumerate(bin_list2):
            f_names_pl.append('packetLengthBin2_' + str(i))
            f_values_pl.append(b)

        f_names_pl.append('Class')
        f_values_pl.append(action)

        if (not written_header_pl):
            arff_pl.write(','.join(f_names_pl).encode('utf-8'))
            arff_pl.write('\n'.encode('utf-8'))
            written_header_pl = True

        l = []
        for v in f_values_pl:
            l.append(str(v))
        arff_pl.write(','.join(l).encode('utf-8'))
        arff_pl.write('\n'.encode('utf-8'))
        
#         print ("TCP Protocols seen: " + str(tcp_protocols_seen))


    arff_stats.close()
    arff_pl.close()
