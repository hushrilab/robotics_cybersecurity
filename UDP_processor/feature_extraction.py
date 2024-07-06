import os
from file_ops import create_directories, list_samples, open_files_for_writing
from packet_analysis import read_pcap, analyze_packets
from stats_comp import compute_all_statistics
from utils import PrintDynamic

def FeatureExtractionCombined(base_dir, dest_ip, source_ip, dst_folder, action, padded=None):
    sampleFolder = os.path.join(base_dir, action)
    samples = list_samples(sampleFolder)
    feature_set_folder_stats, feature_set_folder_pl = create_directories(dst_folder, action)
    print(sampleFolder)
    for i, sample in enumerate(samples):
        PrintDynamic(sampleFolder + "/" + sample + " " + str(i))
        
        arff_stats, arff_pl = open_files_for_writing(feature_set_folder_stats, feature_set_folder_pl, sample)
        written_header_stats = False
        written_header_pl = False

        pcap = read_pcap(sampleFolder, sample)
        print(sample)
        stats = analyze_packets(pcap, source_ip, dest_ip, padded)
        
        packetSizes_stats, packetSizesIn_stats, packetSizesOut_stats, \
        packetTimes_stats, packetTimesIn_stats, packetTimesOut_stats, \
        packetInBurst_stats, packetOutBurst_stats, \
        packetBurstSizesIn_stats, packetBurstSizesOut_stats, \
        packetBurstTimesIn_stats, packetBurstTimesOut_stats = compute_all_statistics(stats)
        
        try:
            # Further processing and writing to files...
            # Stats names and values
            f_names_stats = ['TotalPackets', 'totalPacketsIn', 'totalPacketsOut', 'totalBytes', 'totalBytesIn', 'totalBytesOut']
            f_values_stats = [stats['totalPackets'], stats['totalPacketsIn'], stats['totalPacketsOut'], stats['totalBytes'], stats['totalBytesIn'], stats['totalBytesOut']]
            
            # Append packet size statistics
            for key in packetSizes_stats:
                f_names_stats.append(f'{key}PacketSizes')
                f_values_stats.append(packetSizes_stats[key])
            
            # Append packet size in statistics
            for key in packetSizesIn_stats:
                f_names_stats.append(f'{key}PacketSizesIn')
                f_values_stats.append(packetSizesIn_stats[key])
            
            # Append packet size out statistics
            for key in packetSizesOut_stats:
                f_names_stats.append(f'{key}PacketSizesOut')
                f_values_stats.append(packetSizesOut_stats[key])
            
            # Append packet timing statistics
            for key in packetTimes_stats:
                f_names_stats.append(f'{key}PacketTimes')
                f_values_stats.append(packetTimes_stats[key])
            
            # Append packet timing in statistics
            for key in packetTimesIn_stats:
                f_names_stats.append(f'{key}PacketTimesIn')
                f_values_stats.append(packetTimesIn_stats[key])
            
            # Append packet timing out statistics
            for key in packetTimesOut_stats:
                f_names_stats.append(f'{key}PacketTimesOut')
                f_values_stats.append(packetTimesOut_stats[key])
            
            # Append packet bursts in statistics
            for key in packetInBurst_stats:
                f_names_stats.append(f'{key}PacketBurstsIn')
                f_values_stats.append(packetInBurst_stats[key])
            
            # Append packet bursts out statistics
            for key in packetOutBurst_stats:
                f_names_stats.append(f'{key}PacketBurstsOut')
                f_values_stats.append(packetOutBurst_stats[key])
            
            # Append packet burst sizes in statistics
            for key in packetBurstSizesIn_stats:
                f_names_stats.append(f'{key}PacketBurstSizesIn')
                f_values_stats.append(packetBurstSizesIn_stats[key])

            # Append packet bursts sizes out statistics
            for key in packetBurstSizesOut_stats:
                f_names_stats.append(f'{key}PacketBurstSizesOut')
                f_values_stats.append(packetBurstSizesOut_stats[key])
            
            # Append packet bursts timing in statistics
            for key in packetBurstTimesIn_stats:
                f_names_stats.append(f'{key}PacketBurstTimesIn')
                f_values_stats.append(packetBurstTimesIn_stats[key])
            
            # Append packet burst timing out statistics
            for key in packetBurstTimesOut_stats:
                f_names_stats.append(f'{key}PacketBurstTimesOut')
                f_values_stats.append(packetBurstTimesOut_stats[key])

            f_names_stats.append('Class')
            f_values_stats.append(action)

            if not written_header_stats:
                arff_stats.write(','.join(f_names_stats).encode('utf-8'))
                arff_stats.write('\n'.encode('utf-8'))
                written_header_stats = True

            arff_stats.write(','.join(map(str, f_values_stats)).encode('utf-8'))
            arff_stats.write('\n'.encode('utf-8'))

            # Write PL csv
            f_names_pl = []
            f_values_pl = []
            for i, b in enumerate(sorted(stats['bin_dict'].items())):
                f_names_pl.append(f'packetLengthBin_{i}')
                f_values_pl.append(b[1])

            for i, b in enumerate(sorted(stats['bin_dict2'].items())):
                f_names_pl.append(f'packetLengthBin2_{i}')
                f_values_pl.append(b[1])

            f_names_pl.append('Class')
            f_values_pl.append(action)

            if not written_header_pl:
                arff_pl.write(','.join(f_names_pl).encode('utf-8'))
                arff_pl.write('\n'.encode('utf-8'))
                written_header_pl = True

            arff_pl.write(','.join(map(str, f_values_pl)).encode('utf-8'))
            arff_pl.write('\n'.encode('utf-8'))

            arff_stats.close()
            arff_pl.close()

        except Exception as e:
            print(f"Error when processing {sampleFolder}/{sample}: {e}")
            continue
