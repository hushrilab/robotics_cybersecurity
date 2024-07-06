import numpy as np
from scipy.stats import kurtosis, skew

def calculate_stats(stats):
    if stats:
        return {
            'mean': np.mean(stats),
            'median': np.median(stats),
            'stdev': np.std(stats),
            'variance': np.var(stats),
            'kurtosis': kurtosis(stats),
            'skew': skew(stats),
            'max': np.amax(stats),
            'min': np.amin(stats),
            'p10': np.percentile(stats, 10),
            'p20': np.percentile(stats, 20),
            'p30': np.percentile(stats, 30),
            'p40': np.percentile(stats, 40),
            'p50': np.percentile(stats, 50),
            'p60': np.percentile(stats, 60),
            'p70': np.percentile(stats, 70),
            'p80': np.percentile(stats, 80),
            'p90': np.percentile(stats, 90),
        }
    else:
        return {
            'mean': 0, 'median': 0, 'stdev': 0, 'variance': 0, 'kurtosis': 0, 'skew': 0, 
            'max': 0, 'min': 0, 'p10': 0, 'p20': 0, 'p30': 0, 'p40': 0, 'p50': 0, 
            'p60': 0, 'p70': 0, 'p80': 0, 'p90': 0
        }

def compute_all_statistics(stats):
    packetSizes_stats = packetSizesIn_stats = packetSizesOut_stats = {}
    packetTimes_stats = packetTimesIn_stats = packetTimesOut_stats = {}
    packetInBurst_stats = packetOutBurst_stats = {}
    packetBurstSizesIn_stats = packetBurstSizesOut_stats = {}
    packetBurstTimesIn_stats = packetBurstTimesOut_stats = {}
    try:
        packetSizes_stats = calculate_stats(stats['packetSizes'])
        packetSizesIn_stats = calculate_stats(stats['packetSizesIn'])
        packetSizesOut_stats = calculate_stats(stats['packetSizesOut'])
        packetTimes_stats = calculate_stats(stats['packetTimes'])
        packetTimesIn_stats = calculate_stats(stats['packetTimesIn'])
        packetTimesOut_stats = calculate_stats(stats['packetTimesOut'])
        packetInBurst_stats = calculate_stats(stats['packetBurstsIn'])
        packetOutBurst_stats = calculate_stats(stats['packetBurstsOut'])
        packetBurstSizesIn_stats = calculate_stats(stats['packetBurstSizesIn'])
        packetBurstSizesOut_stats = calculate_stats(stats['packetBurstSizesOut'])
        packetBurstTimesIn_stats = calculate_stats(stats['packetBurstTimesIn'])
        packetBurstTimesOut_stats = calculate_stats(stats['packetBurstTimesOut'])

    except Exception as e:
        print("Error when processing: {}".format(e))
        pass
    # print(len(packetInBurst_stats))
    # print(len(packetOutBurst_stats))
    # print(len(packetBurstSizesIn_stats))
    # print(len(packetBurstSizesOut_stats))
    # print(len(packetBurstTimesIn_stats))
    # print(len(packetBurstTimesOut_stats))

    return packetSizes_stats, packetSizesIn_stats, packetSizesOut_stats, \
            packetTimes_stats, packetTimesIn_stats, packetTimesOut_stats, \
            packetInBurst_stats, packetOutBurst_stats, \
            packetBurstSizesIn_stats, packetBurstSizesOut_stats, \
            packetBurstTimesIn_stats, packetBurstTimesOut_stats
            
