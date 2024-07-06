import os

def create_directories(dst_folder, action):
    feature_set_folder_stats = os.path.join(dst_folder, action, 'traff_stats')
    feature_set_folder_pl = os.path.join(dst_folder, action, 'pkt_len')
    
    os.makedirs(feature_set_folder_stats, exist_ok=True)
    os.makedirs(feature_set_folder_pl, exist_ok=True)
    
    return feature_set_folder_stats, feature_set_folder_pl

def list_samples(sampleFolder):
    return [f for f in os.listdir(sampleFolder) if not f.startswith('.') and f.endswith('.pcap')]

def open_files_for_writing(feature_set_folder_stats, feature_set_folder_pl, sample):
    arff_path_stats = os.path.join(feature_set_folder_stats, sample[:-5] + '.csv')
    arff_path_pl = os.path.join(feature_set_folder_pl, sample[:-5] + '.csv')
    
    arff_stats = open(arff_path_stats, 'wb')
    arff_pl = open(arff_path_pl, 'wb')
    
    return arff_stats, arff_pl
