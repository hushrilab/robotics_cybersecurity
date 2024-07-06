# Cybersecurity for Teleoperation Robot

Please make sure to have Anaconda installed.

In the project directory, run:

#### `conda env create -f cybersecurity_robotics.yaml`

to create the virtual environment for the project, 

#### `conda activate cybersecurity_robotics`

to activate the virtual environment, 

Then run:

#### `jupyter-notebook`

to launch Jupyter Notebook.

## Convert PCAP to DL Directional Size and Timing Dataset

#### `python pcap2dfdata.py </pcap_files_path> <local_ip> </pickle_files_path>`

to convert pcap files to directional size, time, and merged 3-channel series representation datasets saved in the specified directory.

## Convert PCAP to Cell

#### `python pcap2cell.py </pcap_files_path> </cell_files_path>`

## Time-Size Plot

#### `python size_time_plot.py </pcap_files_path> </pcap_files_path> --local_ip <local_ip> --target_ip <destination_ip> --ignored_packet_sizes <size1 size2 size3 ...>`

## Filter PCAP Files with Sizes

#### `python filter_pcap.py </input_pcap_files_path> </output_pcap_files_path> "<size1,size2 ...>"`

## Analysis Pipeline

In main.ipynb, run all cells to run the entire analysis pipeline. All the action data expected to be organized into specific structure. 

## Acknowledgements

The code implemented in this repo for feature analysis incorporates code in the repository https://github.com/dmbb/Protozoa/tree/master.

Original work:

@inproceedings{protozoa,
  title={Poking a Hole in the Wall: Efficient Censorship-Resistant Internet Communications by Parasitizing on WebRTC},
  author={Barradas, Diogo and Santos, Nuno and Rodrigues, Lu{\'i}s and Nunes, V{\'i}tor},
  booktitle={Proceedings of the ACM SIGSAC Conference on Computer and Communications Security},
  year={2020},
  address={Virtual Event, USA}
}
