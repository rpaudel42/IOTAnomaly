# ******************************************************************************
# main.py
#
# Date      Name       Description
# ========  =========  ========================================================
# 6/5/19   Paudel     Initial version,
# ******************************************************************************

import argparse, json
# from csv_parser import CsvParser
from pcap_parser import PcapParser
from graph_utils import GraphUtils
from graph_sketch import ShingleSketch

def parse_args():
    '''
    Usual pythonic way of parsing command line arguments
    :return: all command line arguments read
    '''
    args = argparse.ArgumentParser("IOTAnomaly")
    args.add_argument("-f","--datafile", default='june-01.csv',
                      help="Path to directory containing files to be used for constructing graph")

    args.add_argument('-g','--graphfile', default='data/graph/ihome.g',
                      help='graph file for anomaly detection')

    args.add_argument('-p', "--pcapfile", default="18-06-01.pcap",
                      help="Path to pcap file from wireshark")

    args.add_argument('-t',"--timeslice", default=60, type=int,
                      help="Timestamp for each graph")

    args.add_argument('-v', "--sketch_vector", default="dataset/sh_iot.csv",
                      help="Timestamp for each graph")

    args.add_argument('-s', "--sketch_size", default=128, type=int,
                      help="Sketch Vector Size")

    args.add_argument('-w', "--win_size", default=100, type=int,
                      help="Sliding Window Size")

    args.add_argument('--walk_len', default=200, type=int, help='N time edge count is the length of random walk ')

    args.add_argument('--num_walks', type=int, default=1,
                      help='Number of walks per source. Default is 10.')

    args.add_argument('--k_shingle', default=3, type=int, help='Lenght of a shinle')

    return args.parse_args()

def data_preprocess():
    # csv = CsvParser()
    # csv.read_csv_file(args.datafile)

    pcap = PcapParser()
    # pcap.list_attack_time()
    pcap.read_pcap_file(args.pcapfile, args.datafile)

    graph = GraphUtils()
    # graph.create_graphs(args.datafile)
    g_list = graph.get_weighted_graph_from_csv(args.datafile)

    # Create a gml file for visualization..
    # graph.create_gml(g_list)

    with open('json/iot_june_01.json', 'w') as fp:
        json.dump(g_list, fp, indent=3)

    print("Finish graph construction")

def graph_sketching(args):
    with open('json/iot_june_01.json') as jsonfile:
        graphs = json.load(jsonfile)
    print("[ ", len(graphs), " ] graphs read successfully")


    sketch = ShingleSketch()
    sketch.shingle_sketch(graphs, args)
    print("\n Done Batch Sketching...")


if __name__=="__main__":
    args = parse_args()

    # data_preprocess(args)
    graph_sketching(args)

