# ******************************************************************************
# main.py
#
# Date      Name       Description
# ========  =========  ========================================================
# 6/5/19   Paudel     Initial version,
# ******************************************************************************

import argparse
from csv_parser import CsvParser
from pcap_parser import PcapParser

def parse_args():
    '''
    Usual pythonic way of parsing command line arguments
    :return: all command line arguments read
    '''
    args = argparse.ArgumentParser("IOTAnomaly")
    args.add_argument("-f","--datafile", default = "data/flowdata/74c63b29d71d_flowstats.csv",
                      help="Path to directory containing files to be used for constructing graph")

    args.add_argument('-g','--graphfile', default='data/graph/ihome.g',
                      help='graph file for anomaly detection')

    args.add_argument('-p', "--pcapfile", default = "data/pcap/test.pcap",
                      help="Path to pcap file from wireshark")

    args.add_argument('-t',"--timeslice", default=5, type=int,
                      help="Timestamp for each graph")

    return args.parse_args()


def main(args):
    '''
    :param args:
    1. datafile: name of the csv file
    2. graphfile: name of the prased graph file
    3. pcapfile: name of the packet capture file
    4. timeslice: duration in sec for each individual graph
    :return: None:
    '''
    csv = CsvParser()
    csv.read_csv_file(args.datafile)

    pcap = PcapParser()
    pcap.read_pcap_file(args.pcapfile)

if __name__=="__main__":
    args = parse_args()
    main(args)

