# ******************************************************************************
# pcap_parser.py
#
# Date      Name       Description
# ========  =========  ========================================================
# 6/11/19   Paudel     Initial version,
# ******************************************************************************
from scapy.all import *

class PcapParser:

    def __init__(self):
        print("\n\n..... Parsing PCAP File.....")
        pass

    def read_pcap_file(self, filename):
        pkts = rdpcap(filename)

        for pkt in pkts:
            print(pkt)
            print("\n\n")

        # ports = [80, 25]
        #
        # filtered = (pkt for pkt in pkts if
        #     TCP in pkt and
        #     (pkt[TCP].sport in ports or pkt[TCP].dport in ports))
        #
        # wrpcap('filtered.pcap', filtered)