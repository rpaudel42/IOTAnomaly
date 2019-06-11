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

        if not os.path.isfile(filename):
            print('"{}" does not exist'.format(filename), file=sys.stderr)
            sys.exit(-1)


        packets = rdpcap(filename)

        i = 0
        for packet in packets:
            print(packet.show())
            print("\n\n\n")
            i += 1
        print("Total: ", i)

        # ports = [80, 25]
        #
        # filtered = (pkt for pkt in pkts if
        #     TCP in pkt and
        #     (pkt[TCP].sport in ports or pkt[TCP].dport in ports))
        #
        # wrpcap('filtered.pcap', filtered)