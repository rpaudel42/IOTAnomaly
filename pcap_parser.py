# ******************************************************************************
# pcap_parser.py
#
# Date      Name       Description
# ========  =========  ========================================================
# 6/11/19   Paudel     Initial version,
# ******************************************************************************
import sys
import pandas as pd
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

        time = ["Time"]
        srcip = ["srcIP"]
        srcmac = ["srcMAC"]
        desip = ["desIP"]
        desmac = ["desMAC"]
        pktsize = ["pktSize"]
        ports = ["ports"]
        attack = ["attack"]


        i = 0
        for packet in packets:
            print(packet.show())
            #tempString = packet.show()
            #tempList = tempString.splitlines()
            #srcmac.append([])
            #desmac.append([])
            print("\n\n\n")
            i += 1

        #d = {'Time': time, 'srcIP': srcip, 'srcMAC': srcmac, 'desIP': desip, 'desMAC': desmac, 'pktSize': pktsize,
        #     'ports': ports, 'attack': attack}
        #df = pd.DataFrame(data=d)

        print("Total: ", i)

        # df.to_csv(index=False)

        # Old comments below
        # ports = [80, 25]

        # filtered = (pkt for pkt in pkts if
            # TCP in pkt and
            # (pkt[TCP].sport in ports or pkt[TCP].dport in ports))

        # wrpcap('filtered.pcap', filtered)