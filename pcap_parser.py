# ******************************************************************************
# pcap_parser.py
#
# Date      Name       Description
# ========  =========  ========================================================
# 6/11/19   Paudel     Initial version,
# ******************************************************************************
import sys
import time
import argparse
import os
import pandas as pd
import numpy as np
from scapy.all import *

class PcapParser:

    def __init__(self):
        print("\n\n..... Parsing PCAP File.....")
        pass

    def printable_timestamp(ts, resol):
        ts_sec = ts // resol
        ts_subsec = ts % resol
        ts_sec_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts_sec))
        return '{}.{}'.format(ts_sec_str, ts_subsec)

    def read_pcap_file(self, filename):

        if not os.path.isfile(filename):
            print('"{}" does not exist'.format(filename), file=sys.stderr)
            sys.exit(-1)


        packets = rdpcap(filename)

        timestamp = ["Time"]
        srcip = ["srcIP"]
        srcmac = ["srcMAC"]
        desip = ["desIP"]
        desmac = ["desMAC"]
        pktsize = ["pktSize"]
        ports = ["ports"]
        attack = ["attack"]

        i = 0
        for packet in packets:

            #print(packet.show())

            count = i
            interesting_packet_count = 0

            if (packet.haslayer(IP)):
                tempstringsrcip = packet.getlayer(IP).src
                srcip.extend([tempstringsrcip])
                tempstringdesip = packet.getlayer(IP).dst
                desip.extend([tempstringdesip])

            #tempString = packet.show()
            #tempList = tempString.splitlines()
            #srcmac.extend([])
            #desmac.extend([])
            print("\n\n\n")
            i += 1

        d = {}
        d['Time'] = timestamp
        d['srcIP'] = srcip
        d['srcMAC'] = srcmac
        d['desIP'] = desip
        d['desMAC'] = desmac
        d['pktSize'] = pktsize
        d['ports'] = ports
        d['attack'] = attack
        df = pd.DataFrame.from_dict(d, orient="index")

        print(df)

        print("Total: ", i)

        print('{} contains {} packets ({} interesting)'.
              format(filename, count, interesting_packet_count))


        # df.to_csv(index=False)

        # Old comments below
        # ports = [80, 25]

        # filtered = (pkt for pkt in pkts if
            # TCP in pkt and
            # (pkt[TCP].sport in ports or pkt[TCP].dport in ports))

        # wrpcap('filtered.pcap', filtered)