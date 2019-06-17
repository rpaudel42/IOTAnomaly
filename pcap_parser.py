# ******************************************************************************
# pcap_parser.py
#
# Date      Name       Description
# ========  =========  ========================================================
# 6/11/19   Paudel     Initial version,
# ******************************************************************************
import sys
import time
import datetime
import dpkt
import argparse
import os
import pandas as pd
import numpy as np
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

        tstamp = ["Time"]
        srcip = ["srcIP"]
        srcmac = ["srcMAC"]
        desip = ["desIP"]
        desmac = ["desMAC"]
        pktsize = ["pktSize"]
        srcport = ["srcPort"]
        desport = ["desPort"]
        attack = ["attack"]

        times1 = [[1527860996, 1527861596], [1527862604, 1527863204], [1527864215, 1527864815]]

        attacksforipnum1 = {"192.168.1.248": times1}

        times2 = [[1527893138, 1527893738], [1527889925, 1527890525], [1527891530, 1527892130], [1527961822, 1527962423]
                  , [1527963430, 1527964030], [1527965037, 1527965637], [1527968269, 1527968870],
                  [1527969880, 1527970480], [1527971486, 1527972086]]

        attacksforipnum2 = {"192.168.1.175": times2}

        #attacksforipnum3 = {"": }

        #attack_d = {}

        i = 0
        for packet in packets:

            print(packet.show())

            count = i

            if (packet.haslayer(IP)):
                tempstringsrcip = packet.getlayer(IP).src
                srcip.extend([tempstringsrcip])
                tempstringdesip = packet.getlayer(IP).dst
                desip.extend([tempstringdesip])

            if (packet.haslayer(TCP)):
                tempstringsrcport = packet.getlayer(TCP).sport
                srcport.extend([tempstringsrcport])
                tempstringdesport = packet.getlayer(TCP).dport
                desport.extend([tempstringdesport])
            elif (packet.haslayer(UDP)):
                tempstringsrcport = packet.getlayer(UDP).sport
                srcport.extend([tempstringsrcport])
                tempstringdesport = packet.getlayer(UDP).dport
                desport.extend([tempstringdesport])

            if (packet.haslayer(Ether)):
                tempstringsrcmac = packet.getlayer(Ether).src
                srcmac.extend([tempstringsrcmac])
                tempstringdesmac = packet.getlayer(Ether).dst
                desmac.extend([tempstringdesmac])
                tempstringpktsize = len(packet)
                pktsize.extend([tempstringpktsize])

            tempstringtstamp = str(packet.time)
            tstamp.extend([tempstringtstamp])

            #    tempstringtstamp = str(datetime.datetime.utcfromtimestamp(ts))
            #    tstamp.extend([tempstringtstamp])

            print("\n\n\n")
            i += 1

            if i == 5:
                break

        d = {}
        d['Time'] = tstamp
        d['srcIP'] = srcip
        d['srcMAC'] = srcmac
        d['desIP'] = desip
        d['desMAC'] = desmac
        d['pktSize'] = pktsize
        d['srcPort'] = srcport
        d['desPort'] = desport
        d['attack'] = attack
        df = pd.DataFrame.from_dict(d, orient="index")

        print(df)

        print("Total: ", i)

        # df.to_csv(index=False)
