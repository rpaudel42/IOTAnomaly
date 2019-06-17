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
                  [1527969880, 1527970480], [1527971486, 1527972086], [1540365943, 1540366543], [1540373217, 1540373817]
                  , [1540366855, 1540367455], [1540368674, 1540369275], [1540369583, 1540370183],
                  [1540371397, 1540371998], [1540372308, 1540372908], [1540370492, 1540371092], [1540367763, 1540368363]
                  ]

        attacksforipnum2 = {"192.168.1.175": times2}

        times3 = [[1528001914, 1528002515], [1528002528, 1528003128], [1528003135, 1528003735], [1527955025, 1527955626]
                  , [1527956626, 1527957226], [1527958226, 1527958826], [1528284070, 1528284670],
                  [1528280869, 1528281470], [1528282470, 1528283070]]

        attacksforipnum3 = {"149.171.36.232": times3}

        times4 = [[1528224632, 1528225233], [1528226233, 1528226833], [1528227833, 1528228433]]

        attacksforipnum4 = {"149.171.37.10": times4}

        times5 = [[1540348890, 1540349490], [1540350097, 1540350697], [1540351301, 1540351902]]

        attacksforipnum5 = {"192.168.1.129": times5}

        times6 = [[1540361353, 1540361953], [1540360129, 1540360729], [1540360741, 1540361341], [1540380531, 1540381131]
                  , [1540378530, 1540379131], [1540379531, 1540380131], [1540384708, 1540385308],
                  [1540382707, 1540383308], [1540383708, 1540384308]]

        attacksforipnum6 = {"149.171.37.137": times6}

        times7 = [[1540362695, 1540363296], [1540363696, 1540364296], [1540364696, 1540365296]]

        attacksforipnum7 = {"149.171.37.10": times7}

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
