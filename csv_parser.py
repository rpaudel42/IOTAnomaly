# ******************************************************************************
# csv_parser.py
#
# Date      Name       Description
# ========  =========  ========================================================
# 6/11/19   Paudel     Initial version,
# ******************************************************************************

import pandas as pd
import os
import sys

class CsvParser:

    def __init__(self):
        print("\n\n..... Parsing CSV File.....")
        pass

    def read_csv_file(self, filename):
        exists = os.path.isfile(filename)
        if exists:
            print("Reading csv")
        else:
            print('"{}" does not exist'.format(filename), file=sys.stderr)
            sys.exit(-1)

        headers = ["Timestamp",	"FromLocalUdpPort53IP192.168.1.1Packet", "FromLocalUdpPort53IP192.168.1.1Byte",	"FromLocalUdpPort67IP192.168.1.1Packet", "FromLocalUdpPort67IP192.168.1.1Byte",	"FromLocalArpPortAllPacket", "FromLocalArpPortAllByte",	"ToLocalUdpPort67IP192.168.1.1Packet", "ToLocalUdpPort67IP192.168.1.1Byte",	"ToLocal2PortAllIP224.0.0.251/32Packet", "ToLocal2PortAllIP224.0.0.251/32Byte",	"ToLocalUdpPort53IP192.168.1.1Packet", "ToLocalUdpPort53IP192.168.1.1Byte", "ToLocalUdpPort67IP255.255.255.255/32Packet", "ToLocalUdpPort67IP255.255.255.255/32Byte", "ToLocalUdpPort5353IP224.0.0.251/32Packet", "ToLocalUdpPort5353IP224.0.0.251/32Byte",	"ToLocal58PortAllIPff00::/8Packet",	"ToLocal58PortAllIPff00::/8Byte", "ToLocal0PortAllIPff00::/8Packet", "ToLocal0PortAllIPff00::/8Byte", "ToLocalUdpPort5353IPff00::/8Packet",	"ToLocalUdpPort5353IPff00::/8Byte",	"ToLocal0x888ePortAllPacket", "ToLocal0x888ePortAllByte", "ToLocalArpPortAllPacket", "ToLocalArpPortAllByte", "FromInternetTcpPort80Packet", "FromInternetTcpPort80Byte", "FromInternetTcpPort443Packet", "FromInternetTcpPort443Byte",	"ToInternetTcpPort443Packet", "ToInternetTcpPort443Byte", "ToInternetTcpPort80Packet", "ToInternetTcpPort80Byte", "NoOfFlows"]
        data = pd.read_csv(filename, names=headers)
        print(data.head())
        for i in range(1, len(data)):
            print("Id: ", i)
            print("data: ", data[i]['Timestamp'])

