# ******************************************************************************
# main.py
#
# Date      Name       Description
# ========  =========  ========================================================
# 6/5/19   Paudel     Initial version,
# ******************************************************************************

from scapy.all import *

pkts = rdpcap('test.pcap')


for pkt in pkts:
    print(pkt)
    print("\n\n\n")

# ports = [80, 25]
#
# filtered = (pkt for pkt in pkts if
#     TCP in pkt and
#     (pkt[TCP].sport in ports or pkt[TCP].dport in ports))
#
# wrpcap('filtered.pcap', filtered)