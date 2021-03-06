# ******************************************************************************
# pcap_parser.py
#
# Date      Name       Description
# ========  =========  ========================================================
# 6/11/19   Paudel     Initial version,
# 6/19/19   Muncy      Commented and working version
# ******************************************************************************
import sys
import os
import pandas as pd
from scapy.all import *
from datetime import datetime

class PcapParser:

    def __init__(self):
        print("\n\n..... Parsing PCAP File.....")
        # below lists contain start and end time pairs for attacks with each list seperate based on ip address
        times1 = [
            [1527838552, 1527839153],
            [1527835334, 1527835936],
            [1527836944, 1527837544],
            [1527860996, 1527861596],
            [1527862604, 1527863204],
            [1527864215, 1527864815],
            [1527935202, 1527935802],
            [1527936810, 1527937410],
            [1527938417, 1527939017],
            [1527949904, 1527950504],
            [1527951510, 1527952110],
            [1527953123, 1527953723],
            [1527893138, 1527893738],
            [1527889925, 1527890525],
            [1527891530, 1527892130],
            [1527961822, 1527962423],
            [1527963430, 1527964030],
            [1527965037, 1527965637],
            [1527968269, 1527968870],
            [1527969880, 1527970480],
            [1527971486, 1527972086],
            [1528001914, 1528002515],
            [1528002528, 1528003128],
            [1528003135, 1528003735],
            [1527879896, 1527880496],
            [1527876695, 1527877296],
            [1527878296, 1527878896],
            [1527955025, 1527955626],
            [1527956626, 1527957226],
            [1527958226, 1527958826],
            [1527917995, 1527918596],
            [1527919596, 1527920197],
            [1527921197, 1527921797],
            [1527943358, 1527943958],
            [1527944959, 1527945559],
            [1527946559, 1527947159],
            [1528224632, 1528225233],
            [1528226233, 1528226833],
            [1528227833, 1528228433],
            [1528284070, 1528284670],
            [1528280869, 1528281470],
            [1528282470, 1528283070]]

        times2 = [
            [1540358552, 1540359152],
            [1540357342, 1540357942],
            [1540348890, 1540349490],
            [1540350097, 1540350697],
            [1540351301, 1540351902],
            [1540353718, 1540354318],
            [1540356134, 1540356735],
            [1540352509, 1540353109],
            [1540354923, 1540355523],
            [1540365943, 1540366543],
            [1540373217, 1540373817],
            [1540366855, 1540367455],
            [1540368674, 1540369275],
            [1540369583, 1540370183],
            [1540371397, 1540371998],
            [1540372308, 1540372908],
            [1540370492, 1540371092],
            [1540367763, 1540368363],
            [1540361353, 1540361953],
            [1540360129, 1540360729],
            [1540360741, 1540361341],
            [1540380531, 1540381131],
            [1540378530, 1540379131],
            [1540379531, 1540380131],
            [1540384708, 1540385308],
            [1540382707, 1540383308],
            [1540383708, 1540384308],
            [1540362695, 1540363296],
            [1540363696, 1540364296],
            [1540364696, 1540365296]]

        times3 = [
            [1540218159, 1540218759],
            [1540214943, 1540215543],
            [1540216550, 1540217150],
            [1540240592, 1540241193],
            [1540249401, 1540250001],
            [1540251009, 1540251609],
            [1540305374, 1540305974],
            [1540305984, 1540306584],
            [1540306594, 1540307194]]

        times4 = [
            [1527843385, 1527843985],
            [1527840167, 1527840767],
            [1527841774, 1527842374],
            [1527865835, 1527866436],
            [1527867446, 1527868047],
            [1527869057, 1527869657],
            [1527928594, 1527929195],
            [1527930207, 1527930807],
            [1527931814, 1527932415],
            [1527897987, 1527898587],
            [1527894761, 1527895361],
            [1527896376, 1527896976],
            [1527956962, 1527957562],
            [1527958575, 1527959175],
            [1527960201, 1527960801],
            [1527884697, 1527885297],
            [1527881496, 1527882097],
            [1527883097, 1527883697],
            [1527922797, 1527923398],
            [1527924398, 1527924998],
            [1527925998, 1527926598],
            [1528229672, 1528230273],
            [1528231273, 1528231873],
            [1528232873, 1528233473],
            [1528279106, 1528279706],
            [1528275905, 1528276506],
            [1528277506, 1528278106]]

        times5 = [
            [1527848238, 1527848838],
            [1527844998, 1527845599],
            [1527846610, 1527847210],
            [1527870675, 1527871276],
            [1527872284, 1527872884],
            [1527873890, 1527874490],
            [1527902817, 1527903417],
            [1527899600, 1527900201],
            [1527901207, 1527901807],
            [1527889498, 1527890098],
            [1527886297, 1527886898],
            [1527887898, 1527888498],
            [1527927598, 1527928199],
            [1527929199, 1527929799],
            [1527930799, 1527931399],
            [1528253682, 1528254282],
            [1528255282, 1528255883],
            [1528256883, 1528257483],
            [1528268227, 1528268827],
            [1528265025, 1528265626],
            [1528266626, 1528267226]]

        times6 = [
            [1540227823, 1540228423],
            [1540224603, 1540225204],
            [1540226210, 1540226811]]

        times7 = [
            [1540259613, 1540260213],
            [1540261222, 1540261822],
            [1540262834, 1540263434],
            [1540232657, 1540233257],
            [1540229442, 1540230043],
            [1540231049, 1540231649],
            [1540244228, 1540244828],
            [1540252626, 1540253226],
            [1540254243, 1540254843],
            [1540279892, 1540280492],
            [1540281500, 1540282100],
            [1540283108, 1540283708],
            [1540300287, 1540300887],
            [1540300897, 1540301498],
            [1540301508, 1540302108]]

        times8 = [
            [1527833715, 1527834315],
            [1527830498, 1527831098],
            [1527832106, 1527832706],
            [1527856158, 1527856758],
            [1527857765, 1527858365],
            [1527859377, 1527859977],
            [1527923756, 1527924356],
            [1527925365, 1527925965],
            [1527926974, 1527927574],
            [1527888305, 1527888905],
            [1527885081, 1527885682],
            [1527886693, 1527887293],
            [1527875095, 1527875695],
            [1527871894, 1527872495],
            [1527873495, 1527874095],
            [1527913194, 1527913795],
            [1527914795, 1527915395],
            [1527916395, 1527916995],
            [1528219424, 1528220024],
            [1528221024, 1528221624],
            [1528222625, 1528223225],
            [1528292921, 1528293521],
            [1528289721, 1528290321],
            [1528291321, 1528291921]]

        times9 = [
            [1527828872, 1527829472],
            [1527825643, 1527826244],
            [1527827256, 1527827856],
            [1527851321, 1527851923],
            [1527852933, 1527853533],
            [1527854541, 1527855141],
            [1527918925, 1527919526],
            [1527920532, 1527921132],
            [1527922140, 1527922740],
            [1527945065, 1527945666],
            [1527946676, 1527947276],
            [1527948284, 1527948884],
            [1527883466, 1527884066],
            [1527880245, 1527880845],
            [1527881855, 1527882455],
            [1528014857, 1528015457],
            [1528011637, 1528012237],
            [1528013251, 1528013851],
            [1528008710, 1528009310],
            [1528007499, 1528008099],
            [1528008104, 1528008704],
            [1527870294, 1527870894],
            [1527867093, 1527867694],
            [1527868694, 1527869294],
            [1527939658, 1527940258],
            [1527936456, 1527937057],
            [1527938057, 1527938657],
            [1527908393, 1527908994],
            [1527909994, 1527910594],
            [1527911594, 1527912194],
            [1528213598, 1528214199],
            [1528215199, 1528215799],
            [1528216799, 1528217399],
            [1528298733, 1528299333],
            [1528295532, 1528296133],
            [1528297133, 1528297733]]

        times10 = [
            [1540222987, 1540223588],
            [1540219772, 1540220372],
            [1540221380, 1540221980],
            [1540269173, 1540269773],
            [1540270783, 1540271383],
            [1540272392, 1540272992],
            [1540277898, 1540278498],
            [1540274680, 1540275281],
            [1540276290, 1540276890],
            [1540288528, 1540289128],
            [1540285311, 1540285911],
            [1540286919, 1540287519],
            [1540291862, 1540292462],
            [1540290643, 1540291244],
            [1540291252, 1540291852],
            [1540453525, 1540454125],
            [1540452323, 1540452924],
            [1540315870, 1540316470],
            [1540313470, 1540314070],
            [1540314670, 1540315270],
            [1540311495, 1540312095],
            [1540309095, 1540309695],
            [1540310295, 1540310895],
            [1540462848, 1540463448],
            [1540293174, 1540293774],
            [1540293784, 1540294384],
            [1540294394, 1540294994]]

        # creating a dictionary of attacks using ip addresses as keys
        self.attacksdict = {"192.168.1.248": times1, "192.168.1.129": times2, "192.168.1.239": times3,
                       "192.168.1.227": times4, "192.168.1.241": times5, "192.168.1.163": times6,
                       "192.168.1.118": times7, "192.168.1.223": times8, "192.168.1.165": times9,
                       "192.168.1.119": times10}
        pass

    def is_attack(self, packet_time, device_ip):
        if device_ip in self.attacksdict:
            for time in self.attacksdict[device_ip]:
                if (packet_time >= time[0] and time[1] >= packet_time):
                    return True
        return False

    def list_attack_time(self):
        # check start and end time
        for ip in self.attacksdict.keys():
            print("\n\n.... Device ... ", ip)
            for time in self.attacksdict[ip]:
                print("Start Time: ", datetime.utcfromtimestamp(int(time[0])).strftime('%Y-%m-%d %H:%M:%S.%f'),
                      "    End Time : ", datetime.utcfromtimestamp(int(time[1])).strftime('%Y-%m-%d %H:%M:%S.%f'))

    def read_pcap_file(self, filename, output_file):
        if not os.path.isfile(filename):
            print('"{}" does not exist'.format(filename), file=sys.stderr)
            sys.exit(-1)

        #reads packet capture using scapy
        packets = rdpcap(filename)
        iot = []
        prev_time = 0
        for packet in packets:
            if packet.haslayer(IP):
                if packet.getlayer(IP).src == "192.168.1.239":
                    #above two if statements test for attack IP and  can be substituted for any attack IP
                    ip = "0"
                    https = "0"
                    http = "0"
                    udp = "0"
                    tcp = "0"
                    arp = "0"
                    icmp = "0"

                    if (packet.haslayer(IP)):
                        srcip = packet.getlayer(IP).src
                        desip = packet.getlayer(IP).dst

                    # elif (packet.haslayer(IPv6)):
                    #     srcip = packet.getlayer(IPv6).src
                    #     desip = packet.getlayer(IPv6).dst
                    #
                    # elif (packet.haslayer(Ether)):
                    #     srcip = packet.getlayer(Ether).src
                    #     desip = packet.getlayer(Ether).dst

                    if (packet.haslayer(TCP)):
                        # print(packet.getlayer(TCP).sport)
                        # below if statements determine if packet is http or https based on ports used
                        # this approach can be used on other protocols which are not easily extracted
                        if (packet.getlayer(TCP).sport == 443 or packet.getlayer(TCP).dport == 443):
                            https = "1"
                        elif (packet.getlayer(TCP).sport == 80 or packet.getlayer(TCP).dport == 80):
                            http = "1"
                        else:
                            tcp = "1"

                    if (packet.haslayer(ARP)):
                        arp = "1"

                    if (packet.haslayer(ICMP)):
                        icmp = "1"

                    if (packet.haslayer(UDP)):
                        udp = "1"

                    current_time = packet.time
                    deltat = current_time - prev_time
                    prev_time = current_time

                    # print(packet.show())

                    # if (packet.haslayer(TCP)):
                    #     tempstringsrcport = packet.getlayer(TCP).sport
                    #     srcport.extend([tempstringsrcport])
                    #     tempstringdesport = packet.getlayer(TCP).dport
                    #     desport.extend([tempstringdesport])
                    # elif (packet.haslayer(UDP)):
                    #     tempstringsrcport = packet.getlayer(UDP).sport
                    #     srcport.extend([tempstringsrcport])
                    #     tempstringdesport = packet.getlayer(UDP).dport
                    #     desport.extend([tempstringdesport])
                    #
                    # if (packet.haslayer(Ether)):
                    #     tempstringsrcmac = packet.getlayer(Ether).src
                    #     srcmac.extend([tempstringsrcmac])
                    #     tempstringdesmac = packet.getlayer(Ether).dst
                    #     desmac.extend([tempstringdesmac])

                    tempstringpktsize = len(packet)

                    iot.append([datetime.utcfromtimestamp(int(packet.time)).strftime('%Y-%m-%d %H:%M:%S.%f'), srcip, desip, ip,
                                https, http, udp, tcp, arp, icmp, tempstringpktsize, deltat,
                                self.is_attack(packet_time=packet.time, device_ip=srcip)])


        iot_traffic = pd.DataFrame(iot, columns=['time', 'source', 'destination', 'ip', 'https', 'http',
                                                 'udp', 'tcp', 'arp', 'icmp', 'PktSize', 'deltaT', 'anomaly'])

        print("\n\n.....Finish Dataframe Creation.....")

        #create column for time past since the begining.. checkpoint for each graph.... 60 sec here...
        iot_traffic['time'] = pd.to_datetime(iot_traffic['time'])
        initial_time = iot_traffic['time'].min()
        iot_traffic['time'] = iot_traffic['time'] - initial_time
        iot_traffic['time_past'] = iot_traffic['time'].dt.days * 24 + iot_traffic['time'].dt.seconds // 60
        iot_traffic = iot_traffic.drop('time', axis=1)
        iot_traffic = iot_traffic.sort_values('time_past')

        print(iot_traffic)

        iot_traffic.to_csv(output_file, index=False)
        print("\n\n.....Finish PCAP Parsing.....")
