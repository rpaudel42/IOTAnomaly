# ******************************************************************************
# graph_utils.py
#
# Date      Name       Description
# ========  =========  ========================================================
# 6/20/19   Muncy      Edited to fit data and graphs for current project
# ******************************************************************************

import pandas as pd
import networkx as nx

class GraphUtils:

    def __init__(self):
        # print("\n\n..... Creating graphs.....")
        pass

    def create_graphs(self, csv_file):          #work with this function to create .g from .csv
        print("\n\n ---- Creating G Files -----")
        tcp = pd.DataFrame(index=[], columns=[])
        print(csv_file)
        tcp1 = pd.read_csv(csv_file)
        tcp = tcp.append(tcp1, ignore_index=True)
        tcp = tcp.iloc[:, [0, 1, 2, 3, 4, 5, 6, 7, 8]]
        tcp.columns = ["hours_past", "SrcIP", "SrcMAC", "DesIP", "DesMAC", "PktSize", "SrcPort", "DesPort", "Attack"]
        #Renamed columns for IOTAnomaly

        global_nodes = {}
        local_node = {}
        global_node_id = 1
        local_node_id = 1
        hour = 0
        is_new_graph = False  # XP = 1 and create counter
        xp = 1
        fw = open("graphs/" + str(hour) + ".g", "w")
        fw.write("XP # 1\n")
        count = 0
        old_time = float(tcp['hours_past'].iloc[1]) #tcp[0]['hours_past']
        for index, row in tcp.iterrows():
            # print(index, row)
            if 1 == 1:  # row['hours_past'] < 3:
                #if hour >9:
                #    print(index, row)

                if row['SrcMAC'] not in global_nodes:
                    global_nodes[row['SrcMAC']] = global_node_id
                    global_node_id += 1

                if row['DesMAC'] not in global_nodes:
                    global_nodes[row['DesMAC']] = global_node_id
                    global_node_id += 1

                curr_time = float(row['hours_past'])

                if (curr_time - old_time) >= 3600: # if statement creates to graph every hour
                    hour += 1
                    old_time = curr_time
                    print("\n\n hour Past: ", hour, "    ", index)
                    fw = open("graphs/" + str(hour) + ".g", "w")
                    fw.write("XP # 1\n")
                    # xp += 1
                    #local_node = {}
                    local_node_id = 1
                # else:
                #     fw = open("graphs/" + str(old_time) + ".g", "a")

                # hour = row['hours_past']
                #
                # if row['SrcIP'] not in local_node:
                #     local_node[row['SrcIP']] = local_node_id  # global_nodes[row['source']]
                #     fw.write("v " + str(local_node_id) + " \"" + str(global_nodes[row['SrcIP']]) + "\"\n")
                #     local_node_id += 1
                #
                # if row['DesIP'] not in local_node:
                #     local_node[row['DesIP']] = local_node_id  # global_nodes[row['destination']]
                #     fw.write("v " + str(local_node_id) + " \"" + str(global_nodes[row['DesIP']]) + "\"\n")
                #     local_node_id += 1
                #
                fw.write("v " + str(local_node_id) + " \"" + str(global_nodes[row['SrcMAC']]) + "\"\n")
                local_node_id += 1
                fw.write("v " + str(local_node_id) + " \"" + str(global_nodes[row['DesMAC']]) + "\"\n")
                

                if row["PktSize"] <= 250:
                    call = "low"

                elif row["PktSize"] <= 750:
                    call = "med"

                elif row ["PktSize"] > 750:
                    call = "high"

                else:
                    call = "error"

                fw.write("d " + str(local_node_id-1) + " " + str(local_node_id) +
                         ' "' + call + '"' + "\n")
                local_node_id += 1

                count += 1

        print(count)

    def create_graph(self, graph):
        G = nx.MultiGraph()  # make id di graph is 2 1 and 1 2 need to be different edge
        node = {}
        for n in graph['node']:
            node[n] = graph['node'][n]
            G.add_node(n, label=graph['node'][n])
        for e in graph['edge']:
            src, dest = e.split(' ')
            edge_count = graph['edge'][e]
            # print("Edge:  ", graph['edge'][e])
            # if int(graph['edge'][e]) < 100:
            #     edge_count = int(graph['edge'][e])
            # else:
            #     edge_count = 100
            for i in  range(edge_count): #range(graph['edge'][e]):
                G.add_edge(src, dest, label=graph['edge'][e], weight=graph['edge'][e])
        return G

    def create_gbad_file(self, g_list):
        fw = open("gbad/iot.g", "w")
        for g in g_list:
            # print("G: ", g)
            graph_id = int(g)
            if int(g_list[g]['label']) ==  1:
                fw.write("XN # " + str(graph_id+1) + "\n")
            else:
                fw.write("XP # " + str(graph_id+1) + "\n")
            for n in g_list[g]['node']:
                # print("node: ", n, g_list[g]['node'][n])
                fw.write("v "+ str(n) + " \"" + str(g_list[g]['node'][n])+ "\"\n")
            for e in g_list[g]['edge']:
                # print("Edge: ", e, g_list[g]['edge'][e])
                for i in range(0, int(g_list[g]['edge'][e])):
                    fw.write("d " + str(e.split(' ')[0]) + " " + str(e.split(' ')[0])+ " \"c\"\n")


    def create_gml(self, g_list):
        for g in g_list:
            fw = open("gml/"+ str(g) +".gml", "w")
            fw.write("graph\n[\n")
            for node in g_list[g]['node']:
                fw.write("  node\n  [\n     id "+ str(node) + "\n   ]\n")
            for edge in g_list[g]['edge']:
                fw.write("  edge\n  [\n     source " + str(edge.split(' ')[0]) + "\n     target "+ str(edge.split(' ')[1]) +"\n       ]\n")
            fw.write("]\n")

    def get_weighted_graph_from_csv(self, csv_file):
        print("\n\n ---- Creating Graph Files -----")
        firewall_log = pd.DataFrame(index=[], columns=[])
        log = pd.read_csv(csv_file)
        firewall_log = firewall_log.append(log)
        firewall_log = firewall_log.iloc[:, [0, 1, 2, 3]]
        firewall_log.columns = ['source', 'destination', 'anomaly', 'time_past']
        firewall_log = firewall_log[firewall_log.source != '(empty)'].reset_index()
        # print(firewall_log)

        g_list = {}
        graph = {}
        node = {}
        edge = {}
        label = 0

        global_nodes = {}
        local_node = {}
        global_node_id = 1
        local_node_id = 1
        hour = 0
        anom_count = 0
        for index, row in firewall_log.iterrows():
            if  1==1: #row['time_past'] < 500:
                if row['source'] not in global_nodes:
                    global_nodes[row['source']] = global_node_id
                    global_node_id += 1

                if row['destination'] not in global_nodes:
                    global_nodes[row['destination']] = global_node_id
                    global_node_id += 1

                curr_hour = row['time_past']

                if hour != curr_hour:
                    print("\n\n Hour Past: ", hour, "    ", index)
                    graph['node'] = node
                    graph['edge'] = edge
                    graph['anom_count'] = anom_count
                    if anom_count >= 100:
                        graph['label'] = 1
                    else:
                        graph['label'] = 0
                    g_list[hour] = graph

                    graph = {}
                    node = {}
                    edge = {}
                    local_node = {}
                    local_node_id = 1
                    anom_count = 0

                hour = row['time_past']

                if row['anomaly'] == 1:
                    anom_count += 1

                if row['source'] not in local_node:
                    local_node[row['source']] = local_node_id  # global_nodes[row['source']]
                    node[local_node_id] = global_nodes[row['source']]
                    local_node_id += 1

                if row['destination'] not in local_node:
                    node[local_node_id] = global_nodes[row['destination']]
                    local_node[row['destination']] = local_node_id  # global_nodes[row['destination']]
                    local_node_id += 1
                edge_id = str(local_node[row['source']]) + ' ' + str(local_node[row['destination']])
                if edge_id in edge:
                    count = edge[edge_id]
                    edge[edge_id] = count + 1
                else:
                    edge[edge_id] = 1
        return g_list

    def parse_streamspot(self, csv_file):
        print("\n\n ---- Creating Edge List for Stream Spot -----")
        firewall_log = pd.DataFrame(index=[], columns=[])
        log = pd.read_csv(csv_file)
        firewall_log = firewall_log.append(log)
        firewall_log = firewall_log.iloc[:, [0, 1, 2, 3]]
        firewall_log.columns = ['source', 'destination', 'anomaly', 'time_past']
        firewall_log = firewall_log[firewall_log.source != '(empty)'].reset_index()
        # print(firewall_log)

        g_list = {}
        graph = {}
        node = {}
        edge = []
        label = 0

        global_nodes = {}
        local_node = {}
        global_node_id = 1
        local_node_id = 1
        hour = 0
        anom_count = 0
        fw = open("data/iot_edges.txt", "w")
        for index, row in firewall_log.iterrows():
            if 1 == 1:  # row['time_past'] < 5: #1 == 1: #
                # if row['time_past'] % 50 == 0:
                #     print("Graph   ", row['time_past'])
                if row['source'] not in global_nodes:
                    global_nodes[row['source']] = global_node_id
                    global_node_id += 1

                if row['destination'] not in global_nodes:
                    global_nodes[row['destination']] = global_node_id
                    global_node_id += 1

                fw.write(str(global_nodes[row['source']])+ "\tx\t" + str(global_nodes[row['destination']]) + "\tx\t1\t"+ str(row['time_past'])+"\n")
