# ******************************************************************************
# graph_utils.py
#
# Date      Name       Description
# ========  =========  ========================================================
# 6/20/19   Muncy      Edited to fit data and graphs for current project
# ******************************************************************************

import pandas as pd

class GraphUtils:

    def __init__(self):
        print("\n\n..... Creating graphs.....")
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
            if 1 == 1:  # row['hours_past'] < 5:
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
