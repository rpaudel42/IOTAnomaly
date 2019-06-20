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
        tcp.columns = ["Minutes_past", "SrcIP", "SrcMAC", "DesIP", "DesMAC", "PktSize", "SrcPort", "DesPort", "Attack"]
        #Renamed columns for IOTAnomaly

        global_nodes = {}
        local_node = {}
        global_node_id = 1
        local_node_id = 1
        minute = 0
        is_new_graph = False  # XP = 1 and create counter
        xp = 1
        fw = open("graphs/" + str(minute) + ".g", "w")
        fw.write("XP # 1\n")
        count = 0
        old_time = float(tcp['Minutes_past'].iloc[1]) #tcp[0]['Minutes_past']
        for index, row in tcp.iterrows():
            # print(index, row)
            if 1 == 1:  # row['minutes_past'] < 3:
                if row['SrcIP'] not in global_nodes:
                    global_nodes[row['SrcIP']] = global_node_id
                    global_node_id += 1

                if row['DesIP'] not in global_nodes:
                    global_nodes[row['DesIP']] = global_node_id
                    global_node_id += 1

                curr_time = float(row['Minutes_past'])

                if (curr_time - old_time) >= 60: # if statement creates to graph every minute
                    minute += 1
                    old_time = curr_time
                    print("\n\n Minute Past: ", minute, "    ", index)
                    fw = open("graphs/" + str(minute) + ".g", "w")
                    fw.write("XP # 1\n")
                    # xp += 1
                    local_node = {}
                    local_node_id = 1
                # else:
                #     fw = open("graphs/" + str(old_time) + ".g", "a")

                # minute = row['Minutes_past']

                if row['SrcIP'] not in local_node:
                    local_node[row['SrcIP']] = local_node_id  # global_nodes[row['source']]
                    fw.write("v " + str(local_node_id) + " \"" + str(global_nodes[row['SrcIP']]) + "\"\n")
                    local_node_id += 1

                if row['DesIP'] not in local_node:
                    local_node[row['DesIP']] = local_node_id  # global_nodes[row['destination']]
                    fw.write("v " + str(local_node_id) + " \"" + str(global_nodes[row['DesIP']]) + "\"\n")
                    local_node_id += 1

                fw.write("d " + str(local_node[row['SrcIP']]) + " to " + str(local_node[row['DesIP']]) +
                         " call" + "\n")        # Did have str(row["PktSize"])

                count += 1

        print(count)