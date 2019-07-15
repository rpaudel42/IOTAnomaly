# ******************************************************************************
# graph_sketch.py
#
# Date      Name       Description
# ========  =========  ========================================================
# 7/2/19   Paudel     Initial version,
# ******************************************************************************


# ******************************************************************************
# shingle_sketch.py
#
# Date      Name       Description
# ========  =========  ========================================================
# 5/15/19   Paudel     Initial version,
# ******************************************************************************
import random
import math
import pandas as pd
from tqdm import tqdm
from graph_utils import GraphUtils
import numpy as np
from scipy import spatial

from anomaly_detection import AnomalyDetection

import node2vec


class ShingleSketch():
    win_shingles = {}
    win_sketch = []


    def __init__(self):
        pass

    def arr2str(self, arr):
        result = ""
        for i in arr:
            result += " " + str(i)
        return result

    def get_win_total(self):
        '''
        # ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** **
        # NAME: getTotalCount
        #
        # INPUTS: ()
        #
        # RETURN:
        #
        # PURPOSE: Get the total count of shingle in a window
        #
        # ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** **
        :return:
        '''
        total = 0
        for s in self.win_shingles:
            for arr in self.win_shingles[s]:
                total += arr[0]

        return total

    def calculate_similarity(self, shingles):
        match_count = 0
        win_count = self.get_win_total()
        # print("\n\nWindow Total: ", win_count)
        s_count = sum(shingles[i] for i in shingles)
        # print("Shingle Count: ", s_count)

        for s1 in shingles.keys():
            if s1 in self.win_shingles.keys():
                w_count = sum(g_count[0] for g_count in self.win_shingles[s1])
                #print("Match: ", s1, shingles[s1], win_count)
                if shingles[s1] < w_count:
                    match_count += shingles[s1]
                else:
                    match_count += w_count
        # print("Match Count: ", match_count, win_count+s_count-match_count)
        # jaccard = (match_count/(win_count+s_count-match_count))
        # print("Jaccard: ", jaccard)
        return (match_count/(win_count+s_count-match_count))

    def jaccard_similarity(self, vec1, vec2):
        # print("Shingle 1: ", shingles1)
        total = sum(i for i in vec1 ) + sum(i for i in vec2)
        # print("total: ", total)
        match_count = 0

        for i in range(len(vec1)):
            # print(i)
            if vec1[i] < vec2[i]:
                match_count += vec1[i]
            else:
                match_count += vec2[i]
        # print("Match Count: ", match_count, total-match_count)
        # jaccard = (match_count/(win_count+s_count-match_count))
        # print("Jaccard: ", jaccard)
        return (match_count/(total-match_count))

    def preprocess_transition_probs(self, G):
        '''
        Preprocessing of transition probabilities for guiding the random walks based on edge weight
        '''
        transition_probs = {}
        for node in G.nodes():
            unnormalized_probs = []
            neigbhors = sorted(G.neighbors(node))
            for nbr in neigbhors:
                try:
                    all_edges = [G[node][nbr][i]['weight'] for i in range(0, len(G[node][nbr]))]
                except:
                    all_edges = [1]
                unnormalized_probs.append(sum(all_edges))
            # unnormalized_probs = [G[node][nbr][0]['weight'] for nbr in sorted(G.neighbors(node))]

            norm_const = sum(unnormalized_probs)
            # print("Norm Const: ", norm_const)
            normalized_probs = [float(u_prob) / norm_const for u_prob in unnormalized_probs]
            # print("Norm prob: ", node, normalized_probs)
            transition_probs[node] = [neigbhors, normalized_probs]
        return transition_probs

    def random_walk(self, start_node, G, walk_len, prob):
        walk = []
        while (len(walk) < walk_len):
            try:
                walk.append(G.node[start_node]['label'])
                # print("Nodes: ", prob[start_node][0], " Prob: ", prob[start_node][1])
                start_node = np.random.choice(prob[start_node][0], p = prob[start_node][1])
                # print("Start Nodes: ", start_node)
            except:
                pass
        return walk

    def simulate_random_walks(self, nx_G, walk_len, prob):
        '''
        Repeatedly simulate random walks from each node.
        '''
        walks = []
        nodes = list(nx_G.nodes())
        random.shuffle(nodes)
        for node in nodes:
            walks.append(self.random_walk(start_node = node, G = nx_G, walk_len=walk_len, prob=prob))
        return walks

    def generate_shingles(self, walk_path, k_shingle):
        shingles = {}
        # print(walk_path)
        for node_walk in ([x for x in walk_path]):
            # print("Node: ", node_walk)
            i = 0
            while (i < len(node_walk)-k_shingle+1):
                shingle = node_walk[i]
                for j in range(1, k_shingle):
                    shingle = str(shingle) + '-' + str(node_walk[i+j])
                if shingle not in shingles:
                    shingles[shingle] = 1
                else:
                    freq = shingles[shingle]
                    shingles[shingle] = freq + 1
                i += 1
        # print("Shingles: ", len(shingles), shingles)
        return shingles

    def update_chunk(self, s, graph_count, param_w):
        '''
        # ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** **
        # NAME: update_shingles_frequency()
        #
        # INPUTS: (s) Shingle List with count of instances for current window
        #
        # RETURN: ()
        #
        # PURPOSE: Maintain the list of shingle and their frequency in the window
        #
        # ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** **

        :param s:
        :return:
        '''
        # remove all shingle from the old chunk
        self.win_shingles = {}
        # print("After Deletion S_w: ", self.S_w)
        # add all shingle from current time to the window list
        count_array = []
        for sg in s.keys():
            if len(self.win_shingles) > 0:
                if sg in self.win_shingles.keys():
                    self.win_shingles[sg].append([int(s[sg]), int(graph_count)])
                else:
                    self.win_shingles[sg] = []
                    self.win_shingles[sg].append([int(s[sg]), int(graph_count)])

            if len(self.win_shingles) == 0:
                self.win_shingles[sg] = []
                self.win_shingles[sg].append([int(s[sg]), int(graph_count)])

    def update_one_step_forward_window(self, s, graph_count, param_w):
        '''
        # ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** **
        # NAME: update_shingles_frequency()
        #
        # INPUTS: (s) Shingle List with count of instances for current window
        #
        # RETURN: ()
        #
        # PURPOSE: Maintain the list of shingle and their frequency in the window
        #
        # ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** **

        :param s:
        :return:
        '''
        # remove all shingle from the oldest window

        for id in list(self.win_shingles.keys()):
            # Find Frequency and window number
            filters = list(
                filter(lambda x: param_w <= graph_count - x[1],
                       self.win_shingles[id]))
            # Remove frequency entry from selected filters
            self.win_shingles[id] = [x for x in self.win_shingles[id] if x not in filters]

            if len(self.win_shingles[id]) == 0:  # if it has only subgraph but no frequency
                del self.win_shingles[id]

        # print("After Deletion S_w: ", self.S_w)
        # add all shingle from current time to the window list
        count_array = []
        for sg in s.keys():
            if len(self.win_shingles) > 0:
                if sg in self.win_shingles.keys():
                    self.win_shingles[sg].append([int(s[sg]), int(graph_count)])
                else:
                    self.win_shingles[sg] = []
                    self.win_shingles[sg].append([int(s[sg]), int(graph_count)])

            if len(self.win_shingles) == 0:
                self.win_shingles[sg] = []
                self.win_shingles[sg].append([int(s[sg]), int(graph_count)])

    def get_graph_sketch(self, shingles, disc_shingles):
        vec = []
        for disc_shingle in disc_shingles:
            if disc_shingle in shingles:
                vec.append(shingles[disc_shingle])
            else:
                vec.append(0)
        return vec

    def get_win_sketch(self, disc_shingles):
        self.win_sketch = []
        for disc_shingle in disc_shingles:
            if disc_shingle in self.win_shingles:
                w_count = sum(g_count[0] for g_count in self.win_shingles[disc_shingle])
                self.win_sketch.append(w_count)
            else:
                self.win_sketch.append(0)

    def get_disc_shingle_using_entropy(self, args):
        '''
        :param subgraph:
        :return:
        '''
        d = args.sketch_size
        print("Sketch Size: ", d)
        g = args.win_size
        sh_entropy = {}
        total = self.get_win_total()
        # print("Total: ", total)
        for s in list(self.win_shingles.keys()):
            # print(s, self.win_shingles[s])
            shingle_count_in_window = sum(g_count[0] for g_count in self.win_shingles[s])
            # print("Shingle Present in: ", len(self.win_shingles[s]))
            num_g_shingle_present_in = len(self.win_shingles[s])
            temp = 0
            pS = 0
            # If shingle is present in one Graph then entropy is zero, we ignore it...
            if len(self.win_shingles[s]) > 1:
                # print("Shingle total: ", shingle_count_in_window)
                for shingle_count_in_graph in self.win_shingles[s]:
                    # print("Graph count: ", shingle_count_in_graph)
                    PsGi = shingle_count_in_graph[0] / shingle_count_in_window
                    temp += (PsGi * math.log2(PsGi))
                sh_entropy[s] = -1 * (num_g_shingle_present_in / g) * temp
                # print("Esi: ", eSi)
                # pS = s_total/total
                # eW += -1 * pS * eSi
                # else:
                #     sh_entropy[s] = 0
        # print("\n\nSorted Entropy Shingle: ", len(sh_entropy), sh_entropy)
        sorted_sh = sorted(sh_entropy.items(), key=lambda kv: kv[1], reverse=True)[:d]

        disc_shingles = []
        for sh, val in sorted_sh:
            disc_shingles.append(sh)
        # print("\n\nDiscriminative Shingles: ", len(disc_shingles), disc_shingles)
        return disc_shingles

    def get_disc_shingles(self, d):
        sh_freq = {}
        total = self.get_win_total()
        # print("Window Shingles: ", self.win_shingles)
        for s in self.win_shingles.keys():
            s_count = sum(g_count[0] for g_count in self.win_shingles[s])
            sh_freq[s] = s_count/total
            # sh_freq[s] = s_count

        sorted_sh = sorted(sh_freq.items(), key=lambda kv: kv[1], reverse=True)[:d]
        # print("\n\nSorted Shingle: ", sorted_sh)
        disc_shingles = []
        for sh, val in sorted_sh:
            disc_shingles.append(sh)
        # print("\n\nDiscriminative Shingles: ", disc_shingles)
        return disc_shingles

    def shingle_sketch(self, graphs, args):
        score = {}
        param_w = args.win_size
        graph_ids = [id for id in graphs]
        random.shuffle(graph_ids)
        # print("Total Graph:", graph_ids)
        total_chunk = math.ceil(len(graph_ids)/args.win_size)
        print("Total Chunk: ", total_chunk)
        chunk_index = [i*args.win_size for i in range(0,total_chunk)]
        #add last index
        graph_shingles = {}
        chunk_index.append(len(graph_ids)-1)
        print("Chunk Index: ", chunk_index)
        index = 0
        for chunks in range(0, total_chunk):
            disc_shingles = []
            sketch_list = []
            print("\nChunk:   ", chunks)
            print("\n\nGenerating Disc Shingles....")
            for g in tqdm(range(chunk_index[chunks], chunk_index[chunks+1])):
                # print("Graph : ", graph_ids[g])
                index += 1
                # nx_G = graphs[graph_ids[g]]['graph']
                gu = GraphUtils()
                nx_G = gu.create_graph(graphs[graph_ids[g]])

                walk_len = args.walk_len #len(nx_G.edges()) #args.walk_len

                # G = node2vec.Graph(nx_G, args.directed, p=1, q=1)
                # G.preprocess_transition_probs()
                # walk_path = G.simulate_walks(args.num_walks, walk_len)
                #
                prob = self.preprocess_transition_probs(nx_G)
                # print("Prob: ", prob)
                walk_path = self.simulate_random_walks(nx_G, walk_len, prob)
                # print("\n\n Graph: ", graph_ids[g], "     Walk: ", walk_path)
                shingles = self.generate_shingles(walk_path, args.k_shingle)
                sorted_sh = sorted(shingles.items(), key=lambda kv: kv[1])
                # print("\n\n Graph: ", graph_ids[g], "     Shingles: ", sorted_sh)
                graph_shingles[int(graph_ids[g])] = shingles
                # graph_utils.draw_graph(graph, g)
                self.update_one_step_forward_window(shingles, index, param_w)

            # disc_shingles = self.get_disc_shingle_using_entropy(args)
            disc_shingles = self.get_disc_shingles(args.sketch_size)
            # print("Disc Shingles: ", disc_shingles)
            # print("\n\nGenerating Sketch....")
            for g in tqdm(range(chunk_index[chunks], chunk_index[chunks+1])):
                shingles = graph_shingles[int(graph_ids[g])]
                sketch_vec = self.get_graph_sketch(shingles, disc_shingles)
                sketch_list.append([graph_ids[g], sketch_vec, graphs[graph_ids[g]]['label'], graphs[graph_ids[g]]['anom_count']])
                # print("\n\n Graph: ", graph_ids[g], "     Sketch: ", sketch_vec)

            # print("Final Sketch: ", sketch_list)
            sketch_vecs = pd.DataFrame(sketch_list, columns=['graphid', 'sketch', 'anomaly', 'anom_count'])
            sketch_vecs.to_csv('batch/'+str(chunks)+".csv")

            # classification
            ad = AnomalyDetection()
            rf_acc, dt_acc, svm_acc = ad.anomaly_detection(sketch_vecs, args)
            score[chunks] ={"rf": rf_acc, "dt":dt_acc, "svm":svm_acc}
            print(score)
        # sketch_vecs.to_csv(args.sketch_vector)
        # print(sketch_vecs.shape)




