# ******************************************************************************
# anomaly_detection.py
#
# Date      Name       Description
# ========  =========  ========================================================
# 6/12/19   Paudel     Initial version,
# ******************************************************************************

# anomaly detection based on Isolation Forest

from sklearn.ensemble import IsolationForest
from sklearn import preprocessing
from sklearn import metrics
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn import svm
from sklearn.svm import SVC
from sklearn.model_selection import cross_val_predict, GridSearchCV
from sklearn.cluster import DBSCAN, KMeans
from sklearn.decomposition import PCA


# import matplotlib.pyplot as plt
# from matplotlib.colors import rgb2hex
# import matplotlib as mat
# from matplotlib.cm import get_cmap
# from mpl_toolkits.mplot3d import Axes3D

#anomaly detection based on Robust Random Cut Forest
import rrcf
#
# from matplotlib import pyplot as plt

import pandas as pd
import numpy as np
import random
from daal.algorithms.svm import training, prediction


class AnomalyDetection:

    def __init__(self):
        # print("\n\n------ Start Anomaly Detection ---- ")
        pass

    def read_csv_file(self, csv_file):
        tcp = pd.DataFrame(index=[], columns=[])
        tcp1 = pd.read_csv(csv_file)
        tcp = tcp.append(tcp1, ignore_index=True)
        tcp = tcp.iloc[:, [1, 2, 3, 4]]
        tcp.columns = ['source', 'destination', 'anomaly', 'time_past']
        return tcp

    def read_sketch(self, file_name):
        sketches = pd.DataFrame(index=[], columns=[])
        sketch = pd.read_csv(file_name, converters={"sketch": lambda x: x.strip("[]").split(", ")})
        sketches = sketches.append(sketch, ignore_index=True)
        sketches = sketches.iloc[:, [1, 2, 3, 4]]
        sketches.columns = ['graphid', 'sketch', 'anomaly', 'anom_count']
        sketches['sketch'] = sketches['sketch'].apply(lambda x: pd.to_numeric(x, errors='ignore', downcast='float'))
        sketches['graphid'] = sketches['graphid'].astype(int)
        return sketches

    def get_top_k_anomalies(self, sketch_vector, k):
        top_k_index = []
        for index, row in sketch_vector.nlargest(k, 'anom_count').iterrows():
            top_k_index.append(index)
        return top_k_index

    def get_top_k_performance(self, top_k, true_anomalies, predicted_anomalies):
        print("\n--- Performance on (K = ", len(top_k), " ) ")
        k_true = []
        k_predicted = []

        for index in top_k:
            k_true.append(true_anomalies[index])
            k_predicted.append(predicted_anomalies[index])
        target_names = ['Normal', 'Anomaly']

        print(metrics.classification_report(k_true, k_predicted, target_names=target_names))

    def robust_random_cut(self, sketch_vector):
        # Set tree parameters

        sketch_vector = sketch_vector.sort_values(by='graphid', ascending=False)
        sketch = sketch_vector['sketch'].tolist()
        sketch = preprocessing.scale(sketch)
        num_trees = 50
        shingle_size = 1 #args.win_size
        tree_size = 32

        # Create a forest of empty trees
        forest = []
        for _ in range(num_trees):
            tree = rrcf.RCTree()
            forest.append(tree)

        # Use the "shingle" generator to create rolling window
        points = rrcf.shingle(sketch, size=shingle_size)

        # Create a dict to store anomaly score of each point
        avg_codisp = {}
        # For each shingle...
        for index, point in enumerate(points):
            # For each tree in the forest...
            if index % 50 == 0:
                print("Index: ", index)
            for tree in forest:
                # If tree is above permitted size...
                if len(tree.leaves) > tree_size:
                    # Drop the oldest point (FIFO)
                    tree.forget_point(index - tree_size)
                # Insert the new point into the tree
                tree.insert_point(point, index=index)
                # Compute codisp on the new point...
                new_codisp = tree.codisp(index)
                # And take the average over all trees
                if not index in avg_codisp:
                    avg_codisp[index] = 0
                avg_codisp[index] += new_codisp / num_trees
        # print(avg_codisp)
        disp = pd.Series([avg_codisp[s] for s in avg_codisp])
        pred_rrcf = disp > disp.quantile(0.95)
        print(metrics.classification_report(np.array(sketch_vector['anomaly']), pred_rrcf))
        # plt.plot(disp)
        # plt.plot(disp, marker='.')
        # plt.show()
        return pred_rrcf, disp

    def robust_random_cut_batch(self, sketch):
        # Set tree parameters
        # Specify sample parameters
        sketch_vector = sketch['sketch'].tolist()
        # sketch_vector = preprocessing.scale(sketch_vector)
        sketch_vector = np.array(sketch_vector)
        forest = []
        num_trees = 50
        tree_size = 256
        n = len(sketch_vector)
        sample_size_range = (n // tree_size, tree_size)
        while len(forest) < num_trees:
            # Select random subsets of points uniformly from point set
            ixs = np.random.choice(n, size=sample_size_range,
                                    replace=False)
            trees = [rrcf.RCTree(sketch_vector[ix], index_labels=ix)
                     for ix in ixs]
            forest.extend(trees)

        # Compute average CoDisp
        avg_codisp = pd.Series(0.0, index=np.arange(n))
        index = np.zeros(n)
        for tree in forest:
            codisp = pd.Series({leaf: tree.codisp(leaf)
                                for leaf in tree.leaves})
            avg_codisp[codisp.index] += codisp
            np.add.at(index, codisp.index.values, 1)
        avg_codisp /= index

        pred_rrcf = avg_codisp > avg_codisp.quantile(0.95)
        # pred_rrcf = np.array(pred_rrcf)
        # print("Predicted: ", pred_rrcf)

        print(metrics.classification_report(np.array(sketch_vector['anomaly']), pred_rrcf))
        return pred_rrcf, avg_codisp

    def isolation_forest(self, sketch_vector):
        vectors = preprocessing.scale(sketch_vector)
        clf = IsolationForest(n_estimators=50, max_samples=8, contamination=0.9, behaviour="new")
        clf.fit(vectors)
        if_score = clf.score_samples(vectors)
        predicted = if_score > np.quantile(if_score, 0.90)
        return if_score, predicted

    def print_result(self, y_test, y_pred):
        target_names = ['Normal', 'Anomaly']
        print(metrics.classification_report(y_test, y_pred, target_names=target_names))
        print("Accuracy: ", metrics.accuracy_score(y_test, y_pred))
        # print("Confusion Matrix: \n", metrics.confusion_matrix(y_test, y_pred))

    def plot_2d_scatter(self, X, y_pred):
        # plt.subplot(221)
        pca = PCA(n_components=2).fit(X)
        pca_2d = pca.transform(X)
        # print(pca_3d)
        plt.figure(figsize=(6, 6))
        plt.scatter(pca_2d[:, 0], pca_2d[:, 1], c=y_pred)
        plt.title("2D Scatter Plot")
        plt.show()

    def plot_3d_scatter(self, X, y_pred):
        pca = PCA(n_components=3).fit(X)
        pca_3d = pca.transform(X)
        colormap = get_cmap('viridis')
        colors = [rgb2hex(colormap(col)) for col in np.arange(0, 1.01, 1 / (2 - 1))]
        fig = plt.figure()
        ax = fig.gca(projection='3d')
        ax = Axes3D(fig)
        ax.scatter(pca_3d[:, 0], pca_3d[:, 1], pca_3d[:, 2], c=y_pred, s=50, cmap=mat.colors.ListedColormap(colors))
        plt.title('3D Scatter Plot')
        plt.show()

    def run_kmean(self, sketch_vector):
        X = preprocessing.scale(sketch_vector['sketch'].tolist())
        # X = sketch_vector['sketch'].tolist()
        y_pred = KMeans(n_clusters=2, random_state=10).fit_predict(X)
        print(" \n -- K Mean Results")
        self.print_result(sketch_vector['anomaly'].tolist(), y_pred)
        self.plot_2d_scatter(X, y_pred)
        self.plot_3d_scatter(X, y_pred_rf)

    def run_random_forest(self, sketch_vector):
        X = preprocessing.scale(sketch_vector['sketch'].tolist())
        # X = sketch_vector['sketch'].tolist()
        random_forest_classifier = RandomForestClassifier(n_estimators=50, criterion="entropy")
        y_pred_rf = cross_val_predict(random_forest_classifier, X, sketch_vector['anomaly'].tolist(), cv=5)
        print(" \n -- Random Forest Results")
        self.print_result(sketch_vector['anomaly'].tolist(), y_pred_rf)
        # self.plot_2d_scatter(X, y_pred_rf)
        # self.plot_3d_scatter(X, y_pred_rf)
        return metrics.accuracy_score(sketch_vector['anomaly'].tolist(), y_pred_rf), y_pred_rf

    def run_decision_tree(self, sketch_vector):
        X = preprocessing.scale(sketch_vector['sketch'].tolist())
        # X = sketch_vector['sketch'].tolist()
        decision_tree_classifier = DecisionTreeClassifier()
        y_pred = cross_val_predict(decision_tree_classifier, X, sketch_vector['anomaly'].tolist(), cv=5)
        print(" \n -- Decision Tree Results")
        # print("Predicted: ", y_pred)
        self.print_result(sketch_vector['anomaly'].tolist(), y_pred)
        return metrics.accuracy_score(sketch_vector['anomaly'].tolist(), y_pred)

    def svm_parameter_tuning(self, train_X, train_y, nfold):
        print("\n\n Parameter Tuning ... ")
        param_grid = {'C': [0.001, 0.01, 0.1, 1, 10], 'gamma': [0.001, 0.01, 0.1, 1], 'kernel': ['rbf', 'linear']}
        grid_search = GridSearchCV(svm.SVC(), param_grid, cv=nfold, verbose=1)
        grid_search.fit(train_X, train_y)
        grid_search.best_params_
        return grid_search.best_params_, grid_search.best_estimator_

    def run_svm(self, sketch_vector):
        X = preprocessing.scale(sketch_vector['sketch'].tolist())
        # X = sketch_vector['sketch'].tolist()
        # param, estimator = self.svm_parameter_tuning(X, sketch_vector['anomaly'].tolist(), 5)
        estimator = svm.SVC(kernel="linear")
        # print("Best Estimator: ", estimator)
        # estimator =  SVC(C=1, cache_size=200, class_weight=None, coef0=0.0,
        # decision_function_shape='ovr', degree=3, gamma=0.01, kernel='rbf',
        # max_iter=-1, probability=False, random_state=None, shrinking=True,
        # tol=0.001, verbose=False)
        y_pred = cross_val_predict(estimator, X, sketch_vector['anomaly'].tolist(), cv=5)
        print(" \n -- SVM Results")
        self.print_result(sketch_vector['anomaly'].tolist(), y_pred)
        return metrics.accuracy_score(sketch_vector['anomaly'].tolist(), y_pred), y_pred

    def run_dbscan(self, sketch_vector):
        X = preprocessing.scale(sketch_vector['sketch'].tolist())
        # print(sketch_vector.iloc[0]['graphid'], sketch_vector['graphid'])
        dbscan = DBSCAN(eps=3, metric='euclidean', min_samples=5, algorithm='auto', leaf_size=30)
        dbscan.fit(X)

        # self.print_result(sketch_vector['anomaly'].tolist(), y_pred)
        # y_pred = []
        # for i in range(0, len(dbscan.labels_)):
        #     if dbscan.labels_[i]== 1:
        #         y_pred.append(dbscan.labels_[i])
        #     else:
        #         y_pred.append(1)

        # print("Predicted: ", dbscan.labels_)
        # print("True: ", np.array(sketch_vector['anomaly']))
        # print(metrics.classification_report(np.array(sketch_vector['anomaly']), y_pred))

        pca = PCA(n_components=2).fit(X)
        pca_2d = pca.transform(X)
        # plt.fig()
        colormap = get_cmap('viridis')

        colors = [rgb2hex(colormap(col)) for col in np.arange(0, 1.01, 1 / (6 - 1))]


        for i in range(0, pca_2d.shape[0]):
            # print(dbscan.labels_[i])
            if dbscan.labels_[i] == 0:
                c1 = plt.scatter(pca_2d[i, 0], pca_2d[i, 1], c='b', marker="p")
            elif dbscan.labels_[i] == 1:
                c2 = plt.scatter(pca_2d[i, 0], pca_2d[i, 1], c='b', marker="*")
            elif dbscan.labels_[i] == -1:
                c3 = plt.scatter(pca_2d[i, 0], pca_2d[i, 1], c='b', marker="o")
            # if dbscan.labels_[i] == 0:
            #     c1 = plt.scatter(pca_2d[i, 0], pca_2d[i, 1],  c='r', marker='+')
            # # elif dbscan.labels_[i] == 1:
            # #     c2 = plt.scatter(pca_2d[i, 0], pca_2d[i, 1], pca_2d[i, 2], c='g', marker='o')
            # elif dbscan.labels_[i] == -1:

        plt.legend([c1, c2, c3], ['Cluster 1', 'Cluster 2', 'Noise'])
        plt.title('DBSCAN finds 2 clusters and noise')
        plt.show()


    def anomaly_detection(self, sketch_vector, args):
        '''
        :param sketch_vector:
        :param args:
        :return:
        '''
        # print(sketch_vector)
        # sketch_vector = sketch_vector.sort_values(by='graphid', ascending=False)
        # print(sketch_vector)
        # # Supervised Learning ....
        dt_acc = self.run_decision_tree(sketch_vector)
        rf_acc, y_pred = self.run_random_forest(sketch_vector)
        # # svm_acc = 0
        svm_acc, y_pred = self.run_svm(sketch_vector)

        # self.run_dbscan(sketch_vector)

        #
        # top_k = self.get_top_k_anomalies(sketch_vector, 300)
        #
        # # # print(top_k)
        # target_names = ['Normal', 'Anomaly']
        # # # # #
        # true_anomalies = np.array(sketch_vector['anomaly'])
        # # #
        # # # # if_score, pred_iso = self.isolation_forest(sketch_vector=sketch_vector['sketch'].tolist())
        # # # # #
        # # # # print(" \n -- ISO Results")
        # # # # print(metrics.classification_report(true_anomalies, pred_iso, target_names=target_names))
        # self.get_top_k_performance(top_k, true_anomalies, y_pred)
        # # #
        # # print(" \n -- RRCF Results")
        # pred_rrcf, avg_codisp =self.robust_random_cut(sketch_vector)
        # # pred_rrcf, avg_codisp = self.robust_random_cut_batch(sketch_vector['sketch'].tolist())
        # print(metrics.classification_report(true_anomalies, pred_rrcf, target_names=target_names))
        # print("Accuracy: ", metrics.accuracy_score(true_anomalies, pred_rrcf))

        return rf_acc, dt_acc, svm_acc