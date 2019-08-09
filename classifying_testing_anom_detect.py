# ******************************************************************************
# classifying_testing_anom_detect.py
#
# Date      Name       Description
# ========  =========  ========================================================
# 7/29/19   Muncy     Initial version,
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
from sklearn.metrics import classification_report
import matplotlib.pyplot as plt
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score, roc_curve, auc, \
    mean_squared_error, r2_score
from sklearn import neighbors
import itertools
from datetime import datetime


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
# from daal.algorithms.svm import training, prediction


class ClassifyingTestingAnomDetect:
    ALGORITHMS = {
        "ann": "ann",
        "svm": "svm",
        "random_forest": "random_forest",
        "dt": "dt",
        "ada": "ada",
        "knn": "knn",
        "lreg": "lreg",
        "log": "log",
        "osvm": "osvm",
        "lda": "lda",
        "qda": "qda"
    }

    def __init__(self, csv_file):
        # print("\n\n------ Start Anomaly Detection ---- ")
        self.x, self.y = self.read_csv_file(csv_file)
        self.K_FOLD = 5
        pass

    def read_csv_file(self, csv_file):
        tcp = pd.DataFrame(index=[], columns=[])
        tcp1 = pd.read_csv(csv_file)
        tcp = tcp.append(tcp1, ignore_index=True)
        tcp = tcp.iloc[:, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]]
        tcp.columns = ["source", "destination", "ip", "https", "http", "udp", "tcp", "arp", "icmp", "PktSize", "deltaT",
                       "anomaly", "time_past"]
        # final_df = tcp.drop(['source', 'destination', 'time_past'], axis = 1)
        x= tcp.drop(['source', 'destination', 'time_past','anomaly'], axis=1)
        y = tcp['anomaly']
        return x, y

    def plot_confusion_matrix(self, con_mat, algorithm,
                              normalize=False,
                              title='Confusion matrix',
                              cmap=plt.cm.Blues):
        """
        This function prints and plots the confusion matrix.
        Normalization can be applied by setting `normalize=True`.
        :param con_mat: confusion matrix
        :param algorithm: algorithm used
        :param normalize: boolean to normalize or not
        :param title: title of the graph
        :param cmap: map color palate
        :return: None
        """

        plt.figure()
        plt.imshow(con_mat, interpolation='nearest', cmap=cmap)
        plt.title(title)
        plt.colorbar()
        tick_marks = np.arange(2)
        plt.xticks(tick_marks, ["mci", "healthy"], rotation=45)
        plt.yticks(tick_marks, ["mci", "healthy"])

        if normalize:
            con_mat = con_mat.astype('float') / con_mat.sum(axis=1)[:, np.newaxis]
            print("Normalized confusion matrix")
        else:
            print('Confusion matrix, without normalization')

        print(con_mat)

        thresh = con_mat.max() / 2.
        for i, j in itertools.product(range(con_mat.shape[0]), range(con_mat.shape[1])):
            plt.text(j, i, con_mat[i, j],
                     horizontalalignment="center",
                     color="white" if con_mat[i, j] > thresh else "black")

        plt.tight_layout()
        plt.ylabel('True label')
        plt.xlabel('Predicted label')
        # plt.savefig("figures/CASAS_CM_" + algorithm + ".png")

    def display_report(self, prediction, algorithm):
        """
        Displays the classification report
        :param prediction: Prediction of the model
        :param algorithm: Algorithm used to generate predictions
        :return: None
        """
        print ("Confusion Matrix: ")
        print ("------------------\n")
        self.plot_confusion_matrix(confusion_matrix(self.y, prediction), algorithm)

        print ("\nClassification Report: ")
        print ("-----------------------")
        print("accuracy: ", metrics.accuracy_score(self.y, prediction))
        print("precision: ", metrics.precision_score(self.y, prediction))
        print("recall: ", metrics.recall_score(self.y, prediction))
        print("f1: ", metrics.f1_score(self.y, prediction))
        print("area under curve (auc): ", metrics.roc_auc_score(self.y, prediction))
        print (classification_report(self.y, prediction))
        false_positive_rate, true_positive_rate, thresholds = roc_curve(self.y, prediction)
        print ("(auc): ", auc(false_positive_rate, true_positive_rate))

    def knn_classify(self):
        x_scaled = preprocessing.scale(self.x)
        # print self.x
        neigh = neighbors.KNeighborsClassifier(n_neighbors=5, weights='uniform', algorithm='auto')
        y_pred = cross_val_predict(neigh, x_scaled, self.y, cv=self.K_FOLD)
        print ("KNN Classifier Report")
        print ("===========================================\n")
        self.display_report(y_pred, self.ALGORITHMS["knn"])

    def svm_classify(self):
        """
        Uses Support Vector Machine Classifier
        :return: None
        """
        # for kernel in svm_kernels:
        x_scaled = preprocessing.scale(self.x)

        svm_classifier = svm.SVC(kernel="linear")
        before = datetime.now()
        print (before)
        print (x_scaled.shape)
        svm_output = cross_val_predict(svm_classifier, x_scaled, self.y, cv=self.K_FOLD)
        after = datetime.now()
        print (after)
        print ("Support Vector Machine Classifier Report")
        print ("===========================================\n")
        # classification_report(svm_output, self.ALGORITHMS["svm"])
        self.display_report(svm_output, self.ALGORITHMS["svm"])
        runtime = (after - before).total_seconds()
        print ("Time: ")
        print (runtime)

    def random_forest_classify(self):
        x_scaled = preprocessing.scale(self.x)
        # poly = preprocessing.PolynomialFeatures(degree=3)
        # x_scaled = poly.fit_transform(x_scaled)
        random_forest_classifier = RandomForestClassifier(n_estimators=10, criterion="entropy")
        classification = cross_val_predict(random_forest_classifier, x_scaled, self.y, cv=self.K_FOLD)
        print ("Random Forest Classifier Report")
        print ("===========================================\n")
        self.display_report(classification, self.ALGORITHMS["random_forest"])

    def decision_tree_classify(self):
        x_scaled = preprocessing.scale(self.x)
        # poly = preprocessing.PolynomialFeatures(degree=3)
        # x_scaled = poly.fit_transform(x_scaled)
        decision_tree_classifier = DecisionTreeClassifier()
        classification = cross_val_predict(decision_tree_classifier, x_scaled, self.y, cv=self.K_FOLD)
        print ("Decision Tree Classifier Report")
        print ("===========================================\n")
        # print (classification)
        self.display_report(classification, self.ALGORITHMS["dt"])

    # def svm_parameter_tuning(self, train_X, train_y, nfold):
    #     print("\n\n Parameter Tuning ... ")
    #     param_grid = {'C': [0.001, 0.01, 0.1, 1, 10], 'gamma': [0.001, 0.01, 0.1, 1], 'kernel': ['rbf', 'linear']}
    #     grid_search = GridSearchCV(svm.SVC(), param_grid, cv=nfold, verbose=1)
    #     grid_search.fit(train_X, train_y)
    #     grid_search.best_params_
    #     return grid_search.best_params_, grid_search.best_estimator_

    def classifying_testing_anom_detect(self, args):
        '''
        :param args:
        :return:
        '''
        # print(sketch_vector)
        # sketch_vector = sketch_vector.sort_values(by='graphid', ascending=False)
        # print(sketch_vector)
        # # Supervised Learning ....

        # dt_acc = self.run_decision_tree(sketch_vector)
        
        # self.decision_tree_classify()

        # rf_acc, y_pred = self.run_random_forest(sketch_vector)

        # self.random_forest_classify()

        # # svm_acc = 0

        # svm_acc, y_pred = self.run_svm(sketch_vector)

        # temporary commenting out SVM and KNN so code will run faster
        self.svm_classify()

        # self.knn_classify()

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
