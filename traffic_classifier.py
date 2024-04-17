import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
import os, sys
import csv
import numpy as np
import random
from random import shuffle
import math
import time
import warnings
import pandas as pd
import sklearn
from sklearn import preprocessing
from sklearn.model_selection import ParameterGrid
from xgboost import XGBClassifier
import xgboost as xgb
from sklearn.model_selection import train_test_split, cross_val_score, KFold, StratifiedKFold
from sklearn.metrics import accuracy_score, roc_auc_score, roc_curve, auc, precision_score, recall_score, f1_score, confusion_matrix
from scipy import interp
import seaborn as sns
from matplotlib.colors import LinearSegmentedColormap
from termcolor import colored 
from itertools import combinations
import argparse

sklearn.set_config(assume_finite=True)

def PrintColored(string, color):
    print(colored(string, color))

def mergeDatasets(dir_path):
    le = preprocessing.LabelEncoder()
    action_names = os.listdir(dir_path) 
    all_classes_dataframes = [] 

    for an in action_names:
        if ("." in an):
            continue
        dfs_dict = {}  
        features = os.listdir(os.path.join(dir_path, an)) 
        for feature in features:
            if ("." in feature):
                continue
            fns = os.listdir(os.path.join(dir_path, an, feature)) 
            for fn in fns:
                if (".DS" in fn) or (".ipynb_checkpoints" in fn):
                    continue
                file_path = os.path.join(dir_path, an, feature, fn)
                if os.path.getsize(file_path) == 0:
                    print(f"Skipping empty file: {file_path}")
                    continue
                # print("Attempting to read:", file_path)
                df = pd.read_csv(file_path, header=None)
                df.columns = df.iloc[0]
                if feature in ['cart', 'gripper_position']:
                    df.columns = [f"{feature}_{col}" for col in df.columns]
                df = df.drop(df.index[0])

                if fn in dfs_dict:
                    if 'Class' in df.columns:
                        df = df.drop(columns='Class') 
                
                    dfs_dict[fn] = pd.concat([dfs_dict[fn], df], axis=1)
                else:
                    dfs_dict[fn] = df
                df['Class'] = an
        all_dataframes = list(dfs_dict.values())
        combined_df = pd.concat(all_dataframes, ignore_index=True)
        all_classes_dataframes.append(combined_df)

    total_df = pd.concat(all_classes_dataframes)
    total_df = total_df.drop(total_df.columns[-1], axis=1)
    cols = list(total_df.columns)
    cols.append(cols.pop(cols.index('Class')))
    total_df = total_df.loc[:, cols]
    total_df['Class'] = le.fit_transform(total_df['Class'])
    total_df.to_csv(os.path.join(dir_path, 'all_classes.csv'), index=False)

def preprocess(file_path):
    f = open(file_path, 'r')
    reader = csv.reader(f, delimiter=',')
    pre_data = list(reader)
    features_id = pre_data[0]
    data = []
    for i in pre_data[1:]:
        int_array = []
        for pl in i[:-1]:
            int_array.append(float(pl))
        int_array.append(int(i[-1]))
        data.append(int_array)
        
    shuffled_data = random.sample(data, len(data))
    labels = []
    for i in shuffled_data:
        labels.append(int(i[len(data[0])-1]))

    for i in range(0, len(shuffled_data)):
        shuffled_data[i].pop()
    train_x = shuffled_data
    train_y = labels

    x_shuf = []
    y_shuf = []
    index_shuf = list(range(len(train_x)))
    shuffle(index_shuf)
    for i in index_shuf:
        x_shuf.append(train_x[i])
        y_shuf.append(train_y[i])

    return x_shuf, y_shuf, features_id

def runClassificationKFold_CV(class_labels, data_path, feature_names, save_dir='plots'):
    np.random.seed(1)
    random.seed(1)

    if not os.path.exists(save_dir):
        os.makedirs(save_dir)

    dataset_fraction = 1.0
    train_x, train_y, features_id = preprocess(data_path)
    model = XGBClassifier()

    cv = StratifiedKFold(n_splits=10)
    tprs = []
    aucs = []
    mean_fpr = np.linspace(0, 1, 100)
    train_times = []
    test_times = []
    importances = []

    accuracies = []
    precisions = []
    recalls = []
    f1_scores = []

    i = 0
    accumulative_cm = np.zeros((4, 4))  
    for train, test in cv.split(train_x, train_y):

        start_train = time.time()
        model = model.fit(np.asarray(train_x)[train], np.asarray(train_y)[train])
        end_train = time.time()
        train_times.append(end_train - start_train)

        start_test = time.time()
        probas_ = model.predict_proba(np.asarray(train_x)[test])
        end_test = time.time()
        test_times.append(end_test - start_test)

        fpr, tpr, thresholds = roc_curve(np.asarray(train_y)[test], probas_[:, 1], pos_label=1)
        
        roc_auc = auc(fpr, tpr)


        if(roc_auc < 0.5):
            roc_auc = 1 - roc_auc
            fpr = [1 - e for e in fpr]
            fpr.sort()
            tpr = [1 - e for e in tpr]
            tpr.sort()

        tprs.append(interp(mean_fpr, fpr, tpr))
        tprs[-1][0] = 0.0
        aucs.append(roc_auc)

        y_pred = model.predict(np.asarray(train_x)[test])
        y_true = np.asarray(train_y)[test]

        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, average='micro')
        recall = recall_score(y_true, y_pred, average='micro')
        f1 = f1_score(y_true, y_pred, average='micro')
        cm = confusion_matrix(y_true, y_pred)

        accuracies.append(accuracy)
        precisions.append(precision)
        recalls.append(recall)
        f1_scores.append(f1)
        accumulative_cm += cm
        i += 1
        
    print("Confusion Matrix: ")
    print(accumulative_cm)
    plt.plot([0, 1], [0, 1], linestyle='--', lw=2, color='r', label='Random Guess', alpha=.8)
    print(aucs)
    cmap = LinearSegmentedColormap.from_list('custom', [(0, 'white'), (0.1, 'lightblue'), (1, 'blue')], N=100)
    plt.figure(figsize=(8, 6))
    sns.heatmap(accumulative_cm, annot=True, fmt="d", cmap=cmap, annot_kws={"size": 20})
    plt.ylabel('True Label', fontsize=20)
    plt.xlabel('Predicted Label', fontsize=20)
    plt.xticks(np.arange(len(class_labels)) + 0.5, class_labels, fontsize=15, rotation=45)
    plt.yticks(np.arange(len(class_labels)) + 0.5, class_labels, fontsize=15, rotation=0)
    plt.savefig("confusion_matrix.png")
    mean_tpr = np.mean(tprs, axis=0)
    mean_tpr[-1] = 1.0
    mean_auc = auc(mean_fpr, mean_tpr)
    print ("Model AUC: " + "{0:.3f}".format(mean_auc))

    if(mean_auc < 0.5):
        mean_auc = 1 - mean_auc
        fpr = [1 - e for e in fpr]
        fpr.sort()
        tpr = [1 - e for e in tpr]
        tpr.sort()
    print ("10-Fold AUC: " + "{0:.3f}".format(mean_auc))
    
    mean_accuracy = np.mean(accuracies)
    mean_precision = np.mean(precisions)
    mean_recall = np.mean(recalls)
    mean_f1_score = np.mean(f1_scores)
    
    print("Mean Accuracy: {:.3f}".format(mean_accuracy))
    print("Mean Precision: {:.3f}".format(mean_precision))
    print("Mean Recall: {:.3f}".format(mean_recall))
    print("Mean F1 Score: {:.3f}".format(mean_f1_score))
    
    feature_importance = model.feature_importances_
    sorted_idx = np.argsort(feature_importance)[::-1]
    top_features = [feature_names[idx] for idx in sorted_idx[:10]]
    top_importances = feature_importance[sorted_idx[:10]]

    plt.figure(figsize=(5, 4))
    plt.barh(top_features, top_importances, color='skyblue')
    plt.xlabel('Importance', fontsize=18)
    plt.ylabel('Features', fontsize=18)
    plt.xticks(fontsize=12)
    plt.yticks(fontsize=12)
    plt.gca().invert_yaxis()
    plt.tight_layout()
    plt.savefig(os.path.join(save_dir, 'FeatureImportance.png'))

    for feature in top_features:
        plt.figure(figsize=(5, 3))
        sns.scatterplot(data=train_x, y=feature, x=train_y, hue=train_y, palette='bright', alpha=0.6) 
        plt.title(f'Distribution of {feature} for each class')
        plt.ylabel(feature)
        plt.xlabel('Class')
        plt.legend(title='Class')
        plt.savefig(os.path.join(save_dir, f'{feature}_dotplot.png'))

    fig = plt.figure()
    ax1 = fig.add_subplot(111)

    std_auc = np.std(aucs)

    plt.plot(mean_fpr, mean_tpr, color='b', label=r'Mean ROC (AUC = %0.2f $\pm$ %0.3f)' % (mean_auc, std_auc), lw=2, alpha=.8)

    std_tpr = np.std(tprs, axis=0)
    tprs_upper = np.minimum(mean_tpr + std_tpr, 1)
    tprs_lower = np.maximum(mean_tpr - std_tpr, 0)
    plt.fill_between(mean_fpr, tprs_lower, tprs_upper, color='grey', alpha=.3, label=r'$\pm$ ROC Std. Dev.')

    ax1.plot([0, 1], [0, 1], 'k--', lw=2, color='orange', label = 'Random Guess')
    ax1.grid(color='black', linestyle='dotted')

    plt.title('Receiver Operating Characteristic (ROC)')
    plt.xlabel('False Positive Rate', fontsize='x-large')
    plt.ylabel('True Positive Rate', fontsize='x-large')
    plt.legend(loc='lower right', fontsize='large')

    plt.setp(ax1.get_xticklabels(), fontsize=14)
    plt.setp(ax1.get_yticklabels(), fontsize=14)
    plt.show()

    return mean_tpr, mean_fpr, mean_auc

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Classification KFold.")
    parser.add_argument("directory_path", help="Input directory containing directories of extracted features.")
    parser.add_argument("class_labels", help="Class label names.")
    args = parser.parse_args()
    mergeDatasets(args.directory_path)
    file_path = os.path.join(args.directory_path, "all_classes.csv")
    df = pd.read_csv(file_path)
    df.to_csv(file_path, index=False)
    x, y, feature_id = preprocess(file_path)
    warnings.filterwarnings(action='ignore', category=DeprecationWarning)
    feature_names = df.columns.tolist()
    tpr, fpr, auc = runClassificationKFold_CV(args.class_labels, file_path, feature_names)