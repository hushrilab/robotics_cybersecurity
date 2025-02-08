import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
import os
import sys
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
r = 10
def list_of_strings(arg):
    return arg.split(',')

def PrintColored(string, color):
    print(colored(string, color))


def mergeDatasets(dir_path):
    global open_world_label 

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
        all_dataframes = list(dfs_dict.values())
        combined_df = pd.concat(all_dataframes, ignore_index=True)
        all_classes_dataframes.append(combined_df)

    total_df = pd.concat(all_classes_dataframes)
    cols = list(total_df.columns)
    cols.append(cols.pop(cols.index('Class')))
    total_df = total_df.loc[:, cols]
    total_df['Class'] = le.fit_transform(total_df['Class'])
    class_mapping = dict(zip(le.classes_, le.transform(le.classes_)))
    open_world_label = class_mapping.get('z_open_world')
    print("Assigned labels to each class:", class_mapping)
    total_df.to_csv(os.path.join(dir_path, 'all_classes.csv'), index=False)

def preprocess(file_path, open_world_label, open_world_mode):
    df = pd.read_csv(file_path)
    df.fillna(np.nan, inplace=True) 
    data = df.values.tolist()
    features_id = df.columns.tolist()

    if open_world_mode:
        known_data = [row for row in data if int(row[-1]) != open_world_label]
        open_world_data = [row for row in data if int(row[-1]) == open_world_label]
        random.shuffle(known_data)
        random.shuffle(open_world_data)

        known_labels = [int(row[-1]) for row in known_data]
        for row in known_data:
            row.pop()

        open_world_labels = [int(row[-1]) for row in open_world_data]
        for row in open_world_data:
            row.pop()
        return known_data, known_labels, open_world_data, open_world_labels, features_id
    else:
        shuffled_data = random.sample(data, len(data))
        labels = [int(row[-1]) for row in shuffled_data]
        for row in shuffled_data:
            row.pop()

        return shuffled_data, labels, None, None, features_id

def score_func(ground_truths, predictions, class_num):
    tp, wp, fp, p, n = 0, 0, 0, 0, 0
    for truth, prediction in zip(ground_truths, predictions):
        print(truth)
        print(prediction)
        if truth != class_num:
            p += 1
        else:
            n += 1
        if prediction != class_num:
            if truth == prediction:
                tp += 1
            else:
                if truth != class_num:
                    wp += 1
                else:
                    fp += 1
    print(tp)
    print(wp)
    print(fp)
    print(p)
    print(n)
    try:
        r_precision = tp * n / (tp * n + wp * n + r * p * fp)
    except ZeroDivisionError:
        r_precision = 0.0

    return r_precision

def runClassificationKFold_CV(class_labels, data_path, feature_names, open_world_mode, save_dir='plots'):
    np.random.seed(1)
    random.seed(1)

    if not os.path.exists(save_dir):
        os.makedirs(save_dir)

    train_x, train_y, open_world_x, open_world_y, features_id = preprocess(data_path, open_world_label, open_world_mode)
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
    r_precisions = []

    i = 0
    num_classes = len(class_labels) + (1 if open_world_mode else 0)  
    accumulative_cm = np.zeros((num_classes, num_classes))  
    for i, (train, test) in enumerate(cv.split(train_x, train_y)):
        if open_world_mode:
            start_idx = i * 10
            end_idx = start_idx + 10
            open_world_x_chunk = open_world_x[start_idx:end_idx]
            open_world_y_chunk = open_world_y[start_idx:end_idx]

        start_train = time.time()
        model = model.fit(np.asarray(train_x)[train], np.asarray(train_y)[train])
        end_train = time.time()
        train_times.append(end_train - start_train)

        start_test = time.time()
        probas_ = model.predict_proba(np.asarray(train_x)[test])
        end_test = time.time()
        test_times.append(end_test - start_test)

        y_pred = model.predict(np.asarray(train_x)[test])
        y_true = np.asarray(train_y)[test]

        if open_world_mode:
            max_probas = np.max(probas_, axis=1)
            y_pred = np.where(max_probas < 0.99, open_world_label, y_pred)

        fpr, tpr, thresholds = roc_curve(np.asarray(train_y)[test], probas_[:, 1], pos_label=1)
        
        roc_auc = auc(fpr, tpr)

        if roc_auc < 0.5:
            roc_auc = 1 - roc_auc
            fpr = [1 - e for e in fpr]
            fpr.sort()
            tpr = [1 - e for e in tpr]
            tpr.sort()

        tprs.append(interp(mean_fpr, fpr, tpr))
        tprs[-1][0] = 0.0
        aucs.append(roc_auc)

        if open_world_mode and open_world_x is not None and open_world_y is not None:
            combined_x_test = np.concatenate((np.asarray(train_x)[test], open_world_x_chunk), axis=0)
            combined_y_test = np.concatenate((np.asarray(train_y)[test], open_world_y_chunk), axis=0)
            
            y_pred_combined = model.predict(combined_x_test)
            probas_combined = model.predict_proba(combined_x_test)

            if open_world_mode:
                max_probas_combined = np.max(probas_combined, axis=1)
                y_pred_combined = np.where(max_probas_combined < 0.5, open_world_label, y_pred_combined)
            combined_cm = confusion_matrix(combined_y_test, y_pred_combined, labels=list(range(num_classes)))
            accumulative_cm += combined_cm

        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, average='micro')
        recall = recall_score(y_true, y_pred, average='micro')
        f1 = f1_score(y_true, y_pred, average='micro')
        r_precision = score_func(combined_y_test, y_pred_combined, len(class_labels))
        cm = confusion_matrix(y_true, y_pred, labels=list(range(num_classes)))

        accuracies.append(accuracy)
        precisions.append(precision)
        recalls.append(recall)
        f1_scores.append(f1)
        r_precisions.append(r_precision)

        accumulative_cm += cm
        i += 1

    accumulative_cm = accumulative_cm.astype(int)
    print("Confusion Matrix: ")
    print(accumulative_cm)
    
    plt.figure(figsize=(8, 6))
    cmap = LinearSegmentedColormap.from_list('custom', [(0, 'white'), (0.1, 'lightblue'), (1, 'blue')], N=100)
    sns.heatmap(accumulative_cm, annot=True, fmt="d", cmap=cmap, annot_kws={"size": 20})
    plt.ylabel('True Label', fontsize=20)
    plt.xlabel('Predicted Label', fontsize=20)
    plt.xticks(np.arange(len(class_labels) + (1 if open_world_mode else 0)) + 0.5, class_labels + (['Unknown'] if open_world_mode else []), fontsize=15, rotation=45)
    plt.yticks(np.arange(len(class_labels) + (1 if open_world_mode else 0)) + 0.5, class_labels + (['Unknown'] if open_world_mode else []), fontsize=15, rotation=0)
    plt.tight_layout()
    plt.savefig("confusion_matrix.png")

    mean_tpr = np.mean(tprs, axis=0)
    mean_tpr[-1] = 1.0
    mean_auc = auc(mean_fpr, mean_tpr)
    print("Model AUC: " + "{0:.3f}".format(mean_auc))

    if mean_auc < 0.5:
        mean_auc = 1 - mean_auc
        fpr = [1 - e for e in fpr]
        fpr.sort()
        tpr = [1 - e for e in tpr]
        tpr.sort()
    print("10-Fold AUC: " + "{0:.3f}".format(mean_auc))
    
    mean_accuracy = np.mean(accuracies)
    mean_precision = np.mean(precisions)
    mean_recall = np.mean(recalls)
    mean_f1_score = np.mean(f1_scores)
    mean_r_precision = np.mean(r_precisions)
    
    print("Mean Accuracy: {:.3f}".format(mean_accuracy))
    print("Mean Precision: {:.3f}".format(mean_precision))
    print("Mean Recall: {:.3f}".format(mean_recall))
    print("Mean F1 Score: {:.3f}".format(mean_f1_score))
    print("R_Precision Score: {: .3f}".format(mean_r_precision))
    
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

    df_train_x = pd.DataFrame(train_x, columns=feature_names)
    df_train_x['Class'] = train_y

    for feature in top_features:
        plt.figure(figsize=(5, 3))
        sns.scatterplot(data=df_train_x, y=feature, x="Class", hue="Class", palette='bright', alpha=0.6) 
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

    ax1.plot([0, 1], [0, 1], 'k--', lw=2, color='orange', label='Random Guess')
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
    parser.add_argument("class_labels", type=list_of_strings, help="Class label names.")
    parser.add_argument("--open_world_mode", action='store_true', help="Enable open-world mode.")
    args = parser.parse_args()
    mergeDatasets(args.directory_path)
    file_path = os.path.join(args.directory_path, "all_classes.csv")
    df = pd.read_csv(file_path)
    df.to_csv(file_path, index=False)
    warnings.filterwarnings(action='ignore', category=DeprecationWarning)
    feature_names = df.columns.tolist()
    feature_names.pop()
    tpr, fpr, auc = runClassificationKFold_CV(args.class_labels, file_path, feature_names, args.open_world_mode)
