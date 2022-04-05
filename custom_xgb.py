import xgboost as xgb
import numpy as np
import pandas as pd
import time
import os
import sys
import requests

if sys.version_info[0] >= 3:
    from urllib.request import urlretrieve  # pylint: disable=import-error,no-name-in-module
else:
    from urllib import urlretrieve  # pylint: disable=import-error,no-name-in-module

DATASET_DIR="./data/"

def download_file(url):
    local_filename = DATASET_DIR + url.split('/')[-1]
    with requests.get(url, stream=True) as r:
        r.raise_for_status()
        with open(local_filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=2**20):
                if chunk:
                    f.write(chunk)
    return local_filename

def load_higgs(nrows_train, nrows_test, dtype):
    """
    Higgs dataset from UCI machine learning repository (
    https://archive.ics.uci.edu/ml/datasets/HIGGS).
    TaskType:binclass
    NumberOfFeatures:28
    NumberOfInstances:11M
    """
    if not os.path.isfile(DATASET_DIR + "HIGGS.csv.gz"):
        print("Loading data set...")
        download_file("https://archive.ics.uci.edu/ml/machine-learning-databases/00280/HIGGS.csv.gz")

    print("Reading data set...")
    data = pd.read_csv(DATASET_DIR + "HIGGS.csv.gz", delimiter=",", header=None, compression="gzip", dtype=dtype, nrows=nrows_train+nrows_test)
    print("Pre-processing data set...")

    data = data[list(data.columns[1:])+list(data.columns[0:1])]
    n_features = data.shape[1]-1
    train_data = np.ascontiguousarray(data.values[:nrows_train,:n_features], dtype=dtype)
    train_label = np.ascontiguousarray(data.values[:nrows_train,n_features], dtype=dtype)
    test_data = np.ascontiguousarray(data.values[nrows_train:nrows_train+nrows_test,:n_features], dtype=dtype)
    test_label = np.ascontiguousarray(data.values[nrows_train:nrows_train+nrows_test,n_features], dtype=dtype)
    n_classes = len(np.unique(train_label))
    return train_data, train_label, test_data, test_label, n_classes


def load_higgs1m(dtype):
    return load_higgs(1000000, 500000, dtype)

train_data, train_label, test_data, test_label, n_classes = load_higgs1m(np.float32)

xgb_params = {
    'verbosity':                    0,
    'alpha':                        0.9,
    'max_bin':                      256,
    'scale_pos_weight':             2,
    'learning_rate':                0.1,
    'subsample':                    1,
    'reg_lambda':                   1,
    "min_child_weight":             0,
    'max_depth':                    8,
    'max_leaves':                   2**8,
    'objective':                    'binary:logistic',
    'predictor':                    'cpu_predictor',
    'tree_method':                  'hist',
    'n_estimators':                 1000
}
dtrain = xgb.DMatrix(train_data, train_label)  
model_xgb = xgb.train(xgb_params, dtrain, xgb_params['n_estimators'])

dtest = xgb.DMatrix(test_data)
start = time.time()
result_predict_xgb_test = model_xgb.predict(dtest)
inf_time = time.time() - start
print("Stock XGBoost Inference Time: ", inf_time)

# Convert the XGBoost model to a oneDAL model
import daal4py as d4p

daal_model = d4p.get_gbt_model_from_xgboost(model_xgb)
start = time.time()
daal_prediction = d4p.gbt_classification_prediction(nClasses = n_classes, resultsToEvaluate="computeClassLabels", fptype='float').compute(test_data, daal_model)
inf_daal_time = time.time() - start
print("Daal4py XGBoost: ", inf_daal_time)
