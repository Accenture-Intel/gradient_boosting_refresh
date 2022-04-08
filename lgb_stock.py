import argparse
import lightgbm as lgb
import time
from bench_utils import *

N_PERF_RUNS = 5
DTYPE=np.float32

lgb_params = {
#     'boosting_type':     'gbdt',
#     'learning_rate':     0.01,
#     'verbosity':         0,
#     'num_leaves':        50, 
#     'max_depth':         25
    'learning_rate' : 0.1
    'num_leaves' : 255
    'num_trees' : 500
    'num_threads' : 16
    'min_data_in_leaf' : 0
    'min_sum_hessian_in_leaf' : 100
}

def xbg_fit():
    global daal_model, model_lgb
    model_lgb = lgb.train(lgb_params, lgb.Dataset(x_train, y_train), 100)

def xgb_stock_predict():
    global daal_prediction_train
    result_predict_xgb_test = model_lgb.predict(x_test)

def xgb_daal_predict():
    global daal_prediction_test
    daal_prediction_test = d4p.gbt_classification_prediction(nClasses = n_classes, resultsToEvaluate="computeClassLabels", fptype='float').compute(x_test, daal_model)


def load_dataset(dataset):
    global x_train, y_train, x_test, y_test, n_classes

    try:
        os.mkdir(DATASET_DIR)
    except:
        pass

    datasets_dict = {
        'higgs1m': load_higgs1m,
        'msrank-10k': load_msrank_10k,
        'airline-ohe':load_airline_one_hot
    }

    x_train, y_train, x_test, y_test, n_classes = datasets_dict[dataset](DTYPE)
    print("n_classes: ", n_classes)

    if n_classes == -1:
        lgb_params['objective'] = 'regression'
    elif n_classes == 2:
        lgb_params['objective'] = 'binary'
    else:
        lgb_params['objective'] = 'multiclass'
        lgb_params['num_class'] = n_classes

def parse_args():
    global N_PERF_RUNS
    parser = argparse.ArgumentParser()
#     parser.add_argument('--n_iter', required=False, type=int, default=1000)
    parser.add_argument('--n_runs', default=N_PERF_RUNS, required=False, type=int)
    parser.add_argument('--dataset', choices=['higgs1m', "airline-ohe", "msrank-10k"],
            metavar='stage', required=True)

    args = parser.parse_args()
    N_PERF_RUNS = args.n_runs

    load_dataset(args.dataset)


def main():
    parse_args()

    print("Running ...")
    measure(xbg_fit,                   "XGBOOST training            ", N_PERF_RUNS)
    measure(xgb_stock_predict, "XGBOOST Stock predict (test data)", N_PERF_RUNS)
#     measure(xgb_daal_predict,  "XGBOOST Daal predict (test data) ", N_PERF_RUNS)
   

if __name__ == '__main__':
    main()