import argparse
import lightgbm as lgb
import time
import daal4py as d4p
from bench_utils import *
from lightgbm import LGBMClassifier

N_PERF_RUNS = 5
DTYPE=np.float32

lgb_params = {
############# USE FOR HIGGS1M AND AIRLINE DATASET
    "reg_alpha": 0.9,
    "max_bin": 256,
    "scale_pos_weight": 2,
    "learning_rate": 0.1,
    "subsample": 1,
    "reg_lambda": 1,
    "min_child_weight": 0,
    "max_depth": 8,
    "max_leaves": 256,
    "n_estimators": 1000,
    "objective": "binary"
    
############# USE FOR MSRANK DATASET
#     "max_bin": 256,
#     "learning_rate": 0.3,
#     "subsample": 1,
#     "reg_lambda": 2,
#     "min_child_weight": 1,
#     "min_split_loss": 0.1,
#     "max_depth": 8,
#     "max_leaves": 256,
#     "n_estimators": 200,
#     "objective": "multiclass"
}

def lgb_fit():
    global model_lgb, daal_model
    model_lgb = lgb.train(lgb_params, lgb.Dataset(x_train, y_train), 1000)
    daal_model = d4p.get_gbt_model_from_lightgbm(model_lgb)


def lgb_stock_predict():
    prediction = model_lgb.predict(x_test)
    
def lgb_daal_predict():
    d4p.gbt_classification_prediction(nClasses = n_classes, resultsToEvaluate="computeClassLabels", fptype='float').compute(x_test, daal_model)


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

#     if n_classes == -1:
#         lgb_params['objective'] = 'regression'
#     elif n_classes == 2:
#         lgb_params['objective'] = 'binary'
    if lgb_params['objective'] == 'multiclass':
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
    measure(lgb_fit,                   "XGBOOST training            ", N_PERF_RUNS)
    measure(lgb_stock_predict, "LGB Stock predict (test data)", N_PERF_RUNS)
    measure(lgb_daal_predict,  "LGB Daal predict (test data) ", N_PERF_RUNS)
   

if __name__ == '__main__':
    main()
