import argparse
import lightgbm as lgb
import time
from bench_utils import *

N_PERF_RUNS = 5
DTYPE=np.float32

lgb_params = {
#     "reg-alpha": 0.9,
#     "max-bin": 256,
#     "scale-pos-weight": 2,
#     "learning-rate": 0.1,
#     "subsample": 1,
#     "reg-lambda": 1,
#     "min-child-weight": 0,
#     "max-depth": 8,
#     "max-leaves": 256,
#     "n-estimators": 1000,
#     "objective": "binary"
    
    'learning_rate': 0.3, 
    'max_depth': 8, 
    'colsample_bytree': 1, 
    'colsample_bynode': 1, 
    'reg_lambda': 1.0, 
    'reg_alpha': 0.9, 
    'scale_pos_weight': 2.0, 
    'max_leaves': 256, 
    'max_bin': 256, 
    'objective': 'multiclass', 
    'seed': 12345,
    "n_estimators": 200,
}


def lgb_fit():
    global model_lgb
    model_lgb = lgb.train(lgb_params, lgb.Dataset(x_train, y_train))


def lgb_stock_predict():
    prediction = model_lgb.predict(x_test)
    

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

    datasets_objectives = {
        'higgs1m': "binary",
        'msrank-10k': "multiclass",
        'airline-ohe': "binary"
    }

    lgb_params["objective"] = datasets_objectives[dataset]

    x_train, y_train, x_test, y_test, n_classes = datasets_dict[dataset](DTYPE)
    print("n_classes: ", n_classes)

    if lgb_params['objective'] == 'multiclass':
        lgb_params['num_class'] = n_classes

def parse_args():
    global N_PERF_RUNS
    parser = argparse.ArgumentParser()
    parser.add_argument('--n_iter', required=False, type=int, default=200)
    parser.add_argument('--n_runs', default=N_PERF_RUNS, required=False, type=int)
    parser.add_argument('--dataset', choices=['higgs1m', "airline-ohe", "msrank-10k"],
            metavar='stage', required=True)

    args = parser.parse_args()
    lgb_params["n_estimators"] = args.n_iter
    N_PERF_RUNS = args.n_runs

    load_dataset(args.dataset)


def main():
    parse_args()

    print("Running ...")
    measure(lgb_fit,                   "LightGBM training            ", N_PERF_RUNS)
    measure(lgb_stock_predict, "LightGBM Stock predict (test data)", N_PERF_RUNS)
   

if __name__ == '__main__':
    main()
