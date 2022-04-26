# XGBoost Benchmark on Intel Ice Lake

<h4 align="center">Be sure to :star: this repository so you can keep up to date on any updates!</h4>
<p align="center">
 <img src ='https://forthebadge.com/images/badges/made-with-python.svg'>
 <img src ='https://forthebadge.com/images/badges/open-source.svg'>
</p>



## 📑 Table of Contents 📑
 - [Description](https://github.com/Accenture-Intel/xgboost_refresh/blob/main/README.md#description)
 - [Accenture - Intel Partnerhsip](https://github.com/Accenture-Intel/xgboost_refresh/blob/main/README.md#accenture---intel-partnership)
 - [Benchmark Details](https://github.com/Accenture-Intel/xgboost_refresh/blob/main/README.md#benchmark-details)
 - [Environment Setup & Code Deployment](https://github.com/Accenture-Intel/xgboost_refresh/blob/main/README.md#environment-setup--code-deployment)
 - [Results](https://github.com/Accenture-Intel/xgboost_refresh/blob/main/README.md#results)
 - [Appendix](https://github.com/Accenture-Intel/xgboost_refresh/blob/main/README.md#appendix)

## Description
As part of an Accenture-Intel partnership aimed at accelerating client transformation and driving co-innovation through cutting-edge technology and inudstry experience, we are showcasing Intel's Ice Lake capabilities through an opitimized XGBoost framework. Through this repository, we can share our workloads and findings when running on the instances we are benchmarking. We invite you to explore our workloads and build upon them using the Intel's platform.

## Accenture - Intel Partnership
What do you get when you combine a company that “delivers on the promise of technology and human ingenuity” and another that “shapes the future of technology”?
Accelerated co-innovation; capabilities alignment: the right experts at the right time; and consistent client outcomes thanks to trained Intel solution architects at Accenture. 

Renowned as titans in the high-tech space, Accenture and Intel share a single-minded focus to accelerate client transformation and drive co-innovation. The Accenture and Intel joint partnership bring together cutting-edge technology and unrivaled market & industry expertise allowing for significant expansion into the following portfolio offerings (towers): Multicloud, Network, Analytics and AI, and Digital Workspace. Each tower provides generates significant value not only to both Accenture and Intel, but also to their clients. These towers show the co-dependency Accenture and Intel have, with Intel bringing optimized AI offerings using its Xeon and adjacent technologies and Accenture bringing its Applied Intelligence Platform (AIP) & Solutions.AI offerings for intelligent revenue growth and advanced consumer engagement, for example. Together, Accenture and Intel push industries beyond their limits, providing consistent outcomes and evangelizing success for the benefit of their clients.

To learn more about this partnership, follow this <a href="https://www.accenture.com/us-en/services/high-tech/alliance-intel/" target="_blank">link</a>.

## Benchmark Details
### Description
We used the XGBoost algorithm for classification training and inferencing benchmarks. XGBoost is a gradient boosting algorithm that uses decision trees as its “weak” predictorss. In our benchmark we used the a synthetic Boston Housing Dataset which is then scaled to different sizes.

### Purpose
The purpose of the XGBoost benchmark is to showcase its significant capabilities on Intel's latest Ice Lake as seen through the m6i instance. Our objectives were as follows: 1) Reach same performance at a cheaper price relative to previous generations, or 2) Reach better performance at the same price relative to previous generations.

### Parameters
Below is an visualization detailing the parameters and environment. This experiment utilizes the following software environment setup:
<div align="center">
 
| Machine Learning Solution | Software Specifications                                   |
| ------------------------- | ----------------------------------------------------------|
| ML Application            | Classification                                            |
| ML Model                  | XGBoost                                                   |
| ML Dataset                | Boston Housing (synthetic)                                |
| Hardware Targets          | CPUs                                                      |
| AMI(s)                    | Deep Learning AMI (Ubuntu 18.04) Version 57.0             |
| AWS EC2 Instance(s)       | Intel Ice Lake m6i.xlarge, Intel Cascade Lake m5n.xlarge |

</div>
 
## Environment Setup & Code Deployment
Below are sets of instructions to follow to run the XGBoost scripts. The instructions will take you from start to finish, showing you how to setup the DLAMI, environment, library installs, and code deployment.

### Intel Ice Lake m6i.2xlarge ![image](http://badges.github.io/stability-badges/dist/stable.svg)
Please follow the the instructions given below for setting up the environment. The guide will walk you through the process of setting up your system to run the model on the m6i EC2 instance.
#### Launching the Deep Learning AMI (DLAMI)
To launch the DLAMI, go to your AWS EC2 page and click 'Launch instances'.
![image](https://user-images.githubusercontent.com/91902558/157768843-a3a73db5-9e01-45c2-ac0b-285fa11d6c46.png)

In the searchbar, search 'Deep Learning AMI' and select AWS Marketplace. From the options, select the **Deep Learning AMI (Ubuntu 18.04) Version 57.0** option and press continue on the prompt.
![image](https://user-images.githubusercontent.com/91902558/157768743-dc568c48-5cc6-4951-b81d-ba24d6f6db55.png)

After pressing continue on the prompt, select the **m6i** instance from the _All inistance families_ drop-down as recommended for this AMI and configure the instance details as needed. Click on the **Review and Launch** and **Launch** buttons at the bottom right corner of your screen, and follow the steps for key pairs.
![image](https://user-images.githubusercontent.com/91902558/157769116-01fc2a0a-4846-479f-b65f-2fe75df3468e.png)

Once all of that is complete, you can launch & connect to the Deep Learning AMI (Ubuntu 18.04) Version 57.0

#### Cloning into Repo for Install and Code Deployment
To access the scripts and install requirements from one place, follow the steps below.

1. Obtain python package of XGBoost. There are a few options:
    - Build XGBoost from sources manually:
        ```
        git clone --recursive https://github.com/dmlc/xgboost
        cd xgboost
        make -j8
        cd python-package
        python setup.py install
        cd ..
        ```
    - Or download the latest available version from pip:
        ```
        pip install xgboost
        ```
    - More details are available [here](https://xgboost.readthedocs.io/en/latest/build.html)

2. Resolve dependencies on other python packages. For now it has dependencies on further packages: requests, scikit-learn, pandas, numpy. You can easily download them through pip:
    ```
    pip install requests scikit-learn pandas
    ```
3. Run benchmarks with specified parameters:
    ```
    cd tests/benchmark/hist_method
    python xgboost_bench.py  --dataset <dataset> \
                             --hw <platform>     \
                             --n_iter <n_iter>   \
                             --n_runs <n_runs>   \
                             --log <enable_log>
    ```

The benchmark downloads required datasets from the Internet automatically, you don't need to worry about it.

_Note: For available parameters, please refer to the [Avaialbe Parameters](https://github.com/Accenture-Intel/xgboost_refresh/blob/main/README.md#appendix-available-parameters) section in the Appendix.

## 📊 Results 📊
The comparison shown in the results is meant to showcase how Intel's optimized XGBoost yields a more favorable training time compared to the stock XGBoost package. These results will be updated as updated versions of Intel's optimized XGBoost are released as well as when newer Intel EC2 instances are released.

### Performance
The metric displayed here is accounts for the time taken to run each benchmark on multiple batch sizes, i.e. the throughput. As can be seen, the Intel-optimized version of XGBoost (daal4py) outperforms the vanilla version of XGBoost both on the old gen m5n (Cascade Lake) and new gen m6i (Ice Lake). The lower the time, the faster the throughput.
<div align="center">
 <img width="480" alt="image" src="https://user-images.githubusercontent.com/91902558/164530221-115a66be-d745-4c97-8bf4-0577e852cd9c.png">
</div>

The metric displayed here accounts for both the performance and cost to run each benchmark, i.e. the price-performance. As can be seen, the Intel-optimized version of XGBoost (daal4py) outperforms the vanilla version of XGBoost both on the old gen m5n (Cascade Lake) and new gen m6i (Ice Lake). The base for the benchmark here was the vanilla version of XGBoost on the m5n.xlarge instance. The higher the multiple, the better the price-performance.
<div align="center">
 <img width="435" alt="image" src="https://user-images.githubusercontent.com/91902558/164529704-c6758a91-951d-4ff2-b774-cc0ab217bbc7.png">
</div>

## Appendix
### Available parameters:
* **dataset**    - dataset to use in benchmark. Possible values: *"higgs1m", "airline-ohe", "msrank-10k"* [Required].
* **platform**   - specify platform for computation. Possible values: *cpu, gpu*. [Default=cpu].
* **n_iter**     - amount of boosting iterations. Possible values: *integer > 0*. [Default=1000].
* **n_runs**     - number of training and prediction measurements to obtain stable performance results. Possible values: *integer > 0*. [Default=5].
* **enable_log** - if False - no additional debug info ("silent"=1). If True ("verbosity"=3) it prints execution time by kernels. Possible values: *True, False*. [Default=False].

## Used By

This project is used by the following companies:
![ACN-Intel_logo](https://user-images.githubusercontent.com/91902558/157770015-ea092843-c4ee-4fb4-8207-31c0368d718b.png)



