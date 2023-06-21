#!/usr/bin/bash

# meta script that demonstrates a reproducible scenario
# using shadewatcher scripts to demonstrate shadewatcher evaluation

# disable glob (wildcard expansion),
# since the intermediate scripts will perform expansion on their own.
set -f

# location of APT_CASE_* and APT_CASE_*_GADGET directories
data_dir="/syssec_nas0/prov_graphs/gnn/non-prune"
# hyphen-joined replacement of data_dir path
path_dir="${data_dir//\//-}"
path_dir="${path_dir#-}"
# evaluation output directory
test_dir="tests"
mkdir -p $test_dir

# data caching directory
store_dir="shadewatcher_store"

# model name
model="stage2"

# parse an cache shadewatcher representations of ASI JSON graph data
# path example:
#   PATH/EXCEL.EXE/{anomaly,benign}/nd_*/graph.json
python3.6 shadewatcher_parse.py "$data_dir/APT_CASE_1/stage2/*/*/nd_*/graph.json $data_dir/APT_CASE_1_GADGET/stage2/*/*/nd_*/graph.json"


### train on benign dataset for non-gadget
python3.6 shadewatcher_train.py "$store_dir/$path_dir-APT_CASE_1-*-benign-*" $model-non-gadget --gnn_args='--epoch 100' --cut 1.0

# evaluate on anomaly dataset to obtain tn, fp
python3.6 shadewatcher_eval.py "$store_dir/$path_dir-APT_CASE_1-*-anomaly-*" $store_dir/$model-non-gadget $test_dir/$model-non-gadget.csv
# evaluate on benign dataset to obtain fn, tp
python3.6 shadewatcher_eval.py "$store_dir/$path_dir-APT_CASE_1-*-benign-*" $store_dir/$model-non-gadget $test_dir/$model-non-gadget.csv --benign


### train on benign dataset for gadget
python3.6 shadewatcher_train.py "$store_dir/$path_dir-APT_CASE_1_GADGET-*-benign-*" $model-gadget --gnn_args='--epoch 100' --cut 1.0

# evaluate on anomaly dataset to obtain tn, fp
python3.6 shadewatcher_eval.py "$store_dir/$path_dir-APT_CASE_1_GADGET-*-anomaly-*" $store_dir/$model-gadget $test_dir/$model-gadget.csv
# evaluate on benign dataset to obtain fn, tp
python3.6 shadewatcher_eval.py "$store_dir/$path_dir-APT_CASE_1_GADGET-*-benign-*" $store_dir/$model-gadget $test_dir/$model-gadget.csv --benign


# display metrics in tabular form
python3.6 compare_eval.py $test_dir