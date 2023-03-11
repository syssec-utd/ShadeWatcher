#!/bin/bash

# For each set of benign and anomaly graphs in a dataset,
# collect metrics per anomaly graph (tested on benign) and use to create a csv.
# then compute avg(fp, tn), max(fp, tn), min(fp, tn)

# set EPOCH for number of epochs

# shell settings
shopt -s globstar
set -e

# expected to be passed paths to multiple dataset folders
# use globstar matching or preferred method to fill these paths.
# for example:
#   /datasets/APT_CASE_1*/stage{1,2,3,4,5}/*
dataset_paths="$@"

for dataset_path in $dataset_paths; do
    # try to parallelize the work
    (
        # for each dataset, concat the benign dataset and train a model
        audit_data=($(./aggregate-dataset.sh $dataset_path/benign))
        audit_name=${audit_data[0]}
        audit_entity_count=${audit_data[1]}

        # init a training sequence
        cd $SHADEWATCHER_DIR/recommend
        python3.6 driver.py --dataset $audit_name --epoch ${EPOCH:-30} --threshold ${THRESHOLD:-1.5} --save_model --show_val --show_test
        cd - 

        # parse each anomaly graph and test against the model
        for anomaly_path in $dataset_path/anomaly; do
            rm -rf $SHADEWATCHER_DIR/data/examples/$audit_name
            python3.6 ./graph-to-audit.py \
                $graph_dir/graph.json \
                -o $SHADEWATCHER_DIR/data/examples/$audit_name

            rm -rf $SHADEWATCHER_DIR/data/encoding/$audit_name

            # parse the audit into nodes and edges
            cd $SHADEWATCHER_DIR/parse
            ./driverbeat -dataset $audit_name -trace ../data/examples/$audit_name -multithread 8 -storefile
            cd - 

            # generate the one-hot encodings for each dataset
            python3.6 ./encoding-parser.py \
                $SHADEWATCHER_DIR/data/encoding/$audit_name/edgefact.txt \
                $SHADEWATCHER_DIR/data/encoding/$audit_name/nodefact.txt \
                -o $AGGREGATE_DIR

            cd $SHADEWATCHER_DIR/recommend
            stats=($(python3.6 driver.py --dataset $audit_name --epoch 0 --show_val --show_test --pretrain 2 --test_size 0.89 2>&1 >/dev/null \
                | tail -n 2 \
                | cut -d' ' -f11))
            cd - 

            # print statistics
            echo "$anomaly_path,${stats[0]},${stats[1]},epoch=$EPOCH threshold=$THRESHOLD"
        done
    ) #& # WIP
done

# wait for all processing jobs to finish
wait