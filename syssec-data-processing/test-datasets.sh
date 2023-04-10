#!/bin/bash -x

# similar to `collect-datasets`,
# but meant for using custom train and test data paths,
# which do not follow the benign/anomaly subdirectory structure
# and may not directly match datasets

# >>> Example:
# 
# EPOCH=30 \
# THRESHOLD=1.5 \
# OUTPUT_DIR=./dataset-logs/additional-eval/ \
# TRAIN_PATHS=/datasets/4-5-graph-formatted \
# TEST_PATHS=$(echo /datasets/APT_CASE_*_GADGET/stage{1,2,3,4,5,345}/*/anomaly/nd*) \
# ./test-datasets.sh 


# shell settings
shopt -s globstar
set -e

# expected to be passed paths to multiple dataset folders
# use globstar matching or preferred method to fill these paths.

for train_path in $TRAIN_PATHS; do
    # try to parallelize the work
    (
        # for each dataset, concat the benign dataset and train a model
        audit_data=($(./aggregate-dataset.sh $train_path | tail -n 2))
        audit_name=${audit_data[0]}
        audit_entity_count=${audit_data[1]}

        # init a training sequence
        cd $SHADEWATCHER_DIR/recommend
        python3.6 driver.py --dataset $audit_name --epoch ${EPOCH:=30} --threshold ${THRESHOLD:=1.5} --save_model --show_val --show_test
        cd - 

        # outputfile
        OUTPUT_FILE=${OUTPUT_DIR:="dataset-logs"}/$audit_name-summary.csv

        # start a csv file
        echo "instance,true_negative,false_positive,hyper parameters" > $OUTPUT_FILE

        # parse each anomaly graph and test against the model
        for anomaly_path in $TEST_PATHS; do
            rm -rf $SHADEWATCHER_DIR/data/examples/$audit_name
            python3.6 ./graph-to-audit.py \
                $anomaly_path/graph.json \
                -o $SHADEWATCHER_DIR/data/examples/$audit_name

            rm -rf $SHADEWATCHER_DIR/data/encoding/$audit_name

            # parse the audit into nodes and edges
            cd $SHADEWATCHER_DIR/parse
            ./driverbeat -dataset $audit_name -trace ../data/examples/$audit_name -multithread 8 -storefile
            cd - 

            # generate the one-hot encodings for each dataset
            # NOTE: we are kind of assuming that there is only one edgefact here for single graph instance
            python3.6 ./encoding-parser.py \
                $SHADEWATCHER_DIR/data/encoding/$audit_name/edgefact_0.txt \
                $SHADEWATCHER_DIR/data/encoding/$audit_name/nodefact.txt \
                -o $SHADEWATCHER_DIR/data/encoding/$audit_name $ANOMALY_ENCODER_ARGS

            # pad the anomaly dataset to match the entity2id.txt size of the benign training set
            test_entity_count=$(head -n 1 $SHADEWATCHER_DIR/data/encoding/$audit_name/entity2id.txt)
            max_entity_count=$(( audit_entity_count > test_entity_count ? audit_entity_count : test_entity_count ))

            # adjust the anomaly dataset to reach the max dimensions
            echo "" >> $SHADEWATCHER_DIR/data/encoding/$audit_name/entity2id.txt
            seq $test_entity_count $(expr $max_entity_count - 1) | awk '{print 0 " " $1}' >> $SHADEWATCHER_DIR/data/encoding/$audit_name/entity2id.txt
            sed -i "1s/.*/$max_entity_count/" $SHADEWATCHER_DIR/data/encoding/$audit_name/entity2id.txt

            # run test comparison against existing benign model
            cd $SHADEWATCHER_DIR/recommend
            stats=($(python3.6 driver.py --dataset $audit_name --epoch 0 --show_val --show_test --pretrain 2 --test_size 0.89 2>&1 >/dev/null \
                | tail -n 2 \
                | cut -d' ' -f11))
            cd - 
            # consolidate statistics
            true_negative=${stats[0]}
            false_positive=${stats[1]}

            # dump to record file
            echo "$anomaly_path,$true_negative,$false_positive,epoch=$EPOCH threshold=$THRESHOLD" | sed 's/\x1B\[[0-9;]\{1,\}[A-Za-z]//g' >> $OUTPUT_FILE
        done
    ) & # WIP
done

# wait for all processing jobs to finish
wait