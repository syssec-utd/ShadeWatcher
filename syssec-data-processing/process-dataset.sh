#!/bin/bash -x

# Given the path to a {benign/anomaly} graph dataset,
# concatenates each subset into a new shadewatcher audit and prepares them for recommendation.
# Uses the benign dataset to train the GNN model, and then tests the model on the anomaly dataset (where passing is assumed to be necessary)
#
# Heres how you might run the script:
#
# EPOCH=100 ./process-dataset.sh /files/EXCEL.EXE
#
# once the script finishes,
# you will see test metrics at the end of the output such as:
#
# ...
# 2023-03-01 22:56:56,661 |   INFO | metrics: tn_b, value: 415
# 2023-03-01 22:56:56,661 |   INFO | metrics: fp_b, value: 2362

shopt -s globstar

set -e

ANOMALY_NAME="anomaly"
BENIGN_NAME="benign"

if [ -z ${1+x} ] || [ -z ${SHADEWATCHER_DIR+x} ];
then
    echo "define vars:
        arg 1 : DATASET_PATH        path to directory with {$BENIGN_NAME,$ANOMALY_NAME} subdirectories with [GRAPH_ID]/graph.json
        env : SHADEWATCHER_DIR      absolute path of ShadeWatcher installation"
    exit
fi

# arg 1 is DATASET_PATH
DATASET_PATH=$1

if [ ! -d "$DATASET_PATH/$BENIGN_NAME" ] || [ ! -d "$DATASET_PATH/$ANOMALY_NAME" ];
then
    echo "missing one of {$BENIGN_NAME,$ANOMALY_NAME} subdirectories of DATASET_PATH"
    exit
fi

# unique audit name
AUDIT=$(sed 's/\/\+/-/g' <<< $DATASET_PATH | sed 's/^-\+//')

# use the second cli arg or default to an aggregates folder inside the original dataset
AGGREGATE_DIR=${2:-"/tmp/shadewatcher-aggregates/$AUDIT"}
echo Aggregate Directory: $AGGREGATE_DIR

# make the directory exist.
rm -rf $AGGREGATE_DIR
mkdir -p $AGGREGATE_DIR

for graph_type in $BENIGN_NAME $ANOMALY_NAME
do
    mkdir -p $AGGREGATE_DIR/$graph_type
done

# temoporary audit to reuse
SCRIPT_DIR="$PWD"

# concact benign and anomaly datasets respectively
for graph_type in $BENIGN_NAME $ANOMALY_NAME
do
    # nd_ prefix is to avoid the zip files which got searched before
    for f in $DATASET_PATH/$graph_type/nd*
    do
        rm -rf $SHADEWATCHER_DIR/data/examples/$AUDIT
        python3.6 $SCRIPT_DIR/graph-to-audit.py $f/graph.json -o $SHADEWATCHER_DIR/data/examples/$AUDIT
        rm -rf $SHADEWATCHER_DIR/data/encoding/$AUDIT

        cd $SHADEWATCHER_DIR/parse
        ./driverbeat -dataset $AUDIT -trace ../data/examples/$AUDIT -multithread 8 -storefile

        # capture all edgefact files that may get generated
        for edgefact_path in $SHADEWATCHER_DIR/data/encoding/$AUDIT/edgefact_*
        do
            tail --lines=+2 $edgefact_path >> $AGGREGATE_DIR/$graph_type/edgefact.txt
        done
        tail --lines=+2 $SHADEWATCHER_DIR/data/encoding/$AUDIT/nodefact.txt >> $AGGREGATE_DIR/$graph_type/nodefact.txt
    done
done


# fix the fileline counts for benign and anomaly
for graph_type in $BENIGN_NAME $ANOMALY_NAME
do
    cd $AGGREGATE_DIR/$graph_type
    wc -l edgefact.txt | awk '{print $1}' | cat - edgefact.txt > /tmp/out && mv /tmp/out edgefact.txt
    wc -l nodefact.txt | awk '{print $1}' | cat - nodefact.txt > /tmp/out && mv /tmp/out nodefact.txt
done

# generate the one-hot encodings for each dataset
for graph_type in $BENIGN_NAME $ANOMALY_NAME
do
    python3.6 $SCRIPT_DIR/encoding-parser.py $AGGREGATE_DIR/$graph_type/edgefact.txt $AGGREGATE_DIR/$graph_type/nodefact.txt -o $AGGREGATE_DIR/$graph_type
done

# pad the anomaly dataset to match the entity2id.txt size of the benign training set
train_entity_count=$(head -n 1 $AGGREGATE_DIR/$BENIGN_NAME/entity2id.txt)
test_entity_count=$(head -n 1 $AGGREGATE_DIR/$ANOMALY_NAME/entity2id.txt)
max_entity_count=$(( train_entity_count > test_entity_count ? train_entity_count : test_entity_count ))

# adjust the anomaly dataset to reach the max dimensions
echo "" >> $AGGREGATE_DIR/$ANOMALY_NAME/entity2id.txt
seq $test_entity_count $(expr $max_entity_count - 1) | awk '{print 0 " " $1}' >> $AGGREGATE_DIR/$ANOMALY_NAME/entity2id.txt
sed -i "1s/.*/$max_entity_count/" $AGGREGATE_DIR/$ANOMALY_NAME/entity2id.txt

# adjust the benign dataset to reach the max dimensions
echo "" >> $AGGREGATE_DIR/$BENIGN_NAME/entity2id.txt
seq $train_entity_count $(expr $max_entity_count - 1) | awk '{print 0 " " $1}' >> $AGGREGATE_DIR/$BENIGN_NAME/entity2id.txt
sed -i "1s/.*/$max_entity_count/" $AGGREGATE_DIR/$BENIGN_NAME/entity2id.txt

# train the benign model
rm -rf $SHADEWATCHER_DIR/data/encoding/$AUDIT
cp -R $AGGREGATE_DIR/$BENIGN_NAME $SHADEWATCHER_DIR/data/encoding/$AUDIT

# default 50 epochs but u can set EPOCH
cd $SHADEWATCHER_DIR/recommend
python3.6 driver.py --dataset $AUDIT --epoch ${EPOCH:-50} --save_model --show_val --show_test

# test on the anomaly model
rm -rf $SHADEWATCHER_DIR/data/encoding/$AUDIT
cp -R $AGGREGATE_DIR/$ANOMALY_NAME $SHADEWATCHER_DIR/data/encoding/$AUDIT

cd $SHADEWATCHER_DIR/recommend
python3.6 driver.py --dataset $AUDIT --epoch 0 --show_val --show_test --pretrain 2 --test_size 0.89
