#!/bin/bash -x

# This script has the specialized job of parsing a graph dataset (i.e. FLDR/[GRAPH_IDS*]/graph.json)
# and aggregating them into a single audit.
# 'quick-run.sh' is more suited for running the full ShadeWatcher pipeline on a single graph instance.

# Note:
#   returns the audit name and entity count,
#   you could parse this data like so:
#
#       audit_data=($(./aggregate-dataset.sh $dataset_path/benign | tail -n 2))
#       audit_name=${audit_data[0]}
#       audit_entity_count=${audit_data[1]}

# >>> Example:
# ./aggregate-dataset.sh /datasets/APT_CASE_1/stage3/445/benign


# shell settings
shopt -s globstar
set -e

if [ -z ${1+x} ] || [ -z ${SHADEWATCHER_DIR+x} ];
then
    echo "usage:
        argv[1]                     absolute path to a subdirectories having [GRAPH_ID]/graph.json
        env : SHADEWATCHER_DIR      absolute path of ShadeWatcher installation
        env : AUDIT                 audit-name for the aggregated dataset"
    exit
fi

# arg 1 is DATASET_PATH
GRAPH_COLLECTION_DIR=$1

# generate unique audit name
# replace all folders with '-'
AUDIT=${AUDIT:-$(sed 's/\/\+/-/g' <<< $GRAPH_COLLECTION_DIR | sed 's/^-\+//')}

# use the second cli arg or default to an aggregates folder inside the original dataset
AGGREGATE_DIR=${2:-"/tmp/shadewatcher-aggregates/$AUDIT"}

# make the directory exist.
rm -rf $AGGREGATE_DIR
mkdir -p $AGGREGATE_DIR

# nd_ prefix is to avoid the zip files which got searched before
for graph_dir in $GRAPH_COLLECTION_DIR/nd*; do
    # clean the audit directory and convert the graph to auditbeat
    rm -rf $SHADEWATCHER_DIR/data/examples/$AUDIT
    python3.6 ./graph_to_audit.py $graph_dir/graph.json -o $SHADEWATCHER_DIR/data/examples/$AUDIT
    rm -rf $SHADEWATCHER_DIR/data/encoding/$AUDIT

    # parse the audit into nodes and edges
    cd $SHADEWATCHER_DIR/parse
    ./driverbeat -dataset $AUDIT -trace ../data/examples/$AUDIT -multithread 8 -storefile 

    # aggregate the nodes and edges into the aggregates
    # NOTE: capture all edgefact files that may get generated
    for edgefact_path in $SHADEWATCHER_DIR/data/encoding/$AUDIT/edgefact_*; do
        tail --lines=+2 $edgefact_path >> $AGGREGATE_DIR/edgefact.txt
    done
    tail --lines=+2 $SHADEWATCHER_DIR/data/encoding/$AUDIT/nodefact.txt >> $AGGREGATE_DIR/nodefact.txt
    cd - 
done

# fix the fileline counts for benign and anomaly
wc -l $AGGREGATE_DIR/nodefact.txt | awk '{print $1}' | cat - $AGGREGATE_DIR/nodefact.txt > /tmp/out && mv /tmp/out $AGGREGATE_DIR/nodefact.txt
wc -l $AGGREGATE_DIR/edgefact.txt | awk '{print $1}' | cat - $AGGREGATE_DIR/edgefact.txt > /tmp/out && mv /tmp/out $AGGREGATE_DIR/edgefact.txt

# NOTE:
#   more responsibilities than aggregating.
#   also performs encoding parser, which may want to be left separate

# generate the one-hot encodings for each dataset
python3.6 ./encoding_parser.py $AGGREGATE_DIR/edgefact.txt $AGGREGATE_DIR/nodefact.txt -o $AGGREGATE_DIR

# copy the output back to the audit in shadewatcher
rm -rf $SHADEWATCHER_DIR/data/encoding/$AUDIT
cp -R $AGGREGATE_DIR $SHADEWATCHER_DIR/data/encoding/$AUDIT

# return the name of the audit for calling script
echo $AUDIT
# return the entity count
echo $(head -n 1 $SHADEWATCHER_DIR/data/encoding/$AUDIT/entity2id.txt)