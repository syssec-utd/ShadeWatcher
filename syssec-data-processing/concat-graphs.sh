#!/bin/bash -x
set -e

# Takes a directory and path to dump concatenated dataset (converted to auditbeat)
#
# iterates over all directories found within the DATASET_PATH
# and looks for a "graph.json" in each one to parse using shadewatcher
# and dumps the parser output int a single edge and node file respectively.

shopt -s globstar

if [ -z ${CONCAT_DIR+x} ] || [ -z ${SHADEWATCHER_DIR+x} ];
then 
    echo "define env vars:
    CONCAT_DIR          the path to dump edgefact.txt and nodefact.txt
    SHADEWATCHER_DIR    the path of shadewatcher installation (repo)"
    exit
fi

if [ -z ${DATASET_PATH+x} ];
then 
    echo "define env vars: DATASET_PATH"
    exit
fi

mkdir -p $CONCAT_DIR
rm -ri $CONCAT_DIR
mkdir -p $CONCAT_DIR

for f in $DATASET_PATH/nd*
do
    # reuse the same audit to parse all of the graphs,
    # then concat all of edge and node entries into a shared directory
    AUDIT="reused-audit"

    rm -rf $SHADEWATCHER_DIR/data/examples/$AUDIT
    python3.6 graph-to-audit.py $f/graph.json -o $SHADEWATCHER_DIR/data/examples/$AUDIT
    cd $SHADEWATCHER_DIR/parse
    rm -rf $SHADEWATCHER_DIR/data/encoding/$AUDIT
    ./driverbeat -dataset $AUDIT -trace ../data/examples/$AUDIT -multithread 8 -storefile
    cd - 
    cd $SHADEWATCHER_DIR/data/encoding/$AUDIT
    tail --lines=+2 edgefact_0.txt >> $CONCAT_DIR/edgefact_0.txt
    tail --lines=+2 nodefact.txt >> $CONCAT_DIR/nodefact.txt
    cd -
done

# add the line numbers to the tops of the files
cd $CONCAT_DIR
wc -l edgefact_0.txt | awk '{print $1}' | cat - edgefact_0.txt > /tmp/out && mv /tmp/out edgefact_0.txt
wc -l nodefact.txt | awk '{print $1}' | cat - nodefact.txt > /tmp/out && mv /tmp/out nodefact.txt

