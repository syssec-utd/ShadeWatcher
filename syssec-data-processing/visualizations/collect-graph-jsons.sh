#!/bin/bash -x

shopt -s globstar

if [ -z ${1+x} ] || [ -z ${2+x} ];
then
    echo "pass args: (1) DATASET_PATH, (2) STORAGE_PATH"
    exit
fi

DATASET_PATH="$1"
STORAGE_PATH="$2"

AUDIT=temp-audit

CONVERT_SW_TO_GRAPH=./graph-parser.py

for f in $DATASET_PATH/nd*
do
    rm -rf $SHADEWATCHER_DIR/data/examples/$AUDIT
    # base scripts should be stored in the parent directory
    python3.6 ../graph_to_audit.py $f/graph.json -o $SHADEWATCHER_DIR/data/examples/$AUDIT
    rm -rf $SHADEWATCHER_DIR/data/encoding/$AUDIT

    cd $SHADEWATCHER_DIR/parse
    ./driverbeat -dataset $AUDIT -trace ../data/examples/$AUDIT -multithread 8 -storefile
    cd -

    # nest file paths again to separate files
    file_path="$STORAGE_PATH/$f"
    mkdir -p $file_path

    # collect BGs
    python3.6 $CONVERT_SW_TO_GRAPH \
        $SHADEWATCHER_DIR/data/encoding/$AUDIT/inter_bg_edges.txt \
        $SHADEWATCHER_DIR/data/encoding/$AUDIT/inter_bg_nodes.txt \
        -g BG \
    > $file_path/BG.json

    # collect KGs
    # may need to capture more than just edgefact_0 if dataset large
    python3.6 $CONVERT_SW_TO_GRAPH \
        $SHADEWATCHER_DIR/data/encoding/$AUDIT/edgefact_0.txt \
        $SHADEWATCHER_DIR/data/encoding/$AUDIT/nodefact.txt \
        -g KG \
    > $file_path/KG.json

    # collect PGs
    # TODO
done
