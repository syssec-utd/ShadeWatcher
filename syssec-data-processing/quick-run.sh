#!/bin/bash -x
set -e

# Parses any PATH or URL to a syssec graph.json and performs audit conversion,
# ShadeWatcher parsing, one-hot edge & node encoding, and then runs the 
# gnn trainer on the data

if [ -z ${AUDIT+x} ] || [ -z ${SHADEWATCHER_DIR+x} ];
then 
    echo "define env vars:
            AUDIT               name to store the dataset in shadewatcher
            SHADEWATCHER_DIR    installation path of shadewatcher repo"
    exit
fi

if [ -z ${GRAPH_URL+x} ] && [ -z ${GRAPH_PATH+x} ];
then 
    echo "define env vars: GRAPH_URL or GRAPH_PATH (both for a graph.json)"
    exit
elif [ -z ${GRAPH_PATH+x} ];
then
    GRAPH_PATH=./graph.json
    curl $GRAPH_URL -o $GRAPH_PATH
fi

# don't let all of your examples be removed
rm -rf $SHADEWATCHER_DIR/data/examples/$AUDIT
python3.6 graph-to-audit.py $GRAPH_PATH -o $SHADEWATCHER_DIR/data/examples/$AUDIT
cd $SHADEWATCHER_DIR/parse
rm -rf $SHADEWATCHER_DIR/data/encoding/$AUDIT
./driverbeat -dataset $AUDIT -trace ../data/examples/$AUDIT -multithread 8 -storefile
cd -
python3.6 encoding-parser.py $SHADEWATCHER_DIR/data/encoding/$AUDIT/edgefact_0.txt $SHADEWATCHER_DIR/data/encoding/$AUDIT/nodefact.txt -o $SHADEWATCHER_DIR/data/encoding/$AUDIT
cd $SHADEWATCHER_DIR/recommend
python3.6 driver.py --dataset $AUDIT $REC_ARGS
cd -
