#!/bin/bash

# shortcut script to run the 'process-dataset.sh' in parallel

shopt -s globstar

OUTPUT_DIR=${OUTPUT_DIR:-"dataset-logs"}

mkdir -p $OUTPUT_DIR

# expected to be passed paths to multiple dataset folders
# use globstar matching or preferred method to fill these paths.
# for example:
#   /datasets/APT_CASE_1*/stage{1,2,3,4,5}/*
for f in "$@"
do
    EPOCH=${EPOCH:-100} ./process-dataset.sh $f &> "$OUTPUT_DIR/$(sed 's/\/\+/-/g' <<< $f | sed 's/^-\+//').log" &
done

# wait for all processing jobs to finish
wait

# print short info about what we want.
rm -f $OUTPUT_DIR/summary.log
for f in $OUTPUT_DIR/*
do
    echo -e ">>> $f\n\n$(tail -n 2 $f)\n" | tee -a $OUTPUT_DIR/summary.log
done

echo "results posted to $OUTPUT_DIR/summary.log"
