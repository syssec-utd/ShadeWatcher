#!/bin/bash

# shortcut script to run the 'process-dataset.sh' in parallel

shopt -s globstar

OUTPUT_DIR=${OUTPUT_DIR:-dataset-logs}

mkdir -p ./$OUTPUT_DIR

# expected to be passed paths to multiple dataset folders
# use globstar matching or preferred method to fill these paths.
# for example:
#   /datasets/APT_CASE_1*/stage{1,2,3,4,5}/*
for f in "$@"
do
        EPOCH=${EPOCH:-100} ./process-dataset.sh $f &> "./$OUTPUT_DIR/$(sed 's/\/\+/-/g' <<< $f | sed 's/^-\+//').log" &
done
# wait for all processing jobs to finish
wait
