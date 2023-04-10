"""
Prune a training set before it is fed into Shadewatcher by
building a frequency database of the edges and removing entries 
below a given frequency threshold
"""

import argparse
import glob
import sys
from collections import defaultdict

def prune(encoding_path, threshold):
    frequency_db = defaultdict(int)

    with open(f"{encoding_path}/train2id.txt") as train_file:
        line_count, *lines = train_file.read().splitlines()

        for line in lines:
            node1_id, relation_id, node2_id = line.split()
            frequency_db[f"{node1_id} {relation_id} {node2_id}"] += 1
        
    for key, freq in frequency_db.items():
        print(f"{key} :: {freq}")

    with open(f"{encoding_path}/train2id.txt", "w") as train_file:
        train_file.write(line_count + "\n")

        for key, freq in frequency_db.items():
            if freq >= threshold:
                for _ in range(freq):
                    train_file.write(key + "\n")

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--threshold", default=2, type=int, help="the frequency threshold for training entries before they are dropped")
    parser.add_argument("encoding_path", help="path to the directory of the training encodings (usually <SHADEWATCHER_DIR>/data/encoding/...)")
    args = parser.parse_args()

    print(args, file=sys.stderr)

    encoding_path = args.encoding_path
    threshold = args.threshold

    prune(encoding_path, threshold)