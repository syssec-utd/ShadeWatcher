"""
Prune a training set before it is fed into Shadewatcher by
building a frequency database of the edges and removing entries 
below a given frequency threshold
"""

import argparse
import sys
from collections import defaultdict
from shadewatcher_common import read_factfile

trace_cache = dict()
fact_cache = dict()


def fetch_map(path):
    if path in fact_cache:
        return fact_cache[path]

    facts = read_factfile(path)
    fact_cache[path] = facts
    return facts


def trace(node_id, encoding_path):
    if node_id in trace_cache:  # return already seen nodes
        return trace_cache[node_id]

    # 1. use entity2id mappings to get node hash
    id_to_hash = {
        hot: nhash
        for nhash, hot in map(str.split, fetch_map(f"{encoding_path}/entity2id.txt"))
    }

    # 2. find enumeration of file, proc, and or socket from nodefacts
    hash_to_enum = dict(map(str.split, fetch_map(f"{encoding_path}/nodefact.txt")))

    # 3. use enumerations to read file, proc, or socket in order to get the name of the node (file, executable, ip addr, ...)
    node_hash = id_to_hash[node_id]
    node_enum = hash_to_enum[node_hash]
    if node_enum == 1:  # proc
        proc_map = {
            l[0]: l[2]
            for l in map(str.split, fetch_map(f"{encoding_path}/procfact.txt"))
        }
        name = proc_map[node_hash]

    elif node_enum == 2:  # file
        file_map = {
            l[0]: l[1]
            for l in map(str.split, fetch_map(f"{encoding_path}/filefact.txt"))
        }
        name = file_map[node_hash]

    elif node_enum == 3:  # socket
        socket_map = {
            l[0]: l[1] for l in map(str.split, fe(f"{encoding_path}/socketfact.txt"))
        }
        name = socket_map[node_hash]

    else:
        raise Exception(f"unhandled node enumerations: [{node_enum}]")

    # 4. map the node to its name for its represenation in the frequency database
    trace_cache[node_id] = name
    return name


def prune(encoding_path, threshold):
    frequency_db = defaultdict(int)

    with open(f"{encoding_path}/train2id.txt") as train_file:
        line_count, *lines = train_file.read().splitlines()

        for line in lines:
            node1_id, relation_id, node2_id = line.split()
            node1_name = trace(node1_id, encoding_path=encoding_path)
            node2_name = trace(node2_id, encoding_path=encoding_path)

            frequency_db[f"{node1_name} {relation_id} {node2_name}"] += 1

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
    parser.add_argument(
        "--threshold",
        default=2,
        type=int,
        help="the frequency threshold for training entries before they are dropped",
    )
    parser.add_argument(
        "encoding_path",
        help="path to the directory of the training encodings (usually <SHADEWATCHER_DIR>/data/encoding/...)",
    )
    args = parser.parse_args()

    print(args, file=sys.stderr)

    encoding_path = args.encoding_path
    threshold = args.threshold

    prune(encoding_path, threshold)