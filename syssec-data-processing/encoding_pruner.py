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


def _fetch_map(path):
    if path in fact_cache:
        return fact_cache[path]

    facts = read_factfile(path)
    fact_cache[path] = facts
    return facts


def trace(node_id, encoding_dir):
    if node_id in trace_cache:  # return already seen nodes
        return trace_cache[node_id]

    # 1. use entity2id mappings to get node hash
    id_to_hash = {
        hot: nhash
        for nhash, hot in map(str.split, _fetch_map(f"{encoding_dir}/entity2id.txt"))
    }

    # 2. find enumeration of file, proc, and or socket from nodefacts
    hash_to_enum = dict(map(str.split, _fetch_map(f"{encoding_dir}/nodefact.txt")))

    # 3. use enumerations to read file, proc, or socket in order to get the name of the node (file, executable, ip addr, ...)
    node_hash = id_to_hash[node_id]
    node_enum = int(hash_to_enum[node_hash])  # dont miss int type
    if node_enum == 1:  # proc
        proc_map = {
            l[0]: l[2]
            for l in map(str.split, _fetch_map(f"{encoding_dir}/procfact.txt"))
        }
        name = proc_map[node_hash]

    elif node_enum == 2:  # file
        file_map = {
            l[0]: l[1]
            for l in map(str.split, _fetch_map(f"{encoding_dir}/filefact.txt"))
        }
        name = file_map[node_hash]

    elif node_enum == 3:  # socket
        socket_map = {
            l[0]: l[1]
            for l in map(str.split, _fetch_map(f"{encoding_dir}/socketfact.txt"))
        }
        name = socket_map[node_hash]

    else:
        raise Exception(f"unhandled node enumerations: [{node_enum}]")

    # 4. map the node to its name for its represenation in the frequency database
    trace_cache[node_id] = name
    return name


def prune(encoding_dir, threshold=1):
    """Create a frequency database on the entries in a training encodings file,
    and drop entries whose occurence in the database is below a set threshold
    """
    frequency_db = defaultdict(list)

    # parse the training encodings
    with open(f"{encoding_dir}/train2id.txt", encoding="utf-8") as train_file:
        line_count, *lines = train_file.read().splitlines()

        for line in lines:
            node1_id, node2_id, relation_id = line.split()
            node1_name = trace(node1_id, encoding_dir=encoding_dir)
            node2_name = trace(node2_id, encoding_dir=encoding_dir)

            # group edges by their named node relations
            frequency_db[f"{node1_name} {node2_name} {relation_id}"].append(
                f"{node1_id} {node2_id} {relation_id}"
            )

    for key, freq_set in frequency_db.items():
        print(f"{key} :: {freq_set}")

    # write the new training encodings back to the file
    with open(f"{encoding_dir}/train2id.txt", "w", encoding="utf-8") as train_file:
        train_file.write(line_count + "\n")

        for key, freq_set in frequency_db.items():
            if len(freq_set) >= threshold:
                for edge in freq_set:
                    train_file.write(edge + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--threshold",
        default=2,
        type=int,
        help="the frequency threshold for training entries before they are dropped",
    )
    parser.add_argument(
        "encoding_dir",
        help="path to the directory of the training encodings (usually <SHADEWATCHER_DIR>/data/encoding/...)",
    )
    args = parser.parse_args()

    print(args, file=sys.stderr)

    prune(
        encoding_dir=args.encoding_dir,
        threshold=args.threshold,
    )
