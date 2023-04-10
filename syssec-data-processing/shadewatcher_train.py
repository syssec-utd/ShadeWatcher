"""
Train a model from a set of graphs
"""

import sys
import os
import subprocess
from multiprocessing import Pool

from shadewatcher_common import *
import encoding_parser


def train(train_paths, model_name, gnn_args):
    # aggregate all the file's edgefacts and nodefacts together
    def grab_facts(encoding_dir):
        with open(
            encoding_dir + "/" + EDGEFACT_FILE, encoding="utf-8"
        ) as edgefact_file:
            _, *edges = edgefact_file.read().splitlines()

        with open(
            encoding_dir + "/" + NODEFACT_FILE, encoding="utf-8"
        ) as nodefact_file:
            _, *nodes = nodefact_file.read().splitlines()

        return (edges, nodes)

    # optimize collection of node and edge data from training paths
    all_edges, all_nodes = [], []
    with Pool(20) as pool:
        for edges, nodes in pool.map(grab_facts, train_paths):
            all_edges.extend(edges)
            all_nodes.extend(nodes)

    # create the aggregation directory using the name of the model
    os.makedirs(STORE_DIR + "/" + model_name)
    with open(
        STORE_DIR + "/" + model_name + "/" + EDGEFACT_FILE, "w+", encoding="utf-8"
    ) as edgefact_file:
        print(
            len(all_edges),
            file=edgefact_file,
        )
        print(
            "\n".join(all_edges),
            file=edgefact_file,
        )
    with open(
        STORE_DIR + "/" + model_name + "/" + NODEFACT_FILE, "w+", encoding="utf-8"
    ) as nodefact_file:
        print(
            len(all_nodes),
            file=nodefact_file,
        )
        print(
            "\n".join(all_nodes),
            file=nodefact_file,
        )

    # run the one-hot encoder on the aggregate dataset
    encoding_parser.encode(
        edgefile_path=STORE_DIR + "/" + model_name + "/" + EDGEFACT_FILE,
        nodefile_path=STORE_DIR + "/" + model_name + "/" + NODEFACT_FILE,
        output_path=STORE_DIR + "/" + model_name,
        randomize_edges=False,
    )

    # copy the files to shadewatcher
    subprocess.call(["cp", "-R", STORE_DIR + "/" + model_name, ENCODING_PATH])

    subprocess.check_output(
        ["python3.6", "driver.py", "--dataset", model_name, *gnn_args.split()],
        cwd=GNN_PATH,
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "train_paths",
        help="space delimited set of paths to the encoding directories of training data",
    )
    parser.add_argument(
        "model_name",
        help="identifier for this model",
    )
    parser.add_argument(
        "--gnn_args", help="parameters to the shadewatcher model trainer"
    )
    args = parser.parse_args()

    print(args, file=sys.stderr)

    train_paths = args.train_paths.split()
    model_name = args.model_name
    gnn_args = args.gnn_args

    train(train_paths, model_name, gnn_args)
