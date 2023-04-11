"""
Train a model from a set of graphs
"""

import sys
import os
import subprocess
from collections import defaultdict
from multiprocessing import Pool

from shadewatcher_common import *
import encoding_parser
import encoding_pruner


def grab_facts(encoding_dir):
    """collect fact files"""
    fact_dict = dict()
    for fact_path in (
        EDGEFACT_FILE,
        NODEFACT_FILE,
        PROCFACT_FILE,
        FILEFACT_FILE,
        SOCKETFACT_FILE,
    ):
        fact_dict[fact_path] = read_factfile(encoding_dir + "/" + fact_path)

    return fact_dict


def train(train_paths, model_name, prune_threshold, gnn_args=""):
    """Train a model using a list of paths to directories containing graph filefacts and encodings"""
    # optimize collection of node and edge data from training paths
    fact_dict = defaultdict(list)
    with Pool(20) as pool:
        for slave_facts_dict in pool.map(grab_facts, train_paths):
            for key, facts in slave_facts_dict.items():
                fact_dict[key].extend(facts)

    # create the aggregation directory using the name of the model
    os.makedirs(STORE_DIR + "/" + model_name)

    # write the aggregated facts to files in the new model directory
    for fact_path, facts in fact_dict.items():
        with open(
            STORE_DIR + "/" + model_name + "/" + fact_path, "w+", encoding="utf-8"
        ) as edgefact_file:
            fact_lines = "\n".join(facts)
            print(f"{len(facts)}\n{fact_lines}", file=edgefact_file)

    # run the one-hot encoder on the aggregated dataset
    encoding_parser.encode(
        edgefile_path=STORE_DIR + "/" + model_name + "/" + EDGEFACT_FILE,
        nodefile_path=STORE_DIR + "/" + model_name + "/" + NODEFACT_FILE,
        output_path=STORE_DIR + "/" + model_name,
        randomize_edges=False,
    )
    # copy the files to shadewatcher
    subprocess.call(["cp", "-R", STORE_DIR + "/" + model_name, ENCODING_PATH])
    # prune the encodings in the shadewatcher folder
    encoding_pruner.prune(
        encoding_dir=ENCODING_PATH + "/" + model_name,
        threshold=prune_threshold,
    )

    subprocess.check_output(
        [
            "python3.6",
            "driver.py",
            "--dataset",
            model_name,
            "--save_model",
            *gnn_args.split(),
        ],
        cwd=GNN_PATH,
    )

    # copy embedding files back to model folder
    subprocess.call(["cp", "-R", f"{EMBEDDING_PATH}/{model_name}", STORE_DIR])


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "train_globs",
        help="space delimited set of glob paths to the encoding directories of training data",
    )
    parser.add_argument(
        "model_name",
        help="identifier for this model",
    )
    parser.add_argument(
        "--gnn_args",
        help="parameters to the shadewatcher model trainer",
        default="--epoch 30 --threshold 1.5 --show_val --show_test",
    )
    parser.add_argument(
        "--prune_threshold",
        help="threshold to pass to the pruning step",
        type=int,
        default=1,
    )
    args = parser.parse_args()

    print(args, file=sys.stderr)

    train(
        train_paths=paths_from_globs(args.train_globs.split()),
        model_name=args.model_name,
        gnn_args=args.gnn_args,
        prune_threshold=args.prune_threshold,
    )
