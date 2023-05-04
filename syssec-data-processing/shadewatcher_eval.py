"""
Runs Shadewatcher evaluations against a model
"""

import subprocess
import random
import sys
import os

from shadewatcher_common import *
import encoding_parser


def pad_file(train_entity_path, test_entity_path):
    """Pad anomaly dataset to match the entitiy dimensions of a pretrained model"""
    train_entity_count = len(read_factfile(train_entity_path))
    test_entity_count = len(read_factfile(test_entity_path))

    diff = train_entity_count - test_entity_count
    if diff > 0:
        with open(test_entity_path, "a", encoding="utf-8") as entity_file:
            print("", file=entity_file)
            for i in range(diff):
                print(f"0 {i + test_entity_count}", file=entity_file)

        with open(test_entity_path, encoding="utf-8") as entity_file:
            lines = entity_file.read().splitlines()

        with open(test_entity_path, "w", encoding="utf-8") as entity_file:
            print(len(lines) - 1, file=entity_file)
            print("\n".join(lines[1:]), file=entity_file)


def evaluate(
    test_paths,
    model_path,
    output_file_path,
    randomize=False,
    benign=True,
    token=random.randrange(10000, 10000000),
):
    """Sequentially run each test graph through the model by copying the encodings into the
    correct Shadewatcher directory and running the gnn code with parameter:
        - 0 epoch           no need to train the model on evaluation data
        - 0.99999 test_size closest you can get to 1.0 to make
                            Shadewatcher use 100% of the input data as validation data

    To help differentiate these instances so that evaluations can be run in parallel,
    utilize a token in the filepaths within Shadewatcher
    """
    # copy the model into the Shadewatcher embeddings directory
    subprocess.call(["rm", "-rf", f"{EMBEDDING_PATH}/{token}"])
    subprocess.call(["mkdir", "-p", f"{EMBEDDING_PATH}/{token}"])
    subprocess.call(["cp", "-R", f"{model_path}/.", f"{EMBEDDING_PATH}/{token}"])

    # write header to the file if it doesnt exists
    if not os.path.exists(output_file_path):
        with open(output_file_path, "a", encoding="utf-8") as output_file:
            print("instance,tn,fp,tp,fn", file=output_file)

    issue_count = 0

    for test_path in test_paths:
        if not os.path.exists(test_path):
            print(test_path, "is not a valid path.", file=sys.stderr)
            continue  # skip past already converted graphs

        print(f"{test_path} >> ", end="", file=sys.stderr)

        # copy the encodings from the test instance into the Shadewatcher encodings directory
        subprocess.call(["rm", "-rf", f"{ENCODING_PATH}/{token}"])
        subprocess.call(["mkdir", "-p", f"{ENCODING_PATH}/{token}"])
        subprocess.call(["cp", "-R", f"{test_path}/.", f"{ENCODING_PATH}/{token}"])

        if randomize:  # reparse the encodings with the randomized flag
            # run the one-hot encoder
            encoding_parser.encode(
                edgefile_path=f"{ENCODING_PATH}/{token}/{EDGEFACT_FILE}",
                nodefile_path=f"{ENCODING_PATH}/{token}/{NODEFACT_FILE}",
                output_path=f"{ENCODING_PATH}/{token}",
                randomize_edges=True,
            )

        # pad the test instance to be the size of the model
        pad_file(
            train_entity_path=f"{model_path}/{ENTITY_FILE}",
            test_entity_path=f"{ENCODING_PATH}/{token}/{ENTITY_FILE}",
        )

        # run the test instance against the model
        test_output = subprocess.run(
            [
                "python3.6",
                "driver.py",
                "--dataset",
                str(token),
                "--epoch",
                str(0),
                "--show_val",
                "--show_test",
                "--pretrain",
                str(2),
                "--test_size",
                str(0.99999),
                "--val_size",
                str(0.0),
            ],
            cwd=GNN_PATH,
            stderr=subprocess.PIPE,
            check=False,
        )

        # example lines from output:
        #
        # ...
        # 2021-11-24 19:43:41,785 |   INFO | metrics: tn_b, value: 55
        # 2021-11-24 19:43:41,785 |   INFO | metrics: fp_b, value: 7
        try:
            true_negative, false_positive = (
                int(val[val.rindex(":") + 2 : val.rindex("\x1b")])
                for val in test_output.stderr.decode().splitlines()[-2:]
            )

            if benign:
                tn, fp, tp, fn = true_negative, false_positive, 0, 0
            else:
                tn, fp, tp, fn = 0, 0, false_positive, true_negative

            print(f"[fp: {fp}] [tn: {tn}] [tp: {tp}] [fn: {fn}]", file=sys.stderr)

            # save the results the a file
            with open(output_file_path, "a", encoding="utf-8") as output_file:
                print(
                    f"{stringify_path(test_path)},{tn},{fp},{tp},{fn}",
                    file=output_file,
                )
        except Exception as ex:
            if "LOG_ERR" in os.environ:
                print("Error:", ex, test_output.stderr.decode(), sep="\n", file=sys.stderr)
            else:
                print("fail...", file=sys.stderr)
            issue_count += 1

    print(f"finished writing results to {output_file_path}", file=sys.stderr)
    print(f"{issue_count} graphs failed to evaluate.", file=sys.stderr)

    # cleanup Shadewatcher resources
    subprocess.call(["rm", "-rf", f"{EMBEDDING_PATH}/{token}"])
    subprocess.call(["rm", "-rf", f"{ENCODING_PATH}/{token}"])


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "test_globs", help="space deliited set of glob paths to test graph encodings"
    )
    parser.add_argument("model_path", help="path to the pretrained shadewatcher model")
    parser.add_argument("output_file_path", help="file path to write csv results")
    parser.add_argument(
        "-r",
        "--randomize",
        action="store_true",
        help="randomize the edge relations",
    )
    parser.add_argument(
        "--token", help="unique identifier for this run (for collecting data)"
    )
    parser.add_argument(
        "--count",
        help="number of graphs to sample from the provided list",
        type=int,
        default=0,
    )
    parser.add_argument(
        "--benign",
        help="mark this test set as benign (swap the profile on [tp/fn] to [fp/tn])",
        action="store_true",
    )
    args = parser.parse_args()

    print(args, file=sys.stderr)

    glob_paths = paths_from_globs(args.test_globs.split())
    if args.count > 0:
        test_paths = random.choices(glob_paths, k=args.count)
    else:
        test_paths = glob_paths

    if args.token is not None:
        evaluate(
            test_paths=test_paths,
            model_path=args.model_path,
            output_file_path=args.output_file_path,
            randomize=args.randomize,
            benign=args.benign,
            token=args.token,
        )
    else:
        evaluate(
            test_paths=test_paths,
            model_path=args.model_path,
            output_file_path=args.output_file_path,
            randomize=args.randomize,
            benign=args.benign,
        )
