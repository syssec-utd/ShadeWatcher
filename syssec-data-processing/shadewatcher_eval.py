"""
Runs Shadewatcher evaluations against a model
"""

import subprocess
import random
import sys


from shadewatcher_common import *


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


def evaluate(test_paths, model_path, output_file_path, token):
    # copy the model into the Shadewatcher embeddings directory
    subprocess.call(["rm", "-rf", f"{EMBEDDING_PATH}/{token}"])
    subprocess.call(["mkdir", "-p", f"{EMBEDDING_PATH}/{token}"])
    subprocess.call(["cp", "-R", f"{model_path}/.", f"{EMBEDDING_PATH}/{token}"])

    with open(output_file_path, "a", encoding="utf-8") as output_file:
        print(
            "instance,true_negative,false_positive,hyper_parameters",
            file=output_file,
        )

    for test_path in test_paths:
        if not os.path.exists(test_path):
            print(test_path, "is not a valid path.")
            continue  # skip past already converted graphs

        # copy the encodings from the test instance into the Shadewatcher encodings directory
        subprocess.call(["rm", "-rf", f"{ENCODING_PATH}/{token}"])
        subprocess.call(["mkdir", "-p", f"{ENCODING_PATH}/{token}"])
        subprocess.call(["cp", "-R", f"{test_path}/.", f"{ENCODING_PATH}/{token}"])

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
                str(0.89),
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
        tn, fp = (
            int(val[val.rindex(":") + 2 : val.rindex("\x1b")])
            for val in test_output.stderr.decode().splitlines()[-2:]
        )
        print(f"[fp: {fp}] [tn: {tn}]")

        # save the results the a file
        with open(output_file_path, "a", encoding="utf-8") as output_file:
            print(
                f"{stringify_path(test_path)},{tn},{fp}",
                file=output_file,
            )

    # cleanup Shadewatcher resources
    subprocess.call(["rm", "-rf", f"{EMBEDDING_PATH}/{token}"])
    subprocess.call(["rm", "-rf", f"{ENCODING_PATH}/{token}"])


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "test_paths", help="space deliited set of paths to test graph encodings"
    )
    parser.add_argument("model_path", help="path to the pretrained shadewatcher model")
    parser.add_argument("output_file_path", help="")
    parser.add_argument(
        "--token", help="unique identifier for this run (for collecting data)"
    )
    args = parser.parse_args()

    print(args, file=sys.stderr)

    test_paths = args.test_paths.split()
    model_path = args.model_path
    output_file_path = args.output_file_path
    token = args.token
    if token is None:
        token = random.randrange(5000, 5000000)
        print(f"token: {token}")

    evaluate(test_paths, model_path, output_file_path, token)
