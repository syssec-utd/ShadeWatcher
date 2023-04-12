"""
Runs Shadewatcher evaluations against a model
"""

import sys
from multiprocessing import Pool

from shadewatcher_common import *
from shadewatcher_train import *
from shadewatcher_eval import *


def _test(i, train_paths, test_paths, model_name, output_dir):
    train(
        train_paths=train_paths,
        model_name=f"{model_name}-prune-{i}",
        prune_threshold=i,
    )
    evaluate(
        test_paths=test_paths,
        model_path=f"{STORE_DIR}/{model_name}-prune-{i}",
        output_file_path=f"{output_dir}/prune{i}.csv",
    )


def test(
    test_paths,
    train_paths,
    model_name,
    output_dir,
    lower=1,
    upper=1,
):
    with Pool(20) as pool:
        pool.starmap(
            _test,
            [
                (
                    i,
                    train_paths,
                    test_paths,
                    model_name,
                    output_dir,
                )
                for i in range(lower, upper)
            ],
        )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("test_paths", help="test_paths from shadewatcher_train.py")
    parser.add_argument("train_paths", help="train_paths from shadewatcher_train.py")
    parser.add_argument("model_name", help="model_name from shadewatcher_train.py")
    parser.add_argument("output_dir", help="output folder for evaluations")
    parser.add_argument(
        "lower", help="lower bound on prune threshold from shadewatcher_train.py", type=int
    )
    parser.add_argument(
        "upper", help="upper bound on prune threshold from shadewatcher_train.py", type=int
    )
    args = parser.parse_args()

    print(args, file=sys.stderr)

    test(
        lower=args.lower,
        upper=args.upper,
        model_name=args.model_name,
        output_dir=args.output_dir,
        test_paths=args.test_paths,
        train_paths=args.train_paths,
    )
