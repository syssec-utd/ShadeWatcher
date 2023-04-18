"""
Runs Shadewatcher evaluations against a model
"""

from shadewatcher_common import *
from shadewatcher_train import *
from shadewatcher_eval import *


def _test(threshold, train_paths, test_paths, model_name, gnn_args, output_dir):
    case_name = f"{model_name}-prune-{threshold}-{gnn_args.replace(' ', '')}"

    train(
        train_paths=train_paths,
        model_name=case_name,
        prune_threshold=threshold,
        gnn_args=gnn_args,
    )
    evaluate(
        test_paths=test_paths,
        model_path=f"{STORE_DIR}/{case_name}",
        output_file_path=f"{output_dir}/{case_name}.csv",
    )


def linear_test(
    test_paths,
    train_paths,
    model_name,
    output_dir,
    gnn_args,
    lower=1,
    upper=1,
):
    for i in range(lower, upper + 1):
        _test(
            threshold=i,
            train_paths=train_paths,
            test_paths=test_paths,
            model_name=model_name,
            output_dir=output_dir,
            gnn_args=gnn_args,
        )


def exp_test(
    test_paths,
    train_paths,
    model_name,
    output_dir,
    gnn_args,
    lower=1,
    upper=1,
):
    i = lower if lower >= 1 else 1
    while i <= upper:
        _test(
            threshold=i,
            train_paths=train_paths,
            test_paths=test_paths,
            model_name=model_name,
            output_dir=output_dir,
            gnn_args=gnn_args,
        )
        i *= 2


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser()
    parser.add_argument("test_paths", help="test_paths from shadewatcher_train.py")
    parser.add_argument("train_paths", help="train_paths from shadewatcher_train.py")
    parser.add_argument("model_name", help="model_name from shadewatcher_train.py")
    parser.add_argument("output_dir", help="output folder for evaluations")
    parser.add_argument(
        "--gnn_args",
        default="--epoch 30 --threshold 1.5",
        help="parameters to the shadewatcher model trainer from shadewatcher_train.py",
    )
    parser.add_argument(
        "lower",
        type=int,
        help="lower bound on prune threshold from shadewatcher_train.py",
    )
    parser.add_argument(
        "upper",
        type=int,
        help="upper bound on prune threshold from shadewatcher_train.py",
    )
    parser.add_argument(
        "--curve",
        choices=["exp", "linear"],
        default="linear",
        help="determine the testing threshold curve",
    )
    parser.add_argument(
        "--base",
        action="store_true",
        help="automatically run the 0-prune model",
    )
    args = parser.parse_args()

    print(args, file=sys.stderr)

    # use base flag to automatically run the 0 test case
    if args.base:
        linear_test(
            lower=0,
            upper=0,
            model_name=args.model_name,
            output_dir=args.output_dir,
            gnn_args=args.gnn_args,
            test_paths=paths_from_globs(args.test_paths.split()),
            train_paths=paths_from_globs(args.train_paths.split()),
        )

    if args.curve == "linear":
        linear_test(
            lower=args.lower,
            upper=args.upper,
            model_name=args.model_name,
            output_dir=args.output_dir,
            gnn_args=args.gnn_args,
            test_paths=paths_from_globs(args.test_paths.split()),
            train_paths=paths_from_globs(args.train_paths.split()),
        )
    elif args.curve == "exp":
        exp_test(
            lower=args.lower,
            upper=args.upper,
            model_name=args.model_name,
            output_dir=args.output_dir,
            gnn_args=args.gnn_args,
            test_paths=paths_from_globs(args.test_paths.split()),
            train_paths=paths_from_globs(args.train_paths.split()),
        )
