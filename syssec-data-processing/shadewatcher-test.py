"""
Runs Shadewatcher evaluations against a model
"""

if __name__ == "__main__":
    import argparse
    import pandas
    import glob
    import os
    import subprocess
    import random
    import sys

    from shadewatcher_common import *

    parser = argparse.ArgumentParser()
    parser.add_argument("test_paths", help="")
    parser.add_argument("model_path", help="")
    parser.add_argument("token", help="unique identifier for this run (for collecting data)")
    args = parser.parse_args()

    print(args, file=sys.stderr)

    test_paths = args.test_paths
    model_path = args.model_path
    token = args.token
    if token is None:
        token = random.randrange(5000, 5000000)


    # copy the model into the Shadewatcher embeddings directory
    # (use a token to make it unique)
    subprocess.call(["rm", "-rf", f"{}/{token}"])
    subprocess.call(["mkdir", "-p", f"{embedding_path}/{token}"])
    subprocess.call(["cp", "-R", model_path, f"{embedding_path}/{token}"])

    summary_name = f"{model_path}_{token}"

    for test_path in test_paths:
        subprocess.call(["rm", "-rf", f"{encodin}/data/encoding/{token}"])
        subprocess.call(["mkdir", "-p", f"{shadewatcher_dir}/data/encoding/{token}"])
        subprocess.call(["cp", "-R", test_path, f"{shadewatcher_dir}/data/encoding/{token}"])
    # Evaluation Step
    # 1. pad the test instance to be the size of the model
    # 2. run the test instance against the model
    # 3. store the testing summary in a file (based on a session key)



