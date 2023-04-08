"""
one-off script for parsing the content of mixed GADGET cases
with a custom training set, independent of gadget origins

* csv output from test-datasets.sh
"""

if __name__ == "__main__":
    import argparse
    import pandas
    import glob
    import sys

    parser = argparse.ArgumentParser()
    parser.add_argument("csv_dir", help="path to csv dataset evaluation file")
    parser.add_argument(
        "--smoothing",
        help="constant for laplace smoothing the tn/fp result dataset",
        default=1,
    )
    args = parser.parse_args()

    print(args, file=sys.stderr)

    csv_dir = args.csv_dir

    TRUE_NEGATIVE_KEY = "true_negative"
    FALSE_POSITIVE_KEY = "false_positive"

    for csv_path in glob.glob(f"{csv_dir}/*.csv"):
        df = pandas.read_csv(csv_path)
        df = df.assign(
            detection_ratio=lambda x: (x[TRUE_NEGATIVE_KEY] + 1)
            / (x[FALSE_POSITIVE_KEY] + 1)
        ).dropna()

        # remap the instance assignment
        df["instance"] = df["instance"].apply(
            lambda x: x[len("/datasets/") : x.index("/anomaly")]
        )

        print(df.groupby("instance").mean().round(2).to_markdown())

