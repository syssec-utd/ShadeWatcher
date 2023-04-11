"""
one-off script for parsing the content of mixed GADGET cases
with a custom training set, independent of gadget origins

* csv output from test-datasets.sh
"""


def precision(tp, fp):
    return tp / (tp + fp)


def recall(tp, fn):
    return tp / (tp + fn)


def f1_score(tp, fp, fn):
    prec = precision(tp, fp)
    rec = recall(tp, fn)
    return 2 * prec * rec / (prec + rec)


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
    parser.add_argument(
        "--combine",
        action="store_true",
        help="whether to combine all files in the directory or print each separately",
    )
    args = parser.parse_args()

    print(args, file=sys.stderr)

    csv_dir = args.csv_dir
    smoothing = args.smoothing
    combine = args.combine

    TRUE_NEGATIVE_KEY = "true_negative"
    FALSE_POSITIVE_KEY = "false_positive"

    adf = pandas.DataFrame()

    for csv_path in glob.glob(f"{csv_dir}/*.csv"):
        print(csv_path)
        df = pandas.read_csv(csv_path).dropna()
        df = df.assign(
            f1=lambda x: f1_score(
                tp=x[FALSE_POSITIVE_KEY] + smoothing,
                fp=smoothing,
                fn=x[TRUE_NEGATIVE_KEY] + smoothing,
            )
        )
        df = df.assign(
            recall=lambda x: recall(
                tp=x[FALSE_POSITIVE_KEY] + smoothing,
                fn=x[TRUE_NEGATIVE_KEY] + smoothing,
            )
        )

        # remap the instance assignment
        df["instance"] = df["instance"].apply(
            lambda x: x[len("/datasets/") : x.index("/anomaly")]
        )

        if combine:
            adf = pandas.concat([adf, df])
        else:
            print(df.groupby("instance").mean().round(2).to_markdown())

    if not combine:
        print(adf.groupby("instance").mean().round(2).to_markdown())
