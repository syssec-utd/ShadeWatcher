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
        type=int,
        default=1,
    )
    args = parser.parse_args()

    print(args, file=sys.stderr)

    csv_dir = args.csv_dir
    smoothing = args.smoothing

    TRUE_NEGATIVE_KEY = "true_negative"
    FALSE_POSITIVE_KEY = "false_positive"

    agg_df = pandas.DataFrame()

    for csv_path in glob.glob(f"{csv_dir}/*.csv"):
        df = pandas.read_csv(csv_path).dropna()
        df = df.assign(filename=csv_path)
        df[FALSE_POSITIVE_KEY] = df[FALSE_POSITIVE_KEY].apply(lambda v: v + smoothing)
        df[TRUE_NEGATIVE_KEY] = df[TRUE_NEGATIVE_KEY].apply(lambda v: v + smoothing)
        df = df.assign(
            f1=lambda x: f1_score(
                tp=x[FALSE_POSITIVE_KEY],
                fp=smoothing,
                fn=x[TRUE_NEGATIVE_KEY],
            )
        )
        df = df.assign(
            recall=lambda x: recall(
                tp=x[FALSE_POSITIVE_KEY],
                fn=x[TRUE_NEGATIVE_KEY],
            )
        )

        agg_df = pandas.concat([agg_df, df])

    print(agg_df.groupby("filename").mean().round(2).to_markdown())
