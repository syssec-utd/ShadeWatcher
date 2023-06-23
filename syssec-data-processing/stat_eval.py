def precision(tp, fp):
    return tp / (tp + fp)


def recall(tp, fn):
    return tp / (tp + fn)


def f1_score(tp, fp, fn):
    prec = precision(tp, fp)
    rec = recall(tp, fn)
    return 2 * prec * rec / (prec + rec)


def fpr(fp, tn):
    return fp / (fp + tn)


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
        default=0,
    )
    args = parser.parse_args()

    print(args, file=sys.stderr)

    csv_dir = args.csv_dir
    smoothing = args.smoothing

    TRUE_NEGATIVE_KEY = "tn"
    FALSE_POSITIVE_KEY = "fp"

    TRUE_POSITIVE_KEY = "tp"
    FALSE_NEGATIVE_KEY = "fn"

    agg_df = pandas.DataFrame()

    for csv_path in glob.glob(f"{csv_dir}/*.csv"):
        df = pandas.read_csv(csv_path).dropna()
        df = df.assign(filename=csv_path)
        agg_df = pandas.concat([agg_df, df])

    # sum scores based on source file
    agg_df = agg_df.groupby("filename").sum()

    agg_df[TRUE_NEGATIVE_KEY] = agg_df[TRUE_NEGATIVE_KEY].apply(
        lambda v: v + smoothing,
    )
    agg_df[TRUE_POSITIVE_KEY] = agg_df[TRUE_POSITIVE_KEY].apply(
        lambda v: v + smoothing,
    )

    agg_df = agg_df.drop(columns=[FALSE_NEGATIVE_KEY, FALSE_POSITIVE_KEY])

    print(agg_df.round(4).to_markdown())
