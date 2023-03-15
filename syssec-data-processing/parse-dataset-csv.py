"""
Computes the following for a given graph evaluation csv dataset:
    Avg(false_positive, true_negative)
    Max(false_positive, true_negative)
    Min(false_positive, true_negative)
"""

if __name__ == "__main__":
    import argparse
    import pandas
    import numpy
    import sys

    parser = argparse.ArgumentParser()
    parser.add_argument("csv_path", help="path to csv dataset evaluation file")
    args = parser.parse_args()

    print(args, file=sys.stderr)

    csv_path = args.csv_path

    df = pandas.read_csv(csv_path)
    df = df.assign(detection_ratio=lambda x: x["true_negative"] / x["false_positive"])
    df = df.replace(numpy.inf, 0)
    df = df.sort_values(by="detection_ratio")

    avg_tn, avg_fp = (
        df["true_negative"].sum() / len(df.index),
        df["false_positive"].sum() / len(df.index),
    )
    max_tn, max_fp = (
        df.iloc[-1]["true_negative"].astype(float),
        df.iloc[-1]["false_positive"].astype(float),
    )
    min_tn, min_fp = (
        df.iloc[0]["true_negative"].astype(float),
        df.iloc[0]["false_positive"].astype(float),
    )

    case, stage, program, *_ = csv_path[csv_path.index('APT'):].split('-')
    print("|" + "|".join([
        case, stage, program,
        f"{avg_fp:.2f}, {avg_tn:.2f}",
        f"{max_fp}, {max_tn}",
        f"{min_fp}, {min_tn}",
    ]) + "|")