"""
Computes the percent change between pairing gadget and non-gadget datasets (stage, program)
"""


def fpr(fp, tn):
    return fp / (fp + tn)

def precision(tp, fp):
    return tp / (tp + fp)

def recall(tp, fn):
    return tp / (tp + fn)

def f1_score(tp, fp, fn):
    prec = precision(tp, fp)
    rec = recall(tp, fn)
    return 2 * prec * rec / (prec + rec)

def percent_change(v1, v2):
    return v2 / v1 - 1


if __name__ == "__main__":
    import argparse
    import pandas
    import glob
    import sys

    parser = argparse.ArgumentParser()
    parser.add_argument("csv_dir", help="path to csv dataset evaluation file")
    parser.add_argument("--smoothing", help="constant for laplace smoothing the tn/fp result dataset", default=1)
    args = parser.parse_args()

    print(args, file=sys.stderr)

    csv_dir = args.csv_dir
    SMOOTHING_CONSTANT = args.smoothing

    from collections import defaultdict

    # case :: stage :: {GADGET, NON-GADGET}
    case_comparisons = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))

    GADGET_KEY = "GADGET_KEY"
    NON_GADGET_KEY = "NON_GADGET_KEY"

    TRUE_NEGATIVE_KEY = "true_negative"
    FALSE_POSITIVE_KEY = "false_positive"

    for csv_path in glob.glob(f"{csv_dir}/*.csv"):
        df = pandas.read_csv(csv_path)
        df = df.assign(
            detection_ratio=lambda x: (x[TRUE_NEGATIVE_KEY] + 1)
            / (x[FALSE_POSITIVE_KEY] + 1)
        )
        df = df.dropna()
        df = df.sort_values(by="detection_ratio")

        avg_tn, avg_fp = (
            df[TRUE_NEGATIVE_KEY].sum() / len(df.index),
            df[FALSE_POSITIVE_KEY].sum() / len(df.index),
        )
        max_tn, max_fp = (
            df.iloc[-1][TRUE_NEGATIVE_KEY].astype(float),
            df.iloc[-1][FALSE_POSITIVE_KEY].astype(float),
        )

        min_tn, min_fp = (
            df.iloc[0][TRUE_NEGATIVE_KEY].astype(float),
            df.iloc[0][FALSE_POSITIVE_KEY].astype(float),
        )

        case, stage, program, *_ = csv_path[csv_path.index("APT") :].split("-")

        case_number = int("".join(c for c in case if c.isdigit()))
        case_enum = "Enterprise APT" if case_number == 1 else "Supply-Chain APT"

        if "GADGET" in case:
            case_type = GADGET_KEY
        else:
            case_type = NON_GADGET_KEY

        entries = (
            max_fp,
            max_tn,
            min_fp,
            min_tn,
            avg_fp,
            avg_tn,
        )
        # apply +1 smoothing, beacause we are going to do more processing
        case_comparisons[case_enum][stage][case_type].append(
            list(map(lambda v: v + SMOOTHING_CONSTANT, entries))
        )

    table = list()

    for case_number, cases in case_comparisons.items():
        for stage_number, stage in cases.items():
            N_FP, N_TN = 4, 5  # average
            G_FP, G_TN = 0, 1  # max

            # find the best improvement among cases in the stage
            best_non_gadget = max(
                stage[NON_GADGET_KEY],
                key=lambda e: recall(tp=e[N_FP], fn=e[N_TN]),
            )

            best_gadget = min(
                stage[GADGET_KEY],
                key=lambda e: recall(tp=e[G_FP], fn=e[G_TN]),
            )

            recall_non_gadget = recall(tp=best_non_gadget[N_FP], fn=best_non_gadget[N_TN])
            recall_gadget = recall(tp=best_gadget[G_FP], fn=best_gadget[G_TN])

            recall_percent_improvement = 100 * percent_change(recall_non_gadget, recall_gadget)

            precision_non_gadget = precision(fp=SMOOTHING_CONSTANT, tp=best_non_gadget[N_FP])
            precision_gadget = precision(fp=SMOOTHING_CONSTANT, tp=best_gadget[G_FP])

            precision_percent_improvement = 100 * percent_change(precision_non_gadget, precision_gadget)

            f1_non_gadget = f1_score(fp=SMOOTHING_CONSTANT, fn=best_non_gadget[N_TN], tp=best_non_gadget[N_FP])
            f1_gadget = f1_score(fp=SMOOTHING_CONSTANT, fn=best_gadget[G_TN], tp=best_gadget[G_FP])

            f1_percent_improvement = 100 * percent_change(f1_non_gadget, f1_gadget)

            table.append(
                (
                    case_number,
                    stage_number,
                    precision_non_gadget,
                    recall_non_gadget,
                    f1_non_gadget,
                    precision_gadget,
                    precision_gadget - precision_non_gadget,
                    recall_gadget,
                    recall_gadget - recall_non_gadget,
                    f1_gadget,
                    f1_gadget - f1_non_gadget,
                )
            )

    print(
        pandas.DataFrame(table, columns=["APT", "stage",
            "PRECISION", "RECALL", "F1_SCORE",
            "PRECISION*", "diff", "RECALL*", "diff", "F1_SCORE*", "diff",
        ])
        .set_index("stage")
        .sort_values(by=["stage", "APT"])
        .groupby("APT")
        .mean()
        .round(2)
        .to_markdown()
    )