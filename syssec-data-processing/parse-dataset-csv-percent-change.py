"""
Computes the percent change between pairing gadget and non-gadget datasets (stage, program)
"""


def fpr(fp, tn):
    return fp / (fp + tn)


def percent_change(v1, v2):
    return v2 / v1 - 1


if __name__ == "__main__":
    import argparse
    import pandas
    import glob
    import sys

    parser = argparse.ArgumentParser()
    parser.add_argument("csv_dir", help="path to csv dataset evaluation file")
    args = parser.parse_args()

    print(args, file=sys.stderr)

    csv_dir = args.csv_dir

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

        # apply +1 smoothing, beacause we are going to do more processing
        case_comparisons[case_enum][stage][case_type].append(
            (
                max_fp + 1,
                max_tn + 1,
                min_fp + 1,
                min_tn + 1,
                avg_fp + 1,
                avg_tn + 1,
            )
        )

    table = list()

    for case_number, cases in case_comparisons.items():
        for stage_number, stage in cases.items():
            N_FP, N_TN = 4, 5  # average
            G_FP, G_TN = 0, 1  # max

            # find the best improvement among cases in the stage
            best_non_gadget = max(
                stage[NON_GADGET_KEY],
                key=lambda e: fpr(fp=e[N_FP], tn=e[N_TN]),
            )

            best_gadget = min(
                stage[GADGET_KEY],
                key=lambda e: fpr(fp=e[G_FP], tn=e[G_TN]),
            )

            fpr_non_gadget = fpr(fp=best_non_gadget[N_FP], tn=best_non_gadget[N_TN])
            fpr_gadget = fpr(fp=best_gadget[G_FP], tn=best_gadget[G_TN])

            percent_improvement = 100 * percent_change(fpr_non_gadget, fpr_gadget)

            table.append(
                (
                    case_number,
                    stage_number,
                    f"{fpr_non_gadget:.2f}",
                    f"{fpr_gadget:.2f}",
                    f"{percent_improvement:.0f}%",
                )
            )

    print(
        pandas.DataFrame(table, columns=["APT", "stage", "FPR", "FPR*", "% change"])
        .set_index("stage")
        .sort_values(by=["stage", "APT"])
        .to_markdown()
    )
