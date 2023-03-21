"""
Computes the percent change between pairing gadget and non-gadget datasets (stage, program)
"""

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

    for csv_path in glob.glob(f"{csv_dir}/*.csv"):
        df = pandas.read_csv(csv_path)
        df = df.assign(
            detection_ratio=lambda x: (x["true_negative"] + 1)
            / (x["false_positive"] + 1)
        )
        df = df.dropna()
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
            # find the best improvement among cases in the stage
            best_non_gadget = max(
                stage[NON_GADGET_KEY],
                key=lambda e: e[3] / e[2],
            )
            best_gadget = max(
                stage[GADGET_KEY],
                key=lambda e: e[1] / e[0],
            )

            percent_improvement_tn = ((best_gadget[1] / best_non_gadget[1]) - 1) * 100
            percent_improvement_fp = ((best_gadget[0] / best_non_gadget[0]) - 1) * 100

            table.append(
                (
                    case_number,
                    stage_number,
                    f"[{percent_improvement_fp:.0f}%, {percent_improvement_tn:.0f}%]",
                )
            )

    table_df = pandas.DataFrame(table, columns=["APT", "stage", "change"])
    table_df = table_df.pivot(index="APT", columns="stage", values="change")

    print(table_df.to_markdown())
