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

    graphs = defaultdict(dict)

    for csv_path in glob.glob(f"{csv_dir}/*.csv"):
        df = pandas.read_csv(csv_path)
        df = df.assign(
            detection_ratio=lambda x: (x["true_negative"] + 1)
            / (x["false_positive"] + 1)
        )
        df = df.dropna()
        df = df.sort_values(by="detection_ratio")

        # apply +1 smoothing, beacause we are going to do more processing

        avg_tn, avg_fp = (
            df["true_negative"].sum() / len(df.index) + 1,
            df["false_positive"].sum() / len(df.index) + 1,
        )
        max_tn, max_fp = (
            df.iloc[-1]["true_negative"].astype(float) + 1,
            df.iloc[-1]["false_positive"].astype(float) + 1,
        )
        min_tn, min_fp = (
            df.iloc[0]["true_negative"].astype(float) + 1,
            df.iloc[0]["false_positive"].astype(float) + 1,
        )

        case, stage, program, *_ = csv_path[csv_path.index("APT") :].split("-")

        graphs[f"{stage}-{program}"][case] = (
            case,
            stage,
            program,
            avg_tn,
            avg_fp,
            max_tn,
            max_fp,
            min_tn,
            min_fp,
        )

    for _, cases in graphs.items():
        if len(cases) == 2:
            (
                (
                    case,
                    stage,
                    program,
                    avg_tn,
                    avg_fp,
                    max_tn,
                    max_fp,
                    min_tn,
                    min_fp,
                ),
                (
                    _,
                    _,
                    _,
                    gadget_avg_tn,
                    gadget_avg_fp,
                    gadget_max_tn,
                    gadget_max_fp,
                    gadget_min_tn,
                    gadget_min_fp,
                ),
            ) = cases.values()

            # gadget/base
            avg_ratio = avg_tn / avg_fp
            max_ratio = max_tn / max_fp
            min_ratio = min_tn / min_fp

            avg_ratio_gadget = gadget_avg_tn / gadget_avg_fp
            max_ratio_gadget = gadget_max_tn / gadget_max_fp
            min_ratio_gadget = gadget_min_tn / gadget_min_fp

            avg_imp = (avg_ratio_gadget - avg_ratio) / avg_ratio
            max_imp = (max_ratio_gadget - max_ratio) / max_ratio
            min_imp = (min_ratio_gadget - min_ratio) / min_ratio

            TERMS = "|".join(
                [
                    stage,
                    program,
                    f"{avg_imp * 100:.0f}%",
                    f"{max_imp * 100:.0f}%",
                    f"{min_imp * 100:.0f}%",
                ]
            )

            print(f"|{TERMS}|")
