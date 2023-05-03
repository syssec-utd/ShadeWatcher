# generate commands for shadewatcher
import os

parse_paths = " ".join(
    [
        "/syssec_nas0/prov_graphs/darpa/APT/TC3/*/*/nd/*.json",
        "/syssec_nas0/prov_graphs/darpa/APT/TC5/*/*/nd/*.json",
        "/syssec_nas0/prov_graphs/darpa/APT/benign/*/*/nd/*.json",
    ]
)

gnn_args = {
    "tc3-trace": "--epoch 10",
    "tc3-theia": "--epoch 10",
    "tc3-fiveD": "--epoch 30",
    "tc5-trace": "--epoch 15",
    "tc5-theia": "--epoch 17",
    "tc5-fiveD2": "--epoch 30",
    "gan": "--epoch 30",
}

benign_paths = {
    "tc3-trace": "shadewatcher_store/syssec_nas0-prov_graphs-darpa-APT-benign-tc3-trace-*",
    "tc3-theia": "shadewatcher_store/syssec_nas0-prov_graphs-darpa-APT-benign-tc3-theia-*",
    # "tc3-fiveD": "shadewatcher_store/syssec_nas0-prov_graphs-darpa-APT-benign-tc3-fiveD-*",
    "tc5-trace": "shadewatcher_store/syssec_nas0-prov_graphs-darpa-APT-benign-tc5-trace-*",
    "tc5-theia": "shadewatcher_store/syssec_nas0-prov_graphs-darpa-APT-benign-tc5-theia-*",
    # "tc5-fiveD2": "shadewatcher_store/syssec_nas0-prov_graphs-darpa-APT-benign-tc5-fiveD2-*",
    "gan": "shadewatcher_store/syssec_nas0-prov_graphs-darpa-APT-reconstructed-*",
}
anomaly_paths = {
    "tc3-trace": "shadewatcher_store/syssec_nas0-prov_graphs-darpa-APT-TC3-trace-*",
    "tc3-theia": "shadewatcher_store/syssec_nas0-prov_graphs-darpa-APT-TC3-theia-*",
    # "tc3-fiveD": "shadewatcher_store/syssec_nas0-prov_graphs-darpa-APT-TC3-fivedirections-*",
    "tc5-trace": "shadewatcher_store/syssec_nas0-prov_graphs-darpa-APT-TC5-TRACE-*",
    "tc5-theia": "shadewatcher_store/syssec_nas0-prov_graphs-darpa-APT-TC5-THEIA-*",
    # "tc5-fiveD2": "shadewatcher_store/syssec_nas0-prov_graphs-darpa-APT-TC5-FiveDirections-*",
}

python = "python3.6"
eval_script = "shadewatcher_eval.py"
parse_script = "shadewatcher_parse.py"
train_script = "shadewatcher_train.py"

benign_test_count = 30

test_output_dir = "darpa-tests"

print(f"mkdir -p {test_output_dir}")

assert os.path.exists(eval_script)
assert os.path.exists(parse_script)
assert os.path.exists(train_script)

print(f"{python} {parse_script} '{parse_paths}'")

for train in benign_paths.keys():
    arg_string = gnn_args[train].strip().replace("-", "").replace(" ", "_")
    model_name = f"{train}_{arg_string}"
    print(
        f"{python} {train_script} '{benign_paths[train]}' {model_name} --gnn_args='{gnn_args[train]}'"
    )

    for test in set(anomaly_paths.keys()).intersection(set(benign_paths.keys())):
        if test not in anomaly_paths or test not in benign_paths:
            continue

        test_name = f"{model_name}_{test}.csv"
        print(
            f"{python} {eval_script} '{anomaly_paths[test]}' shadewatcher_store/{model_name} {test_output_dir}/{test_name}"
        )
        print(
            f"{python} {eval_script} '{benign_paths[test]}' shadewatcher_store/{model_name} {test_output_dir}/{test_name} --benign --count {benign_test_count}"
        )

print(f"{python} compare_eval.py {test_output_dir}")
