# generate commands for shadewatcher
import os

datasets = ["tc3-trace", "tc3-theia", "tc5-trace", "tc5-theia"]

parse_paths = " ".join(
    [
        "/syssec_nas0/prov_graphs/darpa/APT/TC3/*/*/nd/*.json",
        "/syssec_nas0/prov_graphs/darpa/APT/TC5/*/*/nd/*.json",
        "/syssec_nas0/prov_graphs/darpa/APT/benign/*/*/nd/*.json",
    ]
)

gnn_args = {
    "tc3-trace": "--epoch 43 --threshold 1.5",
    "tc3-theia": "--epoch 85 --threshold 1.5",
    "tc5-trace": "--epoch 85 --threshold 1.5",
    "tc5-theia": "--epoch 80 --threshold 1.5",
}

benign_paths = {
    "tc3-trace": "shadewatcher_store/syssec_nas0-prov_graphs-darpa-APT-benign-tc3-trace-*",
    "tc3-theia": "shadewatcher_store/syssec_nas0-prov_graphs-darpa-APT-benign-tc3-theia-*",
    "tc5-trace": "shadewatcher_store/syssec_nas0-prov_graphs-darpa-APT-benign-tc5-trace-*",
    "tc5-theia": "shadewatcher_store/syssec_nas0-prov_graphs-darpa-APT-benign-tc5-theia-*",
}
anomaly_paths = {
    "tc3-trace": "shadewatcher_store/syssec_nas0-prov_graphs-darpa-APT-TC3-trace-*",
    "tc3-theia": "shadewatcher_store/syssec_nas0-prov_graphs-darpa-APT-TC3-theia-*",
    "tc5-trace": "shadewatcher_store/syssec_nas0-prov_graphs-darpa-APT-TC5-TRACE-*",
    "tc5-theia": "shadewatcher_store/syssec_nas0-prov_graphs-darpa-APT-TC5-THEIA-*",
}

python = "python3.6"
eval_script = "shadewatcher_eval.py"
parse_script = "shadewatcher_parse.py"
train_script = "shadewatcher_train.py"

test_output_dir = "darpa-tests"

print(f"mkdir -p {test_output_dir}")

assert os.path.exists(eval_script)
assert os.path.exists(parse_script)
assert os.path.exists(train_script)

print(f"{python} {parse_script} '{parse_paths}'")

for train in datasets:
    print(
        f"{python} {train_script} '{benign_paths[train]}' {train} --gnn_args='{gnn_args[train]}'"
    )

    for test in datasets:
        test_name = f"{train}_{test}"
        print(
            f"{python} {eval_script} '{anomaly_paths[train]}' shadewatcher_store/{train} {test_output_dir}/{test_name}"
        )
        print(
            f"{python} {eval_script} '{benign_paths[train]}' shadewatcher_store/{train} {test_output_dir}/{test_name} --count 20 --benign"
        )

print(f"{python} compare_eval.py {test_output_dir}")
