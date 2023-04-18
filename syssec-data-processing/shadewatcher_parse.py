"""
Runs Shadewatcher parser on a list of graphs and saves their output
"""

import sys
import os
import subprocess
from multiprocessing import Pool

from shadewatcher_common import *
import graph_to_audit
import encoding_parser


def parse_graph(graph_path, force_parse):
    """
    Parse `graph.json` files given a list of paths,
    and copy them to the STORE (see shadewatcher_common.py) directory for use in later processing
    """

    instance_name = stringify_path(graph_path)
    graph_store_dir = STORE_DIR + "/" + instance_name

    if os.path.exists(graph_store_dir) and not force_parse:
        print(f"skipping existing graph [{graph_path}]")
        return  # skip past already converted graphs

    # parse the graph into an audit that shadewatcher can handle
    graph_to_audit.parse(graph_path, f"{EXAMPLES_PATH}/{instance_name}")
    # clean out the shadewatcher encoding directory
    subprocess.call(["rm", "-rf", f"{ENCODING_PATH}/{instance_name}"])
    # call the shadewatcher parse on the data
    subprocess.call(
        [
            "./driverbeat",
            "-dataset",
            instance_name,
            "-trace",
            f"{EXAMPLES_PATH}/{instance_name}",
            "-multithread",
            str(8),
            "-storefile",
        ],
        cwd=PARSER_PATH,
    )

    # copy the files to our shadewatcher store
    os.makedirs(graph_store_dir, exist_ok=True)
    subprocess.call(["rm", "-rf", graph_store_dir])
    subprocess.call(["mkdir", "-p", graph_store_dir])
    subprocess.call(["cp", "-R", f"{ENCODING_PATH}/{instance_name}", STORE_DIR])

    # run the one-hot encoder
    encoding_parser.encode(
        edgefile_path=f"{graph_store_dir}/{EDGEFACT_FILE}",
        nodefile_path=f"{graph_store_dir}/{NODEFACT_FILE}",
        output_path=graph_store_dir,
        randomize_edges=False,
    )


def parse(graph_paths, force_parse=False):
    """Parellelize the processing of graphs"""
    with Pool(20) as pool:
        pool.starmap(
            parse_graph,
            [(graph_path, force_parse) for graph_path in graph_paths],
        )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "graph_globs",
        help="space delimited set of paths to graph jsons that supports * globs",
    )
    parser.add_argument(
        "--force_parse",
        action="store_true",
        help="whether to parse graphs that already exist in the store",
    )
    args = parser.parse_args()

    print(args, file=sys.stderr)

    parse(
        graph_paths=paths_from_globs(args.graph_globs.split()),
        force_parse=args.force_parse,
    )
