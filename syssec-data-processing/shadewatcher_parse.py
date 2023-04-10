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


def parse_graph(args):
    graph_path, force_parse = args
    instance_name = stringify_path(graph_path)
    graph_store_dir = STORE_DIR + "/" + instance_name

    if os.path.exists(graph_store_dir) and not force_parse:
        return  # skip past already converted graphs
    os.makedirs(graph_store_dir, exist_ok=True)

    # parse the graph into an audit that shadewatcher can handle
    graph_to_audit.parse(graph_path, EXAMPLES_PATH + "/" + instance_name)
    # clean out the shadewatcher encoding directory
    subprocess.call(["rm", "-rf", ENCODING_PATH + "/" + instance_name])
    # call the shadewatcher parse on the data
    subprocess.call(
        [
            "./driverbeat",
            "-dataset",
            instance_name,
            "-trace",
            EXAMPLES_PATH + "/" + instance_name,
            "-multithread",
            str(8),
            "-storefile",
        ],
        cwd=PARSER_PATH,
    )
    # run the one-hot encoder
    encoding_parser.encode(
        edgefile_path=ENCODING_PATH + "/" + instance_name + "/" + EDGEFACT_FILE,
        nodefile_path=ENCODING_PATH + "/" + instance_name + "/" + NODEFACT_FILE,
        output_path=ENCODING_PATH + "/" + instance_name,
        randomize_edges=False,
    )

    # copy the files to our shadewatcher store
    subprocess.call(["rm", "-rf", graph_store_dir])
    subprocess.call(["mkdir", "-p", graph_store_dir])
    subprocess.call(["cp", "-R", ENCODING_PATH + "/" + instance_name, STORE_DIR])


def parse(graph_paths, force_parse):
    with Pool(20) as pool:
        pool.map(parse_graph, [(x, force_parse) for x in graph_paths])


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "graph_paths", help="space delimited set of paths to graph jsons"
    )
    parser.add_argument(
        "--force_parse",
        action="store_true",
        help="whether to parse graphs that already exist in the store",
    )
    args = parser.parse_args()

    print(args, file=sys.stderr)

    graph_paths = args.graph_paths.split()
    force_parse = args.force_parse

    parse(graph_paths, force_parse)
