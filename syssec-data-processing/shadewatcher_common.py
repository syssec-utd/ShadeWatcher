import os

shadewatcher_dir = os.environ["SHADEWATCHER_DIR"]

embedding_path = shadewatcher_dir + "/data/embedding"
encoding_path = shadewatcher_dir + "/data/encoding"
examples_path = shadewatcher_dir + "/data/examples"
parser_path = shadewatcher_dir + "/parse"
gnn_path = shadewatcher_dir + "/recommend"


def stringify_path(path_str: str):
    """Standard way to convert a path to a valid filename"""
    return path_str.replace("/", "-").replace("\\", "-")
