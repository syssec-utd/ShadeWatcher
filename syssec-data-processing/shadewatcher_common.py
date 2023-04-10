import os

shadewatcher_dir = os.environ["SHADEWATCHER_DIR"]

EMBEDDING_PATH = shadewatcher_dir + "/data/embedding"
ENCODING_PATH = shadewatcher_dir + "/data/encoding"
EXAMPLES_PATH = shadewatcher_dir + "/data/examples"
PARSER_PATH = shadewatcher_dir + "/parse"
GNN_PATH = shadewatcher_dir + "/recommend"

STORE_DIR = "shadewatcher_store"


def stringify_path(path_str: str):
    """Standard way to convert a path to a valid filename"""
    return path_str.replace("/", "-").replace("\\", "-")
