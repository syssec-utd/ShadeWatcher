import os
import glob
from itertools import chain

shadewatcher_dir = os.environ["SHADEWATCHER_DIR"]

EMBEDDING_PATH = shadewatcher_dir + "/data/embedding"
ENCODING_PATH = shadewatcher_dir + "/data/encoding"
EXAMPLES_PATH = shadewatcher_dir + "/data/examples"
PARSER_PATH = shadewatcher_dir + "/parse"
GNN_PATH = shadewatcher_dir + "/recommend"

STORE_DIR_KEY = "STORE_DIR"
STORE_DIR = (
    os.environ[STORE_DIR_KEY] if STORE_DIR_KEY in os.environ else "shadewatcher_store"
)

EDGEFACT_FILE = "edgefact_0.txt"
NODEFACT_FILE = "nodefact.txt"
PROCFACT_FILE = "procfact.txt"
FILEFACT_FILE = "filefact.txt"
SOCKETFACT_FILE = "socketfact.txt"

ENTITY_FILE = "entity2id.txt"
INTERACTION_FILE = "inter2id.txt"
RELATION_FILE = "relation2id.txt"
TRAIN_FILE = "train2id.txt"


def stringify_path(path_str: str):
    """Standard way to convert a path to a valid filename"""
    # convert directories to "-" and remove leading "-"
    return path_str.replace("/", "-").replace("\\", "-").lstrip("-")


def read_factfile(path):
    """Read the lines from a file file

    Returns the lines and ignores the count (since it is len(lines))
    """
    with open(path, encoding="utf-8") as fact_file:
        _, *lines = fact_file.read().splitlines()

    return lines


def path_iter_from_globs(globs):
    """Turn a list of glob matchers into an iterator over all matched paths"""
    return chain(glob.iglob(path) for path in globs)
