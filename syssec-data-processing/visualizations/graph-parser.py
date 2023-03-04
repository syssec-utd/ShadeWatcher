class ForceGraphMapper:

    def map(nodes, edges) -> dict:
        return {
            "nodes": [{
                "id": hash_id,
                "group": meta[0]
            } for hash_id, meta in nodes],
            "links": [{
                "source": n1,
                "target": n2,
                "relation": meta[0],
            } for n1, n2, meta in edges],
        }


if __name__ == "__main__":

    import argparse
    import json

    parser = argparse.ArgumentParser()
    parser.add_argument("edgefile_path")
    parser.add_argument("nodefile_path")
    parser.add_argument("-g", "--graph-type", default="BG")

    args = parser.parse_args()

    edgefile_path = args.edgefile_path
    nodefile_path = args.nodefile_path
    graph_type = args.graph_type

    if graph_type == "BG":
        with open(nodefile_path) as nodefile:
            nodes = []
            for line in nodefile.read().splitlines():
                if len(line) > 0:
                    hash_id, *meta = line.split(",")
                    nodes.append((hash_id, meta))

        with open(edgefile_path) as edgefile:
            edges = []
            for line in edgefile.read().splitlines():
                if len(line) > 0:
                    node1, node2, *meta = line.split(",")
                    edges.append((node1, node2, meta))

        print(json.dumps(ForceGraphMapper.map(nodes, edges), indent=2))

    elif graph_type == "KG":
        with open(nodefile_path) as nodefile:
            nodes = []
            for line in nodefile.read().splitlines()[1:]:
                if len(line) > 0:
                    hash_id, *meta = line.split()
                    nodes.append((hash_id, meta))

        with open(edgefile_path) as edgefile:
            edges = []
            for line in edgefile.read().splitlines()[1:]:
                if len(line) > 0:
                    _, node1, node2, *meta = line.split()
                    edges.append((node1, node2, meta))

        print(json.dumps(ForceGraphMapper.map(nodes, edges), indent=2))
