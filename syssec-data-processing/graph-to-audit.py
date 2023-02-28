#!/usr/bin/env python3
'''
Parses a "graph.json" into the format of auditbeat json records and 
additional procinfo, fdinfo, and socketinfo directories expected by shadewatcher.
'''

from copy import deepcopy
from os.path import join as pathjoin
from os import makedirs


class AuditBeatJsonBuilder:
    '''Helper class for building auditbeat json records'''

    sequence_counter = 0

    def __init__(
        self,
        timestamp="2020-10-31T13:18:31.013Z",
        result: str = "success",
        session: str = "0",
        sequence: int = None,
    ):
        self.record = {
            "@timestamp": str(timestamp),
            "auditd": {
                # results other than "success" get ignored.
                "result": result,
                # required by parser but not used in final encoding script
                "session": session,
            }
        }

        if sequence is not None:
            self.record["auditd"]["sequence"] = sequence
        else:
            self.record["auditd"][
                "sequence"] = AuditBeatJsonBuilder.sequence_counter
            AuditBeatJsonBuilder.sequence_counter += 1

    def set_process(
        self,
        pid: int = None,
        ppid: int = None,
        exe: str = None,
        cwd: str = None,
        args: list = None,
    ):
        process = dict()

        if pid is not None:
            process["pid"] = str(pid)
        if ppid is not None:
            process["ppid"] = str(ppid)
        if exe is not None:
            process["exe"] = exe
        if cwd is not None:
            process["cwd"] = cwd
        if args is not None:
            process["args"] = args

        self.record["process"] = process

        return self

    def set_data(
        self,
        syscall: str,
        exit_code: int = None,
        # file descriptor
        a0: str = None,
        socket: dict = None,
    ):
        data = {
            "syscall": str(syscall),
            # for "a1" usage:
            # see https://github.com/jun-zeng/ShadeWatcher/blob/main/parse/parser/beat/tripletbeat.cpp#L1125
            "a1": "1",
        }

        if a0 is not None:
            data["a0"] = a0
        if exit_code is not None:
            data["exit"] = exit_code
        if socket is not None:
            data["socket"] = socket

        self.record["auditd"]["data"] = data

        return self

    def set_destination(
        self,
        ip: str,
        port: int,
    ):
        self.record["destination"] = {
            "ip": ip,
            "port": str(port),
        }

        return self

    def set_paths(self, paths: list):
        self.record["auditd"]["paths"] = paths

        return self

    def build(self) -> dict:
        '''Return a deep copy of the records dict after performing any required validation'''
        assert "syscall" in self.record["auditd"]["data"]

        return deepcopy(self.record)

    def create_path(
        name: str,
        version: str = "",
        nametype: str = None,
    ) -> dict:
        path = {
            "name": name,
            "version": version,
        }

        if nametype is not None:
            path["nametype"] = nametype

        return path


if __name__ == "__main__":

    #########################################
    # Syssec -> ShadeWatcher syscall mapping
    #########################################

    class EdgeLabel:
        READ = "READ"
        WRITE = "WRITE"
        PROC_CREATE = "PROC_CREATE"

    label2syscall = {
        EdgeLabel.READ: "read",
        EdgeLabel.WRITE: "write",
        EdgeLabel.PROC_CREATE: "execve",
    }

    ##############################
    # String Enum Key Definitions
    ##############################


    class VertexType:
        FILE = "FileNode"
        PROC = "ProcessNode"
        SOCKET = "SocketChannelNode"

    class GraphKey:
        EDGES = "edges"
        VERTICES = "vertices"

    class EdgeKey:
        ID = "_id"
        LABEL = "_label"
        OUT_VERTEX = "_outV"
        IN_VERTEX = "_inV"
        TIME_START_ITEM = "TIME_START"

    class VertexKey:
        # Original Dataset
        ID = "_id"
        PID_ITEM = "PID"
        TYPE_ITEM = "TYPE"
        EXE_ITEM = "EXE_NAME"
        PATH_NAME_ITEM = "PATH_NAME"
        CMD_ITEM = "CMD"
        REMOTE_INET_ADDR_ITEM = "REMOTE_INET_ADDR"
        REMOTE_PORT_ITEM = "REMOTE_PORT"
        LOCAL_INET_ADDR_ITEM = "LOCAL_INET_ADDR"
        LOCAL_PORT_ITEM = "LOCAL_PORT"
        FILENAME_SET_ITEM = "FILENAME_SET"
        BT_HOPCOUNT_ITEM = "BT_HOPCOUNT"
        # Extended Dataset
        FD_ITEM = "FD"

    class ItemKey:
        VALUE = "value"
        TYPE = "type"

    from collections import defaultdict
    import argparse
    import json

    ##################
    # Parse Arguments
    ##################

    parser = argparse.ArgumentParser()
    parser.add_argument("input_path", default="graph.json")
    parser.add_argument("-o", "--output-path", default="audit")
    args = parser.parse_args()

    print(args)

    input_path = args.input_path
    output_path = args.output_path

    with open(input_path, encoding="utf-8") as graph_json:
        graph = json.load(graph_json)

    def find_vertex(vertex_id):
        '''Find vertex in graph vertices based on matching _id field'''
        return next((v for v in graph[GraphKey.VERTICES]
                     if v[VertexKey.ID] == vertex_id), None)

    #########################################
    # auditbeat stored data representations
    #########################################

    audits = list()
    # maps proc to file descriptors
    fdinfo = defaultdict(dict)
    procinfo = {
        "args.txt": list(),
        "exe.txt": list(),
        "general.txt": list(),
        "pid.txt": list(),
        "ppid.txt": list(),
    }
    socketinfo = {
        "device.txt": list(),
        "general.txt": list(),
        "name.txt": list(),
    }

    ############################
    # Process initial Vertices
    ############################

    # find all processes that are either root nodes of the tree or disconnected
    for vertex in graph[GraphKey.VERTICES]:
        # only look at PROC vertices
        is_proc = vertex[VertexKey.TYPE_ITEM][ItemKey.VALUE] == VertexType.PROC
        if not is_proc:
            continue

        # none of the PROC_CREATE edges have this node as the outVertex
        is_child = any(e[EdgeKey.IN_VERTEX] == vertex[VertexKey.ID]
                       for e in graph[GraphKey.EDGES]
                       if e[EdgeKey.LABEL] == EdgeLabel.PROC_CREATE)
        if is_child:
            continue

        # Proc Load format: https://github.com/jun-zeng/ShadeWatcher/blob/main/parse/parser/kg.cpp#L646
        procinfo["args.txt"].append(vertex[VertexKey.CMD_ITEM][ItemKey.VALUE])
        # this exe is an absolute path, which might be a problem
        procinfo["exe.txt"].append(vertex[VertexKey.EXE_ITEM][ItemKey.VALUE])
        procinfo["pid.txt"].append(vertex[VertexKey.PID_ITEM][ItemKey.VALUE])
        procinfo["ppid.txt"].append(1)

        # used to tell ShadeWatcher how many lines to parse:
        procinfo["general.txt"].append("PLACEHOLDER")

        # Insert empty FD Info for the origin node
        fdinfo[vertex[VertexKey.PID_ITEM][ItemKey.VALUE]] = dict()

    ############################
    # Enrich the graph Vertices
    ############################

    # fd serial counter
    file_descriptor_counter = 1

    for vertex in graph[GraphKey.VERTICES]:
        node_type = vertex[VertexKey.TYPE_ITEM][ItemKey.VALUE]

        # add unique file descriptors to the Files and Sockets
        if node_type in [VertexType.FILE, VertexType.SOCKET]:
            vertex[VertexKey.FD_ITEM] = {
                ItemKey.VALUE: file_descriptor_counter
            }

            file_descriptor_counter += 1

    ####################
    # Setup Node Cache
    ####################

    node_cache = set()

    def cache_vertex(vertex, caller_vertex=None):
        '''Track the creation of resource nodes
        
        FILE nodes:
            opens a file upon first contact

        SOCKET nodes:
            opens a socket and then connects the socket to a destination
        '''

        node_type = vertex[VertexKey.TYPE_ITEM][ItemKey.VALUE]

        if node_type == VertexType.FILE:
            record_builder = AuditBeatJsonBuilder()
            record_builder.set_data(
                "open",
                exit_code=vertex[VertexKey.FD_ITEM][ItemKey.VALUE],
            )
            record_builder.set_process(
                pid=caller_vertex[VertexKey.PID_ITEM][ItemKey.VALUE],
                cwd="/",
            )
            filenames = vertex[VertexKey.FILENAME_SET_ITEM][ItemKey.VALUE]
            record_builder.set_paths([
                AuditBeatJsonBuilder.create_path(
                    name=filename[ItemKey.VALUE],
                    # flag: https://github.com/jun-zeng/ShadeWatcher/blob/main/parse/parser/beat/tripletbeat.cpp#L364
                    nametype="CREATE",
                ) for filename in filenames
            ])

            audits.append(record_builder.build())

        elif node_type == VertexType.SOCKET:
            # create socket fd
            record_builder = AuditBeatJsonBuilder()
            record_builder.set_data(
                "socket",
                exit_code=vertex[VertexKey.FD_ITEM][ItemKey.VALUE],
            )
            record_builder.set_process(
                pid=caller_vertex[VertexKey.PID_ITEM][ItemKey.VALUE])

            audits.append(record_builder.build())

            # create connection
            record_builder = AuditBeatJsonBuilder()
            record_builder.set_data(
                "connect",
                # a0=vertex[VertexKey.FD_ITEM][ItemKey.VALUE],
                # socket=dict(),
            )
            record_builder.set_process(
                pid=caller_vertex[VertexKey.PID_ITEM][ItemKey.VALUE])
            record_builder.set_destination(
                ip=vertex[VertexKey.REMOTE_INET_ADDR_ITEM][ItemKey.VALUE],
                port=vertex[VertexKey.REMOTE_PORT_ITEM][ItemKey.VALUE],
            )

            audits.append(record_builder.build())

        # cache the vertex
        node_cache.add(vertex[VertexKey.ID])

    ################
    # Process Edges
    ################

    def is_initial_pid(vertex_id):
        '''Find out if this is in the inital procinfo set'''
        vertex = find_vertex(vertex_id)
        return vertex[VertexKey.TYPE_ITEM][
            ItemKey.VALUE] == VertexType.PROC and vertex[VertexKey.PID_ITEM][
                ItemKey.VALUE] in procinfo["pid.txt"]

    # process edges into the audits
    # sorted by timestamp to preserve causal orderings
    for edge in sorted(
            graph[GraphKey.EDGES],
            key=lambda e: (
                # sort by timestamp
                e[EdgeKey.TIME_START_ITEM][ItemKey.VALUE],
                # processes must come before process edges
                0 if e[EdgeKey.LABEL] == EdgeLabel.PROC_CREATE else 1,
                # priority to processes that belong in the system initial state
                0 if is_initial_pid(e[EdgeKey.OUT_VERTEX]) else 1,
            ),
    ):
        # NOTES:
        #   exit_code's of 0 should be used because those result in the entry being ignored
        #   see: https://github.com/jun-zeng/ShadeWatcher/blob/main/parse/parser/beat/tripletbeat.cpp#L688
        #
        #   when creating record for PROC_CREATE, the ppid can be inferred using the outVertex pid
        label = edge[EdgeKey.LABEL]
        if label not in label2syscall:
            print(f'edge label [{label}] not handled.')
            continue

        syscall = label2syscall[label]

        in_vertex, out_vertex = (
            find_vertex(edge[EdgeKey.IN_VERTEX]),
            find_vertex(edge[EdgeKey.OUT_VERTEX]),
        )

        if label == EdgeLabel.READ:
            if out_vertex[VertexKey.ID] not in node_cache:
                cache_vertex(out_vertex, caller_vertex=in_vertex)

            record_builder = AuditBeatJsonBuilder()
            record_builder.set_data(
                syscall,
                exit_code=1,
                a0=out_vertex[VertexKey.FD_ITEM][ItemKey.VALUE],
            )
            record_builder.set_process(
                # Read is a directed edge from the FileNode -> ProcessNode
                pid=in_vertex[VertexKey.PID_ITEM][ItemKey.VALUE])

            audits.append(record_builder.build())

        elif label == EdgeLabel.WRITE:
            if in_vertex[VertexKey.ID] not in node_cache:
                cache_vertex(in_vertex, caller_vertex=out_vertex)

            record_builder = AuditBeatJsonBuilder()
            record_builder.set_data(
                syscall,
                exit_code=1,
                a0=in_vertex[VertexKey.FD_ITEM][ItemKey.VALUE],
            )
            record_builder.set_process(
                # Read is a directed edge from the FileNode <- ProcessNode
                pid=out_vertex[VertexKey.PID_ITEM][ItemKey.VALUE])

            audits.append(record_builder.build())

        elif label == EdgeLabel.PROC_CREATE:
            record_builder = AuditBeatJsonBuilder()
            record_builder.set_data(syscall)
            record_builder.set_process(
                pid=in_vertex[VertexKey.PID_ITEM][ItemKey.VALUE],
                ppid=out_vertex[VertexKey.PID_ITEM][ItemKey.VALUE],
                exe=in_vertex[VertexKey.EXE_ITEM][ItemKey.VALUE],
                args=in_vertex[VertexKey.CMD_ITEM][ItemKey.VALUE].split(),
            )

            audits.append(record_builder.build())

    ##############################################
    # Save data to respective files & directories
    ##############################################

    makedirs(output_path, exist_ok=True)
    with open(pathjoin(output_path, "auditbeat"), "w") as auditfile:
        auditfile.write("\n".join(map(json.dumps, audits)))

    # PROCINFO
    procinfo_path = pathjoin(output_path, "procinfo")
    makedirs(procinfo_path, exist_ok=True)
    with open(pathjoin(procinfo_path, "args.txt"), "w") as proc_args:
        proc_args.write("COMMAND")
        proc_args.write("".join(f'\n{x}' for x in procinfo["args.txt"]))
    with open(pathjoin(procinfo_path, "exe.txt"), "w") as proc_exe:
        proc_exe.write("COMMAND")
        proc_exe.write("".join(f'\n{x}' for x in procinfo["exe.txt"]))
    with open(pathjoin(procinfo_path, "general.txt"), "w") as proc_general:
        proc_general.write("PLACEHOLDER")
        proc_general.write("".join(f'\n{x}' for x in procinfo["general.txt"]))
        proc_general.write("\x0a")
    with open(pathjoin(procinfo_path, "pid.txt"), "w") as proc_pid:
        proc_pid.write("PID")
        proc_pid.write("".join(f'\n{x}' for x in procinfo["pid.txt"]))
    with open(pathjoin(procinfo_path, "ppid.txt"), "w") as proc_ppid:
        proc_ppid.write("PPID")
        proc_ppid.write("".join(f'\n{x}' for x in procinfo["ppid.txt"]))

    # SOCKETINFO
    socketinfo_path = pathjoin(output_path, "socketinfo")
    makedirs(socketinfo_path, exist_ok=True)
    with open(pathjoin(socketinfo_path, "device.txt"), "w") as socket_device:
        socket_device.write("DEVICE")
        socket_device.write("".join(f'\n{x}'
                                    for x in socketinfo["device.txt"]))
    with open(pathjoin(socketinfo_path, "name.txt"), "w") as socket_name:
        socket_name.write("NAME")
        socket_name.write("".join(f'\n{x}' for x in socketinfo["name.txt"]))
    with open(pathjoin(socketinfo_path, "general.txt"), "w") as socket_general:
        socket_general.write("PLACEHOLDER")
        socket_general.write("".join(f'\n{x}'
                                     for x in socketinfo["general.txt"]))

    # FDINFO
    fdinfo_path = pathjoin(output_path, "fdinfo")
    makedirs(fdinfo_path, exist_ok=True)
    for name, items in fdinfo.items():
        with open(pathjoin(fdinfo_path, str(name)), "w") as fddir:
            padding = 'lr-x------ 1 root root 64 Oct 31 22:04'
            fddir.write(f"PLACEHOLDER\n{padding} .\n{padding} ..")
            fddir.write("".join(f'\n{padding} {pid} -> {desc}'
                                for pid, desc in items.items()))
            fddir.write("\x0a")
