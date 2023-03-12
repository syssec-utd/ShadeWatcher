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
        FILE_EXEC = "FILE_EXEC"
        IP_CONNECTION_EDGE = "IP_CONNECTION_EDGE"
        READ_WRITE = "READ_WRITE"

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

        # part of IP_CONNECTION_EDGE
        REMOTE_INET_ADDR_ITEM = "REMOTE_INET_ADDR"
        REMOTE_PORT_ITEM = "REMOTE_PORT"
        LOCAL_INET_ADDR_ITEM = "LOCAL_INET_ADDR"
        LOCAL_PORT_ITEM = "LOCAL_PORT"

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
    import os
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

    # if the path doesnt exist, we are going to create an
    # empty graph in order to make any pipelining easier
    if not os.path.exists(input_path):
        graph = {GraphKey.EDGES: [], GraphKey.VERTICES: []}
    else:
        with open(input_path, encoding="utf-8") as graph_json:
            graph = json.load(graph_json)

    vertex_table = {v[VertexKey.ID]: v for v in graph[GraphKey.VERTICES]}

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

    # allocate pids backwards when we need to fabricate data.
    # mainly used for FILE_EXEC
    pid_allocator = 99999
    # fd serial counter
    file_descriptor_counter = 1

    for vertex in graph[GraphKey.VERTICES]:
        node_type = vertex[VertexKey.TYPE_ITEM][ItemKey.VALUE]

        # add unique file descriptors to the all nodes
        vertex[VertexKey.FD_ITEM] = {ItemKey.VALUE: file_descriptor_counter}

        file_descriptor_counter += 1

    ####################
    # Setup Node Cache
    ####################

    node_cache = set()

    def cache_fd_vertex(vertex, caller_vertex=None):
        '''Track the creation of resource nodes

        FILE nodes:
            opens a file upon first contact

        SOCKET nodes:
            opens a socket and then connects the socket to a destination
        '''
        if vertex == caller_vertex:
            # dont cache self-loops
            return

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

        # set the fd vertex to remember the PID of its creator.
        # used to handle the cases of FILE_EXEC
        vertex[VertexKey.PID_ITEM] = {
            ItemKey.VALUE: caller_vertex[VertexKey.PID_ITEM][ItemKey.VALUE]
        }

        # cache the vertex
        node_cache.add(vertex[VertexKey.ID])

    ################
    # Process Edges
    ################

    def is_initial_pid(vertex_id):
        '''Find out if this is in the inital procinfo set'''
        vertex = vertex_table[vertex_id]
        return vertex[VertexKey.TYPE_ITEM][
            ItemKey.VALUE] == VertexType.PROC and vertex[VertexKey.PID_ITEM][
                ItemKey.VALUE] in procinfo["pid.txt"]

    # process edges into the audits
    # sorted by timestamp to preserve causal orderings
    for edge in sorted(
            graph[GraphKey.EDGES],
            key=lambda e:
        (
            # prioritize edges with a process that way we can initialize
            # nodes which require a source pid.
            0 if VertexType.PROC in [
                vertex_table[e[EdgeKey.OUT_VERTEX]][VertexKey.TYPE_ITEM][
                    ItemKey.VALUE], vertex_table[e[EdgeKey.IN_VERTEX]][
                        VertexKey.TYPE_ITEM][ItemKey.VALUE]
            ] else 1,
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

        in_vertex, out_vertex = (
            vertex_table[edge[EdgeKey.IN_VERTEX]],
            vertex_table[edge[EdgeKey.OUT_VERTEX]],
        )

        if label == EdgeLabel.READ:
            if out_vertex[VertexKey.ID] not in node_cache:
                cache_fd_vertex(out_vertex, caller_vertex=in_vertex)

            record_builder = AuditBeatJsonBuilder()
            record_builder.set_data(
                "read",
                exit_code=1,
                a0=out_vertex[VertexKey.FD_ITEM][ItemKey.VALUE],
            )
            record_builder.set_process(
                # Read is a directed edge from the FileNode -> ProcessNode
                pid=in_vertex[VertexKey.PID_ITEM][ItemKey.VALUE])

            audits.append(record_builder.build())

        elif label == EdgeLabel.WRITE:
            if in_vertex[VertexKey.ID] not in node_cache:
                cache_fd_vertex(in_vertex, caller_vertex=out_vertex)

            record_builder = AuditBeatJsonBuilder()
            record_builder.set_data(
                "write",
                exit_code=1,
                a0=in_vertex[VertexKey.FD_ITEM][ItemKey.VALUE],
            )
            record_builder.set_process(
                # Read is a directed edge from the FileNode <- ProcessNode
                pid=out_vertex[VertexKey.PID_ITEM][ItemKey.VALUE])

            audits.append(record_builder.build())

        elif label == EdgeLabel.PROC_CREATE:
            record_builder = AuditBeatJsonBuilder()
            record_builder.set_data("execve")

            in_vertex_type, out_vertex_type = (
                in_vertex[VertexKey.TYPE_ITEM][ItemKey.VALUE],
                out_vertex[VertexKey.TYPE_ITEM][ItemKey.VALUE],
            )

            # if it is a process spawning another process then use the pid, ppid, exe, and cmd args
            if in_vertex_type == VertexType.PROC and out_vertex_type == VertexType.PROC:
                record_builder.set_process(
                    pid=in_vertex[VertexKey.PID_ITEM][ItemKey.VALUE],
                    ppid=out_vertex[VertexKey.PID_ITEM][ItemKey.VALUE],
                    exe=in_vertex[VertexKey.EXE_ITEM][ItemKey.VALUE],
                    args=in_vertex[VertexKey.CMD_ITEM][ItemKey.VALUE].split(),
                )

            # if a process is interacting with a file in a PROC_CREATE,
            # then reorient the relationship to from process to file
            elif in_vertex_type == VertexType.PROC and out_vertex_type != VertexType.PROC or in_vertex_type != VertexType.PROC and out_vertex_type == VertexType.PROC:

                proc_node, fd_node = (
                    in_vertex,
                    out_vertex) if in_vertex_type == VertexType.PROC else (
                        out_vertex, in_vertex)

                fd_node[VertexKey.PID_ITEM] = {ItemKey.VALUE: pid_allocator}
                pid_allocator -= 1

                if fd_node[VertexKey.TYPE_ITEM][
                        ItemKey.VALUE] == VertexType.FILE:
                    exe_path = fd_node[VertexKey.FILENAME_SET_ITEM][
                        ItemKey.VALUE][0][ItemKey.VALUE]
                elif fd_node[VertexKey.TYPE_ITEM][
                        ItemKey.VALUE] == VertexType.SOCKET:
                    exe_path = proc_node[VertexKey.CMD_ITEM][ItemKey.VALUE]

                record_builder.set_process(
                    pid=fd_node[VertexKey.PID_ITEM][ItemKey.VALUE],
                    ppid=proc_node[VertexKey.PID_ITEM][ItemKey.VALUE],
                    exe=exe_path,
                )

            # if it is a File, create a new PID to represent the new node
            elif in_vertex_type != VertexType.PROC and out_vertex_type != VertexType.PROC:
                in_vertex[VertexKey.PID_ITEM] = {ItemKey.VALUE: pid_allocator}
                pid_allocator -= 1

                record_builder.set_process(
                    pid=in_vertex[VertexKey.PID_ITEM][ItemKey.VALUE],
                    ppid=out_vertex[VertexKey.PID_ITEM][ItemKey.VALUE],
                    exe=in_vertex[VertexKey.FILENAME_SET_ITEM][
                        ItemKey.VALUE][0][ItemKey.VALUE])

            audits.append(record_builder.build())

        elif label == EdgeLabel.FILE_EXEC:
            record_builder = AuditBeatJsonBuilder()
            record_builder.set_data("execve")

            # The IN_VERTEX of FILE_EXEC is the caller,
            # in which we need to see if the caller is a Process or another File.
            # if it is a process, then use the EXE as the exe path,
            # otherwise, use the first item in the filename set, which is the name of the file.
            if in_vertex[VertexKey.TYPE_ITEM][
                    ItemKey.VALUE] == VertexType.PROC:
                exe_path = in_vertex[VertexKey.EXE_ITEM][ItemKey.VALUE]
            else:
                exe_path = in_vertex[VertexKey.FILENAME_SET_ITEM][
                    ItemKey.VALUE][0][ItemKey.VALUE]

            record_builder.set_process(
                pid=in_vertex[VertexKey.PID_ITEM][ItemKey.VALUE],
                ppid=in_vertex[VertexKey.PID_ITEM][ItemKey.VALUE],
                exe=exe_path,
            )

            audits.append(record_builder.build())

            # for future encounters, remember the process that
            # invoked code execution from this file.
            out_vertex[VertexKey.PID_ITEM] = {
                ItemKey.VALUE: in_vertex[VertexKey.PID_ITEM][ItemKey.VALUE]
            }

            # use the same node caching check as READ and WRITE,
            # but treat the out_vertex as the vertex which may not yet exist
            # NOTE:
            #   need to confirm that this is the right behavior, but it is indeed increasing FILE node count
            #   post-shadewatcher parsing
            if out_vertex[VertexKey.ID] not in node_cache:
                cache_fd_vertex(out_vertex, caller_vertex=in_vertex)

        elif label == EdgeLabel.IP_CONNECTION_EDGE:
            # NOTE:
            #   this code is very similar to the SocketNode creation
            #   upon reading or writing to a socket that does not yet exist
            node_cache.add(in_vertex[VertexKey.ID])

            # create socket fd
            record_builder = AuditBeatJsonBuilder()
            record_builder.set_data(
                "socket",
                exit_code=in_vertex[VertexKey.FD_ITEM][ItemKey.VALUE],
            )
            record_builder.set_process(
                pid=out_vertex[VertexKey.PID_ITEM][ItemKey.VALUE])

            audits.append(record_builder.build())

            # create connection
            record_builder = AuditBeatJsonBuilder()
            record_builder.set_data(
                "connect",
                # a0=vertex[VertexKey.FD_ITEM][ItemKey.VALUE],
                # socket=dict(),
            )
            record_builder.set_process(
                pid=out_vertex[VertexKey.PID_ITEM][ItemKey.VALUE])
            record_builder.set_destination(
                ip=edge[VertexKey.REMOTE_INET_ADDR_ITEM][ItemKey.VALUE],
                port=edge[VertexKey.REMOTE_PORT_ITEM][ItemKey.VALUE],
            )

            # for future encounters, remember the process that
            # invoked code execution from this file.
            in_vertex[VertexKey.PID_ITEM] = {
                ItemKey.VALUE: out_vertex[VertexKey.PID_ITEM][ItemKey.VALUE]
            }
            
        else:
            print(f'edge: id [{edge[EdgeKey.ID]}] label [{label}] from graph: [{input_path}] not handled.')

    ##############################################
    # Save data to respective files & directories
    ##############################################

    makedirs(output_path, exist_ok=True)
    with open(pathjoin(output_path, "auditbeat"), "w",
              encoding="utf-8") as auditfile:
        auditfile.write("\n".join(map(json.dumps, audits)))

    # PROCINFO
    procinfo_path = pathjoin(output_path, "procinfo")
    makedirs(procinfo_path, exist_ok=True)
    with open(pathjoin(procinfo_path, "args.txt"), "w",
              encoding="utf-8") as proc_args:
        proc_args.write("COMMAND")
        proc_args.write("".join(f'\n{x}' for x in procinfo["args.txt"]))
    with open(pathjoin(procinfo_path, "exe.txt"), "w",
              encoding="utf-8") as proc_exe:
        proc_exe.write("COMMAND")
        proc_exe.write("".join(f'\n{x}' for x in procinfo["exe.txt"]))
    with open(pathjoin(procinfo_path, "general.txt"), "w",
              encoding="utf-8") as proc_general:
        proc_general.write("PLACEHOLDER")
        proc_general.write("".join(f'\n{x}' for x in procinfo["general.txt"]))
        proc_general.write("\x0a")
    with open(pathjoin(procinfo_path, "pid.txt"), "w",
              encoding="utf-8") as proc_pid:
        proc_pid.write("PID")
        proc_pid.write("".join(f'\n{x}' for x in procinfo["pid.txt"]))
    with open(pathjoin(procinfo_path, "ppid.txt"), "w",
              encoding="utf-8") as proc_ppid:
        proc_ppid.write("PPID")
        proc_ppid.write("".join(f'\n{x}' for x in procinfo["ppid.txt"]))

    # SOCKETINFO
    socketinfo_path = pathjoin(output_path, "socketinfo")
    makedirs(socketinfo_path, exist_ok=True)
    with open(pathjoin(socketinfo_path, "device.txt"), "w",
              encoding="utf-8") as socket_device:
        socket_device.write("DEVICE")
        socket_device.write("".join(f'\n{x}'
                                    for x in socketinfo["device.txt"]))
    with open(pathjoin(socketinfo_path, "name.txt"), "w",
              encoding="utf-8") as socket_name:
        socket_name.write("NAME")
        socket_name.write("".join(f'\n{x}' for x in socketinfo["name.txt"]))
    with open(pathjoin(socketinfo_path, "general.txt"), "w",
              encoding="utf-8") as socket_general:
        socket_general.write("PLACEHOLDER")
        socket_general.write("".join(f'\n{x}'
                                     for x in socketinfo["general.txt"]))

    # FDINFO
    fdinfo_path = pathjoin(output_path, "fdinfo")
    makedirs(fdinfo_path, exist_ok=True)
    for name, items in fdinfo.items():
        with open(pathjoin(fdinfo_path, str(name)), "w",
                  encoding="utf-8") as fddir:
            padding = 'lr-x------ 1 root root 64 Oct 31 22:04'
            fddir.write(f"PLACEHOLDER\n{padding} .\n{padding} ..")
            fddir.write("".join(f'\n{padding} {pid} -> {desc}'
                                for pid, desc in items.items()))
            fddir.write("\x0a")
