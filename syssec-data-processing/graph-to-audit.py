#!/usr/bin/env python3
"""
Parses a "graph.json" into the format of auditbeat json records and
additional procinfo, fdinfo, and socketinfo directories expected by shadewatcher.
"""

from copy import deepcopy
from os.path import join as pathjoin
from os import makedirs
import sys


class AuditBeatJsonBuilder:
    """Helper class for building auditbeat json records"""

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
            },
        }

        if sequence is not None:
            self.record["auditd"]["sequence"] = sequence
        else:
            self.record["auditd"]["sequence"] = AuditBeatJsonBuilder.sequence_counter
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
        """Return a deep copy of the records dict after performing any required validation"""
        assert "syscall" in self.record["auditd"]["data"]

        return deepcopy(self.record)

    @staticmethod
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

    print(args, file=sys.stderr)

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
    # Enrich the graph Vertices
    ############################

    # allocate pids backwards when we need to fabricate data.
    # mainly used for FILE_EXEC
    pid_allocator = 99999
    # file descriptor serial counter
    fd_allocator = 1

    for vertex in graph[GraphKey.VERTICES]:
        node_type = vertex[VertexKey.TYPE_ITEM][ItemKey.VALUE]

        # add unique file descriptors to the all nodes
        vertex[VertexKey.FD_ITEM] = {ItemKey.VALUE: fd_allocator}
        fd_allocator += 1

        # fabricate PID for resources nodes to avoid errors in edge cases
        # FILE_EXEC, etc.
        if VertexKey.PID_ITEM not in vertex:
            # add unique file descriptors to the all nodes
            vertex[VertexKey.PID_ITEM] = {ItemKey.VALUE: pid_allocator}
            pid_allocator -= 1

    ############################
    # Process initial Vertices
    ############################

    vertex_cache = set()

    # find all processes that are either root nodes of the tree or disconnected
    for vertex in graph[GraphKey.VERTICES]:
        # only look at PROC vertices
        is_proc = vertex[VertexKey.TYPE_ITEM][ItemKey.VALUE] == VertexType.PROC
        if not is_proc:
            continue

        # none of the PROC_CREATE edges have this node as the outVertex
        is_child = any(
            e[EdgeKey.IN_VERTEX] == vertex[VertexKey.ID]
            for e in graph[GraphKey.EDGES]
            if e[EdgeKey.LABEL] == EdgeLabel.PROC_CREATE
        )
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

        vertex_cache.add(vertex[VertexKey.ID])

    ################
    # Process Edges
    ################

    def edge_verticies(edge):
        """Return a tuple of (in_vertex, out_vertex) for the in and out verticies of a graph edge"""
        return (
            vertex_table[edge[EdgeKey.IN_VERTEX]],
            vertex_table[edge[EdgeKey.OUT_VERTEX]],
        )

    def open_file(fd_vertex, proc_vertex):
        record_builder = AuditBeatJsonBuilder()
        record_builder.set_data(
            "open",
            exit_code=fd_vertex[VertexKey.FD_ITEM][ItemKey.VALUE],
        )
        record_builder.set_process(
            pid=proc_vertex[VertexKey.PID_ITEM][ItemKey.VALUE],
            cwd="/",
        )
        filenames = fd_vertex[VertexKey.FILENAME_SET_ITEM][ItemKey.VALUE]
        record_builder.set_paths(
            [
                AuditBeatJsonBuilder.create_path(
                    name=filename[ItemKey.VALUE],
                    # flag: https://github.com/jun-zeng/ShadeWatcher/blob/main/parse/parser/beat/tripletbeat.cpp#L364
                    nametype="CREATE",
                )
                for filename in filenames
            ]
        )

        audits.append(record_builder.build())

        # set the fd vertex to remember the PID of its creator.
        # used to handle the cases of FILE_EXEC
        fd_vertex[VertexKey.PID_ITEM] = {
            ItemKey.VALUE: proc_vertex[VertexKey.PID_ITEM][ItemKey.VALUE]
        }

        # cache created vertex
        vertex_cache.add(fd_vertex[VertexKey.ID])

    def open_socket(fd_vertex, proc_vertex):
        # create socket fd
        record_builder = AuditBeatJsonBuilder()
        record_builder.set_data(
            "socket",
            exit_code=fd_vertex[VertexKey.FD_ITEM][ItemKey.VALUE],
        )
        record_builder.set_process(pid=proc_vertex[VertexKey.PID_ITEM][ItemKey.VALUE])

        audits.append(record_builder.build())

        # create connection
        record_builder = AuditBeatJsonBuilder()
        record_builder.set_data(
            "connect",
            # a0=vertex[VertexKey.FD_ITEM][ItemKey.VALUE],
            # socket=dict(),
        )
        record_builder.set_process(pid=proc_vertex[VertexKey.PID_ITEM][ItemKey.VALUE])
        record_builder.set_destination(
            ip=fd_vertex[VertexKey.REMOTE_INET_ADDR_ITEM][ItemKey.VALUE],
            port=fd_vertex[VertexKey.REMOTE_PORT_ITEM][ItemKey.VALUE],
        )

        audits.append(record_builder.build())

        # set the fd vertex to remember the PID of its creator.
        # used to handle the cases of FILE_EXEC
        fd_vertex[VertexKey.PID_ITEM] = {
            ItemKey.VALUE: proc_vertex[VertexKey.PID_ITEM][ItemKey.VALUE]
        }

        # cache created vertex
        vertex_cache.add(fd_vertex[VertexKey.ID])

    def ensure_process(vertex):
        """Ensure that a process exists by auditing its parent first or adding it as an inital process"""
        if vertex[VertexKey.ID] in vertex_cache:
            return

        vertex_cache.add(vertex[VertexKey.ID])
        return False

    def handle_read_edge(edge):
        proc_vertex, fd_vertex = edge_verticies(edge)

        # ensure the out vertex is a valid process
        if proc_vertex[VertexKey.ID] not in vertex_cache:
            print(
                f"read edge: id [{edge[EdgeKey.ID]}] label [{label}] from graph: [{input_path}] missing process",
                file=sys.stderr,
            )

        # ensure the in vertex is a valid file or socket
        if fd_vertex[VertexKey.ID] not in vertex_cache:
            if fd_vertex[VertexKey.TYPE_ITEM][ItemKey.VALUE] == VertexType.FILE:
                open_file(fd_vertex=fd_vertex, proc_vertex=proc_vertex)
            elif fd_vertex[VertexKey.TYPE_ITEM][ItemKey.VALUE] == VertexType.SOCKET:
                open_socket(fd_vertex=fd_vertex, proc_vertex=proc_vertex)

        record_builder = AuditBeatJsonBuilder()
        record_builder.set_data(
            "read",
            exit_code=1,
            a0=fd_vertex[VertexKey.FD_ITEM][ItemKey.VALUE],
        )
        record_builder.set_process(
            # Read is a directed edge from the FileNode -> ProcessNode
            pid=proc_vertex[VertexKey.PID_ITEM][ItemKey.VALUE]
        )

        audits.append(record_builder.build())

    def handle_write_edge(edge):
        fd_vertex, proc_vertex = edge_verticies(edge)

        # ensure the out vertex is a valid process
        if proc_vertex[VertexKey.ID] not in vertex_cache:
            print(
                f"write edge: id [{edge[EdgeKey.ID]}] label [{label}] from graph: [{input_path}] missing process",
                file=sys.stderr,
            )

        # ensure the in vertex is a valid file or socket
        if fd_vertex[VertexKey.ID] not in vertex_cache:
            if fd_vertex[VertexKey.TYPE_ITEM][ItemKey.VALUE] == VertexType.FILE:
                open_file(fd_vertex=fd_vertex, proc_vertex=proc_vertex)
            elif fd_vertex[VertexKey.TYPE_ITEM][ItemKey.VALUE] == VertexType.SOCKET:
                open_socket(fd_vertex=fd_vertex, proc_vertex=proc_vertex)

            vertex_cache.add(fd_vertex[VertexKey.ID])

        record_builder = AuditBeatJsonBuilder()
        record_builder.set_data(
            "write",
            exit_code=1,
            a0=proc_vertex[VertexKey.FD_ITEM][ItemKey.VALUE],
        )
        record_builder.set_process(
            # Read is a directed edge from the FileNode <- ProcessNode
            pid=fd_vertex[VertexKey.PID_ITEM][ItemKey.VALUE]
        )

        audits.append(record_builder.build())

    def handle_proc_create_edge(edge):
        in_vertex, out_vertex = edge_verticies(edge)

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

            vertex_cache.add(in_vertex[VertexKey.ID])

        # if a process is interacting with a file in a PROC_CREATE,
        # then reorient the relationship to from process to file
        elif (
            in_vertex_type == VertexType.PROC
            and out_vertex_type != VertexType.PROC
            or in_vertex_type != VertexType.PROC
            and out_vertex_type == VertexType.PROC
        ):
            if in_vertex_type == VertexType.PROC:
                proc_vertex, fd_vertex = (in_vertex, out_vertex)
            else:
                proc_vertex, fd_vertex = (out_vertex, in_vertex)

            if fd_vertex[VertexKey.TYPE_ITEM][ItemKey.VALUE] == VertexType.FILE:
                filenames = fd_vertex[VertexKey.FILENAME_SET_ITEM][ItemKey.VALUE]
                exe_path = filenames[0][ItemKey.VALUE]
            elif fd_vertex[VertexKey.TYPE_ITEM][ItemKey.VALUE] == VertexType.SOCKET:
                exe_path = proc_vertex[VertexKey.CMD_ITEM][ItemKey.VALUE]

            record_builder.set_process(
                pid=fd_vertex[VertexKey.PID_ITEM][ItemKey.VALUE],
                ppid=proc_vertex[VertexKey.PID_ITEM][ItemKey.VALUE],
                exe=exe_path,
            )

            vertex_cache.add(fd_vertex[VertexKey.ID])

        # if it is a File, create a new PID to represent the new node
        elif in_vertex_type != VertexType.PROC and out_vertex_type != VertexType.PROC:
            filenames = in_vertex[VertexKey.FILENAME_SET_ITEM][ItemKey.VALUE]

            record_builder.set_process(
                pid=in_vertex[VertexKey.PID_ITEM][ItemKey.VALUE],
                ppid=out_vertex[VertexKey.PID_ITEM][ItemKey.VALUE],
                exe=filenames[0][ItemKey.VALUE],
            )

            vertex_cache.add(in_vertex[VertexKey.ID])

        audits.append(record_builder.build())

    def handle_file_exec_edge(edge):
        exec_caller_vertex, exec_target_vertex = edge_verticies(edge)

        # ensure target file exists
        if exec_target_vertex[VertexKey.ID] not in vertex_cache:
            open_file(fd_vertex=exec_target_vertex, proc_vertex=exec_caller_vertex)

        # The IN_VERTEX of FILE_EXEC is the caller,
        # in which we need to see if the caller is a Process or another File.
        # if it is a process, then use the EXE as the exe path,
        # otherwise, use the first item in the filename set, which is the name of the file.
        if exec_caller_vertex[VertexKey.TYPE_ITEM][ItemKey.VALUE] == VertexType.PROC:
            exe_path = exec_caller_vertex[VertexKey.EXE_ITEM][ItemKey.VALUE]
        else:
            filenames = exec_caller_vertex[VertexKey.FILENAME_SET_ITEM][ItemKey.VALUE]
            exe_path = filenames[0][ItemKey.VALUE]

        record_builder = AuditBeatJsonBuilder()
        record_builder.set_data("execve")
        record_builder.set_process(
            pid=exec_caller_vertex[VertexKey.PID_ITEM][ItemKey.VALUE],
            ppid=exec_caller_vertex[VertexKey.PID_ITEM][ItemKey.VALUE],
            exe=exe_path,
        )

        audits.append(record_builder.build())

        # for future encounters, remember the process that
        # invoked code execution from this file.
        exec_target_vertex[VertexKey.PID_ITEM] = {
            ItemKey.VALUE: exec_caller_vertex[VertexKey.PID_ITEM][ItemKey.VALUE]
        }

    def handle_ip_connection_edge(edge):
        fd_vertex, proc_vertex = edge_verticies(edge)
        # ip connection edges are individual socket creation events
        open_socket(fd_vertex=fd_vertex, proc_vertex=proc_vertex)

    def is_initial_pid(vertex):
        """Find out if this is in the inital procinfo set"""
        return (
            vertex[VertexKey.TYPE_ITEM][ItemKey.VALUE] == VertexType.PROC
            and vertex[VertexKey.PID_ITEM][ItemKey.VALUE] in procinfo["pid.txt"]
        )

    # process edges into the audits
    # sorted by timestamp to preserve causal orderings
    for edge in sorted(
        graph[GraphKey.EDGES],
        key=lambda e: (
            # prioritize edges with a process that way we can initialize
            # nodes which require a source pid.
            0
            if VertexType.PROC
            in [
                vertex_table[e[EdgeKey.OUT_VERTEX]][VertexKey.TYPE_ITEM][ItemKey.VALUE],
                vertex_table[e[EdgeKey.IN_VERTEX]][VertexKey.TYPE_ITEM][ItemKey.VALUE],
            ]
            else 1,
            # sort by timestamp
            e[EdgeKey.TIME_START_ITEM][ItemKey.VALUE],
            # processes must come before process edges
            0 if e[EdgeKey.LABEL] == EdgeLabel.PROC_CREATE else 1,
            # priority to processes that belong in the system initial state
            0 if is_initial_pid(vertex_table[e[EdgeKey.OUT_VERTEX]]) else 1,
        ),
    ):
        # NOTES:
        #   exit_code's of 0 should be used because those result in the entry being ignored
        #   see: https://github.com/jun-zeng/ShadeWatcher/blob/main/parse/parser/beat/tripletbeat.cpp#L688
        #
        #   when creating record for PROC_CREATE, the ppid can be inferred using the outVertex pid
        label = edge[EdgeKey.LABEL]

        # adds a read interaction from file (OUT) -> process (IN)
        if label == EdgeLabel.READ:
            handle_read_edge(edge)
        # adds a write interaction from process (OUT) -> file (IN)
        elif label == EdgeLabel.WRITE:
            handle_write_edge(edge)
        # signals the creation of one process from another (PARENT) -> (CHILD)
        elif label == EdgeLabel.PROC_CREATE:
            handle_proc_create_edge(edge)
        # signals the creation of one process from a file execution
        elif label == EdgeLabel.FILE_EXEC:
            handle_file_exec_edge(edge)
        # creates a new IP connection socket
        elif label == EdgeLabel.IP_CONNECTION_EDGE:
            handle_ip_connection_edge(edge)
        # overloaded Relation capturing both READ and WRITE events.
        # distinguish between the two cases by identifying which node in the relation is a ProcessNode
        elif label == EdgeLabel.READ_WRITE:
            in_vertex, out_vertex = edge_verticies(edge)

            if out_vertex[VertexKey.TYPE_ITEM][ItemKey.VALUE] == VertexType.PROC:
                handle_write_edge(edge)
            elif in_vertex[VertexKey.TYPE_ITEM][ItemKey.VALUE] == VertexType.PROC:
                handle_read_edge(edge)

        # unhandled edge label
        else:
            print(
                f"edge: id [{edge[EdgeKey.ID]}] label [{label}] from graph: [{input_path}] not handled.",
                file=sys.stderr,
            )

    ##############################################
    # Save data to respective files & directories
    ##############################################

    makedirs(output_path, exist_ok=True)
    with open(pathjoin(output_path, "auditbeat"), "w", encoding="utf-8") as auditfile:
        auditfile.write("\n".join(map(json.dumps, audits)))

    # PROCINFO
    procinfo_path = pathjoin(output_path, "procinfo")
    makedirs(procinfo_path, exist_ok=True)
    with open(pathjoin(procinfo_path, "args.txt"), "w", encoding="utf-8") as proc_args:
        proc_args.write("COMMAND")
        proc_args.write("".join(f"\n{x}" for x in procinfo["args.txt"]))
    with open(pathjoin(procinfo_path, "exe.txt"), "w", encoding="utf-8") as proc_exe:
        proc_exe.write("COMMAND")
        proc_exe.write("".join(f"\n{x}" for x in procinfo["exe.txt"]))
    with open(
        pathjoin(procinfo_path, "general.txt"), "w", encoding="utf-8"
    ) as proc_general:
        proc_general.write("PLACEHOLDER")
        proc_general.write("".join(f"\n{x}" for x in procinfo["general.txt"]))
        proc_general.write("\x0a")
    with open(pathjoin(procinfo_path, "pid.txt"), "w", encoding="utf-8") as proc_pid:
        proc_pid.write("PID")
        proc_pid.write("".join(f"\n{x}" for x in procinfo["pid.txt"]))
    with open(pathjoin(procinfo_path, "ppid.txt"), "w", encoding="utf-8") as proc_ppid:
        proc_ppid.write("PPID")
        proc_ppid.write("".join(f"\n{x}" for x in procinfo["ppid.txt"]))

    # SOCKETINFO
    socketinfo_path = pathjoin(output_path, "socketinfo")
    makedirs(socketinfo_path, exist_ok=True)
    with open(
        pathjoin(socketinfo_path, "device.txt"), "w", encoding="utf-8"
    ) as socket_device:
        socket_device.write("DEVICE")
        socket_device.write("".join(f"\n{x}" for x in socketinfo["device.txt"]))
    with open(
        pathjoin(socketinfo_path, "name.txt"), "w", encoding="utf-8"
    ) as socket_name:
        socket_name.write("NAME")
        socket_name.write("".join(f"\n{x}" for x in socketinfo["name.txt"]))
    with open(
        pathjoin(socketinfo_path, "general.txt"), "w", encoding="utf-8"
    ) as socket_general:
        socket_general.write("PLACEHOLDER")
        socket_general.write("".join(f"\n{x}" for x in socketinfo["general.txt"]))

    # FDINFO
    fdinfo_path = pathjoin(output_path, "fdinfo")
    makedirs(fdinfo_path, exist_ok=True)
    for name, items in fdinfo.items():
        with open(pathjoin(fdinfo_path, str(name)), "w", encoding="utf-8") as fddir:
            PADDING = "lr-x------ 1 root root 64 Oct 31 22:04"
            fddir.write(f"PLACEHOLDER\n{PADDING} .\n{PADDING} ..")
            fddir.write(
                "".join(f"\n{PADDING} {pid} -> {desc}" for pid, desc in items.items())
            )
            fddir.write("\x0a")
