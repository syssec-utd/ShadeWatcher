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

    # max number of backwards iterations to try and resolve missing resources
    MAX_BACKTRACE = 5

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

    proc_cache = set()
    fd_cache = set()

    def create_initial_state(init_vertex):
        # add a process to the initial state
        if init_vertex[VertexKey.TYPE_ITEM][ItemKey.VALUE] == VertexType.PROC:
            # Proc Load format: https://github.com/jun-zeng/ShadeWatcher/blob/main/parse/parser/kg.cpp#L646
            procinfo["args.txt"].append(init_vertex[VertexKey.CMD_ITEM][ItemKey.VALUE])
            # this exe is an absolute path, which might be a problem
            procinfo["exe.txt"].append(init_vertex[VertexKey.EXE_ITEM][ItemKey.VALUE])
            procinfo["pid.txt"].append(init_vertex[VertexKey.PID_ITEM][ItemKey.VALUE])
            procinfo["ppid.txt"].append(1)

            # used to tell ShadeWatcher how many lines to parse:
            procinfo["general.txt"].append("PLACEHOLDER")

            # Insert empty FD Info for the origin node
            fdinfo[init_vertex[VertexKey.PID_ITEM][ItemKey.VALUE]] = dict()

            proc_cache.add(init_vertex[VertexKey.ID])

        # fabricate a process to stand-in for the file acting as a process source
        # NOTE: this does not mean the actual file descriptor is created
        elif init_vertex[VertexKey.TYPE_ITEM][ItemKey.VALUE] == VertexType.FILE:
            # see: https://github.com/jun-zeng/ShadeWatcher/blob/main/parse/parser/beat/tripletbeat.cpp#LL227C5-L227C5
            # for empty args argument
            procinfo["args.txt"].append("null")
            # this exe is an absolute path, which might be a problem
            filenames = init_vertex[VertexKey.FILENAME_SET_ITEM][ItemKey.VALUE]
            filename = filenames[0][ItemKey.VALUE]
            procinfo["exe.txt"].append(filename)
            procinfo["pid.txt"].append(init_vertex[VertexKey.PID_ITEM][ItemKey.VALUE])
            procinfo["ppid.txt"].append(1)

            # used to tell ShadeWatcher how many lines to parse:
            procinfo["general.txt"].append("PLACEHOLDER")

            # Insert empty FD Info for the origin node
            fdinfo[init_vertex[VertexKey.PID_ITEM][ItemKey.VALUE]] = {
                init_vertex[VertexKey.FD_ITEM][ItemKey.VALUE]: filename
            }

            proc_cache.add(init_vertex[VertexKey.ID])

        else:
            raise Exception("unhandled initialization case")

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

        create_initial_state(vertex)

    ################
    # Process Edges
    ################

    def edge_verticies(edge):
        """Returns a tuple of ( `in_vertex`, `out_vertex` )
        for the forward and backward participants of a graph edge
        """
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

        if VertexKey.FILENAME_SET_ITEM in fd_vertex:
            filenames = fd_vertex[VertexKey.FILENAME_SET_ITEM][ItemKey.VALUE]
        else:
            print(
                f"vertex [{fd_vertex[VertexKey.ID]}] from graph: [{input_path}] is missing 'FILENAME_SET', defaulting to File Descriptor",
                file=sys.stderr,
            )
            filenames = [{ItemKey.VALUE: fd_vertex[VertexKey.FD_ITEM][ItemKey.VALUE]}]

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

        # cache created vertex
        fd_cache.add(fd_vertex[VertexKey.ID])

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
        if (
            VertexKey.REMOTE_INET_ADDR_ITEM in fd_vertex
            and VertexKey.REMOTE_PORT_ITEM in fd_vertex
        ):
            record_builder.set_destination(
                ip=fd_vertex[VertexKey.REMOTE_INET_ADDR_ITEM][ItemKey.VALUE],
                port=fd_vertex[VertexKey.REMOTE_PORT_ITEM][ItemKey.VALUE],
            )
        else:
            print(
                f"vertex [{fd_vertex[VertexKey.ID]}] from graph: [{input_path}]"
                " is missing 'REMOTE_INET_ADDR' or 'REMOTE_PORT' making it a valid socket,"
                " defaulting to 127.0.0.1:8000",
                file=sys.stderr,
            )
            record_builder.set_destination(ip="127.0.0.1", port="8000")

        audits.append(record_builder.build())

        # cache created vertex
        fd_cache.add(fd_vertex[VertexKey.ID])

    def ensure_process(maybe_proc_vertex):
        """Ensure that a vertex is coercible into a existing process,
        meaning it exists within the audit prior to this call.

        If the vertex does not pass this check, then perform the initialization
        of the vertex by processing its parent first or adding it as an inital process.
        """
        if maybe_proc_vertex[VertexKey.ID] in proc_cache:
            return True

        if ensure_process.backtrace_count > MAX_BACKTRACE:
            create_initial_state(maybe_proc_vertex)
            ensure_process.backtrace_count = 0
            return True

        ensure_process.backtrace_count += 1

        # find any edge/event that comes causally before
        # this vertex and process it
        for source_edge in (
            edge
            for edge in graph[GraphKey.EDGES]
            if (
                edge[EdgeKey.LABEL] == EdgeLabel.PROC_CREATE
                and maybe_proc_vertex[VertexKey.ID] == edge[EdgeKey.IN_VERTEX]
            )
            or (
                edge[EdgeKey.LABEL] == EdgeLabel.FILE_EXEC
                and maybe_proc_vertex[VertexKey.ID] == edge[EdgeKey.OUT_VERTEX]
            )
        ):
            handle_edge(source_edge)
            if maybe_proc_vertex[VertexKey.ID] in proc_cache:
                return True

        # when the node has no possible parent,
        # then initialize it as a stand-alone vertex.
        create_initial_state(maybe_proc_vertex)
        ensure_process.backtrace_count = 0
        return True

    # using function to init variable, since functions are objects
    ensure_process.backtrace_count = 0

    def handle_read_edge(edge):
        proc_vertex, fd_vertex = edge_verticies(edge)

        # ensure the out vertex is a coercible into a process
        ensure_process(proc_vertex)

        # ensure the in vertex is a valid file or socket
        if fd_vertex[VertexKey.ID] not in fd_cache:
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

        # ensure the out vertex is a coercible into a process
        ensure_process(proc_vertex)

        # ensure the in vertex is a valid file or socket
        if fd_vertex[VertexKey.ID] not in fd_cache:
            if fd_vertex[VertexKey.TYPE_ITEM][ItemKey.VALUE] == VertexType.FILE:
                open_file(fd_vertex=fd_vertex, proc_vertex=proc_vertex)
            elif fd_vertex[VertexKey.TYPE_ITEM][ItemKey.VALUE] == VertexType.SOCKET:
                open_socket(fd_vertex=fd_vertex, proc_vertex=proc_vertex)

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
            ensure_process(out_vertex)

            record_builder.set_process(
                pid=in_vertex[VertexKey.PID_ITEM][ItemKey.VALUE],
                ppid=out_vertex[VertexKey.PID_ITEM][ItemKey.VALUE],
                exe=in_vertex[VertexKey.EXE_ITEM][ItemKey.VALUE],
                args=in_vertex[VertexKey.CMD_ITEM][ItemKey.VALUE].split(),
            )

            proc_cache.add(in_vertex[VertexKey.ID])

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

            ensure_process(proc_vertex)

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

            proc_cache.add(fd_vertex[VertexKey.ID])

        # if it is a File, create a new PID to represent the new node
        elif in_vertex_type != VertexType.PROC and out_vertex_type != VertexType.PROC:
            ensure_process(proc_vertex)

            filenames = in_vertex[VertexKey.FILENAME_SET_ITEM][ItemKey.VALUE]
            filename = filenames[0][ItemKey.VALUE]

            record_builder.set_process(
                pid=in_vertex[VertexKey.PID_ITEM][ItemKey.VALUE],
                ppid=out_vertex[VertexKey.PID_ITEM][ItemKey.VALUE],
                exe=filename,
            )

            proc_cache.add(in_vertex[VertexKey.ID])

        audits.append(record_builder.build())

    def handle_file_exec_edge(edge):
        exec_caller_vertex, exec_target_vertex = edge_verticies(edge)

        # The IN_VERTEX of FILE_EXEC is the caller,
        # in which we need to see if the caller is a Process or another File.
        ensure_process(exec_caller_vertex)

        # ensure target file exists
        if exec_target_vertex[VertexKey.ID] not in fd_cache:
            open_file(fd_vertex=exec_target_vertex, proc_vertex=exec_caller_vertex)

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

        proc_cache.add(exec_target_vertex[VertexKey.ID])

    def handle_ip_connection_edge(edge):
        fd_vertex, proc_vertex = edge_verticies(edge)
        # ip connection edges are individual socket creation events
        open_socket(fd_vertex=fd_vertex, proc_vertex=proc_vertex)

    def handle_read_write_edge(edge):
        # distinguish between the two cases by identifying which node in the relation is a ProcessNode
        in_vertex, out_vertex = edge_verticies(edge)

        if out_vertex[VertexKey.TYPE_ITEM][ItemKey.VALUE] == VertexType.PROC:
            handle_write_edge(edge)
        elif in_vertex[VertexKey.TYPE_ITEM][ItemKey.VALUE] == VertexType.PROC:
            handle_read_edge(edge)
        else:
            print(
                f"edge [{edge[EdgeKey.ID]}] label [READ_WRITE] from graph: [{input_path}] missing a process in a READ_WRITE relation.",
                file=sys.stderr,
            )

    edge_cache = set()

    def handle_edge(edge):
        # NOTES:
        #   exit_code's of 0 should be used because those result in the entry being ignored
        #   see: https://github.com/jun-zeng/ShadeWatcher/blob/main/parse/parser/beat/tripletbeat.cpp#L688
        #
        #   when creating record for PROC_CREATE, the ppid can be inferred using the outVertex pid

        # skip processed edges
        if edge[EdgeKey.ID] in edge_cache:
            return

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
        elif label == EdgeLabel.READ_WRITE:
            handle_read_write_edge(edge)
        # unhandled edge label
        else:
            return print(
                f"edge [{edge[EdgeKey.ID]}] label [{label}] from graph: [{input_path}] not handled.",
                file=sys.stderr,
            )

        # mark the edge as seen
        edge_cache.add(edge[EdgeKey.ID])

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
        try:
            handle_edge(edge)
        except Exception as e:
            # dont let errors break the entire conversion,
            # that way we can at least debug the issues with the parial dataset
            print(e, file=sys.stderr)

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
