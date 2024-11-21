import logging
from thrift import TException
from thrift.protocol import TProtocol
from thrift.transport import TTransport
from thrift.server import ThreadingServer
from thrift.Thrift import Thrift
from concurrent.futures import ThreadPoolExecutor, as_completed

class LogCatchUpTask:
    def __init__(self, logs: list, node: dict, raft_id: int, raft_member: dict):
        self.logs = logs
        self.node = node
        self.raft_id = raft_id
        self.raft_member = raft_member
        self.use_batch = ClusterDescriptor.getInstance().getConfig().isUseBatchInLogCatchUp()
        self.abort = False

    def do_log_catch_up(self) -> bool:
        for log in self.logs:
            if not self.append_entry(log):
                return False
        return True

    def append_entry(self, log: dict) -> bool:
        request = AppendEntriesRequest()
        request.set_header(raft_member.get_header())
        request.set_leader(raft_member.this_node)
        request.set_leader_commit(raft_member.log_manager.commit_log_index)

        for i in range(len(self.logs)):
            if not self.append_entry_async(log, request):
                return False
        return True

    def append_entry_async(self, log: dict, request: AppendEntriesRequest) -> bool:
        handler = LogCatchUpHandler()
        handler.set_append_succeed(AtomicBoolean(False))
        handler.set_raft_member(raft_member)
        handler.set_follower(node)

        client = raft_member.get_async_client(node)
        if client is None:
            return False
        client.append_entry(request, handler)
        raft_member.last_catch_up_response_time.put(node, int(time.time()))
        handler.wait(SEND_LOGS_WAIT_MS)
        return handler.get_append_succeed().get()

    def do_log_catch_up_in_batch(self) -> bool:
        log_list = []
        total_log_size = 0
        first_log_pos = 0

        for i in range(len(self.logs)):
            if not self.append_entry_async(log, request):
                return False
        return True

class LogCatchUpHandler:
    def __init__(self):
        self.append_succeed = AtomicBoolean(False)
        self.raft_member = None
        self.follower = None
        self.log_list = []

    def set_append_succeed(self, append_succeed: bool) -> None:
        self.append_succeed.set(append_succeed)

    def on_complete(self, result: int) -> None:
        pass

    def onError(self, e: TException) -> None:
        pass
