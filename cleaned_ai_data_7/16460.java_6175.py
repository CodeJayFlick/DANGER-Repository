import logging
from thrift import TException
from concurrent.futures import Future
from typing import List

class SnapshotCatchUpTask:
    def __init__(self, logs: List['Log'], snapshot: 'Snapshot', node: 'Node', raft_id: int, raft_member: 'RaftMember'):
        self.logger = logging.getLogger(__name__)
        self.snapshot = snapshot
        super().__init__(logs, node, raft_id, raft_member)

    def do_snapshot_catch_up(self) -> None:
        request = SendSnapshotRequest()
        if raft_member.header is not None:
            request.set_header(raft_member.header)
        self.logger.info("Start to send snapshot to %s", node)
        data = self.snapshot.serialize()
        if self.logger.isEnabledFor(logging.INFO):
            self.logger.info("Do snapshot catch up with size %d", len(data))
        request.set_snapshot_bytes(data)

        with raft_member.term:
            # make sure this node is still a leader
            if raft_member.character != NodeCharacter.LEADER:
                raise LeaderUnknownException(raft_member.all_nodes)
        
        if ClusterDescriptor.getInstance().getConfig().is_use_async_server():
            abort = not self.send_snapshot_async(request)
        else:
            abort = not self.send_snapshot_sync(request)

    def send_snapshot_async(self, request: 'SendSnapshotRequest') -> Future[bool]:
        succeed = AtomicBoolean(False)
        handler = SnapshotCatchUpHandler(succeed, node, snapshot)
        client = raft_member.get_async_client(node)
        if client is None:
            self.logger.info("%s: client null for node %s", raft_member.this_node, node)
            abort = True
            return False

        self.logger.info("Send snapshot request size=%d to %s", len(request.snapshot_bytes), node)

        with succeed:
            client.send_snapshot(request, handler)
            raft_member.last_catch_up_response_time[node] = int(time.time())
            succeed.wait(SEND_SNAPSHOT_WAIT_MS)

        if self.logger.isEnabledFor(logging.INFO):
            self.logger.info("Send snapshot to %s success=%d", raft_member.this_node, succeed.get())

        return succeed

    def send_snapshot_sync(self, request: 'SendSnapshotRequest') -> bool:
        self.logger.info("%s: sending a snapshot request size=%d to %s", raft_member.name, len(request.snapshot_bytes), node)
        client = raft_member.get_sync_client(node)
        if client is None:
            return False

        try:
            client.send_snapshot(request)
            self.logger.info("%s: snapshot is sent to %s", raft_member.name, node)
            return True
        except TException as e:
            client.input_protocol.transport.close()
            raise e
        finally:
            ClientUtils.put_back_sync_client(client)

    def call(self) -> bool:
        do_snapshot_catch_up()

        if abort:
            self.logger.warn("%s: Snapshot catch up %s failed", raft_member.name, node)
            del raft_member.last_catch_up_response_time[node]
            return False

        self.logger.info("%s: Snapshot catch up %s finished, begin to catch up log", raft_member.name, node)
        do_log_catch_up()

        if not abort:
            self.logger.info("%s: Catch up %s finished", raft_member.name, node)
        else:
            self.logger.warn("%s: Log catch up %s failed", raft_member.name, node)

        # the next catch up is enabled
        del raft_member.last_catch_up_response_time[node]
        return not abort

class SendSnapshotRequest:
    def __init__(self):
        pass

    def set_header(self, header):
        self.header = header

    def set_snapshot_bytes(self, data: bytes):
        self.snapshot_bytes = data

class SnapshotCatchUpHandler:
    def __init__(self, succeed: 'AtomicBoolean', node: 'Node', snapshot: 'Snapshot'):
        self.succeed = succeed
        self.node = node
        self.snapshot = snapshot

# Note that the following classes are not implemented in Python as they seem to be part of a larger system.
class Log:
    pass

class Snapshot:
    def serialize(self) -> bytes:
        pass

class NodeCharacter:
    LEADER = 0

class LeaderUnknownException(Exception):
    pass
