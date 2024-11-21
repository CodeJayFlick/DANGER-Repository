import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Iterator

class PullSnapshotHintService:
    def __init__(self, member):
        self.member = member
        self.hints = []

    def start(self):
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.executor.submit(self.send_hints)

    def stop(self):
        if self.executor is not None:
            self.executor.shutdown()

    def register_hint(self, descriptor: 'PullSnapshotTaskDescriptor'):
        hint = PullSnapshotHint()
        hint.partition_group = descriptor.get_previous_holders()
        hint.receivers = PartitionGroup(hint.partition_group)
        hint.slots = descriptor.get_slots()
        self.hints.append(hint)

    def send_hints(self):
        for hint in self.hints:
            receivers = hint.receivers
            for receiver in receivers:
                if not member.meta_group_member.partition_table.all_nodes.contains(receiver):
                    receivers.remove(receiver)
                else:
                    try:
                        logging.debug(f"{member.name}: start to send hint to target group {hint.partition_group}, receiver {receiver}, slot is {hint.slots[0]} and other {len(hint.slots) - 1}")
                        result = self.send_hint(receiver, hint)
                        if result:
                            receivers.remove(receiver)
                    except TException as e:
                        logging.warn(f"Cannot send pull snapshot hint to {receiver}")
                    except InterruptedException as e:
                        Thread.current_thread().interrupt()
                        logging.warn("Sending hint to {} interrupted".format(receiver))

            # all nodes in remote group know the hint, the hint can be removed
            if receivers.is_empty():
                self.hints.remove(hint)

    def send_hint(self, receiver: 'Node', hint):
        try:
            return SyncClientAdaptor.on_snapshot_applied(member.async_client(receiver), hint.header(), hint.slots)
        except TException as e:
            logging.warn(f"Cannot send pull snapshot hint to {receiver}")
        except InterruptedException as e:
            Thread.current_thread().interrupt()
            logging.warn("Sending hint to {} interrupted".format(receiver))

class PullSnapshotHint:
    def __init__(self):
        self.receivers = None
        self.partition_group = None
        self.slots = []

    @property
    def header(self) -> 'RaftNode':
        return self.partition_group.header

    @property
    def raft_id(self) -> int:
        return self.receivers.id


class PartitionGroup:
    def __init__(self, partition_group):
        self._partition_group = partition_group

    @property
    def id(self) -> int:
        return self._partition_group.id

    @property
    def header(self) -> 'RaftNode':
        return self._partition_group.header


class RaftNode:
    pass  # This class is not implemented in the original Java code, so it's left as a placeholder.
