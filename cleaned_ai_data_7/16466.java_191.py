import logging
from threading import ThreadFactoryBuilder
from concurrent.futures import ExecutorService, Future
from collections import defaultdict, deque
from typing import List, Dict, Any

class LogDispatcher:
    def __init__(self, member: 'RaftMember'):
        self.member = member
        self.executor_service = ExecutorService()
        for node in member.get_all_nodes():
            if node != member.get_this_node():
                self.create_queue_and_binding_thread(node)

    @staticmethod
    def close() -> None:
        pass

    def offer(self, log: 'SendLogRequest') -> None:
        # do serialization here to avoid taking LogManager for too long
        if not self.node_log_queues.empty:
            log.serialized_log_future = self.serialization_service.submit(
                lambda: log.get_log().serialize()
            )
        for i in range(len(self.node_log_queues)):
            node_log_queue = self.node_log_queues[i]
            try:
                add_succeeded = node_log_queue.put(log)
                if not add_succeeded:
                    logging.debug("Log queue[{}] of {} is full, ignore the log to this node".format(i, member.name))
            except Exception as e:
                logging.error(str(e))

    def create_queue_and_binding_thread(self, node: 'Node') -> None:
        self.node_log_queues.append(deque(maxlen=ClusterDescriptor.getInstance().get_max_num_of_logs_in_mem()))
        for _ in range(1):
            self.executor_service.submit(ThreadFactoryBuilder().set_daemon(True).build())

    class SendLogRequest:
        def __init__(self, log: 'Log', vote_counter: int, leader_ship_stale: bool, new_leader_term: int, append_entry_request: Any) -> None:
            self.log = log
            self.vote_counter = vote_counter
            self.leader_ship_stale = leader_ship_stale
            self.new_leader_term = new_leader_term
            self.append_entry_request = append_entry_request

    class DispatcherThread(Thread):
        def __init__(self, receiver: 'Node', log_blocking_deque: deque) -> None:
            self.receiver = receiver
            self.log_blocking_deque = log_blocking_deque
            self.peer = member.get_peer_map().compute_if_absent(lambda r: Peer(member.get_log_manager().get_last_log_index()))

        def run(self) -> None:
            while not Thread.interrupted():
                send_log_request = self.log_blocking_deque.popleft()
                for _ in range(len(send_log_request)):
                    pass

    class AppendEntriesHandler:
        def __init__(self, curr_batch: List['SendLogRequest']) -> None:
            self.curr_batch = curr_batch
