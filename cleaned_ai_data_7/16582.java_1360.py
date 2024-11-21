import logging
from thrift import TException

class MetaHeartbeatThread:
    def __init__(self, meta_member):
        self.logger = logging.getLogger(__name__)
        self.local_meta_member = meta_member

    def pre_send_heartbeat(self, node):
        if not node.node_identifier_set:
            request.require_identifier = True
        with local_meta_member.id_conflict_nodes_lock():
            request.regenerate_identifier = id_conflict_nodes.contains(node)
        if local_meta_member.is_node_blind(node) and local_meta_member.partition_table is not None:
            self.logger.debug("Sending partition table to {}".format(node))
            request.partition_table_bytes = local_meta_member.partition_table.serialize()
            local_meta_member.remove_blind_node(node)

    def send_heartbeat_sync(self, node):
        self.pre_send_heartbeat(node)
        super().send_heartbeat_sync(node)
        request.partition_table_bytes = None

    def send_heartbeat_async(self, node):
        self.pre_send_heartbeat(node)
        super().send_heartbeat_async(node)
        request.partition_table_bytes = None

    def start_election(self):
        super().start_election()
        if local_meta_member.character == NodeCharacter.LEADER:
            # A new raft leader needs to have at least one log in its term for committing logs with older
            # terms. In the meta group, log frequency is very low.
            self.local_meta_member.append_log_thread_pool.submit(
                lambda: self.local_meta_member.process_empty_content_log()
            )
