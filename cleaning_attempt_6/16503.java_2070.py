import logging
from typing import List, Dict, Any

class SlotPartitionTable:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.slot_strategy = DefaultStrategy()
        self.replication_num = ClusterConstant.SLOT_NUM
        self.multi_raft_factor = ClusterConstant.MULTI_RAFT_FACTOR
        self.node_ring: List[Any] = []
        self.total_slot_numbers: int = 0
        self.last_meta_log_index: int = -1
        self.node_slot_map: Dict[RaftNode, List[int]] = {}
        self.slot_nodes: RaftNode[] = [None for _ in range(ClusterConstant.SLOT_NUM)]
        self.previous_node_map: Dict[RaftNode, Dict[int, PartitionGroup]] = {}
        self.node_removal_result: NodeRemovalResult = SlotNodeRemovalResult()
        self.local_groups: List[PartitionGroup] = []
        self.global_groups: List[PartitionGroup] = []

    def get_slot_strategy(self) -> DefaultStrategy:
        return self.slot_strategy

    def set_slot_strategy(self, slot_strategy: DefaultStrategy):
        self.slot_strategy = slot_strategy

    def get_load_balancer(self) -> SlotBalancer:
        return self.slot_balancer

    def set_load_balancer(self, load_balancer: SlotBalancer):
        self.slot_balancer = load_balancer

    # ... other methods ...
