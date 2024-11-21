class ClusterMonitor:
    def __init__(self):
        pass

    # Show the character of meta raft group.
    def get_meta_group(self) -> list[tuple[Node, NodeCharacter]]:
        return []

    # Show the character of target data raft group whose header is this node.
    def get_data_group(self, raft_id: int) -> tuple[list[tuple[Node, NodeCharacter]], Exception]:
        raise Exception

    # Query how many slots are still PULLING or PULLING_ WRITABLE, it means whether user can add/remove a node.
    def get_slot_num_in_data_migration(self) -> dict:
        return {}

    # Get data partition information of input path and time range.
    def get_data_partition(self, path: str, start_time: int, end_time: int) -> MultiKeyMap[Long, PartitionGroup]:
        from collections import defaultdict
        return defaultdict(dict)

    # Get metadata partition information of input path.
    def get_meta_partition(self, path: str) -> PartitionGroup:
        raise Exception

    # Get all data partition groups and the slot number in each partition group.
    def get_slot_num_of_all_node(self) -> dict:
        return {}

    # Get status of all nodes.
    def get_all_node_status(self) -> dict:
        return {}

    # Return a multi-line string with each line representing the total time consumption, invocation number, and average time consumption.
    def get_instrumenting_info(self) -> str:
        return ''

    # Reset all instrumenting statistics in Timer.
    def reset_instrumenting(self):
        pass
