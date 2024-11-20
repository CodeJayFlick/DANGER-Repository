import collections

class SlotTimePartitionFilter:
    def __init__(self, slot_set):
        self.slot_set = set(slot_set)

    def satisfy(self, storage_group_name: str, time_partition_id: int) -> bool:
        slot = SlotPartitionTable.get_slot_strategy().calculate_slot_by_partition_num(
            storage_group_name, time_partition_id, ClusterConstant.SLOT_NUM
        )
        return slot in self.slot_set

    def __eq__(self, other):
        if not isinstance(other, SlotTimePartitionFilter):
            return False
        return self.slot_set == other.slot_set

    def __hash__(self) -> int:
        return hash(self.slot_set)
