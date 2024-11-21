Here's your Java code translated into Python:

```Python
import logging

class SlotTSFileFilter:
    def __init__(self, slots):
        self.slots = set(slots)

    @staticmethod
    def file_not_in_slots(resource, node_slots):
        sg_name_and_partition_id_pair = FilePathUtils.get_logical_sg_name_and_time_partition_id_pair(
            resource.ts_file_path)
        slot = SlotPartitionTable.get_slot_strategy().calculate_slot_by_partition_num(
            sg_name_and_partition_id_pair[0],
            sg_name_and_partition_id_pair[1],
            ClusterConstant.SLOT_NUM
        )
        contained = slot in node_slots
        logging.debug(f"The slot of {resource.ts_file_path} is {slot}, contained: {contained}")
        return not contained

    def file_not_satisfy(self, resource):
        return self.file_not_in_slots(resource, self.slots)
```

Please note that you'll need to implement the following functions yourself:

- `FilePathUtils.get_logical_sg_name_and_time_partition_id_pair()`
- `SlotPartitionTable.get_slot_strategy().calculate_slot_by_partition_num()`
- `ClusterConstant.SLOT_NUM`