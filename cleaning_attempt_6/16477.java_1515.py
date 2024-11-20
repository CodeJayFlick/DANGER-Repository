import logging
from collections import defaultdict, OrderedDict

class PartitionedSnapshotLogManager:
    def __init__(self,
                 log_applier,
                 partition_table,
                 this_node,
                 factory,
                 data_group_member):
        self.logger = logging.getLogger(__name__)
        self.slot_snapshots = {}
        self.factory = factory
        self.partition_table = partition_table
        self.this_node = this_node
        self.data_group_member = data_group_member

    def take_snapshot_for_specific_slots(self, required_slots, need_leader=False):
        # TO DO: implement me!
        pass

    def get_snapshot(self, min_index):
        with lock(self.slot_snapshots):
            partitioned_snapshot = PartitionedSnapshot(self.factory)
            for slot, snapshot in self.slot_snapshots.items():
                partitioned_snapshot.put_snapshot(slot, snapshot)
            partitioned_snapshot.set_last_log_index(self.snapshot_last_log_index)
            partitioned_snapshot.set_last_log_term(self.snapshot_last_log_term)
            partitioned_snapshot.truncate_before(min_index)
            return partitioned_snapshot

    def collect_timeseries_schemas(self, required_slots):
        self.slot_timeseries = defaultdict(set)
        all_sg_paths = IoTDB.meta_manager.get_all_storage_group_paths()
        for sg_path in all_sg_paths:
            storage_group_name = sg_path.full_path
            slot = SlotPartitionTable.calculate_slot_by_time(storage_group_name, 0, ClusterConstant.SLOT_NUM)
            if slot not in required_slots:
                continue
            schemas = self.slot_timeseries[slot]
            IoTDB.meta_manager.collect_timeseries_schema(sg_path, schemas)
            self.logger.debug(f"{self.name}: {len(schemas)} timeseries are snapshoted in slot {slot}")

class PartitionedSnapshot:
    def __init__(self, factory):
        self.snapshots = {}
        self.last_log_index = 0
        self.last_log_term = 0

    def put_snapshot(self, slot, snapshot):
        self.snapshots[slot] = snapshot

    def set_last_log_index(self, index):
        self.last_log_index = index

    def set_last_log_term(self, term):
        self.last_log_term = term

    def truncate_before(self, min_index):
        for slot in list(self.snapshots.keys()):
            if self.snapshots[slot].last_log_index < min_index:
                del self.snapshots[slot]
