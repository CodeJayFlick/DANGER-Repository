import logging
from typing import List, Dict, Set

class FilePartitionedSnapshotLogManager:
    def __init__(self,
                 log_applier: object,
                 partition_table: object,
                 header_node: object,
                 this_node: object,
                 data_group_member: object):
        self.logger = logging.getLogger(__name__)
        super().__init__(log_applier, partition_table, header_node, this_node, Factory.INSTANCE, data_group_member)

    def sync_flush_all_processor(self, required_slots: List[int], need_leader: bool) -> None:
        self.logger.info(f"{self.getName()}: Start flush all storage group processor in one data group")
        working_storage_groups = StorageEngine.getInstance().get_working_storage_group_partitions()
        if not working_storage_groups:
            self.logger.info(f"{self.getName()}: no need to flush processor")
            return
        self.data_group_member.flush_file_when_do_snapshot(working_storage_groups, required_slots, need_leader)

    def take_snapshot(self) -> None:
        self.take_snapshot_for_specific_slots(
            (SlotPartitionTable)(partition_table).get_node_slots(data_group_member.get_header()), True)
        StorageEngine.getInstance().reset_block_applied_commit_index()

    def take_snapshot_for_specific_slots(self, required_slots: List[int], need_leader: bool) -> None:
        try:
            self.logger.info(f"{self.getName()}: Taking snapshots, flushing IoTDB")
            # record current commit index and prevent further logs from being applied
            set_block_applied_commit_index(get_commit_log_index())
            super().take_snapshot()
            sync_flush_all_processor(required_slots, need_leader)
            self.logger.info(f"{self.getName()}: Taking snapshots, IoTDB is flushed")

        except EntryCompactedException as e:
            self.logger.error("failed to do snapshot.", e)

    def collect_timeseries_schemas(self, required_slots: List[int]) -> None:
        for entry in slot_timeseries.items():
            if slots and not slots.contains(entry.key):
                continue
            file_snapshot = slot_snapshots.setdefault(entry.key, FileSnapshot())
            if not file_snapshot.get_timeseries_schemas():
                file_snapshot.set_timeseries_schemas(entry.value)

    def collect_ts_files(self) -> None:
        self.slot_snapshots.clear()
        all_closed_storage_group_ts_file = StorageEngine.getInstance().get_all_closed_storage_group_ts_file()
        created_hardlinks = []
        for entry in all_closed_storage_group_ts_file.items():
            partial_path, storage_groups_files = entry
            for partition_num, resource_list in storage_groups_files.items():
                if not collect_ts_files(partition_num, resource_list, partial_path, created_hardlinks):
                    # some file is deleted during the collecting, clean created hardlinks and restart from the beginning
                    for created_hardlink in created_hardlinks:
                        created_hardlink.remove()
                    self.collect_ts_files(required_slots)
                    return

    def collect_ts_files(self,
                          partition_num: int,
                          resource_list: List[object],
                          partial_path: object,
                          created_hardlinks: List[object],
                          required_slots: List[int]) -> bool:
        slot_num = SlotPartitionTable.get_slot_strategy().calculate_slot_by_partition_num(
            partial_path, partition_num, ClusterConstant.SLOT_NUM)
        if not required_slots.contains(slot_num):
            return True
        file_snapshot = self.slot_snapshots.setdefault(slot_num, FileSnapshot())
        for ts_file_resource in resource_list:
            hardlink = ts_file_resource.create_hardlink()
            created_hardlinks.append(hardlink)
            logger.debug(f"{self.getName()}: File {ts_file_resource} is put into snapshot #{slot_num}")
            file_snapshot.add_file(hardlink, this_node, self.is_plan_index_range_unique(ts_file_resource, resource_list))
        return True

    def is_plan_index_range_unique(self,
                                    ts_file_resource: object,
                                    others: List[object]) -> bool:
        for other in others:
            if other != ts_file_resource and other.is_plan_index_overlap(ts_file_resource):
                return False
        return True

    @property
    def getName(self) -> str:
        pass  # implement this method to get the name of your class

class FileSnapshot:
    def __init__(self):
        self.timeseries_schemas = []
        self.data_files = []

    def add_file(self, hardlink: object, node: object, is_plan_index_range_unique: bool) -> None:
        pass  # implement this method to add a file into the snapshot

class Factory:
    @staticmethod
    def INSTANCE() -> 'Factory':
        return Factory()

# usage example
log_applier = LogApplier()
partition_table = PartitionTable()
header_node = Node()
this_node = Node()
data_group_member = DataGroupMember()
file_partitioned_snapshot_log_manager = FilePartitionedSnapshotLogManager(
    log_applier,
    partition_table,
    header_node,
    this_node,
    data_group_member)
