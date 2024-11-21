import logging
from typing import List

class InplaceCompactionTask:
    def __init__(self,
                 logical_storage_group_name: str,
                 virtual_storage_group_name: str,
                 time_partition_id: int,
                 merge_resource: 'CrossSpaceMergeResource',
                 storage_group_dir: str,
                 seq_ts_file_resource_list: 'TsFileResourceList',
                 unseq_ts_file_resource_list: 'TsFileResourceList',
                 selected_seq_ts_file_resources: List['TsFileResource'],
                 selected_unseq_ts_file_resources: List['TsFileResource'],
                 concurrent_merge_count: int) -> None:
        self.logical_storage_group_name = logical_storage_group_name
        self.virtual_storage_group_name = virtual_storage_group_name
        self.merge_resource = merge_resource
        self.storage_group_dir = storage_group_dir
        self.seq_ts_file_resource_list = seq_ts_file_resource_list
        self.unseq_ts_file_resource_list = unseq_ts_file_resource_list
        self.selected_seq_ts_file_resources = selected_seq_ts_file_resources
        self.selected_unseq_ts_file_resources = selected_unseq_ts_file_resources
        self.concurrent_merge_count = concurrent_merge_count

    def do_compaction(self) -> None:
        task_name = f"{self.full_storage_group_name}-{int(time.time())}"
        merge_task = CrossSpaceMergeTask(
            self.merge_resource,
            self.storage_group_dir,
            self.merge_end_action,
            task_name,
            IoTDBDescriptor.getInstance().getConfig().is_force_full_merge(),
            self.concurrent_merge_count,
            self.logical_storage_group_name
        )
        merge_task.call()

    def merge_end_action(self, seq_files: List['TsFileResource'], unseq_files: List['TsFileResource'], merge_log: 'Path') -> None:
        logging.info(f"{self.full_storage_group_name} a merge task is ending...")
        
        if Thread.current_thread().is_interrupted() or not unseq_files:
            # merge task abort, or merge runtime exception arose, just end this merge
            logging.info(f"{self.full_storage_group_name} a merge task abnormally ends")
            return
        
        self.remove_unseq_files(unseq_files)
        
        for i in range(len(seq_files)):
            seq_file = seq_files[i]
            # get both seqFile lock and merge lock
            self.double_write_lock(seq_file)

            try:
                # if meet error(like file not found) in merge task, the .merge file may not be deleted
                merged_file_path = f"{seq_file.ts_file_path}{MERGE_SUFFIX}"
                if os.path.exists(merged_file_path):
                    if not os.remove(merged_file_path):
                        logging.warn(f"Delete file {merged_file_path} failed")
                
                self.update_merge_modification(seq_file, unseq_files)
            finally:
                self.double_write_unlock(seq_file)

        try:
            self.remove_merging_modification(seq_files, unseq_files)
            merge_log.delete()
        except IOException as e:
            logging.error(f"{self.full_storage_group_name} a merge task ends but cannot delete log {merge_log}")
        
        logging.info(f"{self.full_storage_group_name} a merge task ends")

    def remove_unseq_files(self, unseq_files: List['TsFileResource']) -> None:
        self.un_seq_ts_file_resource_list.write_lock()
        try:
            for unseq_file in selected_unseq_ts_file_resources:
                self.un_seq_ts_file_resource_list.remove(unseq_file)
            
            if IoTDBDescriptor.getInstance().getConfig().is_meta_data_cache_enable():
                ChunkCache.getInstance().clear()
                TimeSeriesMetadataCache.getInstance().clear()

        finally:
            self.un_seq_ts_file_resource_list.write_unlock()

        for unseq_file in unseq_files:
            unseq_file.write_lock()
            try:
                unseq_file.remove()
            finally:
                unseq_file.write_unlock()

    def double_write_lock(self, seq_file: 'TsFileResource') -> None:
        while True:
            if seq_file.try_write_lock() and self.seq_ts_file_resource_list.try_write_lock():
                break
            else:
                # did not get all of them, release the gotten one and retry
                if self.seq_ts_file_resource_list.write_locked:
                    self.seq_ts_file_resource_list.write_unlock()
                if seq_file.write_locked:
                    seq_file.write_unlock()

    def double_write_unlock(self, seq_file: 'TsFileResource') -> None:
        self.seq_ts_file_resource_list.write_unlock()
        seq_file.write_unlock()

    def update_merge_modification(self, seq_file: 'TsFileResource', unseq_files: List['TsFileResource']) -> None:
        try:
            # remove old modifications and write modifications generated during merge
            seq_file.remove_mod_file()
            compaction_modification_file = ModificationFile.get_compaction_mods(seq_file)
            for modification in compaction_modification_file.modifications():
                seq_file.mod_file.write(modification)

            for unseq_file in unseq_files:
                compaction_unseq_modification_file = ModificationFile.get_compaction_mods(unseq_file)
                for modification in compaction_unseq_modification_file.modifications():
                    seq_file.mod_file.write(modification)

            try:
                seq_file.mod_file.close()
            except IOException as e:
                logging.error(f"Cannot close the ModificationFile {seq_file.mod_file}")
        except IOException as e:
            logging.error(f"{self.full_storage_group_name} cannot clean the ModificationFile of {seq_file.ts_file_path} after cross space merge", e)

    def remove_merging_modification(self, seq_files: List['TsFileResource'], unseq_files: List['TsFileResource']) -> None:
        try:
            for seq_file in seq_files:
                compaction_mods = ModificationFile.get_compaction_mods(seq_file)
                compaction_mods.remove()

            for unseq_file in unseq_files:
                compaction_unseq_modification_file = ModificationFile.get_compaction_mods(unseq_file)
                compaction_unseq_modification_file.remove()
        except IOException as e:
            logging.error(f"{self.full_storage_group_name} cannot remove merging modification", e)

    def equals_other_task(self, other: 'AbstractCompactionTask') -> bool:
        if isinstance(other, InplaceCompactionTask):
            other_task = other
            return not (other_task.selected_seq_ts_file_resources != self.selected_seq_ts_file_resources or 
                        other_task.selected_unseq_ts_file_resources != self.selected_unseq_ts_file_resources)
        return False

    @property
    def full_storage_group_name(self) -> str:
        return f"{self.logical_storage_group_name}-{self.virtual_storage_group_name}"
