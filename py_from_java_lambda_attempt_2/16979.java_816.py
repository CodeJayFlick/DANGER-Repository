Here is the translation of the Java code into Python:

```Python
import logging
from typing import List, Tuple
from queue import PriorityQueue

class MergeMultiChunkTask:
    def __init__(self,
                 merge_context: object,
                 task_name: str,
                 merge_logger: object,
                 resource: object,
                 full_merge: bool,
                 unmerged_series: List[object],
                 concurrent_merge_series_num: int,
                 storage_group_name: str):
        self.merge_context = merge_context
        self.task_name = task_name
        self.merge_logger = merge_logger
        self.resource = resource
        self.full_merge = full_merge
        self.unmerged_series = unmerged_series
        self.concurrent_merge_series_num = concurrent_merge_series_num
        self.storage_group_name = storage_group_name

    def merge_series(self) -> None:
        if logging.getLogger().isEnabledFor(logging.INFO):
            logging.info(f"{self.task_name} starts to merge {len(self.unmerged_series)} series")
        start_time = int(time.time())
        for seq_file in self.resource.get_seq_files():
            # record the unmerge_chunk_start_times for each sensor in each file
            self.merge_context.get_unmerged_chunk_start_times().put(seq_file, {})
        # merge each series and write data into each seqFile's corresponding temp merge file
        device_paths = [list(self.unmerged_series)]
        for path_list in device_paths:
            if logging.getLogger().isEnabledFor(logging.INFO):
                logging.info(f"Processing {path_list}")
            self.merge_paths(path_list)
            self.resource.clear_chunk_writer_cache()
            if threading.current_thread().interrupted():
                logging.error(f"{self.task_name} aborted")
                return
        measurement_chunk_metadata_list_map_iterator = {}
        for seq_file in self.resource.get_seq_files():
            # all paths in one call are from the same device
            device_id = path_list[0].get_device()
            curr_device_min_time = int(seq_file.get_start_time(device_id))
            for time_value_pair in self.curr_time_value_pairs:
                if time_value_pair and time_value_pair.timestamp < curr_device_min_time:
                    curr_device_min_time = time_value_pair.timestamp
        is_last_file = len(self.resource.get_seq_files()) - 1 == i
        ts_file_sequence_reader = self.resource.get_file_reader(seq_file)
        list_of_list_chunk_metadata = []
        for _ in range(len(path_list)):
            list_of_list_chunk_metadata.append([])
        # merge unseq data with seq data in this file or small chunks in this file into a larger chunk
        restorable_ts_file_iowriter = self.resource.get_merge_file_writer(seq_file)
        start_chunk_group(device_id)
        for path_idx, (path, time_value_pair) in enumerate(zip(path_list, self.curr_time_value_pairs)):
            if seq_chunk_meta[path_idx] is None or not seq_chunk_meta[path_idx]:
                continue
            meta_entry = MetaListEntry(path_idx, seq_chunk_meta[path_idx])
            entry.next()
        end_chunk_group()

    def merge_paths(self, path_list: List[object]) -> None:
        for i in range(len(path_list)):
            if logging.getLogger().isEnabledFor(logging.INFO):
                logging.info(f"Processing {path_list[i]}")
            self.merge_context.get_unmerged_chunk_start_times().put(seq_file, {})
        # record the unmerge_chunk_start_times for each sensor in each file
        measurement_chunk_metadata_list_map_iterator = {}
        for seq_file in self.resource.get_seq_files():
            # all paths in one call are from the same device
            device_id = path_list[0].get_device()
            curr_device_min_time = int(seq_file.get_start_time(device_id))
            for time_value_pair in self.curr_time_value_pairs:
                if time_value_pair and time_value_pair.timestamp < curr_device_min_time:
                    curr_device_min_time = time_value_pair.timestamp
        is_last_file = len(self.resource.get_seq_files()) - 1 == i

    def get_progress(self) -> str:
        return f"Processed {len(self.unmerged_series)} series"

class MetaListEntry:
    def __init__(self, path_idx: int, chunk_metadata_list: List[object]):
        self.path_idx = path_idx
        self.chunk_metadata_list = chunk_metadata_list

    @property
    def current(self) -> object:
        return self.chunk_metadata_list[self.path_idx]

class MergeChunkHeapTask:
    def __init__(self,
                 chunk_idx_heap: PriorityQueue[int],
                 meta_list_entries: List[MetaListEntry],
                 pt_writtens: List[int],
                 ts_file_sequence_reader: object,
                 restorable_ts_file_iowriter: object,
                 unseq_readers: List[object],
                 curr_file: object):
        self.chunk_idx_heap = chunk_idx_heap
        self.meta_list_entries = meta_list_entries
        self.pt_writtens = pt_writtens
        self.ts_file_sequence_reader = ts_file_sequence_reader
        self.restorable_ts_file_iowriter = restorable_ts_file_iowriter
        self.unseq_readers = unseq_readers

    def merge_chunk_heap(self) -> None:
        while not self.chunk_idx_heap.empty():
            path_idx = self.chunk_idx_heap.poll()
            # chunkWriter will keep the data in memory
            measurement_schema = resource.get_schema(path_list[path_idx])
            if threading.current_thread().interrupted():
                logging.error(f"{self.task_name} aborted")
                return

    def get_storage_group_name(self) -> str:
        return self.storage_group_name

class MergeManager:
    @staticmethod
    def submit_chunk_sub_task(task: object, chunk_writer: object):
        pass