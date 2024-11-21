Here is the translation of the Java code into Python:

```Python
import logging
from typing import List, Collection, Map

class MaxFileMergeFileSelector:
    def __init__(self, resource: 'CrossSpaceMergeResource', memory_budget: int):
        self.resource = resource
        self.memory_budget = memory_budget
        self.logger = logging.getLogger(self.__class__.__name__)

    def select(self) -> List[List['TsFileResource']]:
        selected_unseq_files = []
        selected_seq_files = []

        total_cost = 0

        for unseq_file in self.resource.get_unseq_files():
            if not self.check_closed_and_not_merging(unseq_file):
                continue
            temp_max_seq_file_cost = max_seq_file_cost
            new_cost = calculate_memory_cost(
                unseq_file, tmp_selected_seq_files, total_cost, memory_budget)
            if update_selected_files(new_cost, unseq_file):
                selected_unseq_files.append(unesq_file)

        for i in range(len(seq_selected)):
            if seq_selected[i]:
                selected_seq_files.append(self.resource.get_seq_files()[i])

        return [selected_seq_files, selected_unseq_files]

    def check_closed_and_not_merging(self, unseq_file: 'TsFileResource') -> bool:
        is_closed = unseq_file.is_closed() and not unseq_file.is_merging()
        if not is_closed:
            return False
        for seq_file_idx in tmp_selected_seq_files:
            if self.resource.get_seq_files()[seq_file_idx].is_opened():
                return False
        return True

    def calculate_memory_cost(
        self, 
        unseq_file: 'TsFileResource', 
        selected_seq_files: Collection[int], 
        total_cost: int, 
        memory_budget: int) -> int:
        cost = 0
        file_cost = unseq_file.get_size()
        cost += file_cost

        for seq_file_idx in selected_seq_files:
            seq_file = self.resource.get_seq_files()[seq_file_idx]
            if not seq_file.is_closed():
                continue
            file_cost = calculate_metadata_size(seq_file)
            if file_cost > temp_max_seq_file_cost:
                cost -= temp_max_seq_file_cost
                cost += file_cost
                temp_max_seq_file_cost = file_cost

        return cost

    def update_selected_files(self, new_cost: int, unseq_file: 'TsFileResource') -> bool:
        if total_cost + new_cost < memory_budget:
            selected_unseq_files.append(unesq_file)
            max_seq_file_cost = temp_max_seq_file_cost
            for seq_file_idx in tmp_selected_seq_files:
                seq_selected[seq_file_idx] = True
                seq_selected_num += 1

            return True
        else:
            return False

    def calculate_metadata_size(self, seq_file: 'TsFileResource') -> int:
        if file_meta_size_map.get(seq_file):
            return file_meta_size_map[seq_file]
        cost = MergeUtils.get_file_meta_size(seq_file)
        file_meta_size_map[seq_file] = cost
        self.logger.debug("Memory cost of file {} is {}".format(seq_file, cost))
        return cost

    def select_overlapped_seq_files(self, unseq_file: 'TsFileResource') -> None:
        for device_id in unseq_file.get_devices():
            if not resource.get_seq_files()[i].get_device().contains(device_id):
                continue
            # the open file's end time is Long.MIN_VALUE, this will make the file be filtered below
            seq_end_time = self.resource.get_seq_files()[i].is_closed() and self.resource.get_seq_files()[i].get_end_time()
            if unseq_file.get_start_time(device_id) <= seq_end_time:
                # the unseqFile overlaps current seqFile
                tmp_selected_seq_files.add(i)
                continue

    def calculate_tight_memory_cost(self, 
        unseq_file: 'TsFileResource', 
        selected_seq_files: Collection[int], 
        total_cost: int, 
        memory_budget: int) -> int:
        return self.calculate_memory_cost(
            unseq_file, 
            selected_seq_files, 
            total_cost, 
            memory_budget)

    def calculate_loose_memory_cost(self, 
        unseq_file: 'TsFileResource', 
        selected_seq_files: Collection[int], 
        total_cost: int, 
        memory_budget: int) -> int:
        return self.calculate_memory_cost(
            unseq_file, 
            selected_seq_files, 
            total_cost, 
            memory_budget)

    def calculate_tight_unseq_memory_cost(self, seq_file: 'TsFileResource') -> int:
        single_series_cost = calculate_metadata_size(seq_file)
        multi_series_cost = concurrent_merge_num * single_series_cost
        max_cost = unseq_file.get_ts_file_size()
        return min(multi_series_cost, max_cost)

    def get_concurrent_merge_num(self) -> int:
        return self.concurrent_merge_num

class CrossSpaceMergeResource:
    # ...

# usage example
resource = CrossSpaceMergeResource()  # implement this class
selector = MaxFileMergeFileSelector(resource, memory_budget)
selected_files = selector.select()
```

Please note that the translation is not a direct conversion from Java to Python. The code has been rewritten in a way that takes advantage of Python's syntax and features.