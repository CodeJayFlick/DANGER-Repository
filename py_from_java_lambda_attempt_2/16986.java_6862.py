Here is the translation of the Java code into Python:

```Python
import logging
from typing import List, Tuple

class SizeTieredCompactionSelector:
    def __init__(self,
                 logical_storage_group_name: str,
                 virtual_storage_group_name: str,
                 time_partition: int,
                 ts_file_manager: object,
                 ts_file_resources: list,
                 sequence: bool,
                 task_factory: object):
        self.logical_storage_group_name = logical_storage_group_name
        self.virtual_storage_group_name = virtual_storage_group_name
        self.time_partition = time_partition
        self.ts_file_manager = ts_file_manager
        self.ts_file_resources = ts_file_resources
        self.sequence = sequence
        self.task_factory = task_factory

    def select_and_submit(self) -> bool:
        logging.debug(f"{self.logical_storage_group_name}-{self.virtual_storage_group_name} [Compaction] SizeTiredCompactionSelector start to select, target file size is {config.target_compaction_file_size}, target file num is {config.max_compaction_candidate_file_num}, current task num is {compaction_task_manager.current_task_num.get()}, total task num is {compaction_task_manager.task_count}, max task num is {config.concurrent_compaction_thread}")
        self.ts_file_resources.read_lock()
        try:
            max_level = self.search_max_file_level()
            for level in range(max_level + 1):
                if not self.select_level_task(level, priority_queue):
                    break
            while priority_queue.qsize() > 0:
                self.create_and_submit_task(priority_queue.get().left)
        except Exception as e:
            logging.error("Exception occurs while selecting files", e)
        finally:
            self.ts_file_resources.read_unlock()
        return True

    def select_level_task(self, level: int, priority_queue) -> bool:
        should_continue_to_search = True
        selected_file_list = []
        selected_file_size = 0
        target_compaction_file_size = config.target_compaction_file_size

        for file in self.ts_file_resources[::-1]:
            name = TsFileNameGenerator.get_ts_filename(file.ts_file.name)
            if name.inner_compaction_cnt != level:
                selected_file_list.clear()
                selected_file_size = 0
                continue
            logging.debug(f"Current File is {file}, size is {file.ts_file_size}")
            selected_file_list.append(file)
            selected_file_size += file.ts_file_size
            logging.debug(f"Add tsfile {file}, current select file num is {len(selected_file_list)}, size is {selected_file_size}")
            if selected_file_size >= target_compaction_file_size or len(selected_file_list) >= config.max_compaction_candidate_file_num:
                # submit the task
                priority_queue.put((ArrayList(selected_file_list), selected_file_size))
                selected_file_list = []
                selected_file_size = 0
                should_continue_to_search = False
        return should_continue_to_search

    def search_max_file_level(self) -> int:
        max_level = -1
        for file in self.ts_file_resources:
            name = TsFileNameGenerator.get_ts_filename(file.ts_file.name)
            if name.inner_compaction_cnt > max_level:
                max_level = name.inner_compaction_cnt
        return max_level

    def create_and_submit_task(self, selected_file_list: list) -> bool:
        task = self.task_factory.create_task(
            self.logical_storage_group_name,
            self.virtual_storage_group_name,
            self.time_partition,
            self.ts_file_manager,
            self.ts_file_resources,
            selected_file_list,
            self.sequence
        )
        return compaction_task_manager.add_task_to_waiting_queue(task)

    def __del__(self):
        logging.debug(f"SizeTieredCompactionSelector {self.logical_storage_group_name}-{self.virtual_storage_group_name} is being deleted")

config = IoTDBConfig()
compaction_task_manager = CompactionTaskManager()

class SizeTieredCompactionTaskComparator:
    def compare(self, o1: Tuple[List[object], int], o2: Tuple[List[object], int]) -> int:
        resource_of_o1 = o1[0][0]
        resource_of_o2 = o2[0][0]
        try:
            name_of_o1 = TsFileNameGenerator.get_ts_filename(resource_of_o1.ts_file.name)
            name_of_o2 = TsFileNameGenerator.get_ts_filename(resource_of_o2.ts_file.name)
            if name_of_o1.inner_compaction_cnt != name_of_o2.inner_compaction_cnt:
                return name_of_o2.inner_compaction_cnt - name_of_o1.inner_compaction_cnt
        except Exception as e:
            logging.error("Exception occurs while comparing", e)
            return 0
        if len(o1[0]) != len(o2[0]):
            return len(o2[0]) - len(o1[0])
        else:
            return o2[1] - o1[1]

priority_queue = PriorityQueue()
```

Note: This translation is not a direct conversion from Java to Python. It's more like rewriting the code in Python, while trying to maintain the same logic and functionality as the original Java code.