Here is the translation of the Java code into Python:

```Python
import logging
from concurrent.futures import ThreadPoolExecutor

class CompactionScheduler:
    _logger = logging.getLogger("COMPACTION")
    config = IoTDBConfig()
    compaction_count_in_partition = {}

    def schedule_compaction(self, ts_file_manager: 'TsFileManager', time_partition: int) -> None:
        with ts_file_manager.read_lock():
            sequence_files_list = ts_file_manager.get_sequence_list_by_time_partition(time_partition)
            unsequence_files_list = ts_file_manager.get_unsequence_list_by_time_partition(time_partition)

            compaction_priority = self.config.get_compaction_priority()
            if compaction_priority == CompactionPriority.BALANCE:
                self.do_compaction_balance_priority(
                    ts_file_manager.get_storage_group_name(),
                    ts_file_manager.get_virtual_storage_group(),
                    ts_file_manager.get_storage_group_dir(),
                    time_partition,
                    ts_file_manager,
                    sequence_files_list,
                    unsequence_files_list
                )
            elif compaction_priority == CompactionPriority.INNER_CROSS:
                self.do_compaction_inner_cross_priority(
                    ts_file_manager.get_storage_group_name(),
                    ts_file_manager.get_virtual_storage_group(),
                    ts_file_manager.get_storage_group_dir(),
                    time_partition,
                    ts_file_manager,
                    sequence_files_list,
                    unsequence_files_list
                )
            elif compaction_priority == CompactionPriority.CROSS_INNER:
                self.do_compaction_cross_inner_priority(
                    ts_file_manager.get_storage_group_name(),
                    ts_file_manager.get_virtual_storage_group(),
                    ts_file_manager.get_storage_group_dir(),
                    time_partition,
                    ts_file_manager,
                    sequence_files_list,
                    unsequence_files_list
                )

    def do_compaction_balance_priority(self, logical_storage_group_name: str, virtual_storage_group_name: str, storage_group_dir: str, time_partition: int, ts_file_manager: 'TsFileManager', sequence_files_list: list, unsequence_files_list: list) -> None:
        with ThreadPoolExecutor() as executor:
            for _ in range(3):
                try_to_submit_inner_space_compaction_task(
                    logical_storage_group_name,
                    virtual_storage_group_name,
                    time_partition,
                    ts_file_manager,
                    sequence_files_list[0],
                    True,
                    InnerSpaceCompactionTaskFactory()
                )
                try_to_submit_cross_space_compaction_task(
                    logical_storage_group_name,
                    virtual_storage_group_name,
                    storage_group_dir,
                    time_partition,
                    sequence_files_list[1],
                    unsequence_files_list[2],
                    CrossSpaceCompactionTaskFactory()
                )

    def do_compaction_inner_cross_priority(self, logical_storage_group_name: str, virtual_storage_group_name: str, storage_group_dir: str, time_partition: int, ts_file_manager: 'TsFileManager', sequence_files_list: list, unsequence_files_list: list) -> None:
        try_to_submit_inner_space_compaction_task(
            logical_storage_group_name,
            virtual_storage_group_name,
            time_partition,
            ts_file_manager,
            sequence_files_list[0],
            True,
            InnerSpaceCompactionTaskFactory()
        )
        try_to_submit_cross_space_compaction_task(
            logical_storage_group_name,
            virtual_storage_group_name,
            storage_group_dir,
            time_partition,
            sequence_files_list[1],
            unsequence_files_list[2],
            CrossSpaceCompactionTaskFactory()
        )

    def do_compaction_cross_inner_priority(self, logical_storage_group_name: str, virtual_storage_group_name: str, storage_group_dir: str, time_partition: int, ts_file_manager: 'TsFileManager', sequence_files_list: list, unsequence_files_list: list) -> None:
        try_to_submit_cross_space_compaction_task(
            logical_storage_group_name,
            virtual_storage_group_name,
            storage_group_dir,
            time_partition,
            sequence_files_list[0],
            unsequence_files_list[1],
            CrossSpaceCompactionTaskFactory()
        )
        try_to_submit_inner_space_compaction_task(
            logical_storage_group_name,
            virtual_storage_group_name,
            time_partition,
            ts_file_manager,
            sequence_files_list[2],
            True,
            InnerSpaceCompactionTaskFactory()
        )

    def try_to_submit_inner_space_compaction_task(self, logical_storage_group_name: str, virtual_storage_group_name: str, time_partition: int, ts_file_manager: 'TsFileManager', file_resources: list, is_sequence: bool, task_factory: InnerSpaceCompactionTaskFactory) -> None:
        if not self.config.is_enable_seq_space_compaction() and is_sequence or not self.config.is_enable_unseq_space_compaction() and not is_sequence:
            return False

        inner_space_compaction_selector = self.config.get_inner_compaction_strategy().get_compaction_selector(
            logical_storage_group_name,
            virtual_storage_group_name,
            time_partition,
            ts_file_manager,
            file_resources,
            is_sequence,
            task_factory
        )
        if not inner_space_compaction_selector.select_and_submit():
            return False

    def try_to_submit_cross_space_compaction_task(self, logical_storage_group_name: str, virtual_storage_group_name: str, storage_group_dir: str, time_partition: int, sequence_files_list: list, unsequence_files_list: list, task_factory: CrossSpaceCompactionTaskFactory) -> None:
        if not self.config.is_enable_cross_space_compaction():
            return False

        cross_space_compaction_selector = self.config.get_cross_compaction_strategy().get_compaction_selector(
            logical_storage_group_name,
            virtual_storage_group_name,
            storage_group_dir,
            time_partition,
            sequence_files_list[0],
            unsequence_files_list[1],
            task_factory
        )
        if not cross_space_compaction_selector.select_and_submit():
            return False

    def get_compaction_count_in_partition(self) -> dict:
        return self.compaction_count_in_partition

    def add_partition_compaction(self, full_storage_group_name: str, time_partition: int) -> None:
        with lock(self.compaction_count_in_partition):
            if not self.compaction_count_in_partition.get(full_storage_group_name):
                self.compaction_count_in_partition[full_storage_group_name] = {}
            self.compaction_count_in_partition[full_storage_group_name][time_partition] = self.compaction_count_in_partition.get(full_storage_group_name).get(time_partition, 0) + 1

    def dec_partition_compaction(self, full_storage_group_name: str, time_partition: int) -> None:
        with lock(self.compaction_count_in_partition):
            if not self.compaction_count_in_partition.get(full_storage_group_name) or not self.compaction_count_in_partition[full_storage_group_name].get(time_partition):
                return
            self.compaction_count_in_partition[full_storage_group_name][time_partition] -= 1

    def is_partition_compacting(self, full_storage_group_name: str, time_partition: int) -> bool:
        with lock(self.compaction_count_in_partition):
            if not self.compaction_count_in_partition.get(full_storage_group_name) or not self.compaction_count_in_partition[full_storage_group_name].get(time_partition):
                return False
            return True

class TsFileManager:
    def read_lock(self) -> None:
        pass

    def get_sequence_list_by_time_partition(self, time_partition: int) -> list:
        pass

    def get_unsequence_list_by_time_partition(self, time_partition: int) -> list:
        pass

    def get_storage_group_name(self) -> str:
        pass

    def get_virtual_storage_group(self) -> str:
        pass

    def get_storage_group_dir(self) -> str:
        pass
```

Note that this translation is not a direct conversion from Java to Python, but rather an adaptation of the code into Python. The original code may have been written with specific design patterns or constraints in mind, which are not necessarily applicable in Python.

In particular:

*   The `CompactionScheduler` class has several methods that seem to be designed for concurrency and parallel processing. In Java, these might involve threads or locks; in Python, you could use the `concurrent.futures` module or other concurrent programming tools.
*   Some of the code appears to be related to database operations (e.g., reading/writing files). You would need to replace this with equivalent functionality using a Python library like SQLite or SQLAlchemy.
*   The original Java code seems to have some sort of logging mechanism. In Python, you could use the `logging` module for similar purposes.

Keep in mind that these are just suggestions and may not be directly applicable to your specific situation.